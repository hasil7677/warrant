"""
test_identity_delegation.py
───────────────────────────
Red-team suite for the delegation layer (`warrant/identity.py`).

`test_policy_adversarial.py` asks whether the model can talk its way past the
policy. This file asks the other question, the one the delegation layer exists
to answer:

    Can an agent end up wielding authority nobody gave it?

There are two independent ways that can happen, and `identity.py` claims two
independent mechanisms against them. The organising principle of this file is
that **each mechanism is tested with the other one disabled**, because a suite
that only ever tests them together cannot tell you which one is load-bearing -
and a refactor that silently removes one would keep passing.

  §A  Amplification.   A holder mints a child that claims more than it holds.
                       Every signature is valid; nothing is forged. Defended by
                       the attenuation checks. Tested by hand-building grants
                       that are *correctly signed* and still widen - i.e. with
                       the MAC defence fully intact and useless.

  §B  Forgery.         A grant is fabricated or edited. It may attenuate
                       perfectly. Defended by the chained MAC. Tested with
                       chains that would sail through every attenuation check.

  §C  Structure.       Chains that are individually-valid grants stitched
                       together wrongly - spliced, truncated, reordered,
                       repeated.

  §D  Time.            Expiry, including the "child outlives parent" case.

  §E  Revocation.      Killing any link kills its descendants.

  §F  Leaf authority.  The sub-agent is authorized as ITSELF, never as its
                       delegator. This is the property the whole design is for.

  §G  Fail closed.     Missing secret, unreadable revocation list, garbage
                       input, naive timestamps.

  §H  Integration.     Through `policy.check()` and through `Broker.execute()`,
                       including what lands in the journal.

Tests assert on `rule_ids`, which are stable, more than on message text.
"""

from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from warrant import identity as ident  # noqa: E402
from warrant import journal as journal_mod  # noqa: E402
from warrant import policy as policy_mod  # noqa: E402
from warrant.broker import Broker  # noqa: E402
from warrant.contract import Proposal  # noqa: E402
from warrant.identity import (  # noqa: E402
    AmplificationError,
    Grant,
    IdentityError,
    Principal,
    Revocations,
    attenuate,
    authorize,
    issue_root,
    verify_chain,
)
from warrant.ledger import Ledger  # noqa: E402

SECRET = b"test-root-secret-not-the-real-one"

OPERATOR = Principal("user", "sahil")
RESEARCH = Principal("agent", "research-1")
ANALYSIS = Principal("agent", "analysis-1")
EXECUTION = Principal("agent", "execution-1")
INTRUDER = Principal("agent", "intruder")

# notion.create_page is the workhorse tool here: the registry tags it
# write+reversible, so its only *hazard* class is `write` (reversibility is
# excluded from the grant comparison - see Grant.permits_tool) and a grant
# carrying {write} covers it exactly. gmail.send additionally carries
# third_party and irreversible, which makes it the natural "further out" tool
# for testing that a narrowed grant stops short.
NOTION = "notion.create_page"
GMAIL = "gmail.send"

FUTURE = datetime(2099, 1, 1, tzinfo=timezone.utc)
PAST = datetime(2000, 1, 1, tzinfo=timezone.utc)


# ── builders ────────────────────────────────────────────────────────────────


def root(classes=("write", "third_party", "irreversible"), **kw) -> Grant:
    """The operator's grant to the research agent - the top of every chain
    below unless a test is specifically attacking the root."""
    return issue_root(
        grant_id=kw.pop("grant_id", "g-root"),
        issuer=kw.pop("issuer", OPERATOR),
        subject=kw.pop("subject", RESEARCH),
        classes=classes,
        secret=SECRET,
        **kw,
    )


def resign(chain: list[Grant]) -> list[Grant]:
    """Re-seal a hand-built chain so every signature is correct.

    This helper is what makes §A meaningful. An amplification attack that also
    happened to break a signature would be caught by the MAC, and the test
    would pass for the wrong reason - proving nothing about the attenuation
    check. Running a malicious chain through here first removes the forgery
    defence entirely, so the only thing left that can refuse it is attenuation.
    """
    sealed = [chain[0].seal(SECRET)]
    for link in chain[1:]:
        sealed.append(link.seal(sealed[-1].sig.encode("utf-8")))
    return sealed


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """No test here may read the machine's real revocation list or root secret."""
    monkeypatch.setattr(ident, "REVOCATION_FILE", tmp_path / "revoked-grants.txt")
    monkeypatch.delenv(ident.ROOT_SECRET_ENV, raising=False)
    return tmp_path


# ════════════════════════════════════════════════════════════════════════════
# §A  Amplification - correctly signed chains that try to widen
# ════════════════════════════════════════════════════════════════════════════


def test_the_happy_path_actually_works():
    """The baseline that keeps the rest of this file honest.

    Almost every assertion below is a refusal, so this one exists to prove the
    layer is not trivially refusing everything - which would make the whole
    suite pass while the feature did nothing.
    """
    r = root()
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    verdict = authorize([r, child], NOTION, secret=SECRET)
    assert verdict.allowed, verdict.reasons
    assert verdict.principal == ANALYSIS
    assert verdict.on_behalf_of == OPERATOR
    assert verdict.chain_ids == ("g-root", "g-1")


def test_attenuate_refuses_to_mint_a_wider_child():
    """The first line of defence: the mistake is caught where it is made, with
    a traceback pointing at the delegating code."""
    r = root(classes=["write"])
    with pytest.raises(AmplificationError) as exc:
        attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write", "spend"])
    assert "spend" in str(exc.value)


def test_a_hand_built_wider_child_is_refused_even_though_it_is_correctly_signed():
    """§A's core test, and the reason `attenuate()` is not the security boundary.

    Nothing here goes through `attenuate()`. The attacker constructs the child
    directly, gives it a class its parent never held, and seals the whole chain
    with `resign()` so every MAC verifies. The forgery defence is therefore
    completely satisfied and completely irrelevant - if the attenuation re-check
    in `verify_chain()` were removed, this chain would be honoured.
    """
    r = root(classes=["write"])
    widened = Grant(
        grant_id="g-1",
        issuer=RESEARCH,
        subject=ANALYSIS,
        classes=frozenset({"write", "spend"}),
        parent_id="g-root",
    )
    chain = resign([r, widened])

    assert chain[1].signature_matches(chain[0].sig.encode("utf-8")), (
        "the attack chain must be correctly signed, or this test proves nothing"
    )
    verdict = verify_chain(chain, secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_amplified",)
    assert "spend" in verdict.reasons[0]


def test_a_grandchild_cannot_recover_a_class_its_parent_dropped():
    """Authority lost on the way down stays lost. A three-link chain where the
    middle narrows and the leaf tries to widen back to the root's set - the leaf
    is compared against its PARENT, not against the root."""
    r = root(classes=["write", "third_party", "irreversible"])
    mid = Grant(
        grant_id="g-1", issuer=RESEARCH, subject=ANALYSIS,
        classes=frozenset({"write"}), parent_id="g-root",
    )
    leaf = Grant(
        grant_id="g-2", issuer=ANALYSIS, subject=EXECUTION,
        classes=frozenset({"write", "third_party"}), parent_id="g-1",
    )
    verdict = verify_chain(resign([r, mid, leaf]), secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_amplified",)
    assert "third_party" in verdict.reasons[0]


def test_a_child_cannot_widen_the_tool_restriction():
    r = root()
    narrowed = attenuate(r, grant_id="g-1", subject=ANALYSIS, tools=[NOTION])
    with pytest.raises(AmplificationError):
        attenuate(narrowed, grant_id="g-2", subject=EXECUTION, tools=[NOTION, GMAIL])


def test_emptying_the_tool_list_does_not_lift_the_restriction():
    """The subtle one. `tools=frozenset()` means "no tool-level restriction", so
    a child that empties a restricted parent's list is WIDER, not narrower - and
    a naive subset check (`child.tools <= parent.tools`) returns True for the
    empty set and lets it through."""
    r = root()
    narrowed = attenuate(r, grant_id="g-1", subject=ANALYSIS, tools=[NOTION])

    with pytest.raises(AmplificationError):
        attenuate(narrowed, grant_id="g-2", subject=EXECUTION, tools=[])

    # And again at verification time, hand-built and correctly signed.
    unrestricted = Grant(
        grant_id="g-2", issuer=ANALYSIS, subject=EXECUTION,
        classes=narrowed.classes, tools=frozenset(), parent_id="g-1",
    )
    verdict = verify_chain(resign([r, narrowed, unrestricted]), secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_amplified",)


def test_a_chain_can_only_ever_narrow_never_widen():
    """The invariant stated directly, over a five-link chain: every link's
    capability set is a subset of the one before it, and the leaf's is a subset
    of the root's."""
    chain = [root(classes=["write", "third_party", "irreversible", "egress"])]
    for i, classes in enumerate(
        [
            ["write", "third_party", "irreversible"],
            ["write", "third_party"],
            ["write"],
            ["write"],
        ]
    ):
        chain.append(
            attenuate(chain[-1], grant_id=f"g-{i}", subject=Principal("agent", f"a{i}"),
                      classes=classes)
        )

    assert verify_chain(chain, secret=SECRET).allowed
    for parent, child in zip(chain, chain[1:]):
        assert child.classes <= parent.classes
    assert chain[-1].classes < chain[0].classes


# ════════════════════════════════════════════════════════════════════════════
# §B  Forgery - perfectly-attenuating chains that were never issued
# ════════════════════════════════════════════════════════════════════════════


def test_a_fabricated_root_is_refused():
    """An attacker who knows the whole schema but not the secret. The chain
    attenuates perfectly; there is nothing for §A's defence to catch."""
    forged = Grant(
        grant_id="g-root", issuer=OPERATOR, subject=INTRUDER,
        classes=frozenset({"write", "third_party", "irreversible"}),
    ).seal(b"the-wrong-secret")

    verdict = verify_chain([forged], secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_forged",)


def test_an_unsigned_grant_is_not_trusted():
    """There is no "unsigned but obviously fine" grant. A Grant built by hand
    and never sealed carries `sig=""`, and the empty signature must not compare
    equal to anything."""
    bare = Grant(grant_id="g-root", issuer=OPERATOR, subject=INTRUDER,
                 classes=frozenset({"write"}))
    assert bare.sig == ""
    verdict = verify_chain([bare], secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_forged",)


@pytest.mark.parametrize(
    "field,value",
    [
        ("classes", frozenset({"write", "third_party", "irreversible", "spend"})),
        ("subject", INTRUDER),
        ("expires_at", FUTURE),
        ("tools", frozenset({GMAIL})),
        ("grant_id", "g-something-else"),
    ],
)
def test_editing_a_sealed_grant_invalidates_it(field, value):
    """Every field in `_body()` is covered by the MAC. A test per field, because
    a field accidentally left out of `_body()` is exactly the bug that would not
    show up any other way - the grant would verify AND carry the edit."""
    r = root()
    tampered = replace(r, **{field: value})
    verdict = verify_chain([tampered], secret=SECRET)
    assert not verdict.allowed, f"editing {field} was not detected"
    assert verdict.rule_ids == ("delegation_forged",)


def test_editing_an_ancestor_invalidates_every_descendant():
    """The chaining property. The attacker widens the ROOT - which they cannot
    re-sign, but suppose they could: the child's MAC was keyed by the ORIGINAL
    root signature, so a re-sealed root breaks the child even though the child
    itself was never touched."""
    r = root(classes=["write"])
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS)

    widened_root = replace(r, classes=frozenset({"write", "spend"})).seal(SECRET)
    assert widened_root.signature_matches(SECRET), "the widened root is itself well-formed"

    verdict = verify_chain([widened_root, child], secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_forged",)
    assert "g-1" in verdict.reasons[0]


def test_a_holder_cannot_mint_a_sibling_of_its_own_grant():
    """The macaroon property that bounds what a holder can do.

    The research agent holds `g-root` and therefore knows `g-root.sig` - enough
    to mint children. It tries instead to mint a *replacement for itself* with
    more authority, keyed by the only secret it has (its own signature). That
    produces a grant whose MAC is keyed one level too deep, and the root check
    rejects it.
    """
    r = root(classes=["write"])
    self_promotion = Grant(
        grant_id="g-root-v2", issuer=OPERATOR, subject=RESEARCH,
        classes=frozenset({"write", "spend", "egress"}),
    ).seal(r.sig.encode("utf-8"))  # the best key the holder has

    verdict = verify_chain([self_promotion], secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_forged",)


def test_signature_comparison_is_constant_time():
    """`==` on a hex digest leaks the correct prefix byte by byte. Asserted
    structurally because the timing itself is not testable in a unit test."""
    import inspect

    src = inspect.getsource(Grant.signature_matches)
    assert "compare_digest" in src
    assert "==" not in src.split('"""')[-1], "signature comparison must not use =="


# ════════════════════════════════════════════════════════════════════════════
# §C  Structure - valid grants stitched together wrongly
# ════════════════════════════════════════════════════════════════════════════


def test_a_grant_spliced_from_another_chain_is_refused():
    """Two chains issued by the same operator. A child minted under chain A is
    presented hanging off chain B's root - both roots are genuine, the child is
    genuine, and the combination is not."""
    root_a = root(grant_id="g-a", subject=RESEARCH)
    root_b = root(grant_id="g-b", subject=EXECUTION)
    child_of_a = attenuate(root_a, grant_id="g-a1", subject=ANALYSIS, classes=["write"])

    verdict = verify_chain([root_b, child_of_a], secret=SECRET)
    assert not verdict.allowed
    # Caught on structure (it names g-a as its parent, but follows g-b) before
    # the MAC is ever consulted - a broken chain should not need crypto to
    # notice.
    assert verdict.rule_ids == ("delegation",)
    assert "g-a" in verdict.reasons[0]


def test_authority_does_not_jump_between_principals():
    """A grant issued BY a principal that does not hold the preceding link.
    Correctly signed via `resign()`, so only the contiguity check can catch it."""
    r = root()
    orphan = Grant(
        grant_id="g-1", issuer=INTRUDER, subject=INTRUDER,
        classes=frozenset({"write"}), parent_id="g-root",
    )
    verdict = verify_chain(resign([r, orphan]), secret=SECRET)
    assert not verdict.allowed
    assert "does not jump" in verdict.reasons[0]


def test_a_truncated_chain_is_refused():
    """Dropping the middle link would hide a narrowing. The leaf is presented
    directly under the root it descends from transitively."""
    r = root()
    mid = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    leaf = attenuate(mid, grant_id="g-2", subject=EXECUTION, classes=["write"])

    verdict = verify_chain([r, leaf], secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation",)


def test_a_root_that_claims_a_parent_is_refused():
    """The other half of truncation: a chain whose first link admits something
    preceded it."""
    orphan = Grant(
        grant_id="g-1", issuer=RESEARCH, subject=ANALYSIS,
        classes=frozenset({"write"}), parent_id="g-root",
    ).seal(SECRET)
    verdict = verify_chain([orphan], secret=SECRET)
    assert not verdict.allowed
    assert "nothing precedes it" in verdict.reasons[0]


def test_a_repeated_grant_id_is_refused():
    """A duplicate id makes revocation ambiguous - revoking it would kill one
    copy and not obviously the other - and makes the journal unable to say which
    grant authorized the action."""
    r = root()
    child = attenuate(r, grant_id="g-root", subject=ANALYSIS, classes=["write"])
    verdict = verify_chain([r, child], secret=SECRET)
    assert not verdict.allowed
    assert "repeats a grant id" in verdict.reasons[0]


def test_an_empty_chain_is_refused():
    verdict = verify_chain([], secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation",)


def test_a_chain_deeper_than_the_limit_is_refused():
    chain = [root()]
    for i in range(ident.MAX_CHAIN_DEPTH + 2):
        chain.append(
            attenuate(chain[-1], grant_id=f"g-{i}", subject=Principal("agent", f"a{i}"))
        )
    verdict = verify_chain(chain, secret=SECRET)
    assert not verdict.allowed
    assert "deep" in verdict.reasons[0]


def test_a_chain_rooted_at_an_undeclared_authority_is_refused():
    """A validly-signed grant from an identity the policy does not recognise.
    This matters for a multi-tenant host: one root secret, many operators, and
    tenant A's genuine grant must not be authority in tenant B's gate."""
    r = root(issuer=Principal("user", "someone-else"))
    verdict = verify_chain([r], secret=SECRET, roots=["sahil"])
    assert not verdict.allowed
    assert "not a declared root authority" in verdict.reasons[0]

    assert verify_chain([root()], secret=SECRET, roots=["sahil"]).allowed


# ════════════════════════════════════════════════════════════════════════════
# §D  Time
# ════════════════════════════════════════════════════════════════════════════


def test_an_expired_grant_is_refused():
    r = issue_root(
        grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
        classes=["write"], expires_at=PAST, secret=SECRET,
    )
    verdict = verify_chain([r], secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_expired",)


def test_an_expired_ancestor_kills_a_live_descendant():
    """The leaf's own expiry is in the future; its parent's is not."""
    now = datetime.now(timezone.utc)
    r = issue_root(
        grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
        classes=["write"], expires_at=now + timedelta(hours=1), secret=SECRET,
    )
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS,
                      expires_at=now + timedelta(minutes=30))

    assert verify_chain([r, child], secret=SECRET, now=now).allowed
    later = verify_chain([r, child], secret=SECRET, now=now + timedelta(hours=2))
    assert not later.allowed
    assert later.rule_ids == ("delegation_expired",)


def test_a_child_cannot_outlive_its_parent():
    now = datetime.now(timezone.utc)
    r = issue_root(
        grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
        classes=["write"], expires_at=now + timedelta(hours=1), secret=SECRET,
    )
    with pytest.raises(AmplificationError):
        attenuate(r, grant_id="g-1", subject=ANALYSIS, expires_at=now + timedelta(days=1))

    # A child with NO expiry is unbounded, which also outlives a bounded parent.
    with pytest.raises(AmplificationError):
        attenuate(r, grant_id="g-1", subject=ANALYSIS, expires_at=None)


def test_an_immortal_hand_built_child_of_a_mortal_parent_is_refused():
    """Same attack as above, routed around `attenuate()` and correctly signed."""
    now = datetime.now(timezone.utc)
    r = issue_root(
        grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
        classes=["write"], expires_at=now + timedelta(hours=1), secret=SECRET,
    )
    immortal = Grant(
        grant_id="g-1", issuer=RESEARCH, subject=ANALYSIS,
        classes=frozenset({"write"}), expires_at=None, parent_id="g-root",
    )
    verdict = verify_chain(resign([r, immortal]), secret=SECRET, now=now)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_amplified",)


def test_a_naive_timestamp_is_refused_not_assumed_utc():
    """An expiry with no zone means a different lifetime on every machine that
    reads it - up to a day of authority appearing or vanishing by geography."""
    with pytest.raises(IdentityError) as exc:
        issue_root(
            grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
            classes=["write"], expires_at=datetime(2099, 1, 1), secret=SECRET,
        )
    assert "timezone" in str(exc.value)


# ════════════════════════════════════════════════════════════════════════════
# §E  Revocation
# ════════════════════════════════════════════════════════════════════════════


def test_revoking_the_root_kills_the_whole_tree():
    r = root()
    mid = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    leaf = attenuate(mid, grant_id="g-2", subject=EXECUTION, classes=["write"])

    rev = Revocations()
    rev.revoke("g-root")
    verdict = authorize([r, mid, leaf], NOTION, secret=SECRET, revocations=rev)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_revoked",)


def test_revoking_a_middle_link_kills_its_descendants_but_not_its_ancestors():
    """The property that makes a flat set sufficient: no subtree walk, and no
    way for a deep leaf to survive a revoked ancestor."""
    r = root()
    mid = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    leaf = attenuate(mid, grant_id="g-2", subject=EXECUTION, classes=["write"])

    rev = Revocations()
    rev.revoke("g-1")

    assert not authorize([r, mid, leaf], NOTION, secret=SECRET, revocations=rev).allowed
    assert not authorize([r, mid], NOTION, secret=SECRET, revocations=rev).allowed
    # The root itself is untouched - revoking a delegate must not disable the
    # operator.
    assert authorize([r], NOTION, secret=SECRET, revocations=rev).allowed


def test_revocations_are_read_from_an_operator_file_not_passed_by_the_caller(isolated):
    """A revocation list the governed layer hands in is a list it can hand in
    empty. `load_revocations` reads it off disk, like the kill switch."""
    (isolated / "revoked-grants.txt").write_text(
        "# the compromised analysis agent, 2026-09-25\ng-1\n\n", encoding="utf-8"
    )
    rev = ident.load_revocations()
    assert rev.is_revoked("g-1")
    assert not rev.is_revoked("# the compromised analysis agent, 2026-09-25")


def test_a_missing_revocation_list_means_nothing_revoked(isolated):
    assert ident.load_revocations().revoked == set()


def test_an_unreadable_revocation_list_is_an_error_not_an_empty_one(isolated):
    """"This file exists and I could not read it" must never round down to
    "nothing is revoked"."""
    bad = isolated / "revoked-grants.txt"
    bad.write_bytes(b"\xff\xfe\x00 invalid utf-8 \xc3\x28")
    with pytest.raises(IdentityError) as exc:
        ident.load_revocations(bad)
    assert "Refusing" in str(exc.value)


# ════════════════════════════════════════════════════════════════════════════
# §F  Leaf authority - the point of the whole design
# ════════════════════════════════════════════════════════════════════════════


def test_a_sub_agent_is_authorized_as_itself_not_as_its_delegator():
    """The research agent may send mail (`third_party`). It delegates a
    write-only authority to an analysis sub-agent. The sub-agent must not be
    able to send mail - and the only reason it could would be if `authorize()`
    consulted the root, or the union, instead of the leaf."""
    r = root(classes=["write", "third_party", "irreversible"])
    assert authorize([r], GMAIL, secret=SECRET).allowed, "the delegator itself can send"

    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    verdict = authorize([r, child], GMAIL, secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_capability",)
    assert "third_party" in verdict.reasons[0]

    # ...and it can still do the thing it WAS given.
    assert authorize([r, child], NOTION, secret=SECRET).allowed


def test_a_grant_must_carry_every_hazard_a_tool_has_not_merely_one():
    """Subset, not intersection. A grant holding only `write` does not cover a
    tool that is write AND third_party - the burden is on the grant to enumerate
    what it accepts."""
    r = issue_root(grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
                   classes=["write"], secret=SECRET)
    verdict = authorize([r], GMAIL, secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_capability",)


def test_an_empty_grant_authorizes_nothing():
    r = issue_root(grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
                   classes=[], secret=SECRET)
    assert verify_chain([r], secret=SECRET).allowed, "the chain is structurally fine"
    assert not authorize([r], NOTION, secret=SECRET).allowed, "but it confers nothing"


def test_a_tool_restriction_bites_even_when_the_classes_cover_it():
    r = root()
    scoped = attenuate(r, grant_id="g-1", subject=ANALYSIS, tools=[NOTION])
    assert authorize([r, scoped], NOTION, secret=SECRET).allowed
    denied = authorize([r, scoped], GMAIL, secret=SECRET)
    assert not denied.allowed
    assert "restricted to tools" in denied.reasons[0]


def test_no_grant_can_authorize_a_tool_the_registry_does_not_declare():
    """A grant cannot conjure a tool surface. Every capability class in the
    world does not add up to permission for an action nobody declared."""
    r = issue_root(
        grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
        classes=list(ident.CAPABILITY_CLASSES), secret=SECRET,
    )
    verdict = authorize([r], "shell.run_command", secret=SECRET)
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_capability",)


def test_a_grant_naming_an_unknown_tool_or_class_will_not_construct():
    """Caught at mint time: a typo'd class silently authorizes nothing, which
    looks exactly like a working grant until the day it matters."""
    with pytest.raises(IdentityError):
        Grant(grant_id="g", issuer=OPERATOR, subject=RESEARCH,
              classes=frozenset({"wrtie"}))
    with pytest.raises(IdentityError):
        Grant(grant_id="g", issuer=OPERATOR, subject=RESEARCH,
              classes=frozenset({"write"}), tools=frozenset({"notion.creat_page"}))


# ════════════════════════════════════════════════════════════════════════════
# §G  Fail closed
# ════════════════════════════════════════════════════════════════════════════


def test_no_root_secret_means_every_delegated_action_is_refused(isolated):
    """"We cannot check" and "it is fine" must not be the same code path."""
    verdict = verify_chain([root()])  # no secret= and none in the environment
    assert not verdict.allowed
    assert verdict.rule_ids == ("delegation_unconfigured",)


def test_an_agent_cannot_mint_itself_a_root_grant(isolated):
    """`issue_root` needs the secret, and the secret is not in the agent's
    environment. This is the intended answer to "an agent granted itself
    authority"."""
    with pytest.raises(IdentityError) as exc:
        issue_root(grant_id="g", issuer=OPERATOR, subject=INTRUDER, classes=["write"])
    assert ident.ROOT_SECRET_ENV in str(exc.value)


def test_an_empty_root_secret_is_refused():
    with pytest.raises(IdentityError):
        ident.root_secret(b"")


@pytest.mark.parametrize("junk", [["not-a-grant"], [None], [{"grant_id": "g"}], [42]])
def test_a_chain_of_non_grants_is_refused_not_coerced(junk):
    verdict = verify_chain(junk, secret=SECRET)
    assert not verdict.allowed
    assert "not a Grant" in verdict.reasons[0]


def test_an_unsigned_parent_cannot_key_a_child():
    bare = Grant(grant_id="g", issuer=OPERATOR, subject=RESEARCH, classes=frozenset({"write"}))
    with pytest.raises(IdentityError):
        attenuate(bare, grant_id="g-1", subject=ANALYSIS)


def test_an_unknown_principal_kind_is_refused():
    with pytest.raises(IdentityError):
        Principal("robot", "r2d2")
    with pytest.raises(IdentityError):
        Principal("agent", "   ")


def test_a_chain_survives_a_json_round_trip():
    """Serialization must be canonical, or a chain would stop verifying the
    first time it crossed a process boundary - which is the only way a
    delegation chain is ever actually used."""
    r = root()
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    wire = json.loads(json.dumps(ident.chain_to_dicts([r, child])))
    rebuilt = ident.chain_from_dicts(wire)
    assert authorize(rebuilt, NOTION, secret=SECRET).allowed
    assert rebuilt[1].sig == child.sig


# ════════════════════════════════════════════════════════════════════════════
# §H  Integration - policy.check(), Broker.execute(), the journal
# ════════════════════════════════════════════════════════════════════════════

DELEGATED_POLICY = {
    "version": 1,
    "rules": {
        "delegation": {"roots": ["sahil"]},
        "notion_parent_allowlist": {"allowed_parents": ["1" * 32]},
    },
}


@pytest.fixture
def delegated_gate(tmp_path, monkeypatch):
    """A gate whose policy names the `delegation` rule, fully isolated."""
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "policy.yaml")
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    monkeypatch.setattr(ident, "REVOCATION_FILE", tmp_path / "revoked-grants.txt")
    monkeypatch.setenv(ident.ROOT_SECRET_ENV, SECRET.decode())
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(DELEGATED_POLICY), encoding="utf-8")
    return tmp_path


def page(**kw) -> Proposal:
    params = {"parent_id": "1" * 32, "title": "Research note", "body_md": "GDP is up."}
    params.update(kw)
    return Proposal(tool=NOTION, params=params, rationale="summarising findings")


def test_check_level_rules_are_all_handled_by_check():
    """`CHECK_LEVEL_RULES` suppresses the "policy names a rule this build does
    not implement" guard. A name added to that set without a matching branch in
    `check()` would therefore become a silently-ignored policy rule - a rule the
    operator wrote and the gate skipped."""
    import inspect

    src = inspect.getsource(policy_mod.check)
    for name in policy_mod.CHECK_LEVEL_RULES:
        assert name not in policy_mod.RULES, f"{name} is in both RULES and CHECK_LEVEL_RULES"
        assert f'rule_name == "{name}"' in src, f"{name} is exempted but never handled"


def test_omitting_the_chain_is_a_refusal_not_a_skip(delegated_gate):
    """The property that makes `chain=` admissible as a parameter of `check()`.

    There is no value - including the default - that turns the rule off once
    policy.yaml has named it.
    """
    verdict = policy_mod.check(page())
    assert not verdict.allowed
    assert "delegation" in verdict.rule_ids
    assert "carried none" in " ".join(verdict.reasons)


def test_a_valid_chain_passes_the_gate(delegated_gate):
    r = root()
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    verdict = policy_mod.check(page(), chain=[r, child])
    assert verdict.allowed, verdict.reasons


def test_delegation_does_not_override_the_rest_of_the_policy(delegated_gate):
    """The most important integration test. A maximally-powerful, perfectly
    valid chain does not buy an exemption from any other rule - the two axes are
    conjunctive. An agent holding every capability class there is cannot
    delegate its way past the one place policy.yaml says it may write.
    """
    r = issue_root(
        grant_id="g-root", issuer=OPERATOR, subject=RESEARCH,
        classes=list(ident.CAPABILITY_CLASSES), secret=SECRET,
    )
    verdict = policy_mod.check(page(parent_id="2" * 32), chain=[r])
    assert not verdict.allowed
    assert "notion_parent_allowlist" in verdict.rule_ids


def test_the_kill_switch_still_outranks_a_valid_chain(delegated_gate):
    (delegated_gate / "KILL_SWITCH").write_text("stop", encoding="utf-8")
    verdict = policy_mod.check(page(), chain=[root()])
    assert not verdict.allowed
    assert verdict.rule_ids == ["kill_switch"]


def test_a_revoked_chain_is_refused_through_the_policy_gate(delegated_gate):
    """End to end via the operator's file, not a passed-in `Revocations`."""
    r = root()
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    assert policy_mod.check(page(), chain=[r, child]).allowed

    (delegated_gate / "revoked-grants.txt").write_text("g-1\n", encoding="utf-8")
    verdict = policy_mod.check(page(), chain=[r, child])
    assert not verdict.allowed
    assert "delegation_revoked" in verdict.rule_ids


def test_a_chain_from_an_undeclared_root_is_refused_through_the_gate(delegated_gate):
    r = root(issuer=Principal("user", "mallory"))
    verdict = policy_mod.check(page(), chain=[r])
    assert not verdict.allowed
    assert "delegation" in verdict.rule_ids


def test_a_serialized_chain_is_accepted_by_the_gate(delegated_gate):
    """The platform layer hands the gate JSON off the wire, not Grant objects."""
    r = root()
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    verdict = policy_mod.check(page(), chain=ident.chain_to_dicts([r, child]))
    assert verdict.allowed, verdict.reasons


def test_a_malformed_chain_is_refused_not_ignored(delegated_gate):
    verdict = policy_mod.check(page(), chain=[{"grant_id": "g", "issuer": "not-a-mapping"}])
    assert not verdict.allowed
    assert "delegation" in verdict.rule_ids


def test_the_policy_is_ignored_entirely_when_delegation_is_not_named(tmp_path, monkeypatch):
    """A policy that does not name `delegation` behaves exactly as it did before
    this layer existed - no chain required, nothing refused for its absence."""
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "policy.yaml")
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    monkeypatch.delenv(ident.ROOT_SECRET_ENV, raising=False)
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump(
            {"version": 1, "rules": {"notion_parent_allowlist": {
                "allowed_parents": ["1" * 32]}}}
        ),
        encoding="utf-8",
    )
    assert policy_mod.check(page()).allowed


# ── through the broker, into the journal ────────────────────────────────────


def _broker(tmp_path, chain):
    return Broker(
        gmail=object(), calendar=object(), notion=_FakeNotion(),
        ledger=Ledger(path=tmp_path / "ledger.db"),
        journal_path=tmp_path / "journal.db",
        chain=chain,
    )


class _FakeNotion:
    """Minimal stand-in - the point of these tests is the gate and the journal,
    not Notion's API shape."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def create_page(self, **kwargs):
        self.calls.append(kwargs)
        return "page-123"


def _journal_rows(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM decisions ORDER BY id")]
    conn.close()
    return rows


def test_the_broker_records_who_acted_and_on_whose_behalf(delegated_gate):
    """§4's auditability requirement: a journal row must answer "who, acting as
    whom, under which authority", not only "what happened"."""
    r = root()
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    broker = _broker(delegated_gate, [r, child])

    result = broker.execute(page())
    assert result["status"] == "EXECUTED", result

    row = _journal_rows(delegated_gate / "journal.db")[-1]
    assert row["decision"] == "ALLOWED"
    assert row["principal"] == "agent:analysis-1"
    assert row["on_behalf_of"] == "user:sahil"
    assert json.loads(row["chain_json"]) == ["g-root", "g-1"]


def test_a_refused_delegation_is_journalled_with_the_chain_that_was_claimed(delegated_gate):
    """A rejected claim of authority is exactly the row worth having - so the
    chain is recorded even though it did not verify, and the decision still
    reads REFUSED."""
    r = root(classes=["write"])
    forged = Grant(
        grant_id="g-1", issuer=RESEARCH, subject=INTRUDER,
        classes=frozenset({"write", "spend"}), parent_id="g-root",
    )
    notion = _FakeNotion()
    broker = Broker(
        gmail=object(), calendar=object(), notion=notion,
        ledger=Ledger(path=delegated_gate / "ledger.db"),
        journal_path=delegated_gate / "journal.db",
        chain=resign([r, forged]),
    )

    result = broker.execute(page())
    assert result["status"] == "REJECTED_BY_POLICY_GATE"
    assert "delegation_amplified" in result["rule_ids"]
    assert notion.calls == [], "the app must never be reached on a refusal"

    row = _journal_rows(delegated_gate / "journal.db")[-1]
    assert row["decision"] == "REFUSED"
    assert row["principal"] == "agent:intruder"
    assert json.loads(row["chain_json"]) == ["g-root", "g-1"]


def test_the_journal_never_stores_a_grant_signature(delegated_gate):
    """A signature is the key that mints children. A journal holding one would
    be an audit file that confers authority."""
    r = root()
    child = attenuate(r, grant_id="g-1", subject=ANALYSIS, classes=["write"])
    broker = _broker(delegated_gate, [r, child])
    broker.execute(page())

    blob = (delegated_gate / "journal.db").read_bytes()
    assert r.sig.encode() not in blob
    assert child.sig.encode() not in blob


def test_an_older_journal_gains_the_identity_columns_without_losing_rows(tmp_path):
    """The migration. Refusals already on disk are the evidence this project
    exists to produce - a schema change that orphaned them would destroy the
    thing being protected."""
    path = tmp_path / "journal.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc TEXT NOT NULL,
            thread_id TEXT, tool TEXT NOT NULL, params_json TEXT, rationale TEXT,
            decision TEXT NOT NULL, rule_ids_json TEXT, reasons_json TEXT,
            external_id TEXT, error TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO decisions (ts_utc, tool, decision) VALUES ('2026-01-01T00:00:00', ?, 'REFUSED')",
        (NOTION,),
    )
    conn.commit()
    conn.close()

    from warrant.contract import Verdict

    journal_mod.log_decision(page(), Verdict(False, ["nope"], ["r"]), journal_path=path)

    rows = _journal_rows(path)
    assert len(rows) == 2, "the pre-existing refusal must survive the migration"
    assert rows[0]["principal"] is None, "a row written before principals existed claims none"
    assert "chain_json" in rows[1]


# ════════════════════════════════════════════════════════════════════════════
# §I  Tenant binding — a valid chain must be the RIGHT chain
# ════════════════════════════════════════════════════════════════════════════
#
# verify_chain proves a chain is genuine, unexpired and attenuating. It cannot
# prove it is the chain for the account being acted on — it never sees the
# facts. A perfectly valid chain for tenant A, presented alongside facts read
# for tenant B, passes every check in identity.py. `_bind_chain_to_facts` in
# policy.py is where the two halves meet.

TENANT_A = Principal("tenant", "aaaa-1111")
TENANT_B = Principal("tenant", "bbbb-2222")
PLATFORM = Principal("service", "finlm-platform")


def _tenant_chain(tenant: Principal, classes=("write", "spend", "irreversible")):
    """platform -> tenant -> agent, the shape a multi-tenant host uses. Note
    the tenant is the MIDDLE link, named by neither end of the chain."""
    r = issue_root(
        grant_id=f"root:{tenant.id}", issuer=PLATFORM, subject=tenant,
        classes=classes, secret=SECRET,
    )
    agent = attenuate(
        r, grant_id=f"execution:{tenant.id}",
        subject=Principal("agent", f"execution:{tenant.id}"),
        classes=classes, tools=["kite.place_order"],
    )
    return [r, agent]


class _KiteFactsStub:
    """Only the attribute the binding reads. The real KiteFacts carries a
    dozen fields none of which this rule has any business looking at."""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id


BOUND_POLICY = {
    "version": 1,
    "rules": {"delegation": {"require_tenant_binding": True}},
}


@pytest.fixture
def bound_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "policy.yaml")
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    monkeypatch.setattr(ident, "REVOCATION_FILE", tmp_path / "revoked-grants.txt")
    monkeypatch.setenv(ident.ROOT_SECRET_ENV, SECRET.decode())
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(BOUND_POLICY), encoding="utf-8")
    return tmp_path


def order(**kw) -> Proposal:
    params = {
        "tradingsymbol": "RELIANCE", "transaction_type": "BUY", "quantity": 1,
        "order_type": "LIMIT", "price": 100.0, "product": "CNC", "exchange": "NSE",
    }
    params.update(kw)
    return Proposal(tool="kite.place_order", params=params)


def test_the_tenant_is_found_even_though_it_is_the_middle_link(bound_gate):
    """The binding would be useless if it only looked at the chain's ends -
    platform -> tenant -> agent names the tenant at neither."""
    chain = _tenant_chain(TENANT_A)
    verdict = ident.authorize(chain, "kite.place_order", secret=SECRET)
    assert verdict.on_behalf_of == PLATFORM  # not the tenant
    assert verdict.principal.kind == "agent"  # not the tenant
    assert TENANT_A in verdict.subjects  # but it IS here

    assert policy_mod.check(
        order(), facts=_KiteFactsStub(TENANT_A.id), chain=chain
    ).allowed


def test_a_valid_chain_for_the_wrong_tenant_is_refused(bound_gate):
    """§I's core test. Tenant A's chain is entirely genuine - correct
    signatures, correct attenuation, unexpired, unrevoked - and authorizes
    nothing against tenant B's account."""
    chain = _tenant_chain(TENANT_A)
    assert ident.authorize(chain, "kite.place_order", secret=SECRET).allowed

    verdict = policy_mod.check(order(), facts=_KiteFactsStub(TENANT_B.id), chain=chain)
    assert not verdict.allowed
    assert "delegation_tenant_binding" in verdict.rule_ids
    assert "aaaa-1111" in " ".join(verdict.reasons)
    assert "bbbb-2222" in " ".join(verdict.reasons)


def test_require_tenant_binding_refuses_facts_that_cannot_be_matched(bound_gate):
    """"I could not check" must not read as "it matched". With the flag on,
    facts carrying no tenant_id are a refusal, not a skip."""

    class _NoTenantFacts:
        pass

    verdict = policy_mod.check(order(), facts=_NoTenantFacts(), chain=_tenant_chain(TENANT_A))
    assert not verdict.allowed
    assert "delegation_tenant_binding" in verdict.rule_ids


def test_require_tenant_binding_refuses_a_chain_with_no_tenant_link(bound_gate):
    """A platform -> agent chain has nothing to bind. Legitimate for a
    single-operator install, refused once the policy says binding is required."""
    r = issue_root(
        grant_id="root", issuer=PLATFORM, subject=Principal("agent", "solo"),
        classes=["write", "spend", "irreversible"], secret=SECRET,
    )
    verdict = policy_mod.check(order(), facts=_KiteFactsStub("aaaa-1111"), chain=[r])
    assert not verdict.allowed
    assert "delegation_tenant_binding" in verdict.rule_ids


def test_a_chain_that_changes_tenant_partway_down_is_refused(bound_gate):
    """Attenuation is about capability, not identity - identity.py does not
    forbid a chain whose links name different tenants, and it should not have
    to. A delegation that crosses tenants has no honest meaning, and picking
    one of them to bind against would be arbitrary."""
    r = issue_root(
        grant_id="root:a", issuer=PLATFORM, subject=TENANT_A,
        classes=["write", "spend", "irreversible"], secret=SECRET,
    )
    crossed = attenuate(r, grant_id="cross", subject=TENANT_B, classes=["write", "spend"])
    assert ident.verify_chain([r, crossed], secret=SECRET).allowed, (
        "identity.py has no opinion on this; the refusal must come from the binding"
    )

    verdict = policy_mod.check(order(), facts=_KiteFactsStub(TENANT_A.id), chain=[r, crossed])
    assert not verdict.allowed
    assert "delegation_tenant_binding" in verdict.rule_ids
    assert "more than one tenant" in " ".join(verdict.reasons)


def test_binding_is_off_by_default_so_a_single_operator_install_still_works(
    tmp_path, monkeypatch
):
    """Enabling `delegation` must not force a tenant model on a deployment
    that has none - ThreadFacts has no tenant_id and never will."""
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "policy.yaml")
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    monkeypatch.setattr(ident, "REVOCATION_FILE", tmp_path / "revoked-grants.txt")
    monkeypatch.setenv(ident.ROOT_SECRET_ENV, SECRET.decode())
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump({"version": 1, "rules": {"delegation": {}}}), encoding="utf-8"
    )
    # A tenant chain, facts with no tenant concept at all: skipped, not refused.
    assert policy_mod.check(order(), facts=None, chain=_tenant_chain(TENANT_A)).allowed


def test_binding_still_catches_a_mismatch_even_when_not_required(bound_gate, tmp_path, monkeypatch):
    """Off-by-default applies to the "cannot check" case only. When both sides
    ARE present, a mismatch is always a refusal - there is no configuration
    that lets tenant A act on tenant B."""
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump({"version": 1, "rules": {"delegation": {}}}), encoding="utf-8"
    )
    verdict = policy_mod.check(
        order(), facts=_KiteFactsStub(TENANT_B.id), chain=_tenant_chain(TENANT_A)
    )
    assert not verdict.allowed
    assert "delegation_tenant_binding" in verdict.rule_ids
