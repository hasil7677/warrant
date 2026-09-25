"""
identity.py
───────────
Who is asking, on whose behalf, and under what authority.

`policy.py` answers "is this action within the rules the operator wrote."
It has never been able to answer the other half of the question:

    "Is THIS agent allowed to perform this exact action, in this exact
     context, ON BEHALF OF this exact user?"

Everything the gate knew until now was about the *action*. A proposal
carried a tool and params; the rules graded them. Nothing carried a
principal, so nothing could distinguish the research agent that may only
read from the execution agent that may place an order - they were the same
anonymous caller wearing the same policy.yaml.

This module adds the missing axis. It does not replace a single policy
rule: a delegated authority says what an agent MAY be permitted to do, and
policy.yaml still says what ANYONE is permitted to do. Both must pass. An
agent cannot delegate its way around a spend cap, because the cap is not
part of the delegation graph at all.

## The one hard problem

    Can an agent safely delegate a subset of its authority without
    accidentally granting more authority than it possesses?

Two distinct failure modes hide in that sentence, and they need two
different mechanisms. Conflating them is how capability systems get this
wrong:

  • **Amplification.** A holder mints a child grant claiming more than the
    parent held - the research agent, allowed only `write`, hands its
    sub-agent a grant that also carries `spend`. No forgery is involved;
    every signature is valid. This is caught by the attenuation checks in
    `verify_chain()`, which re-derive the subset relation on every link at
    verification time rather than trusting that whoever minted the child
    checked.

  • **Forgery.** Someone fabricates a grant that was never issued, or edits
    one that was - flipping `expires_at`, swapping the subject, adding a
    class to an ancestor. Attenuation checking cannot see this: a forged
    chain can be internally consistent and perfectly attenuating. This is
    caught by the chained MAC below.

A system with only the first is trivially bypassed by writing your own
chain. A system with only the second lets any holder issue itself a
superset. Warrant needs both, so it has both, and the test suite for each
is written against the other's absence.

## The chained MAC (macaroons, and why that shape)

Each grant carries `sig`, an HMAC over its own canonical bytes. The key is
what makes this interesting:

    root grant:   sig = HMAC(root_secret, canonical(body))
    child grant:  sig = HMAC(parent.sig,  canonical(body))

The root secret exists in exactly one place - the operator's environment -
and is never handed to an agent. A holder of grant G knows `G.sig`, and
`G.sig` is precisely the key needed to mint a child of G. So:

  • Any holder can delegate downward with no round trip to an authority
    and no secret it was not already given. Delegation is offline, which
    is what makes it usable by an agent mid-run.
  • No holder can mint a *sibling*, a *parent*, or a fresh root: those
    require a MAC keyed by something upstream of it, which it does not
    have. Editing an ancestor invalidates every signature computed from
    it, because each link's key IS the previous link's signature.
  • The most a holder can do unilaterally is issue children - and every
    child is then subject to the attenuation check. Which is exactly the
    authority we intend a holder to have.

This is the macaroon construction (Birgisson et al., 2014). It is chosen
over signing every grant with the root key because that would require the
root secret at every delegation point, i.e. giving every agent the ability
to mint anything - the precise thing being prevented.

HMAC-SHA256, not a public-key signature: there is exactly one verifier
(this gate, holding the root secret) and no third party that needs to
check a grant without being able to issue one. Asymmetric crypto buys that
property and nothing else here, at the cost of key management this project
would then have to be honest about not having done.

## What a grant can carry

Nothing new. A grant is scoped in the vocabulary `registry.py` already
established - the capability *classes* (`write`, `spend`, `egress`,
`irreversible`, ...) that every tool is already tagged with, and which the
existing policy rules already reason about instead of app names.

That reuse is the point. A grant that named tools only would need editing
every time an app is added; a grant that carries `classes=frozenset()`
authorizes nothing hazardous today and still authorizes nothing hazardous
after app number sixteen ships, because the new app's hazards are declared
in the registry and the subset check picks them up for free.

A grant authorizes a tool when the tool's hazard classes are a SUBSET of
the grant's. Not an intersection, not "any overlap" - a grant that omits
`spend` refuses every tool that moves money, and the burden is on the
grant to enumerate what it accepts. `reversible`/`irreversible` are
excluded from this comparison: they are properties of an action rather
than hazards to be conferred, and `policy.py`'s `irreversible_gate` rule
already governs them. Including them would mean every grant had to list
`reversible` to permit anything at all, which teaches holders to list
classes they have not thought about.

`tools` narrows further, to named actions, and is the escape hatch for
"this sub-agent may write, but only to Notion." Empty means "no
tool-level restriction beyond classes" - the class check still applies.

## Revocation

`Revocations` is a set of grant ids. Revoking any grant in a chain kills
that grant and everything descended from it, and it does so without a tree
walk or a database: verification checks every link, so a revoked ancestor
fails the chain no matter how deep the leaf is. Revoking the root disables
every agent at once, which is the property an operator actually wants at
3am.

There is no un-revoke. A grant is a bearer credential; if it was worth
revoking, the holder may still have it, and the only sound recovery is
issuing a new one.

## Fail closed

Every function here refuses on anything it cannot positively verify:
malformed input, an unparseable timestamp, a missing root secret, a chain
whose links do not join, an unknown tool, a grant whose signature does not
recompute. There is no code path that returns `allowed=True` by falling
off the end of a function, and `authorize()` builds its verdict from an
explicit list of reasons rather than a boolean anyone can flip.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from warrant.registry import (
    ACTIONS,
    CAPABILITY_CLASSES,
    REVERSIBILITY_CLASSES,
    tool_spec,
)

# ── principals ──────────────────────────────────────────────────────────────

USER = "user"
TENANT = "tenant"
AGENT = "agent"
SERVICE = "service"
SESSION = "session"

PRINCIPAL_KINDS: tuple[str, ...] = (USER, TENANT, AGENT, SERVICE, SESSION)

# How deep a delegation chain may go before it is refused outright. Not a
# performance limit - eight links is already a delegation nobody can reason
# about, and an unbounded chain is a denial-of-service surface (each link
# costs a MAC) as well as an audit trail no human will read.
MAX_CHAIN_DEPTH = 8

ROOT_SECRET_ENV = "WARRANT_ROOT_SECRET"


class IdentityError(ValueError):
    """A grant or chain could not be constructed.

    Raised, not returned: these are programming errors at mint time (a
    caller trying to amplify, a malformed principal), and a caller that
    gets a None back tends to carry on holding something it believes is a
    credential.
    """


class AmplificationError(IdentityError):
    """A delegation tried to confer authority its issuer does not hold.

    Its own subclass rather than a generic message because this is THE
    error this module exists to make impossible, and a test asserting
    `pytest.raises(IdentityError)` would also pass if the mint had failed
    for an unrelated typo.
    """


@dataclass(frozen=True)
class Principal:
    """Who an authority belongs to.

    `kind` is constrained to PRINCIPAL_KINDS at construction because the
    kind is load-bearing in the audit trail - "agent research-1 acting for
    user sahil" reads differently from "user research-1", and a free-text
    kind means the journal cannot be queried for "every action any agent
    took on behalf of a human".

    Frozen and compared by value: chain contiguity is `issuer == subject`,
    and a principal that compared by identity would break the moment a
    chain was serialized and read back.
    """

    kind: str
    id: str

    def __post_init__(self) -> None:
        if self.kind not in PRINCIPAL_KINDS:
            raise IdentityError(
                f"Unknown principal kind {self.kind!r}. Known kinds: {list(PRINCIPAL_KINDS)}."
            )
        if not isinstance(self.id, str) or not self.id.strip():
            raise IdentityError("Principal id must be a non-empty string.")

    def __str__(self) -> str:
        return f"{self.kind}:{self.id}"

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "id": self.id}

    @staticmethod
    def from_dict(raw: Any) -> "Principal":
        if not isinstance(raw, dict):
            raise IdentityError(f"Principal must be a mapping, got {type(raw).__name__}.")
        return Principal(kind=str(raw.get("kind", "")), id=str(raw.get("id", "")))


def _parse_ts(value: Any, what: str) -> Optional[datetime]:
    """An ISO-8601 instant, or None for "no expiry".

    Naive datetimes are refused rather than assumed-UTC. A grant that
    expires "at 5pm" with no zone is a grant whose lifetime depends on
    which machine verifies it, and silently stamping UTC on it would make
    an hour of extra authority appear for anyone east of Greenwich.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except (TypeError, ValueError) as exc:
            raise IdentityError(
                f"{what} is not a valid ISO-8601 timestamp: {value!r} ({exc})."
            ) from exc
    if dt.tzinfo is None:
        raise IdentityError(
            f"{what} must carry a timezone offset - a naive timestamp means a different "
            "expiry on every machine that reads it."
        )
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class Grant:
    """One link of delegated authority: `issuer` confers on `subject` the
    right to propose actions bounded by `classes`/`tools` until `expires_at`.

    `sig` is not part of what the grant *says* - it is the proof that the
    grant was said by someone entitled to say it. `_body()` deliberately
    excludes it, because a MAC cannot cover itself.

    Constructed through `issue_root()` / `attenuate()` rather than directly
    in normal use: both compute `sig` correctly, and a Grant built by hand
    with a wrong or absent signature will simply fail verification. That is
    the intended failure mode - there is no "unsigned but trusted" grant.
    """

    grant_id: str
    issuer: Principal
    subject: Principal
    classes: frozenset[str]
    tools: frozenset[str] = frozenset()
    expires_at: Optional[datetime] = None
    parent_id: Optional[str] = None
    sig: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.grant_id, str) or not self.grant_id.strip():
            raise IdentityError("grant_id must be a non-empty string.")
        unknown_classes = sorted(set(self.classes) - set(CAPABILITY_CLASSES))
        if unknown_classes:
            raise IdentityError(
                f"Grant {self.grant_id!r} names capability classes this build does not know: "
                f"{unknown_classes}. Known: {sorted(CAPABILITY_CLASSES)}. A class the registry "
                "never tags a tool with would silently authorize nothing, which is a typo that "
                "looks like a working grant."
            )
        unknown_tools = sorted(set(self.tools) - set(ACTIONS))
        if unknown_tools:
            raise IdentityError(
                f"Grant {self.grant_id!r} names tools that do not exist: {unknown_tools}. "
                f"Known actions: {sorted(ACTIONS)}."
            )

    # ── canonical form ──────────────────────────────────────────────────
    def _body(self) -> dict[str, Any]:
        """Everything the MAC commits to.

        Sorted sets and `sort_keys` in `_canonical` are what make the bytes
        reproducible: two grants that say the same thing must hash the
        same, or a chain would stop verifying the first time it
        round-tripped through JSON with a different dict ordering.
        """
        return {
            "grant_id": self.grant_id,
            "issuer": self.issuer.to_dict(),
            "subject": self.subject.to_dict(),
            "classes": sorted(self.classes),
            "tools": sorted(self.tools),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "parent_id": self.parent_id,
        }

    def _canonical(self) -> bytes:
        return json.dumps(self._body(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def seal(self, key: bytes) -> "Grant":
        """Return this grant with `sig` computed under `key`.

        Returns a new Grant rather than mutating: the dataclass is frozen
        precisely so a grant cannot be edited after it is signed, and an
        in-place `seal` would be a hole in that.
        """
        return replace(self, sig=hmac.new(key, self._canonical(), hashlib.sha256).hexdigest())

    def signature_matches(self, key: bytes) -> bool:
        """Constant-time comparison.

        `hmac.compare_digest`, not `==`: signature comparison is the one
        place in this package where an early-exit string compare leaks,
        byte by byte, what the correct answer would have been.
        """
        expected = hmac.new(key, self._canonical(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.sig or "")

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def permits_tool(self, tool: str) -> tuple[bool, str]:
        """Whether this grant alone covers `tool`, and if not, why not.

        Returns the reason alongside the boolean because every caller needs
        it for the refusal message, and recomputing "which class was
        missing" at the call site is how two code paths end up disagreeing
        about what was actually wrong.
        """
        spec = tool_spec(tool)
        if spec is None:
            return False, (
                f"Unknown tool {tool!r} - no grant can authorize an action the registry does "
                "not declare."
            )
        if self.tools and tool not in self.tools:
            return False, (
                f"Grant {self.grant_id!r} is restricted to tools {sorted(self.tools)}, which "
                f"does not include {tool!r}."
            )
        hazards = frozenset(spec.classes) - REVERSIBILITY_CLASSES
        missing = sorted(hazards - self.classes)
        if missing:
            return False, (
                f"Grant {self.grant_id!r} does not carry {missing} - {tool!r} requires "
                f"{sorted(hazards)} and the grant holds {sorted(self.classes)}."
            )
        return True, ""

    def to_dict(self) -> dict[str, Any]:
        body = self._body()
        body["sig"] = self.sig
        return body

    @staticmethod
    def from_dict(raw: Any) -> "Grant":
        if not isinstance(raw, dict):
            raise IdentityError(f"Grant must be a mapping, got {type(raw).__name__}.")
        return Grant(
            grant_id=str(raw.get("grant_id", "")),
            issuer=Principal.from_dict(raw.get("issuer")),
            subject=Principal.from_dict(raw.get("subject")),
            classes=frozenset(str(c) for c in (raw.get("classes") or [])),
            tools=frozenset(str(t) for t in (raw.get("tools") or [])),
            expires_at=_parse_ts(raw.get("expires_at"), "Grant expires_at"),
            parent_id=(str(raw["parent_id"]) if raw.get("parent_id") is not None else None),
            sig=str(raw.get("sig", "")),
        )


# ── minting ─────────────────────────────────────────────────────────────────


def root_secret(explicit: Optional[bytes] = None) -> bytes:
    """The one secret that can originate authority.

    Read from the environment, never from a file this package could write,
    and never defaulted. A default root secret is a published root secret:
    every clone of this repo would be able to mint a valid root grant
    against every other clone's gate. Absent means refuse - the same shape
    `policy.py` takes with a missing policy.yaml, because consent has to
    originate outside the agent.

    `explicit` exists for tests and for a host that keeps its secret in a
    vault rather than an env var. It is a parameter of the *operator*
    layer, not of anything a proposal can reach.
    """
    if explicit is not None:
        if not explicit:
            raise IdentityError("Root secret must not be empty.")
        return explicit
    raw = os.getenv(ROOT_SECRET_ENV, "").strip()
    if not raw:
        raise IdentityError(
            f"{ROOT_SECRET_ENV} is not set, so no delegation chain can be verified and every "
            "delegated action is refused. Generate one with:\n"
            '  python -c "import secrets; print(secrets.token_urlsafe(32))"\n'
            f"and set {ROOT_SECRET_ENV} in the environment (or .env). It must never be given "
            "to an agent: holding it is the ability to mint any authority at all."
        )
    return raw.encode("utf-8")


def issue_root(
    *,
    grant_id: str,
    issuer: Principal,
    subject: Principal,
    classes: Iterable[str],
    tools: Iterable[str] = (),
    expires_at: Any = None,
    secret: Optional[bytes] = None,
) -> Grant:
    """Mint a chain's first grant, signed with the root secret.

    Only the operator can call this meaningfully - it needs the secret. An
    agent calling it gets `IdentityError` from `root_secret()`, which is
    the intended answer to "an agent tried to grant itself authority".
    """
    grant = Grant(
        grant_id=grant_id,
        issuer=issuer,
        subject=subject,
        classes=frozenset(classes),
        tools=frozenset(tools),
        expires_at=_parse_ts(expires_at, "issue_root expires_at"),
        parent_id=None,
    )
    return grant.seal(root_secret(secret))


def attenuate(
    parent: Grant,
    *,
    grant_id: str,
    subject: Principal,
    classes: Optional[Iterable[str]] = None,
    tools: Optional[Iterable[str]] = None,
    expires_at: Any = None,
) -> Grant:
    """Delegate a SUBSET of `parent`'s authority to `subject`.

    Keyed by `parent.sig`, so this needs no secret beyond the parent grant
    the caller already holds - an agent can do this mid-run, offline. The
    issuer is forced to `parent.subject` rather than accepted as an
    argument: a holder delegates as itself or not at all, and an issuer
    field the caller picks is an impersonation field.

    `classes=None` means "inherit the parent's" - the common case is
    narrowing tools or shortening the lifetime while keeping the same
    hazard surface, and making the caller retype the set invites a typo
    that widens it.

    Raises `AmplificationError` on any attempt to widen. The check is here
    so the mistake surfaces at the delegation point, where someone can read
    the traceback - but it is deliberately NOT the security boundary.
    `verify_chain()` re-derives the same subset relation at authorization
    time, because a Grant can also be hand-constructed or deserialized
    without ever passing through this function.
    """
    if not isinstance(parent, Grant):
        raise IdentityError(f"parent must be a Grant, got {type(parent).__name__}.")
    if not parent.sig:
        raise IdentityError(
            f"Parent grant {parent.grant_id!r} is unsigned; an unsigned grant confers nothing "
            "and cannot key a child."
        )

    child_classes = frozenset(parent.classes if classes is None else classes)
    widened = sorted(child_classes - parent.classes)
    if widened:
        raise AmplificationError(
            f"Grant {grant_id!r} would confer {widened}, which its issuer {parent.subject} "
            f"does not hold (parent {parent.grant_id!r} holds {sorted(parent.classes)}). "
            "A delegation can only ever narrow."
        )

    if tools is None:
        child_tools = frozenset(parent.tools)
    else:
        child_tools = frozenset(tools)
        if parent.tools and not child_tools:
            raise AmplificationError(
                f"Grant {grant_id!r} would lift its parent's tool restriction "
                f"{sorted(parent.tools)} by naming no tools at all. An empty `tools` means "
                "'no tool-level restriction', which is wider than the parent, not narrower - "
                "pass the subset you mean explicitly."
            )
        if parent.tools:
            widened_tools = sorted(child_tools - parent.tools)
            if widened_tools:
                raise AmplificationError(
                    f"Grant {grant_id!r} would confer tools {widened_tools} that parent "
                    f"{parent.grant_id!r} does not hold (it holds {sorted(parent.tools)})."
                )

    child_expiry = _parse_ts(expires_at, "attenuate expires_at")
    if parent.expires_at is not None:
        if child_expiry is None or child_expiry > parent.expires_at:
            # Silently clamping would be friendlier and wrong: the caller
            # asked for a lifetime it cannot give, and a grant that expires
            # earlier than its holder believes is a bug they will hit in
            # production rather than here.
            raise AmplificationError(
                f"Grant {grant_id!r} would outlive its parent - parent {parent.grant_id!r} "
                f"expires {parent.expires_at.isoformat()}, child asks for "
                f"{child_expiry.isoformat() if child_expiry else 'never'}."
            )

    child = Grant(
        grant_id=grant_id,
        issuer=parent.subject,
        subject=subject,
        classes=child_classes,
        tools=child_tools,
        expires_at=child_expiry,
        parent_id=parent.grant_id,
    )
    return child.seal(parent.sig.encode("utf-8"))


# ── revocation ──────────────────────────────────────────────────────────────


@dataclass
class Revocations:
    """Revoked grant ids.

    A flat set, and that is sufficient: `verify_chain()` checks every link,
    so revoking a grant in the middle of a chain refuses every descendant
    without this structure knowing the tree shape. There is no subtree walk
    to get wrong, and no way for a deep leaf to survive its revoked
    ancestor.

    In-memory by design at this layer. A host that needs revocation to
    survive a restart passes a set it loaded from its own store - the gate
    should not own a second database when the platform already has one.
    """

    revoked: set[str] = field(default_factory=set)

    def revoke(self, grant_id: str) -> None:
        if not isinstance(grant_id, str) or not grant_id.strip():
            raise IdentityError("Cannot revoke an empty grant id.")
        self.revoked.add(grant_id)

    def is_revoked(self, grant_id: str) -> bool:
        return grant_id in self.revoked

    def __contains__(self, grant_id: object) -> bool:
        return isinstance(grant_id, str) and grant_id in self.revoked


REVOCATION_FILE = Path(os.getenv("WARRANT_REVOCATIONS_FILE", ".warrant/revoked-grants.txt"))


def load_revocations(path: Optional[Path] = None) -> Revocations:
    """Read revoked grant ids from an operator-owned file, one per line.

    A FILE, and read by the gate rather than passed in by the caller, for
    the same reason `policy.py` reads the kill switch off disk instead of
    taking a `stop=True` argument: a revocation list the governed layer
    hands to the gate is a revocation list the governed layer can hand over
    empty. The operator writes this file; nothing in this package writes
    it.

    A missing file means "nothing revoked", which is the one safe default
    here - unlike a missing policy, an absent revocation list does not
    widen anything beyond what the grants already say. An *unreadable* file
    is different and raises, because "this file exists and I could not read
    it" must never be rounded down to "nothing is revoked".

    `#` comments and blank lines are allowed, because a revocation list is
    read by humans at exactly the worst moment and "which one was the
    compromised agent" should be answerable from the file itself.
    """
    path = Path(path if path is not None else REVOCATION_FILE)
    revocations = Revocations()
    if not path.exists():
        return revocations
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise IdentityError(
            f"Revocation list at {path} exists but could not be read ({exc}). Refusing to "
            "treat an unreadable revocation list as an empty one."
        ) from exc
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            revocations.revoke(line)
    return revocations


# ── verification ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuthorityVerdict:
    """Why a chain was or was not honoured.

    Mirrors `contract.Verdict` deliberately - `allowed` is the only field a
    caller may branch on, `rule_ids` name what fired. It is a separate type
    because `policy.py` combines the two, and merging them here would let a
    delegation refusal be presented as a policy pass.
    """

    allowed: bool
    reasons: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    principal: Optional[Principal] = None
    on_behalf_of: Optional[Principal] = None
    chain_ids: tuple[str, ...] = ()
    # Every subject in the chain, root-most first. `principal` and
    # `on_behalf_of` are only the two ENDS, which is not enough for a caller
    # that needs an intermediate link: a multi-tenant host delegates
    # platform -> tenant -> agent, and the tenant - the one identity it most
    # needs to cross-check against its own facts - is in the middle, named
    # by neither end. Exposed as a tuple rather than left to the caller to
    # re-walk the chain, so the thing it cross-checks is the same thing
    # verify_chain actually validated.
    subjects: tuple[Principal, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "rule_ids": list(self.rule_ids),
            "principal": str(self.principal) if self.principal else None,
            "on_behalf_of": str(self.on_behalf_of) if self.on_behalf_of else None,
            "chain_ids": list(self.chain_ids),
            "subjects": [str(p) for p in self.subjects],
        }


def _deny(reason: str, rule_id: str = "delegation") -> AuthorityVerdict:
    return AuthorityVerdict(False, (reason,), (rule_id,))


def verify_chain(
    chain: Iterable[Grant],
    *,
    now: Optional[datetime] = None,
    secret: Optional[bytes] = None,
    revocations: Optional[Revocations] = None,
    roots: Optional[Iterable[str]] = None,
    max_depth: int = MAX_CHAIN_DEPTH,
) -> AuthorityVerdict:
    """Check that `chain` is a genuine, unbroken, unexpired, unrevoked,
    strictly-attenuating delegation rooted in the operator's secret.

    Says nothing about any particular action - `authorize()` adds that.
    Split so a chain can be validated once (at session start, say) and the
    per-action check run many times, and so the tests for "is this chain
    real" are not entangled with "does it cover gmail.send".

    `roots`, when given, is the set of principal ids allowed to sit at the
    top. A valid signature already proves the root secret was involved, so
    this is a second, narrower question: WHICH operator identity may
    originate authority. A host running one gate for many tenants needs it;
    a single-operator install can omit it.
    """
    grants = list(chain)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    if not grants:
        return _deny(
            "No delegation chain was presented. This gate is configured to require one, so "
            "there is no anonymous caller to fall back to - every action is taken by some "
            "principal on some principal's behalf, or it is refused."
        )
    if len(grants) > max_depth:
        return _deny(
            f"Delegation chain is {len(grants)} links deep; the maximum is {max_depth}. "
            "A chain nobody can read is a chain nobody is auditing."
        )
    for g in grants:
        if not isinstance(g, Grant):
            return _deny(
                f"Chain contains a {type(g).__name__}, not a Grant. Refusing rather than "
                "coercing something that merely looks like a credential."
            )

    try:
        key = root_secret(secret)
    except IdentityError as exc:
        # The operator has not configured an authority to verify against.
        # That is a refusal, not an exemption: "we cannot check" and "it is
        # fine" are the same code path in exactly the systems this project
        # is an argument against.
        return _deny(str(exc), "delegation_unconfigured")

    if roots is not None:
        allowed_roots = {str(r) for r in roots}
        root_issuer = grants[0].issuer
        if str(root_issuer) not in allowed_roots and root_issuer.id not in allowed_roots:
            return _deny(
                f"Chain is rooted at {root_issuer}, which is not a declared root authority "
                f"({sorted(allowed_roots)}). A validly-signed grant from an identity the "
                "policy does not recognise is still not authority here."
            )

    if grants[0].parent_id is not None:
        return _deny(
            f"Root grant {grants[0].grant_id!r} claims parent {grants[0].parent_id!r}, but "
            "nothing precedes it in the chain. Either a link is missing or the chain was "
            "truncated to hide one."
        )

    seen_ids: set[str] = set()
    for depth, grant in enumerate(grants):
        where = f"link {depth} ({grant.grant_id!r})"

        if grant.grant_id in seen_ids:
            # A repeated id would let a revocation apply to one copy and not
            # the other, and makes the audit trail ambiguous about which
            # grant actually authorized the action.
            return _deny(f"{where} repeats a grant id already used earlier in the chain.")
        seen_ids.add(grant.grant_id)

        if revocations is not None and revocations.is_revoked(grant.grant_id):
            return _deny(
                f"{where} has been revoked. Every authority descended from it is refused, "
                "including this one.",
                "delegation_revoked",
            )

        if grant.is_expired(now):
            assert grant.expires_at is not None  # is_expired() is False when it is None
            return _deny(
                f"{where} expired at {grant.expires_at.isoformat()} (now {now.isoformat()}).",
                "delegation_expired",
            )

        if depth == 0:
            if not grant.signature_matches(key):
                return _deny(
                    f"{where} is not signed by the root secret. Either it was never issued "
                    "by this operator, or its contents were edited after issue.",
                    "delegation_forged",
                )
            continue

        parent = grants[depth - 1]

        if grant.parent_id != parent.grant_id:
            return _deny(
                f"{where} names parent {grant.parent_id!r} but follows {parent.grant_id!r} "
                "in the chain."
            )
        if grant.issuer != parent.subject:
            return _deny(
                f"{where} was issued by {grant.issuer}, but the preceding link was held by "
                f"{parent.subject}. Authority does not jump between principals."
            )
        if not grant.signature_matches(parent.sig.encode("utf-8")):
            return _deny(
                f"{where} is not signed by its parent's signature - it was not minted from "
                f"{parent.grant_id!r}, or one of them was edited after issue.",
                "delegation_forged",
            )

        # Re-derive attenuation. `attenuate()` checked this at mint time,
        # but a chain arrives here as data - possibly deserialized,
        # possibly hand-built - and a check that only runs on the honest
        # path is not a check.
        widened = sorted(grant.classes - parent.classes)
        if widened:
            return _deny(
                f"{where} confers {widened}, which its parent {parent.grant_id!r} does not "
                f"hold ({sorted(parent.classes)}). Delegation can only narrow.",
                "delegation_amplified",
            )
        if parent.tools and (not grant.tools or (grant.tools - parent.tools)):
            widened_tools = (
                sorted(grant.tools - parent.tools) if grant.tools else ["<unrestricted>"]
            )
            return _deny(
                f"{where} confers tools {widened_tools} beyond its parent's "
                f"{sorted(parent.tools)}.",
                "delegation_amplified",
            )
        if parent.expires_at is not None and (
            grant.expires_at is None or grant.expires_at > parent.expires_at
        ):
            return _deny(
                f"{where} outlives its parent {parent.grant_id!r} "
                f"(expires {parent.expires_at.isoformat()}).",
                "delegation_amplified",
            )

    leaf = grants[-1]
    return AuthorityVerdict(
        True,
        (f"Delegation chain verified: {' -> '.join(str(g.subject) for g in grants)}.",),
        (),
        principal=leaf.subject,
        on_behalf_of=grants[0].issuer,
        chain_ids=tuple(g.grant_id for g in grants),
        subjects=tuple(g.subject for g in grants),
    )


def authorize(
    chain: Iterable[Grant],
    tool: str,
    *,
    now: Optional[datetime] = None,
    secret: Optional[bytes] = None,
    revocations: Optional[Revocations] = None,
    roots: Optional[Iterable[str]] = None,
    max_depth: int = MAX_CHAIN_DEPTH,
) -> AuthorityVerdict:
    """Verify the chain, then ask whether the LEAF grant covers `tool`.

    The leaf, not the union and not the root. The leaf is the authority the
    acting agent actually holds, and every ancestor is - by the attenuation
    invariant `verify_chain` just re-derived - at least as wide. Checking
    the root would authorize a sub-agent with its delegator's powers, which
    is the whole thing being prevented; checking the union would do the
    same, more subtly.
    """
    grants = list(chain)
    verdict = verify_chain(
        grants, now=now, secret=secret, revocations=revocations, roots=roots, max_depth=max_depth
    )
    if not verdict.allowed:
        return verdict

    leaf = grants[-1]
    permitted, why = leaf.permits_tool(tool)
    if not permitted:
        return AuthorityVerdict(
            False,
            (f"{leaf.subject} is not authorized for {tool!r}: {why}",),
            ("delegation_capability",),
            principal=leaf.subject,
            on_behalf_of=grants[0].issuer,
            chain_ids=tuple(g.grant_id for g in grants),
            subjects=tuple(g.subject for g in grants),
        )

    return AuthorityVerdict(
        True,
        (
            f"{leaf.subject} is authorized for {tool!r} on behalf of {grants[0].issuer} "
            f"via {len(grants)} grant(s).",
        ),
        (),
        principal=leaf.subject,
        on_behalf_of=grants[0].issuer,
        chain_ids=tuple(g.grant_id for g in grants),
        subjects=tuple(g.subject for g in grants),
    )


def chain_to_dicts(chain: Iterable[Grant]) -> list[dict[str, Any]]:
    """Serialize a chain for transport or for the journal."""
    return [g.to_dict() for g in chain]


def chain_from_dicts(raw: Any) -> list[Grant]:
    """Rebuild a chain from JSON.

    Signatures are NOT checked here - that is `verify_chain`'s job, and a
    deserializer that also verified would make it tempting to treat "it
    parsed" as "it is valid".
    """
    if not isinstance(raw, list):
        raise IdentityError(f"A delegation chain must be a list, got {type(raw).__name__}.")
    return [Grant.from_dict(item) for item in raw]
