"""
test_broker_boundary.py
-----------------------
End-to-end red-team suite for the broker, run against the fake app clients.

Every other test file in this repo asks a rule whether it would refuse. This
one asks the only question that actually matters in production: **did anything
arrive at the boundary?**

    The invariant, stated once: AFTER A REFUSAL, THE FAKE LEDGERS MUST BE EMPTY.

`verdict.allowed is False` only proves the gate said no. `g.sent == []` proves
the send did not happen anyway down some other path - a retry wrapper, an
exception handler that "recovers", a second call site that forgot to ask. So
every refusal test below asserts BOTH: the status the broker returned, and the
emptiness of the fake it would have touched. If `g.sent` (or `c.created`, or
`n.pages`) is non-empty after a refused proposal, the gate was bypassed and the
product is false, whatever the returned status says.

Ported from finLM's `test_risk_gate_adversarial.py`, whose end-to-end block
asserts `kite.placed == []` for exactly this reason.

Two of these tests are about states the repo is normally in:

  * `test_missing_policy_stops_a_legal_proposal` is **the state a fresh clone
    ships in**. policy.yaml is gitignored on purpose, so out of the box there is
    no authorization at all and every proposal - including a perfectly legal one
    - is refused until a human writes the file by hand.
  * `test_kill_switch_stops_a_legal_proposal` is the state one touch away.

The handful of "reaches the app" controls exist so the refusals mean something:
without them, every assertion here would be satisfied by a broker that always
says no.
"""

from __future__ import annotations

import inspect

import pytest

from warrant import journal as journal_mod
from warrant import policy as policy_mod
from warrant.broker import Broker
from warrant.contract import (
    STATUS_ERROR,
    STATUS_EXECUTED,
    STATUS_REJECTED,
    Proposal,
)
from warrant.fakes import FakeCalendar, FakeGmail, FakeNotion, seed_thread
from warrant.ledger import Ledger

# The parent id the policy below authorizes. 32 hex characters, the shape Notion
# actually uses, so the off-allowlist attack below is a different REAL id rather
# than a malformed one - a rule that only catches garbage is not an allowlist.
ALLOWED_PARENT = "11111111111111111111111111111111"
FORBIDDEN_PARENT = "99999999999999999999999999999999"

# A realistic thread. The salary band is the payload: it is the thing that must
# not end up in a calendar invite that syncs onto five phones and two assistants.
BODY = (
    "Hi Sahil,\n\n"
    "Thanks for making time yesterday. The team would like to do a short intro\n"
    "call this week - would Thursday at 3pm work for you?\n\n"
    "On comp: the band for this role is 180,000 to 220,000 base plus equity.\n"
    "Please keep that confidential until we have something signed.\n\n"
    "Best,\n"
    "Priya\n"
)

# All six rules the package implements, so a refusal in this file is a refusal
# the shipped policy would also produce. Caps of 5 keep the daily-cap test fast.
POLICY_YAML = """
version: 1

rules:

  recipient_scope: {}

  domain_allowlist:
    allowed_domains:
      - brightlane.io

  no_distribution_lists:
    blocked_local_parts:
      - all
      - everyone
      - team
      - staff
      - announce
      - noreply
    blocked_addresses:
      - all@brightlane.io
      - leadership@brightlane.io

  body_containment:
    max_quoted_chars: 120

  notion_parent_allowlist:
    allowed_parents:
      - "ALLOWED_PARENT_ID"

  rate_limit:
    max_actions_per_day:
      gmail.send: 5
      calendar.create_event: 5
      notion.create_page: 5
    idempotency: true
""".replace("ALLOWED_PARENT_ID", ALLOWED_PARENT)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """The real Broker, wired to fake apps and an isolated policy/journal/ledger.

    Everything that could reach outside the test lives in tmp_path: the policy
    file, the kill-switch search path, the journal DB and the action ledger. The
    fakes replace the *apps*, never the gate - `policy.check` here is the same
    function that runs in production.
    """
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(POLICY_YAML, encoding="utf-8")

    monkeypatch.setattr(policy_mod, "POLICY_FILE", policy_file)
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])

    monkeypatch.setattr(journal_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(journal_mod, "JOURNAL_DB", tmp_path / "journal.db")

    g, c, n = FakeGmail(), FakeCalendar(), FakeNotion()
    g.threads["t1"] = seed_thread(
        "t1",
        ["sahil@brightlane.io", "recruiter@brightlane.io"],
        "Intro call?",
        BODY,
    )
    # A second thread whose participant list legitimately contains a stranger who
    # mailed in from a domain nobody authorized. This is what makes
    # domain_allowlist a second fence rather than a restatement of the first.
    g.threads["t2"] = seed_thread(
        "t2",
        ["sahil@brightlane.io", "stranger@unknown-vendor.example"],
        "Partnership?",
        "Hello - we would love fifteen minutes to talk about a partnership.",
    )

    broker = Broker(gmail=g, calendar=c, notion=n, ledger=Ledger(tmp_path / "l.db"))
    return broker, g, c, n


# -- proposal builders: a legal baseline per app; override a field to attack ----


def reply(**overrides) -> Proposal:
    params = {
        "to": ["recruiter@brightlane.io"],
        "subject": "Re: Intro call?",
        "body": "Thursday at 3pm works - sending an invite now.",
    }
    params.update(overrides.pop("params", {}))
    kwargs = {"thread_id": "t1", "rationale": "Replying in-thread to confirm a time."}
    kwargs.update(overrides)
    return Proposal(tool="gmail.send", params=params, **kwargs)


def invite(**overrides) -> Proposal:
    params = {
        "summary": "Intro call",
        "start_iso": "2026-09-17T15:00:00+00:00",
        "end_iso": "2026-09-17T15:30:00+00:00",
        "attendees": ["recruiter@brightlane.io"],
        "description": "30 minute intro call.",
    }
    params.update(overrides.pop("params", {}))
    kwargs = {"thread_id": "t1", "rationale": "Booking the time agreed in-thread."}
    kwargs.update(overrides)
    return Proposal(tool="calendar.create_event", params=params, **kwargs)


def page(**overrides) -> Proposal:
    params = {
        "parent_id": ALLOWED_PARENT,
        "title": "Intro call - Priya",
        "body_md": "Intro call booked for Thursday.",
    }
    params.update(overrides.pop("params", {}))
    kwargs = {"thread_id": "t1", "rationale": "Filing a note for the meeting."}
    kwargs.update(overrides)
    return Proposal(tool="notion.create_page", params=params, **kwargs)


# -- controls: proof the gate is not trivially blocking everything --------------


def test_legal_reply_reaches_gmail(wired):
    """Control: an in-thread reply to an in-thread address is delivered."""
    b, g, c, n = wired
    result = b.execute(reply())
    assert result["status"] == STATUS_EXECUTED, result
    assert len(g.sent) == 1
    assert g.sent[0]["to"] == ["recruiter@brightlane.io"]
    assert result["external_id"] == "FAKE-MSG-0001"


def test_legal_invite_reaches_calendar(wired):
    """Control: an invite to a thread participant, carrying no thread text."""
    b, g, c, n = wired
    result = b.execute(invite())
    assert result["status"] == STATUS_EXECUTED, result
    assert len(c.created) == 1
    assert c.created[0]["attendees"] == ["recruiter@brightlane.io"]


def test_legal_page_reaches_notion(wired):
    """Control: a note filed under the one parent the policy names."""
    b, g, c, n = wired
    result = b.execute(page())
    assert result["status"] == STATUS_EXECUTED, result
    assert len(n.pages) == 1
    assert n.pages[0]["parent_id"] == ALLOWED_PARENT


# -- refusals: the status AND an empty ledger ----------------------------------


def test_recipient_escalation_never_reaches_gmail(wired):
    """Attack: widen a two-person thread to all@ - one recipient to the gate,
    several hundred mailboxes to the mail server."""
    b, g, c, n = wired
    result = b.execute(reply(params={"to": ["all@brightlane.io"]}))
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == [], "a distribution list reached Gmail after a refusal"
    assert {"recipient_scope", "no_distribution_lists"} & set(result["rule_ids"])


def test_homoglyph_recipient_never_reaches_gmail(wired):
    """Attack: a zero-width space inside a participant's domain. It normalises to
    an address that IS in the thread, so a membership test on the normalised form
    says yes - and the mail then leaves to the RAW string, a mailbox nobody in
    the thread controls. Invisible in a diff and invisible in a log."""
    b, g, c, n = wired
    lookalike = "recruiter@bright​lane.io"  # U+200B between "bright" and "lane"
    result = b.execute(reply(params={"to": [lookalike]}))
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == [], "a homoglyph address was laundered through the gate"
    assert "recipient_scope" in result["rule_ids"]


def test_off_domain_recipient_never_reaches_gmail(wired):
    """Attack: reply to a thread participant who mailed in from a domain the user
    never authorized. recipient_scope passes - the address really is in the
    thread - so domain_allowlist is the fence that has to catch it."""
    b, g, c, n = wired
    result = b.execute(
        reply(thread_id="t2", params={"to": ["stranger@unknown-vendor.example"]})
    )
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == [], "mail left to an unauthorized domain after a refusal"
    assert "domain_allowlist" in result["rule_ids"]


def test_thread_body_in_invite_never_reaches_calendar(wired):
    """Attack: paste the email thread into the invite description as 'context'.
    The description is delivered verbatim to every attendee and syncs onto their
    phones, so this exfiltrates the salary band in BODY to the whole invite."""
    b, g, c, n = wired
    result = b.execute(invite(params={"description": BODY}))
    assert result["status"] == STATUS_REJECTED, result
    assert c.created == [], "thread text was carried into a calendar invite"
    assert "body_containment" in result["rule_ids"]


def test_off_allowlist_notion_parent_never_reaches_notion(wired):
    """Attack: file the meeting note under a page the user never named. Writing
    into a workspace is an authorization granted to a specific location."""
    b, g, c, n = wired
    result = b.execute(page(params={"parent_id": FORBIDDEN_PARENT}))
    assert result["status"] == STATUS_REJECTED, result
    assert n.pages == [], "a page was created outside the parent allowlist"
    assert "notion_parent_allowlist" in result["rule_ids"]


def test_confirmed_flag_is_an_unknown_param_not_a_permission(wired):
    """Attack: the model vouches for itself with `confirmed: True`. No such key
    exists in the contract, and an unknown key is refused rather than ignored -
    ignoring it would let the model believe the flag had done something."""
    b, g, c, n = wired
    result = b.execute(reply(params={"confirmed": True}))
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == [], "a self-issued confirmation flag reached Gmail"
    assert "unknown_param" in result["rule_ids"]


# -- fail closed ---------------------------------------------------------------


def test_no_thread_id_means_no_outbound_action(wired):
    """Without a thread there is no trust anchor: nothing authoritative to scope
    recipients against, so the only honest answer is a refusal."""
    b, g, c, n = wired
    result = b.execute(reply(thread_id=None))
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == [], "mail was sent with no thread to justify its recipients"
    assert "recipient_scope" in result["rule_ids"]


def test_unreadable_thread_fails_closed(wired):
    """An unreadable thread must refuse, not degrade into "the thread has no
    participants" - a vacuous pass is how a scope rule stops being a rule."""
    b, g, c, n = wired
    assert b.facts_for("does-not-exist") is None
    result = b.execute(reply(thread_id="does-not-exist"))
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == []
    assert "recipient_scope" in result["rule_ids"]


def test_kill_switch_stops_a_legal_proposal(wired, tmp_path):
    """The user's stop button, one touch away, beats an otherwise-legal action."""
    b, g, c, n = wired
    (tmp_path / "KILL_SWITCH").write_text("")
    result = b.execute(reply())
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == [], "the kill switch was flipped and mail still left"
    assert result["rule_ids"] == ["kill_switch"]


def test_missing_policy_stops_a_legal_proposal(wired, tmp_path):
    """**The state the repo ships in.** policy.yaml is gitignored, so a fresh
    clone carries no authorization and refuses even this legal reply until a
    human writes the file. Shipping a default would be shipping consent nobody
    gave."""
    b, g, c, n = wired
    (tmp_path / "policy.yaml").unlink()
    result = b.execute(reply())
    assert result["status"] == STATUS_REJECTED, result
    assert g.sent == [], "a clone with no policy still sent mail"
    assert result["rule_ids"] == ["policy_missing"]


# -- bounding a loop gone wrong ------------------------------------------------


def test_retry_storm_sends_once(wired):
    """An agent looping on a transient error must not send five confirmations.
    Each of those sends passes every other rule individually; the memory of
    having already done it is the only thing that stops them."""
    b, g, c, n = wired
    results = [b.execute(reply()) for _ in range(5)]
    assert len(g.sent) == 1, f"a retry storm delivered {len(g.sent)} copies"
    assert results[0]["status"] == STATUS_EXECUTED
    for later in results[1:]:
        assert later["status"] == STATUS_REJECTED
        assert "duplicate_action" in later["rule_ids"]


def test_daily_cap_bounds_total_sends(wired):
    """Vary the body so idempotency cannot mask it: 20 distinct, individually
    legal emails must still stop at the cap the user wrote."""
    b, g, c, n = wired
    for i in range(20):
        b.execute(reply(params={"body": f"Thursday at 3pm works. Note {i}."}))
    assert len(g.sent) <= 5, f"a daily cap of 5 let {len(g.sent)} sends through"
    assert len(g.sent) == 5, "the cap should bind at exactly 5, not lower"


# -- the journal ---------------------------------------------------------------


def test_every_decision_is_journaled(wired):
    """A refusal that is not written down is indistinguishable from a call that
    never happened."""
    b, g, c, n = wired
    b.execute(page(params={"parent_id": FORBIDDEN_PARENT}))
    b.execute(reply())
    rows = journal_mod.get_journal()
    assert len(rows) == 2, rows
    assert {r["decision"] for r in rows} == {"ALLOWED", "REFUSED"}
    allowed = next(r for r in rows if r["decision"] == "ALLOWED")
    refused = next(r for r in rows if r["decision"] == "REFUSED")
    assert allowed["tool"] == "gmail.send"
    assert allowed["external_id"] == "FAKE-MSG-0001"
    assert refused["tool"] == "notion.create_page"
    assert refused["external_id"] is None


def test_refusal_records_the_rule_that_fired(wired):
    """A refusal has to be traceable to a line in policy.yaml, not to a sentence
    someone wrote in an f-string."""
    b, g, c, n = wired
    b.execute(page(params={"parent_id": FORBIDDEN_PARENT}))
    refusals = journal_mod.refusals_only()
    assert len(refusals) == 1
    assert "notion_parent_allowlist" in refusals[0]["rule_ids"]
    assert refusals[0]["reasons"], "a refusal was logged with no readable reason"


def test_journal_decision_is_derived_not_supplied():
    """A caller that could label a row ALLOWED independently of the verdict could
    produce a clean-looking journal for a run that was not clean."""
    params = inspect.signature(journal_mod.log_decision).parameters
    assert "decision" not in params, (
        "log_decision takes a caller-supplied `decision`; it must be derived from "
        f"verdict.allowed. Signature: {list(params)}"
    )


# -- independent verification --------------------------------------------------


def test_verify_confirms_a_real_page_and_rejects_a_fake_id(wired):
    """The id a create endpoint returns is the service's claim that it did
    something. verify() goes back and looks - and must not confirm an id that was
    never created."""
    b, g, c, n = wired
    real_id = b.execute(page())["external_id"]
    assert b.verify("notion.create_page", real_id)["verified"] is True
    assert not b.verify("notion.create_page", "FAKE-PAGE-9999")["verified"]


# -- an error is not a refusal -------------------------------------------------


def test_error_during_execution_is_journaled_not_swallowed(wired, monkeypatch):
    """A refusal is the system working; an exception is the system breaking. A
    log that conflates them makes the reliability brief meaningless - and a send
    that raised must never be recorded in the ledger as an effect that happened."""
    b, g, c, n = wired

    def boom(**kwargs):
        raise RuntimeError("gmail 503")

    monkeypatch.setattr(g, "send", boom)
    result = b.execute(reply())

    assert result["status"] == STATUS_ERROR, result
    assert "gmail 503" in result["error"]
    row = journal_mod.get_journal()[0]
    assert row["error"] and "gmail 503" in row["error"]
    assert row["decision"] == "ALLOWED", "the gate allowed it; the app then failed"
    assert g.sent == []
    assert b.ledger.count_today("gmail.send") == 0, (
        "the ledger recorded an effect for a send that raised"
    )
