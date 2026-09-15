"""
test_policy_multi_app.py
──────────────────────────
Red-team suite for the four rules the multi-app suite added:
`destination_allowlist`, `spend_cap`, `irreversible_gate`, `audience_bound`.

`test_policy_adversarial.py` covers the original six rules against the
three-app scenario they were written for. This file is the same kind of
suite for the rules that reason about capability classes instead of app
names - which means every test here deliberately reaches for an app
`test_policy_adversarial.py` has never heard of (Slack, Stripe, Twilio,
GitHub, Linear), to prove the new rules actually generalize rather than only
having been exercised against the one app each was designed against.

Same asymmetry as the original suite: almost every assertion here is a
refusal, with a handful of controls proving the rule is not simply blocking
everything.
"""

from __future__ import annotations

import pytest
import yaml

from warrant import policy as policy_mod
from warrant.contract import Proposal
from warrant.ledger import Ledger

PARENT = "11111111111111111111111111111111"


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "policy.yaml")
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    return tmp_path


def write_policy(gate, rules: dict) -> None:
    (gate / "policy.yaml").write_text(yaml.safe_dump({"version": 1, "rules": rules}), encoding="utf-8")


@pytest.fixture
def ledger(tmp_path):
    return Ledger(tmp_path / "ledger.db")


def reasons_text(verdict) -> str:
    return " ".join(verdict.reasons)


# ── destination_allowlist ─────────────────────────────────────────────────


def test_destination_in_the_allowlist_is_allowed(gate, ledger):
    write_policy(gate, {"destination_allowlist": {"allowed": {"slack.post_message": ["C0OK"]}}})
    proposal = Proposal(tool="slack.post_message", params={"channel": "C0OK", "text": "hi"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert verdict.allowed, reasons_text(verdict)


def test_destination_not_in_the_allowlist_is_refused_even_when_others_are(gate, ledger):
    """The exact allowlist-bypass shape: one destination for this tool IS
    configured, and the proposal targets a different one. A rule that only
    checked 'is anything configured for this tool' rather than 'is THIS
    destination configured' would wave this through."""
    write_policy(gate, {"destination_allowlist": {"allowed": {"slack.post_message": ["C0OK"]}}})
    proposal = Proposal(tool="slack.post_message", params={"channel": "C0EVIL", "text": "hi"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "destination_allowlist" in verdict.rule_ids


def test_tool_with_no_configured_destinations_at_all_is_refused(gate, ledger):
    """Empty or missing allowlist for a tool means nowhere is writable, the
    same asymmetry notion_parent_allowlist established - absence authorizes
    nothing."""
    write_policy(gate, {"destination_allowlist": {"allowed": {}}})
    proposal = Proposal(tool="github.create_issue", params={"repo": "org/repo", "title": "x"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "destination_allowlist" in verdict.rule_ids
    assert "allows nothing" in reasons_text(verdict)


def test_missing_destination_param_is_refused_not_skipped(gate, ledger):
    write_policy(gate, {"destination_allowlist": {"allowed": {"linear.create_issue": ["team_1"]}}})
    proposal = Proposal(tool="linear.create_issue", params={"title": "x"})  # no team_id
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "destination_allowlist" in verdict.rule_ids


def test_notion_create_page_is_governed_by_its_own_rule_not_this_one(gate, ledger):
    """notion.create_page is grandfathered under notion_parent_allowlist - an
    empty destination_allowlist.allowed must not refuse it a second time for
    a config key it does not use."""
    write_policy(
        gate,
        {
            "destination_allowlist": {"allowed": {}},
            "notion_parent_allowlist": {"allowed_parents": [PARENT]},
        },
    )
    proposal = Proposal(tool="notion.create_page", params={"parent_id": PARENT, "title": "x"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert verdict.allowed, reasons_text(verdict)


def test_a_tool_with_no_destination_param_is_not_graded_by_this_rule(gate, ledger):
    """twilio.send_sms has recipients, not a destination - destination_allowlist
    must return no objection for it regardless of what is configured."""
    write_policy(gate, {"destination_allowlist": {"allowed": {}}, "irreversible_gate": {"allowed_tools": ["twilio.send_sms"]}})
    proposal = Proposal(
        tool="twilio.send_sms",
        params={"to": ["+15550001111"], "from_number": "+15550009999", "body": "hi"},
    )
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert verdict.allowed, reasons_text(verdict)


# ── spend_cap ───────────────────────────────────────────────────────────────


def test_spend_under_both_caps_is_allowed(gate, ledger):
    write_policy(
        gate,
        {
            "irreversible_gate": {"allowed_tools": ["stripe.create_refund"]},
            "spend_cap": {
                "currency": "usd",
                "max_per_action_minor": {"stripe.create_refund": 5000},
                "max_per_day_minor": {"stripe.create_refund": 20000},
            },
        },
    )
    proposal = Proposal(
        tool="stripe.create_refund",
        params={"payment_intent": "pi_1", "amount": 4000, "currency": "usd"},
    )
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert verdict.allowed, reasons_text(verdict)


def test_a_single_action_over_the_per_action_cap_is_refused(gate, ledger):
    """No max_per_day_minor configured at all here - if this failed to refuse,
    the only possible cause is the per-action check itself, not the daily one
    picking up the slack. This is the test that pins down
    `scripts/mutate.py`'s spend-cap-ignores-per-action-limit mutation."""
    write_policy(
        gate,
        {
            "irreversible_gate": {"allowed_tools": ["stripe.create_refund"]},
            "spend_cap": {"currency": "usd", "max_per_action_minor": {"stripe.create_refund": 5000}},
        },
    )
    proposal = Proposal(
        tool="stripe.create_refund",
        params={"payment_intent": "pi_1", "amount": 999999, "currency": "usd"},
    )
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "spend_cap" in verdict.rule_ids


def test_cumulative_spend_over_the_daily_cap_is_refused_on_the_second_call(gate, ledger):
    """No max_per_action_minor here - only the running total, read from the
    ledger, can catch this. Executes through the broker (not just check())
    so the ledger actually accumulates a real row between the two calls."""
    from warrant.broker import Broker
    from warrant.fakes import FakeStripe

    write_policy(
        gate,
        {
            "destination_allowlist": {"allowed": {"stripe.create_refund": ["pi_1"]}},
            "irreversible_gate": {"allowed_tools": ["stripe.create_refund"]},
            "spend_cap": {"currency": "usd", "max_per_day_minor": {"stripe.create_refund": 15000}},
        },
    )
    broker = Broker(apps={"stripe": FakeStripe()}, ledger=ledger)
    first = broker.execute(Proposal(
        tool="stripe.create_refund", params={"payment_intent": "pi_1", "amount": 8000, "currency": "usd"}
    ))
    second = broker.execute(Proposal(
        tool="stripe.create_refund", params={"payment_intent": "pi_1", "amount": 8001, "currency": "usd"}
    ))
    assert first["status"] == "EXECUTED"
    assert second["status"] == "REJECTED_BY_POLICY_GATE"
    assert "spend_cap" in second["rule_ids"]


def test_currency_mismatch_is_refused_rather_than_converted(gate, ledger):
    write_policy(
        gate,
        {
            "irreversible_gate": {"allowed_tools": ["stripe.create_refund"]},
            "spend_cap": {"currency": "usd", "max_per_action_minor": {"stripe.create_refund": 500000}},
        },
    )
    proposal = Proposal(
        tool="stripe.create_refund",
        params={"payment_intent": "pi_1", "amount": 100, "currency": "eur"},
    )
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "spend_cap" in verdict.rule_ids
    assert "convert" not in reasons_text(verdict).lower() or "refusing rather than converting" in reasons_text(verdict).lower()


def test_flat_cost_tool_is_priced_by_recipient_count(gate, ledger):
    """twilio.send_sms has no amount param - registry.flat_cost_minor prices
    it, multiplied by how many numbers are in `to`. Three recipients at the
    registry's flat cost must trip a cap sized for one message."""
    write_policy(
        gate,
        {
            "irreversible_gate": {"allowed_tools": ["twilio.send_sms"]},
            "spend_cap": {"currency": "usd", "max_per_action_minor": {"twilio.send_sms": 1}},
        },
    )
    proposal = Proposal(
        tool="twilio.send_sms",
        params={"to": ["+1550000001", "+1550000002", "+1550000003"], "from_number": "+1550009999", "body": "hi"},
    )
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "spend_cap" in verdict.rule_ids


def test_spend_cap_does_not_apply_to_a_tool_that_does_not_spend(gate, ledger):
    write_policy(gate, {"spend_cap": {"currency": "usd", "max_per_action_minor": {"slack.post_message": 1}}})
    proposal = Proposal(tool="slack.post_message", params={"channel": "C0OK", "text": "hi"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    # spend_cap has nothing to say about a non-spend tool; whether the overall
    # proposal is allowed depends on whatever OTHER rules are configured, and
    # none are here, so it is allowed.
    assert "spend_cap" not in verdict.rule_ids


# ── irreversible_gate ────────────────────────────────────────────────────────


def test_an_allowlisted_irreversible_tool_is_allowed(gate, ledger):
    write_policy(gate, {"irreversible_gate": {"allowed_tools": ["gmail.send"]}})
    proposal = Proposal(
        tool="gmail.send", params={"to": ["a@b.com"], "subject": "x", "body": "y"}, thread_id="t1",
    )
    from warrant.fakes import seed_thread

    verdict = policy_mod.check(proposal, facts=seed_thread("t1", ["a@b.com"], "s", "b"), ledger=ledger)
    assert verdict.allowed, reasons_text(verdict)


def test_an_irreversible_tool_absent_from_the_allowlist_is_refused(gate, ledger):
    write_policy(gate, {"irreversible_gate": {"allowed_tools": []}})
    proposal = Proposal(tool="twilio.send_sms", params={"to": ["+15550001111"], "from_number": "+15550009999", "body": "hi"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "irreversible_gate" in verdict.rule_ids


def test_missing_allowed_tools_refuses_every_irreversible_action(gate, ledger):
    write_policy(gate, {"irreversible_gate": {}})
    proposal = Proposal(tool="slack.post_message", params={"channel": "C1", "text": "hi"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert not verdict.allowed
    assert "irreversible_gate" in verdict.rule_ids


def test_a_reversible_tool_is_not_graded_by_irreversible_gate(gate, ledger):
    """notion.create_page is REVERSIBLE - irreversible_gate must return no
    objection for it even with an empty allowlist, or every Notion write
    would need to appear in a config block meant for a different hazard."""
    write_policy(
        gate,
        {"irreversible_gate": {"allowed_tools": []}, "notion_parent_allowlist": {"allowed_parents": [PARENT]}},
    )
    proposal = Proposal(tool="notion.create_page", params={"parent_id": PARENT, "title": "x"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert verdict.allowed, reasons_text(verdict)


# ── audience_bound ────────────────────────────────────────────────────────


def test_distinct_audiences_under_the_cap_are_allowed(gate, ledger):
    from warrant.broker import Broker
    from warrant.fakes import FakeSlack

    write_policy(
        gate,
        {
            "destination_allowlist": {"allowed": {"slack.post_message": ["C1", "C2", "C3"]}},
            "irreversible_gate": {"allowed_tools": ["slack.post_message"]},
            "audience_bound": {"max_distinct_per_day": {"slack.post_message": 2}},
        },
    )
    broker = Broker(apps={"slack": FakeSlack()}, ledger=ledger)
    r1 = broker.execute(Proposal(tool="slack.post_message", params={"channel": "C1", "text": "a"}))
    r2 = broker.execute(Proposal(tool="slack.post_message", params={"channel": "C2", "text": "b"}))
    assert r1["status"] == "EXECUTED"
    assert r2["status"] == "EXECUTED"


def test_a_third_distinct_audience_over_the_cap_is_refused(gate, ledger):
    from warrant.broker import Broker
    from warrant.fakes import FakeSlack

    write_policy(
        gate,
        {
            "destination_allowlist": {"allowed": {"slack.post_message": ["C1", "C2", "C3"]}},
            "irreversible_gate": {"allowed_tools": ["slack.post_message"]},
            "audience_bound": {"max_distinct_per_day": {"slack.post_message": 2}},
        },
    )
    broker = Broker(apps={"slack": FakeSlack()}, ledger=ledger)
    broker.execute(Proposal(tool="slack.post_message", params={"channel": "C1", "text": "a"}))
    broker.execute(Proposal(tool="slack.post_message", params={"channel": "C2", "text": "b"}))
    third = broker.execute(Proposal(tool="slack.post_message", params={"channel": "C3", "text": "c"}))
    assert third["status"] == "REJECTED_BY_POLICY_GATE"
    assert "audience_bound" in third["rule_ids"]


def test_repeating_the_same_audience_does_not_count_as_a_new_one(gate, ledger):
    """Posting to the SAME channel five times is not five distinct audiences -
    audience_bound counts DISTINCT destinations, and a rule that counted raw
    calls instead would be indistinguishable from rate_limit."""
    from warrant.broker import Broker
    from warrant.fakes import FakeSlack

    write_policy(
        gate,
        {
            "destination_allowlist": {"allowed": {"slack.post_message": ["C1"]}},
            "irreversible_gate": {"allowed_tools": ["slack.post_message"]},
            "audience_bound": {"max_distinct_per_day": {"slack.post_message": 1}},
        },
    )
    broker = Broker(apps={"slack": FakeSlack()}, ledger=ledger)
    for i in range(4):
        result = broker.execute(Proposal(tool="slack.post_message", params={"channel": "C1", "text": f"msg {i}"}))
        assert result["status"] == "EXECUTED", result

    assert len(broker._client("slack").posted) == 4


def test_audience_bound_without_a_configured_cap_does_not_apply(gate, ledger):
    write_policy(gate, {"destination_allowlist": {"allowed": {"slack.post_message": ["C1"]}},
                        "irreversible_gate": {"allowed_tools": ["slack.post_message"]},
                        "audience_bound": {"max_distinct_per_day": {}}})
    proposal = Proposal(tool="slack.post_message", params={"channel": "C1", "text": "hi"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert verdict.allowed, reasons_text(verdict)


def test_audience_bound_does_not_apply_to_a_tool_without_an_audience(gate, ledger):
    """github.create_issue has a destination but is not AUDIENCE - a repo is
    not a crowd. audience_bound must have nothing to say about it."""
    write_policy(gate, {"audience_bound": {"max_distinct_per_day": {"github.create_issue": 1}}})
    proposal = Proposal(tool="github.create_issue", params={"repo": "org/repo", "title": "x"})
    verdict = policy_mod.check(proposal, facts=None, ledger=ledger)
    assert "audience_bound" not in verdict.rule_ids
