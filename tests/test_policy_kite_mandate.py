"""
test_policy_kite_mandate.py
────────────────────────────
Red-team suite for `_rule_kite_mandate` - the thin adapter that delegates a
kite.place_order proposal to llmfin.risk.check_order() instead of
reimplementing its mandate logic natively.

`llmfin` is not installed in warrant's own test environment by design (see
policy.py's docstring: warrant must not gain a hard dependency on it) - which
means `test_llmfin_not_importable_fails_closed` below exercises the REAL
current state of this environment, not a simulated one. The delegation tests
that need `check_order` to actually run monkeypatch `sys.modules['llmfin.risk']`
with a fake module, which is the standard way to unit-test a lazy import
without installing the real package into an environment that must not depend
on it.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass

import pytest
import yaml

from warrant import policy as policy_mod
from warrant.contract import KiteFacts, Proposal
from warrant.ledger import Ledger

TOOL = "kite.place_order"


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "policy.yaml")
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump({"version": 1, "rules": {"kite_mandate": {}}}), encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def ledger(tmp_path):
    return Ledger(tmp_path / "ledger.db")


def _proposal(**overrides) -> Proposal:
    params = {
        "tradingsymbol": "RELIANCE",
        "transaction_type": "BUY",
        "quantity": 1,
        "order_type": "MARKET",
        "exchange": "NSE",
        "product": "CNC",
    }
    params.update(overrides)
    return Proposal(tool=TOOL, params=params)


def _facts(**overrides) -> KiteFacts:
    defaults = dict(
        tenant_id="tenant-a",
        mandate={"max_order_value_inr": 50000},
        kill_switch_reason=None,
        orders_today=0,
        value_today=0.0,
        live_quote=100.0,
        quote_source="market",
    )
    defaults.update(overrides)
    return KiteFacts(**defaults)


@dataclass
class _FakeRiskVerdict:
    allowed: bool
    reasons: list[str]


def _install_fake_llmfin(monkeypatch, check_order_fn) -> None:
    fake_risk = types.ModuleType("llmfin.risk")
    fake_risk.check_order = check_order_fn
    fake_llmfin = types.ModuleType("llmfin")
    fake_llmfin.risk = fake_risk
    monkeypatch.setitem(sys.modules, "llmfin", fake_llmfin)
    monkeypatch.setitem(sys.modules, "llmfin.risk", fake_risk)


def reasons_text(verdict) -> str:
    return " ".join(verdict.reasons)


# ── kill switch, checked before anything else ───────────────────────────────


def test_kill_switch_in_facts_refuses_regardless_of_mandate(gate, ledger, monkeypatch):
    """A permissive mandate must not matter once KiteFacts says the kill
    switch is active - checked before llmfin is even imported."""

    def _should_never_be_called(**kwargs):
        raise AssertionError("check_order was called despite an active kill switch")

    _install_fake_llmfin(monkeypatch, _should_never_be_called)

    facts = _facts(kill_switch_reason="tenant flipped the kill switch")
    verdict = policy_mod.check(_proposal(), facts=facts, ledger=ledger)

    assert not verdict.allowed
    assert "kite_kill_switch" in verdict.rule_ids
    assert "tenant flipped the kill switch" in reasons_text(verdict)


# ── missing/wrong facts type fails closed ───────────────────────────────────


def test_missing_kite_facts_refuses(gate, ledger):
    """A kite proposal with no KiteFacts (facts=None, or the platform forgot
    to wire a facts_providers closure) must refuse rather than evaluate
    against anything the proposal itself claims."""
    verdict = policy_mod.check(_proposal(), facts=None, ledger=ledger)

    assert not verdict.allowed
    assert "kite_mandate" in verdict.rule_ids


def test_wrong_facts_type_refuses(gate, ledger):
    """ThreadFacts (the Gmail-shaped trust anchor) is not KiteFacts - a bug
    that wired the wrong facts type must still fail closed, not duck-type
    its way through."""
    from warrant.contract import ThreadFacts

    verdict = policy_mod.check(
        _proposal(), facts=ThreadFacts(thread_id="t1", participants=["a@b.com"]), ledger=ledger
    )

    assert not verdict.allowed
    assert "kite_mandate" in verdict.rule_ids


# ── llmfin not importable: the REAL current state of this environment ──────


def test_llmfin_not_importable_fails_closed(gate, ledger):
    """warrant must not depend on llmfin - this is not simulated, llmfin is
    genuinely absent from warrant's own test environment by design."""
    assert "llmfin" not in sys.modules or not hasattr(sys.modules.get("llmfin"), "risk")

    verdict = policy_mod.check(_proposal(), facts=_facts(), ledger=ledger)

    assert not verdict.allowed
    assert "kite_mandate" in verdict.rule_ids
    assert "llmfin is not installed" in reasons_text(verdict)


# ── delegation to check_order actually happens ──────────────────────────────


def test_mandate_violating_order_is_refused_via_delegated_check_order(gate, ledger, monkeypatch):
    _install_fake_llmfin(
        monkeypatch,
        lambda **kwargs: _FakeRiskVerdict(False, ["order value exceeds max_order_value_inr"]),
    )

    verdict = policy_mod.check(_proposal(), facts=_facts(), ledger=ledger)

    assert not verdict.allowed
    assert "kite_mandate" in verdict.rule_ids
    assert "exceeds max_order_value_inr" in reasons_text(verdict)


def test_legitimate_order_within_mandate_is_allowed(gate, ledger, monkeypatch):
    _install_fake_llmfin(monkeypatch, lambda **kwargs: _FakeRiskVerdict(True, []))

    verdict = policy_mod.check(_proposal(), facts=_facts(), ledger=ledger)

    assert verdict.allowed, reasons_text(verdict)


def test_check_order_receives_the_facts_derived_values_not_the_proposals_own_claims(
    gate, ledger, monkeypatch
):
    """The whole point of KiteFacts: check_order must be called with the
    broker-verified live_quote/quote_source and the platform-fetched
    mandate/counts - never anything the model's Proposal itself asserts (the
    Proposal here carries no price/mandate/order-count fields at all, so
    there is nothing for the rule to leak even by accident - this test pins
    exactly what does get passed)."""
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return _FakeRiskVerdict(True, [])

    _install_fake_llmfin(monkeypatch, _capture)

    facts = _facts(
        mandate={"max_order_value_inr": 999},
        orders_today=3,
        value_today=1234.5,
        live_quote=2500.75,
        quote_source="kite_ltp",
    )
    verdict = policy_mod.check(_proposal(), facts=facts, ledger=ledger)

    assert verdict.allowed
    assert captured["injected_mandate"] == {"max_order_value_inr": 999}
    assert captured["orders_today"] == 3
    assert captured["value_today"] == 1234.5
    assert captured["est_price"] == 2500.75
    assert captured["est_price_source"] == "kite_ltp"
    assert captured["symbol"] == "RELIANCE"
    assert captured["transaction_type"] == "BUY"


def test_non_kite_tools_are_unaffected(gate, ledger):
    """_rule_kite_mandate must be a no-op for every other tool - the same
    'not applicable, returns []' shape as every other single-app rule."""
    from warrant.contract import Proposal as P

    verdict = policy_mod.check(P(tool="unknown.tool", params={}), facts=None, ledger=ledger)
    # Refused, but for unknown_tool - not kite_mandate.
    assert not verdict.allowed
    assert "kite_mandate" not in verdict.rule_ids
