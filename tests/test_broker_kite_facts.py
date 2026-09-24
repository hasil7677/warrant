"""
test_broker_kite_facts.py
───────────────────────────
`Broker._gather_facts()` dispatch: a `facts_providers` closure is called for
the app it's registered against, and every app absent from that dict keeps
`facts_for(proposal.thread_id)` byte-for-byte - the acceptance bar for this
change is that all twelve pre-existing apps are provably unaffected, not just
assumed to be. `test_broker_boundary.py` already covers the full existing
Gmail/Calendar/Notion path end-to-end; this file adds the facts-dispatch
seam itself, plus one full kite.place_order run through the real
`Broker.execute()` - registry, broker, policy, ledger and journal together.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass

import pytest
import yaml

from warrant import journal as journal_mod
from warrant import policy as policy_mod
from warrant.broker import Broker
from warrant.contract import STATUS_EXECUTED, STATUS_REJECTED, KiteFacts, Proposal
from warrant.fakes import FakeCalendar, FakeGmail, FakeKite, FakeNotion, seed_thread
from warrant.ledger import Ledger


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "policy.yaml")
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    monkeypatch.setattr(journal_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(journal_mod, "JOURNAL_DB", tmp_path / "journal.db")
    return tmp_path


def write_policy(gate, rules: dict) -> None:
    (gate / "policy.yaml").write_text(yaml.safe_dump({"version": 1, "rules": rules}), encoding="utf-8")


@dataclass
class _FakeRiskVerdict:
    allowed: bool
    reasons: list[str]


def _install_fake_llmfin(monkeypatch, allowed: bool) -> None:
    fake_risk = types.ModuleType("llmfin.risk")
    fake_risk.check_order = lambda **kwargs: _FakeRiskVerdict(allowed, [] if allowed else ["over mandate"])
    fake_llmfin = types.ModuleType("llmfin")
    fake_llmfin.risk = fake_risk
    monkeypatch.setitem(sys.modules, "llmfin", fake_llmfin)
    monkeypatch.setitem(sys.modules, "llmfin.risk", fake_risk)


# ── _gather_facts dispatch ───────────────────────────────────────────────────


def test_facts_provider_is_called_only_for_its_own_app(gate):
    write_policy(gate, {"kite_mandate": {}, "notion_parent_allowlist": {"allowed_parents": ["p1"]}})

    calls: list[str] = []

    def kite_facts(proposal):
        calls.append(proposal.tool)
        return KiteFacts(
            tenant_id="t1", mandate={}, kill_switch_reason=None,
            orders_today=0, value_today=0.0, live_quote=100.0, quote_source="market",
        )

    notion = FakeNotion()
    broker = Broker(
        notion=notion,
        apps={"kite": FakeKite()},
        ledger=Ledger(gate / "ledger.db"),
        facts_providers={"kite": kite_facts},
    )

    # A notion proposal must NOT invoke the kite facts provider.
    broker.execute(Proposal(tool="notion.create_page", params={"parent_id": "p1", "title": "x"}))
    assert calls == [], "kite's facts_providers closure was called for a non-kite tool"


def test_facts_provider_is_called_for_its_own_app(gate, monkeypatch):
    _install_fake_llmfin(monkeypatch, allowed=True)
    write_policy(gate, {"kite_mandate": {}})

    calls: list[str] = []

    def kite_facts(proposal):
        calls.append(proposal.tool)
        return KiteFacts(
            tenant_id="t1", mandate={}, kill_switch_reason=None,
            orders_today=0, value_today=0.0, live_quote=100.0, quote_source="market",
        )

    broker = Broker(
        apps={"kite": FakeKite()},
        ledger=Ledger(gate / "ledger.db"),
        facts_providers={"kite": kite_facts},
        journal_path=gate / "journal.db",
    )
    result = broker.execute(
        Proposal(tool="kite.place_order", params={
            "tradingsymbol": "RELIANCE", "transaction_type": "BUY", "quantity": 1,
            "order_type": "MARKET", "exchange": "NSE", "product": "CNC",
        })
    )

    assert calls == ["kite.place_order"]
    assert result["status"] == STATUS_EXECUTED, result


def test_pre_existing_apps_are_unaffected_by_facts_providers_being_set(gate):
    """The critical regression check: wiring a facts_providers dict for kite
    must not change behaviour for any of the twelve apps that never appear
    in it - Gmail's thread-scoped facts_for() path must still run exactly as
    it did before this change existed."""
    write_policy(gate, {"recipient_scope": {}})

    gmail = FakeGmail()
    gmail.threads["t1"] = seed_thread(
        thread_id="t1", participants=["a@b.com"], subject="hi", body_text="hi"
    )

    broker = Broker(
        gmail=gmail,
        calendar=FakeCalendar(),
        notion=FakeNotion(),
        ledger=Ledger(gate / "ledger.db"),
        facts_providers={"kite": lambda proposal: (_ for _ in ()).throw(
            AssertionError("kite's facts provider must never be called for gmail.send")
        )},
    )
    result = broker.execute(
        Proposal(tool="gmail.send", params={"to": ["a@b.com"], "subject": "hi", "body": "hi"}, thread_id="t1")
    )
    assert result["status"] == STATUS_EXECUTED, result


# ── end-to-end kite.place_order through the real gate ───────────────────────


def test_mandate_violating_kite_order_never_reaches_the_fake_broker(gate, monkeypatch):
    """Same invariant test_broker_boundary.py enforces for the original
    three apps: after a refusal, the fake ledger must be empty."""
    _install_fake_llmfin(monkeypatch, allowed=False)
    write_policy(gate, {"kite_mandate": {}})

    kite = FakeKite()
    broker = Broker(
        apps={"kite": kite},
        ledger=Ledger(gate / "ledger.db"),
        facts_providers={"kite": lambda proposal: KiteFacts(
            tenant_id="t1", mandate={"max_order_value_inr": 1}, kill_switch_reason=None,
            orders_today=0, value_today=0.0, live_quote=100000.0, quote_source="market",
        )},
        journal_path=gate / "journal.db",
    )
    result = broker.execute(
        Proposal(tool="kite.place_order", params={
            "tradingsymbol": "RELIANCE", "transaction_type": "BUY", "quantity": 100,
            "order_type": "MARKET", "exchange": "NSE", "product": "CNC",
        })
    )

    assert result["status"] == STATUS_REJECTED, result
    assert kite.orders == [], "a mandate-violating order reached the fake Kite client anyway"


def test_legitimate_kite_order_reaches_the_fake_broker_with_variety_injected(gate, monkeypatch):
    _install_fake_llmfin(monkeypatch, allowed=True)
    write_policy(gate, {"kite_mandate": {}})

    kite = FakeKite()
    broker = Broker(
        apps={"kite": kite},
        ledger=Ledger(gate / "ledger.db"),
        facts_providers={"kite": lambda proposal: KiteFacts(
            tenant_id="t1", mandate={}, kill_switch_reason=None,
            orders_today=0, value_today=0.0, live_quote=2500.0, quote_source="market",
        )},
        journal_path=gate / "journal.db",
    )
    result = broker.execute(
        Proposal(tool="kite.place_order", params={
            "tradingsymbol": "RELIANCE", "transaction_type": "BUY", "quantity": 1,
            "order_type": "MARKET", "exchange": "NSE", "product": "CNC",
        })
    )

    assert result["status"] == STATUS_EXECUTED, result
    assert len(kite.orders) == 1
    assert kite.orders[0]["variety"] == "regular", "Broker._perform did not inject variety='regular'"
    assert kite.orders[0]["tradingsymbol"] == "RELIANCE"
