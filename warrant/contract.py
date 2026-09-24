"""
contract.py
───────────
The shapes every other module agrees on. Nothing here executes anything - it is
the vocabulary, not the machinery.

The one idea this file encodes: a Proposal is a *claim by the model*, and
ThreadFacts is *what the broker read for itself*. Every interesting policy rule
is a comparison between the two. Keeping them in separate types means a rule
can never accidentally trust the model's version of a fact - it has to reach
into the object that came from the API.

The tool surface used to be two tuples typed out below by hand: three apps,
five actions. It is now derived from `warrant.registry`, which is the same kind
of file - a table, no behaviour - and is the only import this module makes.
`ACTIONS` and `ACTION_PARAMS` keep their names and shapes exactly, so every
existing caller (`policy.py`'s tool-surface check, the structural tests, the
broker's dispatch) is unchanged; what moved is where the thirteen apps' worth
of entries actually live.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from warrant.registry import ACTION_PARAMS, ACTIONS  # noqa: F401  (re-exported)

# ── the tool surface ────────────────────────────────────────────────────────
# Thirteen apps, twenty-two actions, all declared in registry.py. Read actions
# are not proposals - the broker performs them itself to build ThreadFacts,
# because a read is how trust enters the system and the model does not get to
# narrate it.
#
# These three names stay spelled out here because they are the load-bearing
# ones: the scheduling scenario, the live smoke path, and every module that
# still dispatches on them directly by name. The other nineteen tool names are
# read out of `warrant.registry.ACTIONS` rather than given their own constants
# - the point of the registry is that a new app does not need a new constant
# threaded through this file, the broker, and the policy module by hand.

GMAIL_SEND = "gmail.send"
CALENDAR_CREATE_EVENT = "calendar.create_event"
NOTION_CREATE_PAGE = "notion.create_page"
KITE_PLACE_ORDER = "kite.place_order"


@dataclass(frozen=True)
class Proposal:
    """What the model wants to do. Untrusted by construction.

    `rationale` is recorded in the journal and never read by the gate. A reason
    is not a permission, and a gate that reads the model's justification is a
    gate the model can argue with.
    """

    tool: str
    params: dict[str, Any]
    thread_id: Optional[str] = None
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "params": self.params,
            "thread_id": self.thread_id,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class KiteFacts:
    """What the platform layer read for itself before a kite proposal reaches
    the gate - the same "never from the proposal" property ThreadFacts has,
    applied to a per-tenant trading account instead of an email thread.

    `mandate`/`kill_switch_reason`/`orders_today`/`value_today` are fetched
    from Postgres by the platform (finLM-platform/api), BEFORE any Proposal
    exists - there is no synchronous Postgres call available once
    Broker.execute() is running. `live_quote` is the one fact that must be
    fetched fresh at gate time (a stale quote is a claim about the market a
    minute ago, not now), so it is filled in by a closure the platform hands
    to Broker as a `facts_providers["kite"]` callable - see broker.py's
    `_gather_facts()`. Neither half alone is enough to evaluate a kite
    proposal; this dataclass is where both halves meet.
    """

    tenant_id: str
    mandate: Optional[dict[str, Any]]
    kill_switch_reason: Optional[str]
    orders_today: int
    value_today: float
    live_quote: Optional[float]
    quote_source: str = "unavailable"


@dataclass(frozen=True)
class ThreadFacts:
    """What the broker read from Gmail itself. The trust anchor.

    `participants` is the authoritative recipient set: every address that
    appeared in From/To/Cc across the thread, as the API reported them. Policy
    rules scope outbound recipients to this set, which is why it must never be
    populated from anything the model said.
    """

    thread_id: str
    participants: list[str] = field(default_factory=list)
    subject: str = ""
    body_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "thread_id": self.thread_id,
            "participants": self.participants,
            "subject": self.subject,
            "body_len": len(self.body_text),
        }


@dataclass
class Verdict:
    """The gate's answer. `allowed` is the only field the broker may branch on.

    `rule_ids` names which policy rules fired, so a refusal in the log can be
    traced back to a line in policy.yaml rather than to a sentence someone
    wrote in an f-string.
    """

    allowed: bool
    reasons: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reasons": self.reasons, "rule_ids": self.rule_ids}


# Status strings the broker returns. REJECTED is deliberately loud and
# deliberately not a synonym for "error" - a refusal is the system working.
STATUS_EXECUTED = "EXECUTED"
STATUS_REJECTED = "REJECTED_BY_POLICY_GATE"
STATUS_ERROR = "ERROR"
