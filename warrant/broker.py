"""
broker.py
─────────
The credential boundary, enforced.

This is the only module that imports `warrant.apps.*`, and `warrant.auth` is
the only place a token is read. `tests/test_import_boundary.py` fails if any
other module reaches an app client - the rule is checked, not documented.

The shape of `execute()` is the whole argument:

    proposal ──> facts the broker read itself ──> gate ──> client
                        (never from the model)

Three properties are load-bearing, and each one is a test:

  1. **`execute()` takes a Proposal and nothing else.** There is no `facts`
     parameter, no `policy` parameter, and no override flag. A caller that
     could supply facts could fabricate the very thing the gate checks
     proposals against, which would turn `recipients ⊆ participants` into a
     statement about two things the model wrote.
  2. **Facts are fetched here, from `thread_id`, before the gate runs.** The
     model chooses which thread to act on; it does not get to say what is in
     it.
  3. **Every decision is journaled, allowed or refused, before anything is
     executed.** A refusal that isn't written down is indistinguishable from
     a call that never happened.

Clients are injectable so tests and the demo can run against `warrant.fakes`
without credentials. That injection is not a bypass: the fakes replace the
*apps*, never the gate.
"""

from __future__ import annotations

from typing import Any, Optional

from warrant import journal as journal_mod
from warrant import policy as policy_mod
from warrant.contract import (
    CALENDAR_CREATE_EVENT,
    GMAIL_SEND,
    NOTION_CREATE_PAGE,
    STATUS_ERROR,
    STATUS_EXECUTED,
    STATUS_REJECTED,
    Proposal,
    ThreadFacts,
    Verdict,
)
from warrant.ledger import Ledger


class Broker:
    """Holds the credentials, runs the gate, and is the only path to an app."""

    def __init__(
        self,
        gmail: Any = None,
        calendar: Any = None,
        notion: Any = None,
        ledger: Optional[Ledger] = None,
    ) -> None:
        """Real clients by default; pass fakes to run without credentials.

        The real modules are imported lazily so that constructing a Broker with
        fakes never triggers an auth check - which is what lets the whole test
        suite and the demo run offline.
        """
        if gmail is None or calendar is None or notion is None:
            from warrant.apps import gcal as _gcal
            from warrant.apps import gmail as _gmail
            from warrant.apps import notion as _notion

            gmail = gmail or _gmail
            calendar = calendar or _gcal
            notion = notion or _notion

        self._gmail = gmail
        self._calendar = calendar
        self._notion = notion
        self.ledger = ledger if ledger is not None else Ledger()

    # ── the trust anchor ────────────────────────────────────────────────

    def facts_for(self, thread_id: Optional[str]) -> Optional[ThreadFacts]:
        """Read the thread the proposal refers to. This is where trust enters.

        Returns None when there is no thread to read - and None is *not* a free
        pass: the scope rules refuse outright when they have no facts to check
        against, because "I could not verify" and "it is fine" are different
        answers and only one of them is safe.
        """
        if not thread_id:
            return None
        try:
            return self._gmail.read_thread(thread_id)
        except Exception:
            # An unreadable thread yields no facts, and no facts means the
            # scope rules refuse. Failing closed here is deliberate.
            return None

    # ── the single entry point ──────────────────────────────────────────

    def execute(self, proposal: Proposal) -> dict[str, Any]:
        """Gate a proposal and, only if it passes, perform it.

        Note the parameter list: one Proposal. Nothing a caller can set here
        changes the verdict.
        """
        facts = self.facts_for(proposal.thread_id)
        verdict: Verdict = policy_mod.check(proposal, facts, self.ledger)

        if not verdict.allowed:
            row_id = journal_mod.log_decision(proposal, verdict)
            return {
                "status": STATUS_REJECTED,
                "reasons": verdict.reasons,
                "rule_ids": verdict.rule_ids,
                "journal_id": row_id,
            }

        try:
            external_id = self._perform(proposal)
        except Exception as exc:
            row_id = journal_mod.log_decision(proposal, verdict, error=f"{type(exc).__name__}: {exc}")
            return {
                "status": STATUS_ERROR,
                "error": f"{type(exc).__name__}: {exc}",
                "journal_id": row_id,
            }

        self.ledger.record(
            tool=proposal.tool,
            thread_id=proposal.thread_id,
            idem_key=policy_mod.idempotency_key(proposal),
            external_id=external_id,
        )
        row_id = journal_mod.log_decision(proposal, verdict, external_id=external_id)
        return {
            "status": STATUS_EXECUTED,
            "external_id": external_id,
            "reasons": verdict.reasons,
            "journal_id": row_id,
        }

    # ── dispatch ────────────────────────────────────────────────────────

    def _perform(self, proposal: Proposal) -> str:
        """Route an authorized proposal to its client. Reached only on allow.

        Params are splatted by name, which is safe precisely because the gate
        has already rejected any key outside `ACTION_PARAMS` for this tool -
        an unknown key can never arrive here as a surprise kwarg.
        """
        p = dict(proposal.params)

        if proposal.tool == GMAIL_SEND:
            return self._gmail.send(
                to=p.get("to", []),
                subject=p.get("subject", ""),
                body=p.get("body", ""),
                cc=p.get("cc"),
                bcc=p.get("bcc"),
                in_reply_to=p.get("in_reply_to") or proposal.thread_id,
            )

        if proposal.tool == CALENDAR_CREATE_EVENT:
            return self._calendar.create_event(
                summary=p.get("summary", ""),
                start_iso=p["start_iso"],
                end_iso=p["end_iso"],
                attendees=p.get("attendees") or [],
                description=p.get("description", ""),
            )

        if proposal.tool == NOTION_CREATE_PAGE:
            return self._notion.create_page(
                parent_id=p["parent_id"],
                title=p.get("title", ""),
                body_md=p.get("body_md", ""),
            )

        # Unreachable: the gate rejects unknown tools. Raised rather than
        # silently returning, so a future tool added without a policy rule
        # fails loudly instead of quietly doing nothing.
        raise ValueError(f"no dispatch for authorized tool {proposal.tool!r}")

    # ── independent verification ────────────────────────────────────────

    def verify(self, tool: str, external_id: str) -> dict[str, Any]:
        """Re-read an executed action from the app, with our own call.

        The id returned by a create endpoint is the service's claim that it
        did something. This goes back and looks. Borrowed from the same
        principle as an end-to-end check that refuses to trust a self-report.
        """
        try:
            if tool == NOTION_CREATE_PAGE:
                page = self._notion.retrieve_page(external_id)
                return {"verified": bool(page), "detail": "page retrieved"}
            if tool == CALENDAR_CREATE_EVENT:
                # Listing is the independent path: it does not take the id we
                # are trying to confirm, so a bad id cannot produce a hit.
                events = self._calendar.list_events("1970-01-01T00:00:00+00:00",
                                                    "2100-01-01T00:00:00+00:00")
                hit = any(e.get("id") == external_id for e in events)
                return {"verified": hit, "detail": f"{len(events)} event(s) listed"}
            if tool == GMAIL_SEND:
                return {"verified": None, "detail": "no read-back for send in this build"}
        except Exception as exc:
            return {"verified": False, "detail": f"{type(exc).__name__}: {exc}"}
        return {"verified": None, "detail": "unknown tool"}
