"""
broker.py
─────────
The credential boundary, enforced.

This is the only module that imports `warrant.apps.*`, and `warrant.auth` is
the only place a token is read. `tests/test_structure.py` fails if any other
module reaches an app client - the rule is checked, not documented.

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
  4. **A retry never gets a second real attempt while the first one's
     outcome is unknown.** `execute()` writes a `'pending'` ledger row
     *before* calling `_perform`, not after it returns - so if the app call
     raises (a timeout, a dropped connection), there is no way to tell
     whether the write landed server-side before the response was lost. The
     honest answer is not "assume it failed and retry" - that duplicates a
     write that actually went through - so the identical proposal is refused
     until the ambiguity is resolved by a human, rather than either guess
     being made for them. See `warrant/ledger.py`'s "status" section.

Clients are injectable so tests and the demo can run against `warrant.fakes`
without credentials. That injection is not a bypass: the fakes replace the
*apps*, never the gate.

## Dispatch, generalized

`_perform` used to be three `if proposal.tool == X:` blocks, one per app, each
naming its client's keyword arguments by hand. That does not scale to
thirteen apps, so dispatch now reads `warrant.registry`: every tool declares
which app it belongs to (`ToolSpec.app`) and which method performs it
(`ToolSpec.function`), and `_perform` resolves both and splats the proposal's
params at the result. A new adapter needs a `ToolSpec` and a client with a
matching method - nothing in this file changes.

One case stays hand-written: `gmail.send`'s `in_reply_to` defaults to the
thread the broker read when the model did not supply one, which keeps the
reply actually threaded in Gmail. That is domain behaviour specific to one
app, not a dispatch mechanism, so it stays as one explicit line rather than
becoming a registry field every other tool would carry uselessly.
"""

from __future__ import annotations

import importlib
from typing import Any, Optional

from warrant import journal as journal_mod
from warrant import policy as policy_mod
from warrant import registry as registry_mod
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
        apps: Optional[dict[str, Any]] = None,
        ledger: Optional[Ledger] = None,
    ) -> None:
        """Real clients by default; pass fakes to run without credentials.

        `gmail`, `calendar` and `notion` stay named parameters - they are the
        three apps with live credentials and a smoke artifact behind them, and
        every existing caller (the console, `eval/run.py`, the demo, this
        module's own tests) already constructs a Broker this way. `apps` is
        the general path for the other ten: a dict of app name -> client,
        e.g. `apps={"slack": FakeSlack(), "stripe": FakeStripe()}`. An app
        named in neither place resolves lazily to its real module on first
        use, the same way gmail/calendar/notion always have - constructing a
        Broker never triggers an auth check on its own.
        """
        if gmail is None or calendar is None or notion is None:
            from warrant.apps import gcal as _gcal
            from warrant.apps import gmail as _gmail
            from warrant.apps import notion as _notion

            gmail = gmail or _gmail
            calendar = calendar or _gcal
            notion = notion or _notion

        self._clients: dict[str, Any] = dict(apps or {})
        self._clients["gmail"] = gmail
        self._clients["calendar"] = calendar
        self._clients["notion"] = notion
        self.ledger = ledger if ledger is not None else Ledger()

    def _client(self, app_name: str) -> Any:
        """The client for one app, resolving to the real adapter on first use.

        `importlib.import_module` rather than a static `from warrant.apps
        import x` for the ten apps that are not gmail/calendar/notion: this
        keeps the credential-boundary test's accounting simple (it walks
        `ast.Import`/`ast.ImportFrom` nodes) without changing what the test
        actually guarantees - this remains the only module in the package that
        can reach an app client, static import or dynamic.
        """
        if app_name not in self._clients:
            spec = registry_mod.app_spec(app_name)
            if spec is None:
                raise ValueError(f"no such app {app_name!r}")
            self._clients[app_name] = importlib.import_module(f"warrant.apps.{spec.module}")
        return self._clients[app_name]

    @property
    def _gmail(self) -> Any:
        return self._client("gmail")

    @property
    def _calendar(self) -> Any:
        return self._client("calendar")

    @property
    def _notion(self) -> Any:
        return self._client("notion")

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
        idem_key = policy_mod.idempotency_key(proposal)

        # A prior attempt at this exact fingerprint whose outcome is unknown -
        # `_perform` may have raised because the app never got the call, or
        # because it got it, did it, and the response was what was lost. This
        # gate cannot tell those apart, so it refuses the retry rather than
        # guess: a second `_perform` here could be a genuine retry of a
        # no-op, or it could be a duplicate email that already left. Runs
        # before the policy check and before facts are even read - an
        # unresolved attempt is refused regardless of what the gate would
        # otherwise say. See warrant/ledger.py's "status" section.
        if self.ledger.pending_attempt(idem_key):
            verdict = Verdict(
                False,
                [
                    f"A previous attempt at this exact {proposal.tool} action has an unknown "
                    "outcome - the call may have failed before reaching the app, or it may "
                    "have reached the app and the response was lost. Retrying the identical "
                    "proposal could duplicate a real effect, so it is refused until the prior "
                    "attempt is reconciled."
                ],
                ["ambiguous_external_state"],
            )
            row_id = journal_mod.log_decision(proposal, verdict)
            return {
                "status": STATUS_REJECTED,
                "reasons": verdict.reasons,
                "rule_ids": verdict.rule_ids,
                "journal_id": row_id,
            }

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

        # Written BEFORE the call, not after - so a row marking this attempt
        # exists for the entire duration of `_perform`, including the window
        # where a client-side failure could follow a server-side success.
        pending_row_id = self.ledger.mark_pending(
            tool=proposal.tool, thread_id=proposal.thread_id, idem_key=idem_key
        )

        try:
            external_id = self._perform(proposal)
        except Exception as exc:
            row_id = journal_mod.log_decision(proposal, verdict, error=f"{type(exc).__name__}: {exc}")
            # The ledger row stays 'pending' - deliberately not resolved
            # either way here, because we do not know which way is true.
            # `pending_attempt()` is what makes the next identical proposal
            # refuse instead of reaching `_perform` a second time.
            return {
                "status": STATUS_ERROR,
                "error": f"{type(exc).__name__}: {exc}",
                "journal_id": row_id,
            }

        self.ledger.resolve_success(
            pending_row_id,
            external_id=external_id,
            **self._effect_fields(proposal),
        )
        row_id = journal_mod.log_decision(proposal, verdict, external_id=external_id)
        return {
            "status": STATUS_EXECUTED,
            "external_id": external_id,
            "reasons": verdict.reasons,
            "journal_id": row_id,
        }

    def _effect_fields(self, proposal: Proposal) -> dict[str, Any]:
        """The ledger columns `spend_cap` and `audience_bound` read back later.

        Computed from the registry the same way the rules that will read them
        compute it, so the two sides can never quietly drift - a spend amount
        recorded one way and priced another would make the cap meaningless
        without either check ever failing.
        """
        spec = registry_mod.tool_spec(proposal.tool)
        if spec is None:
            return {}
        params = proposal.params if isinstance(proposal.params, dict) else {}
        out: dict[str, Any] = {}

        if registry_mod.SPEND in spec.classes:
            if spec.amount_param:
                try:
                    out["amount_minor"] = int(params.get(spec.amount_param))
                except (TypeError, ValueError):
                    out["amount_minor"] = None
                out["currency"] = (
                    str(params.get(spec.currency_param) or spec.flat_cost_currency).lower()
                    if spec.currency_param
                    else spec.flat_cost_currency
                )
            elif spec.flat_cost_minor:
                count = 1
                if spec.recipient_params:
                    value = params.get(spec.recipient_params[0])
                    count = max(1, len(value) if isinstance(value, (list, tuple, set)) else 1)
                out["amount_minor"] = int(spec.flat_cost_minor) * count
                out["currency"] = spec.flat_cost_currency

        if registry_mod.AUDIENCE in spec.classes:
            field = spec.audience_param or (spec.recipient_params[0] if spec.recipient_params else None)
            if field:
                value = params.get(field)
                out["audience_key"] = " ".join(str(value).split()).lower() if value is not None else None

        return out

    # ── dispatch ────────────────────────────────────────────────────────

    def _perform(self, proposal: Proposal) -> str:
        """Route an authorized proposal to its client. Reached only on allow.

        Params are splatted by name, which is safe precisely because the gate
        has already rejected any key outside `ACTION_PARAMS` for this tool -
        an unknown key can never arrive here as a surprise kwarg. The tool ->
        (app, function) mapping comes from `warrant.registry`; adding an app
        does not touch this method.
        """
        spec = registry_mod.tool_spec(proposal.tool)
        if spec is None:
            # Unreachable in practice: the gate rejects an unknown tool before
            # execute() ever calls this. Raised rather than returning quietly,
            # so a future tool added to the registry with a typo'd function
            # name fails loudly instead of doing nothing.
            raise ValueError(f"no dispatch for authorized tool {proposal.tool!r}")

        client = self._client(spec.app)
        fn = getattr(client, spec.function)
        kwargs = dict(proposal.params) if isinstance(proposal.params, dict) else {}

        if proposal.tool == GMAIL_SEND and not kwargs.get("in_reply_to"):
            kwargs["in_reply_to"] = proposal.thread_id

        result = fn(**kwargs)
        return str(result)

    # ── independent verification ────────────────────────────────────────

    def verify(self, tool: str, external_id: str) -> dict[str, Any]:
        """Re-read an executed action from the app, with our own call.

        The id returned by a create endpoint is the service's claim that it
        did something. This goes back and looks. Borrowed from the same
        principle as an end-to-end check that refuses to trust a self-report.

        Only the three proven-live apps have a read-back path wired here -
        the point of `verify()` is to re-check a *live* claim independently,
        and the ten fake-only apps have never made a live claim to check.
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
        return {"verified": None, "detail": "no read-back wired for this tool"}
