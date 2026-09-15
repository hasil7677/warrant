"""
ledger.py
─────────
The record of what actually happened at the boundary - one row per action the
gate let through and the broker executed.

Why this is a separate store from the journal: the journal records *decisions*
(including refusals), and a decision is a claim about intent. The ledger records
*effects*, and an effect is a fact about the outside world. Two rules in
policy.py need facts rather than claims:

  • rate limits - "at most N emails per day" is unanswerable from the journal,
    because a journal row says the gate approved a send, not that a send
    occurred. Approve-then-crash would inflate the count forever.
  • idempotency - a retry storm is the normal failure mode of an agent loop.
    Without `seen()`, a wrapper that retries on timeout sends the same email
    five times and every one of those sends is individually policy-compliant.
    The cap is not the defence here; the memory of having already done it is.

This is a class rather than module functions so the gate can be handed a Ledger
pointed at a tmp_path in tests, instead of tests reaching into the user's real
`.warrant` directory or monkeypatching a global.

Connections are opened and closed per call. At this volume the cost is nothing
and it buys immunity from the entire family of bugs where a long-lived handle
outlives a fork, a thread, or a test's teardown.

Two columns were added for the multi-app suite, both nullable so an old row
written before this change reads back fine:

  • `amount_minor` / `currency` - what `spend_cap` sums. Written only for
    tools the registry marks `spend`; every other action leaves them NULL,
    and NULL is excluded from the sum rather than treated as zero, so a
    spend-tracking bug shows up as an undercount error surface, not a silent
    free action.
  • `audience_key` - what `audience_bound` counts distinct values of. The
    single destination a fan-out tool delivers to (a Slack channel) -
    recorded so the rule can tell "the fifth message to a channel already
    used today" from "the first message to a fifth channel", which is the
    distinction a distinct-count bound exists to make.

## `status`, and the ambiguous-write reliability fix

A third column, added for the same reason: `record()` used to be the only way
a row got written, and it was always called *after* `_perform` returned
successfully - so every row meant "this definitely happened." That is false
the moment a client-side call fails **after** a server-side write already
landed (a timeout on the response, a dropped connection) - the broker sees an
exception, never calls `record()`, and a caller retrying the identical
proposal finds `seen(idem_key) is False`, because nothing was ever written
down. The gate lets the retry through and a second real write happens. See
`warrant/broker.py::execute` for where this is closed.

`status` is `'pending'` or `'succeeded'` (NULL reads as `'succeeded'`, so a
row written by the old single-step `record()` - directly, as the adversarial
policy tests still do to seed a ledger - or by a pre-migration database reads
back exactly as before). The broker now writes a `'pending'` row via
`mark_pending()` *before* calling out to the app - so a row exists the instant
an attempt is made, win or lose - and only flips it to `'succeeded'` via
`resolve_success()` once the call actually returns. A row still marked
`'pending'` means the outcome is unknown: maybe the call never reached the
app, maybe it landed and the response was lost. Either way, `pending_attempt()`
refuses a same-fingerprint retry rather than guess which one it was.

Every counting method (`count_today`, `spend_today`, `distinct_audience_today`,
`seen`, `tools_executed_today`) excludes `'pending'` rows on purpose: an
attempt of unknown outcome must not count toward a cap or a "seen" check as if
it definitely happened, or a genuinely-failed attempt would silently eat into
the next day's budget. The cost is a small, stated undercount if a pending
write actually did land and is never reconciled - `pending_attempt()` is the
mechanism that actually stops the duplicate, not the counts.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DATA_DIR = Path(os.getenv("WARRANT_DATA_DIR", ".warrant"))


def _utc_day() -> str:
    """Today in UTC as YYYY-MM-DD.

    UTC and not local time, deliberately: the day boundary has to be the same
    one the rows were written under, or a daily cap silently resets when the
    machine's timezone changes or the process moves region.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class Ledger:
    """SQLite-backed record of executed actions."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path is not None else DATA_DIR / "ledger.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc        TEXT,
                day           TEXT,      -- YYYY-MM-DD (UTC), so daily caps are countable
                tool          TEXT,      -- gmail.send / calendar.create_event / ...
                thread_id     TEXT,
                idem_key      TEXT,      -- caller-stable key; the retry defence
                external_id   TEXT,      -- id the provider handed back, if any
                amount_minor  INTEGER,   -- spend_cap: minor units moved, NULL if not a spend tool
                currency      TEXT,      -- spend_cap: ISO 4217, NULL if not a spend tool
                audience_key  TEXT,      -- audience_bound: the destination reached, NULL if not fan-out
                status        TEXT       -- 'pending' | 'succeeded'; NULL reads as 'succeeded'
            )
            """
        )
        # A ledger opened against a database written before this column existed
        # gets the columns added rather than left behind - the alternative is a
        # daily cap and a spend cap that mysteriously stop working the first
        # time someone runs the console against yesterday's .warrant directory.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(actions)")}
        for column in ("amount_minor", "currency", "audience_key", "status"):
            if column not in existing:
                kind = "INTEGER" if column == "amount_minor" else "TEXT"
                conn.execute(f"ALTER TABLE actions ADD COLUMN {column} {kind}")
        return conn

    # Every counting query excludes a row still marked 'pending' - see the
    # module docstring's "status" section for why an attempt of unknown
    # outcome must not count as though it definitely happened.
    _SUCCEEDED = "(status IS NULL OR status = 'succeeded')"

    def count_today(self, tool: str) -> int:
        """How many times this tool has fired today. Feeds the daily cap rule."""
        conn = self._connect()
        n = conn.execute(
            f"SELECT COUNT(*) FROM actions WHERE tool = ? AND day = ? AND {self._SUCCEEDED}",
            (tool, _utc_day()),
        ).fetchone()[0]
        conn.close()
        return int(n)

    def tools_executed_today(self) -> list[str]:
        """The tool of every action recorded today, in the order they ran.

        Exists for reporting rather than for a policy rule - `eval/run.py` and
        the workflow runner both want "how many actions actually reached an
        app, broken down by which app" without hand-rolling a per-app ledger
        count for all ten apps and thirty-plus fake attribute names. One row
        per executed action, tool name only; the caller maps tool -> app
        through `warrant.registry.app_of`.
        """
        conn = self._connect()
        rows = conn.execute(
            f"SELECT tool FROM actions WHERE day = ? AND {self._SUCCEEDED} ORDER BY id",
            (_utc_day(),),
        ).fetchall()
        conn.close()
        return [str(r[0]) for r in rows]

    def seen(self, idem_key: str) -> bool:
        """True if this idempotency key has a KNOWN-successful row.

        Not scoped to today on purpose. "Already sent" does not stop being true
        at midnight, and a retry that crosses the day boundary is precisely the
        case a day-scoped check would wave through.

        Scoped to `status = 'succeeded'` on purpose too: a key whose only row is
        still `'pending'` has not been proven to have happened, and `seen()`
        answering the policy's `duplicate_action` rule must not claim it has.
        `pending_attempt()` below is the dedicated check for that ambiguous
        case, and it runs unconditionally in the broker rather than only when
        `rate_limit.idempotency` is configured.
        """
        conn = self._connect()
        row = conn.execute(
            f"SELECT 1 FROM actions WHERE idem_key = ? AND {self._SUCCEEDED} LIMIT 1", (idem_key,)
        ).fetchone()
        conn.close()
        return row is not None

    def external_id_for(self, idem_key: str) -> Optional[str]:
        """The external_id of the KNOWN-successful row for this idempotency
        key, if any - the most recent one, if `record()`/`resolve_success()`
        somehow wrote more than one (should not happen; belt and braces).

        This is what lets `warrant.workflow.resume_workflow()` reconstruct a
        completed step's result - specifically the id a later step's
        `${steps.<id>.external_id}` template needs - without re-proposing a
        step that already genuinely executed in an earlier, crashed run.
        """
        conn = self._connect()
        row = conn.execute(
            f"SELECT external_id FROM actions WHERE idem_key = ? AND {self._SUCCEEDED} "
            "ORDER BY id DESC LIMIT 1",
            (idem_key,),
        ).fetchone()
        conn.close()
        return str(row[0]) if row and row[0] is not None else None

    def pending_attempt(self, idem_key: str) -> bool:
        """True if this idempotency key has an attempt whose outcome is
        unknown - a `mark_pending()` row `resolve_success()` never reached.

        This is what closes the ambiguous-external-failure gap: `_perform`
        raising after a server-side write already landed leaves exactly this
        state, and a caller retrying the identical proposal must be refused
        here rather than reach `_perform` a second time.
        """
        conn = self._connect()
        row = conn.execute(
            "SELECT 1 FROM actions WHERE idem_key = ? AND status = 'pending' LIMIT 1",
            (idem_key,),
        ).fetchone()
        conn.close()
        return row is not None

    def record(
        self,
        tool: str,
        thread_id: Optional[str],
        idem_key: str,
        external_id: Optional[str],
        amount_minor: Optional[int] = None,
        currency: Optional[str] = None,
        audience_key: Optional[str] = None,
    ) -> None:
        """Write a completed effect in one step. Called *after* the side
        effect succeeded, never before.

        Kept for callers that only care about the end state - the adversarial
        policy tests seed a ledger this way, and doing so is equivalent to
        `mark_pending()` immediately followed by `resolve_success()`. The
        broker itself uses the two-step form so a row exists (as `'pending'`)
        for the entire duration of the call to the app, not only after it
        returns - see the module docstring's "status" section.
        """
        now = datetime.now(timezone.utc)
        conn = self._connect()
        conn.execute(
            "INSERT INTO actions "
            "(ts_utc, day, tool, thread_id, idem_key, external_id, amount_minor, currency, "
            "audience_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'succeeded')",
            (
                now.isoformat(timespec="seconds"),
                now.strftime("%Y-%m-%d"),
                tool,
                thread_id,
                idem_key,
                external_id,
                amount_minor,
                currency,
                audience_key,
            ),
        )
        conn.commit()
        conn.close()

    def mark_pending(self, tool: str, thread_id: Optional[str], idem_key: str) -> int:
        """Record an ATTEMPT before calling out to the app. Returns the row id.

        This is the row that makes the ambiguous-failure case detectable: if
        the process never calls `resolve_success()` for this id - because
        `_perform` raised, or the process died before it could - the row stays
        `'pending'` forever, and `pending_attempt()` sees it on any retry with
        the same idempotency key.
        """
        now = datetime.now(timezone.utc)
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO actions (ts_utc, day, tool, thread_id, idem_key, status) "
            "VALUES (?, ?, ?, ?, ?, 'pending')",
            (
                now.isoformat(timespec="seconds"),
                now.strftime("%Y-%m-%d"),
                tool,
                thread_id,
                idem_key,
            ),
        )
        conn.commit()
        row_id = int(cur.lastrowid)
        conn.close()
        return row_id

    def resolve_success(
        self,
        row_id: int,
        external_id: Optional[str],
        amount_minor: Optional[int] = None,
        currency: Optional[str] = None,
        audience_key: Optional[str] = None,
    ) -> None:
        """Finalize a `mark_pending()` row once `_perform` actually returns.

        Updates the SAME row rather than inserting a second one, so a pending
        attempt that succeeds leaves exactly one row behind - the same shape
        `record()` would have produced in one step.
        """
        now = datetime.now(timezone.utc)
        conn = self._connect()
        conn.execute(
            "UPDATE actions SET status = 'succeeded', external_id = ?, amount_minor = ?, "
            "currency = ?, audience_key = ?, ts_utc = ? WHERE id = ?",
            (external_id, amount_minor, currency, audience_key,
             now.isoformat(timespec="seconds"), row_id),
        )
        conn.commit()
        conn.close()

    def spend_today(self, tool: str, currency: str) -> int:
        """Minor units already moved by this tool today, in this currency.

        NULL `amount_minor` rows (every non-spend action, and every still-
        `'pending'` row) are excluded by the WHERE clause rather than coerced
        to zero by SUM - a row that was never priced, or never confirmed, must
        not silently participate in a sum that decides whether more money may
        move.
        """
        conn = self._connect()
        n = conn.execute(
            f"SELECT COALESCE(SUM(amount_minor), 0) FROM actions "
            f"WHERE tool = ? AND day = ? AND currency = ? AND amount_minor IS NOT NULL "
            f"AND {self._SUCCEEDED}",
            (tool, _utc_day(), currency),
        ).fetchone()[0]
        conn.close()
        return int(n)

    def distinct_audience_today(self, tool: str) -> set[str]:
        """Every distinct audience destination this tool has reached today.

        A set, not a count: `audience_bound` needs to know whether *this*
        proposal's destination is already in it (in which case it adds nothing
        to the blast radius) before deciding whether one more would breach the
        cap.
        """
        conn = self._connect()
        rows = conn.execute(
            f"SELECT DISTINCT audience_key FROM actions "
            f"WHERE tool = ? AND day = ? AND audience_key IS NOT NULL AND {self._SUCCEEDED}",
            (tool, _utc_day()),
        ).fetchall()
        conn.close()
        return {str(r[0]) for r in rows}

    def close(self) -> None:
        """No-op: connections do not outlive the call that opened them.

        Kept so callers can use the Ledger in a with-style teardown without
        knowing that, and so the lifetime can change later without a caller
        change.
        """
        return None
