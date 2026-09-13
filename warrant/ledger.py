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
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc      TEXT,
                day         TEXT,      -- YYYY-MM-DD (UTC), so daily caps are countable
                tool        TEXT,      -- gmail.send / calendar.create_event / ...
                thread_id   TEXT,
                idem_key    TEXT,      -- caller-stable key; the retry defence
                external_id TEXT       -- id the provider handed back, if any
            )
            """
        )
        return conn

    def count_today(self, tool: str) -> int:
        """How many times this tool has fired today. Feeds the daily cap rule."""
        conn = self._connect()
        n = conn.execute(
            "SELECT COUNT(*) FROM actions WHERE tool = ? AND day = ?",
            (tool, _utc_day()),
        ).fetchone()[0]
        conn.close()
        return int(n)

    def seen(self, idem_key: str) -> bool:
        """True if this idempotency key has ever been recorded.

        Not scoped to today on purpose. "Already sent" does not stop being true
        at midnight, and a retry that crosses the day boundary is precisely the
        case a day-scoped check would wave through.
        """
        conn = self._connect()
        row = conn.execute(
            "SELECT 1 FROM actions WHERE idem_key = ? LIMIT 1", (idem_key,)
        ).fetchone()
        conn.close()
        return row is not None

    def record(
        self,
        tool: str,
        thread_id: Optional[str],
        idem_key: str,
        external_id: Optional[str],
    ) -> None:
        """Write the effect. Called *after* the side effect succeeded, never before."""
        now = datetime.now(timezone.utc)
        conn = self._connect()
        conn.execute(
            "INSERT INTO actions (ts_utc, day, tool, thread_id, idem_key, external_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                now.isoformat(timespec="seconds"),
                now.strftime("%Y-%m-%d"),
                tool,
                thread_id,
                idem_key,
                external_id,
            ),
        )
        conn.commit()
        conn.close()

    def close(self) -> None:
        """No-op: connections do not outlive the call that opened them.

        Kept so callers can use the Ledger in a with-style teardown without
        knowing that, and so the lifetime can change later without a caller
        change.
        """
        return None
