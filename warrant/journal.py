"""
journal.py
──────────
The decision log. Every gate decision lands here - allowed and refused, without
exception.

Why refusals are the important half: a system that only logs what it did is a
system whose safety claims cannot be checked. "The gate blocked the exfiltration
attempt" is an assertion; a journal row naming the rule id that fired, the
params that triggered it, and the timestamp, is evidence. The refusals are the
product, so they get first-class storage rather than a log line that scrolls off
a terminal.

Two shapes are deliberate:

  • `decision` is derived from `verdict.allowed`, not passed in. A caller that
    could label a row ALLOWED independently of the verdict object could produce
    a clean-looking journal for a run that wasn't clean. The log has to be a
    function of the gate's output, not of the caller's narration of it.
  • `rationale` is recorded but never read by anything that authorizes. It is
    the model's stated reason, stored so a human can read it afterwards and
    notice when the stated reason and the actual params diverge. That divergence
    is the most interesting thing in the log.

`params_json`, `rule_ids_json` and `reasons_json` are JSON text columns because
SQLite has no array type. `summary()` pays for that by unpacking them in Python.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from warrant.contract import Proposal, Verdict

DATA_DIR = Path(os.getenv("WARRANT_DATA_DIR", ".warrant"))
JOURNAL_DB = DATA_DIR / "journal.db"

ALLOWED = "ALLOWED"
REFUSED = "REFUSED"


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(JOURNAL_DB)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS decisions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc        TEXT NOT NULL,
            thread_id     TEXT,
            tool          TEXT NOT NULL,
            params_json   TEXT,          -- the proposal verbatim, not a summary
            rationale     TEXT,          -- the model's stated reason; never authorizes
            decision      TEXT NOT NULL, -- ALLOWED | REFUSED, derived from the verdict
            rule_ids_json TEXT,          -- which policy rules fired
            reasons_json  TEXT,          -- human-readable text for each
            external_id   TEXT,          -- provider id, when the action executed
            error         TEXT           -- execution failure, distinct from a refusal
        )
        """
    )
    return conn


def log_decision(
    proposal: Proposal,
    verdict: Verdict,
    external_id: Optional[str] = None,
    error: Optional[str] = None,
) -> int:
    """Record one gate decision. Returns the row id.

    `error` is deliberately a separate column from the refusal path: a refusal
    is the system working and an exception is the system breaking, and a log
    that conflates them makes the reliability brief meaningless.
    """
    now = datetime.now(timezone.utc)
    conn = _connect()
    cur = conn.execute(
        """
        INSERT INTO decisions
        (ts_utc, thread_id, tool, params_json, rationale, decision,
         rule_ids_json, reasons_json, external_id, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now.isoformat(timespec="seconds"),
            proposal.thread_id,
            proposal.tool,
            json.dumps(proposal.params, default=str),
            proposal.rationale,
            ALLOWED if verdict.allowed else REFUSED,
            json.dumps(list(verdict.rule_ids or [])),
            json.dumps(list(verdict.reasons or [])),
            external_id,
            error,
        ),
    )
    conn.commit()
    decision_id = cur.lastrowid
    conn.close()
    return int(decision_id)


def _loads(raw: Any, fallback: Any) -> Any:
    """Parse a JSON column back into an object, tolerating a bad row.

    A single malformed row must not take down the whole brief - a log you cannot
    read because one entry is corrupt is worse than a log with one gap in it.
    """
    if raw is None:
        return fallback
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return fallback


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["params"] = _loads(d.pop("params_json", None), {})
    d["rule_ids"] = _loads(d.pop("rule_ids_json", None), [])
    d["reasons"] = _loads(d.pop("reasons_json", None), [])
    return d


def get_journal(limit: int = 50) -> list[dict[str, Any]]:
    """Newest decisions first, JSON columns parsed back into objects."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def refusals_only(limit: int = 50) -> list[dict[str, Any]]:
    """The half of the log that proves the gate exists."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM decisions WHERE decision = ? ORDER BY id DESC LIMIT ?",
        (REFUSED, limit),
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def summary() -> dict[str, Any]:
    """Counts for the reliability brief: totals, and which rules did the work.

    `by_rule` cannot be a GROUP BY - rule_ids is a JSON array and one decision
    can fire several rules, so the arrays are unpacked in Python and counted
    across every decision, not only refusals (an allowed decision may still name
    the rules that were evaluated).
    """
    conn = _connect()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT decision, rule_ids_json FROM decisions").fetchall()
    conn.close()

    counts = Counter(r["decision"] for r in rows)
    by_rule: Counter[str] = Counter()
    for r in rows:
        for rule_id in _loads(r["rule_ids_json"], []) or []:
            by_rule[str(rule_id)] += 1

    return {
        "total": len(rows),
        "allowed": counts.get(ALLOWED, 0),
        "refused": counts.get(REFUSED, 0),
        "by_rule": dict(by_rule.most_common()),
    }
