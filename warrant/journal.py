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


def _connect(journal_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open the journal DB, defaulting to the module-global JOURNAL_DB.

    `journal_path` is the per-tenant equivalent of Ledger's own `path:`
    constructor argument (see ledger.py) - additive, and every existing
    caller (omitting it) is byte-for-byte unaffected. Passed explicitly
    rather than read from an env var per call, for the same reason
    db.tenant_session() takes tenant_id as a plain argument: a value every
    call site has to thread explicitly is a value a reviewer can see is
    present at every call site.
    """
    path = journal_path if journal_path is not None else JOURNAL_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
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
    _ensure_identity_columns(conn)
    return conn


# The three columns that answer "who, acting as whom, under which authority" -
# added after the original schema shipped, so they arrive by ALTER rather than
# in the CREATE above. An existing journal must keep opening: the refusals
# already in it are the evidence this project is built to produce, and a schema
# change that orphaned them would destroy the thing being protected.
_IDENTITY_COLUMNS: tuple[tuple[str, str], ...] = (
    ("principal", "TEXT"),  # the agent that actually proposed the action
    ("on_behalf_of", "TEXT"),  # the human/tenant at the root of its authority
    ("chain_json", "TEXT"),  # the grant ids traversed, root -> leaf
)


def _ensure_identity_columns(conn: sqlite3.Connection) -> None:
    """Add the delegation columns to a journal written before they existed.

    `PRAGMA table_info` rather than catching the "duplicate column name"
    OperationalError: the error path would also swallow a genuinely failed
    ALTER, and a journal silently missing a column would record every
    action as having no principal - which is indistinguishable, when read
    back, from an action that genuinely had none.

    Rows written before this migration keep NULL in all three, and that is
    the honest value: nothing knew who was acting when they were written,
    so nothing should claim to now.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(decisions)")}
    for column, sql_type in _IDENTITY_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE decisions ADD COLUMN {column} {sql_type}")
    conn.commit()


def log_decision(
    proposal: Proposal,
    verdict: Verdict,
    external_id: Optional[str] = None,
    error: Optional[str] = None,
    journal_path: Optional[Path] = None,
    chain: Any = None,
) -> int:
    """Record one gate decision. Returns the row id.

    `error` is deliberately a separate column from the refusal path: a refusal
    is the system working and an exception is the system breaking, and a log
    that conflates them makes the reliability brief meaningless.

    `journal_path`, when supplied, writes against that file instead of the
    module-global `JOURNAL_DB` - see `_connect()`. Every existing caller
    omits it and is unaffected.

    `chain` is the delegation chain the proposal was made under, recorded so a
    row answers "who did this, and on whose behalf" and not only "what
    happened". It is written verbatim from the chain the gate was GIVEN, which
    is the honest thing to store: if that chain failed verification, the row is
    a record of a rejected claim of authority, and those are exactly the rows
    worth having. `decision` still comes from the verdict, so a chain recorded
    here can never make a refusal look like an allow.

    Grant signatures are deliberately NOT stored - only ids. A sig is the key
    that mints children (see `identity.attenuate`), so a journal holding them
    would be a file that confers authority, and this one is meant to be
    readable by anyone auditing the system.
    """
    now = datetime.now(timezone.utc)
    principal, on_behalf_of, chain_ids = _chain_fields(chain)
    conn = _connect(journal_path)
    cur = conn.execute(
        """
        INSERT INTO decisions
        (ts_utc, thread_id, tool, params_json, rationale, decision,
         rule_ids_json, reasons_json, external_id, error,
         principal, on_behalf_of, chain_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            principal,
            on_behalf_of,
            chain_ids,
        ),
    )
    conn.commit()
    decision_id = cur.lastrowid
    conn.close()
    return int(decision_id)


def _chain_fields(chain: Any) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Flatten a delegation chain into the three journal columns.

    Tolerant on purpose, and it is worth saying why a logger is allowed to be
    tolerant when nothing else in this package is: by the time anything calls
    this, the gate has already decided. A malformed chain has already been
    refused by the `delegation` rule; this function's only job is to preserve
    whatever was presented so a human can see what was attempted. Raising here
    would lose the record of a rejected attempt, which is the opposite of what
    a journal is for - so an unreadable chain is recorded as NULL rather than
    allowed to take the write down with it.
    """
    if not chain:
        return None, None, None
    try:
        grants = list(chain)
        ids = [str(getattr(g, "grant_id", "")) or str(g.get("grant_id", "")) for g in grants]  # type: ignore[union-attr]
        leaf = grants[-1]
        root = grants[0]
        principal = getattr(leaf, "subject", None)
        issuer = getattr(root, "issuer", None)
        return (
            str(principal) if principal is not None else None,
            str(issuer) if issuer is not None else None,
            json.dumps(ids),
        )
    except Exception:
        return None, None, None


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
    d["chain"] = _loads(d.pop("chain_json", None), [])
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
