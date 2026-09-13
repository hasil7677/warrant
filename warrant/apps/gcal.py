"""
apps/gcal.py
────────────
The Google Calendar client: list a window, find conflicts in a window, create
an event.

Only the broker imports this module.

`find_conflicts` exists because "book a meeting" is the action where a
plausible-sounding proposal does the most quiet damage - double-booking is not
refused by any credential check, it just happens. Conflicts are read from the
API, not asked of the model, for the same reason ThreadFacts is: a fact the
model supplies is a fact the model can choose.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


def _service():
    """Build the Calendar API client, importing auth lazily.

    Lazy so `import warrant.apps.gcal` never asks for credentials.
    """
    from googleapiclient.discovery import build

    from warrant.auth import get_google_creds

    return build(
        "calendar", "v3", credentials=get_google_creds(), cache_discovery=False
    )


def _parse_iso(value: str) -> Optional[datetime]:
    """Parse an RFC3339/ISO-8601 instant into an aware UTC datetime.

    Naive input is read as UTC rather than as local time: a comparison between
    a naive and an aware datetime raises, and silently guessing the machine's
    timezone would make conflict detection depend on where the process runs.
    Returns None for anything unparseable, which the caller treats as "cannot
    prove there is no overlap" - see find_conflicts.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _edge(node: Any) -> str:
    """Pull the timestamp out of a Calendar start/end node.

    All-day events carry `date` instead of `dateTime`; losing them would make a
    day blocked out as PTO look free.
    """
    if isinstance(node, dict):
        return str(node.get("dateTime") or node.get("date") or "")
    return str(node or "")


def _shape(event: dict[str, Any]) -> dict:
    return {
        "id": event.get("id", ""),
        "summary": event.get("summary", ""),
        "start": _edge(event.get("start")),
        "end": _edge(event.get("end")),
    }


def list_events(
    time_min_iso: str, time_max_iso: str, calendar_id: str = "primary"
) -> list[dict]:
    """Events in `[time_min_iso, time_max_iso)`: `[{"id","summary","start","end"}]`.

    `singleEvents=True` expands recurring series into their instances. Without
    it a weekly standup comes back as one master event with a recurrence rule,
    and every occurrence of it becomes invisible to conflict detection.
    """
    result = (
        _service()
        .events()
        .list(
            calendarId=calendar_id,
            timeMin=time_min_iso,
            timeMax=time_max_iso,
            singleEvents=True,
            orderBy="startTime",
        )
        .execute()
    )
    return [_shape(event) for event in result.get("items", []) or []]


def find_conflicts(
    start_iso: str, end_iso: str, calendar_id: str = "primary"
) -> list[dict]:
    """Events overlapping `[start_iso, end_iso)`.

    Overlap is strict: an event ending exactly when the proposed one starts is
    not a conflict, because back-to-back meetings are the normal case and a
    checker that flags them gets ignored, which is worse than not having one.

    An event whose timestamps cannot be parsed is reported as a conflict. The
    failure mode of this function is "the agent is told the slot is busy when
    it is free", which costs a retry; the opposite failure mode books over a
    real meeting.
    """
    window_start = _parse_iso(start_iso)
    window_end = _parse_iso(end_iso)

    candidates = list_events(start_iso, end_iso, calendar_id=calendar_id)
    if window_start is None or window_end is None:
        return candidates

    conflicts: list[dict] = []
    for event in candidates:
        event_start = _parse_iso(event["start"])
        event_end = _parse_iso(event["end"])
        if event_start is None or event_end is None:
            conflicts.append(event)
            continue
        if event_start < window_end and event_end > window_start:
            conflicts.append(event)
    return conflicts


def create_event(
    summary: str,
    start_iso: str,
    end_iso: str,
    attendees: Optional[list[str]] = None,
    description: str = "",
    calendar_id: str = "primary",
) -> str:
    """Create an event. Returns the created event id.

    Parameter names match `ACTION_PARAMS["calendar.create_event"]` exactly
    (`calendar_id` is broker-side plumbing, not a model-settable param), so the
    broker can splat an approved Proposal's params in directly.
    """
    body: dict[str, Any] = {
        "summary": summary,
        "description": description,
        "start": {"dateTime": start_iso},
        "end": {"dateTime": end_iso},
    }
    if attendees:
        body["attendees"] = [{"email": a} for a in attendees]

    created = (
        _service().events().insert(calendarId=calendar_id, body=body).execute()
    )
    return str(created.get("id", ""))
