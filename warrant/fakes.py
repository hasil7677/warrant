"""
fakes.py
────────
Stand-ins for the three real app clients, each of which records everything that
reaches it.

**If these ledgers are non-empty after a refused proposal, the gate was
bypassed.** That single assertion is the point of this module and of the demo:
a refusal is only real if nothing arrived at the boundary. `verdict.allowed is
False` proves the gate said no; `fake.sent == []` proves the send did not
happen anyway down some other path - a retry wrapper, an exception handler that
"recovers", a second call site that forgot to ask.

The method signatures here mirror `warrant.apps.gmail`, `warrant.apps.gcal` and
`warrant.apps.notion` exactly, keyword for keyword. That is not tidiness: the
broker splats an approved Proposal's params into whichever client it holds, so
a fake that accepted a looser signature would let a params bug pass every test
and appear for the first time against the live API.

Nothing in here imports the real clients (they are broker-only) and nothing
here touches the network, so importing this module needs no credentials.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from warrant.contract import ThreadFacts


def seed_thread(
    thread_id: str, participants: list[str], subject: str, body_text: str
) -> ThreadFacts:
    """Build a ThreadFacts fixture.

    Fixtures are constructed through this helper rather than inline so that the
    thing under test is unmistakable: the *facts* are handed in by the test
    author, the *claims* come from the Proposal, and a rule that confuses the
    two has nowhere to hide.
    """
    return ThreadFacts(
        thread_id=thread_id,
        participants=list(participants),
        subject=subject,
        body_text=body_text,
    )


def _parse_iso(value: str) -> Optional[datetime]:
    """Same lenient ISO parse as gcal, duplicated so fakes import nothing real."""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class FakeGmail:
    """Gmail stand-in. `sent` is the evidence ledger.

    Preload `threads` to control what the trust anchor reports, and `unread` to
    control triage. `read_thread` raising KeyError on an unknown id mirrors the
    real client raising on a 404 - a fake that returned empty ThreadFacts would
    turn "I could not read the thread" into "the thread has no participants",
    which is the exact shape of a rule passing vacuously.
    """

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.threads: dict[str, ThreadFacts] = {}
        self.unread: list[dict] = []
        self._counter = 0

    # ── reads ───────────────────────────────────────────────────────────────

    def read_thread(self, thread_id: str) -> ThreadFacts:
        if thread_id not in self.threads:
            raise KeyError(
                f"FakeGmail has no thread {thread_id!r}; "
                f"preload it with fake.threads[{thread_id!r}] = seed_thread(...)"
            )
        return self.threads[thread_id]

    def list_unread(self, query: str = "is:unread", max_results: int = 5) -> list[dict]:
        return list(self.unread[:max_results])

    # ── the write the whole project is about ────────────────────────────────

    def send(
        self,
        to: list[str],
        subject: str,
        body: str,
        cc: Optional[list[str]] = None,
        bcc: Optional[list[str]] = None,
        in_reply_to: Optional[str] = None,
    ) -> str:
        """Record the full call and return a fake message id.

        Every keyword is stored, including the ones a given test does not
        assert on. Bcc in particular: the interesting attack is a proposal that
        looks clean in `to` and exfiltrates via `bcc`, and a ledger that only
        kept `to` would show that attack as a well-behaved email.
        """
        self._counter += 1
        self.sent.append(
            {
                "to": list(to),
                "subject": subject,
                "body": body,
                "cc": list(cc) if cc else None,
                "bcc": list(bcc) if bcc else None,
                "in_reply_to": in_reply_to,
            }
        )
        return f"FAKE-MSG-{self._counter:04d}"


class FakeCalendar:
    """Calendar stand-in. `created` is the evidence ledger.

    Preload `events` with `{"id","summary","start","end"}` dicts to give
    `list_events` and `find_conflicts` something to report.
    """

    def __init__(self) -> None:
        self.created: list[dict] = []
        self.events: list[dict] = []
        self._counter = 0

    # ── reads ───────────────────────────────────────────────────────────────

    def list_events(
        self, time_min_iso: str, time_max_iso: str, calendar_id: str = "primary"
    ) -> list[dict]:
        return [
            event
            for event in self.events
            if self._overlaps(event, time_min_iso, time_max_iso)
        ]

    def find_conflicts(
        self, start_iso: str, end_iso: str, calendar_id: str = "primary"
    ) -> list[dict]:
        return self.list_events(start_iso, end_iso, calendar_id=calendar_id)

    @staticmethod
    def _overlaps(event: dict, start_iso: str, end_iso: str) -> bool:
        """Strict overlap, matching gcal.find_conflicts: touching is not
        conflicting, and anything unparseable counts as a conflict so the fake
        fails in the same direction as the real client."""
        window_start = _parse_iso(start_iso)
        window_end = _parse_iso(end_iso)
        if window_start is None or window_end is None:
            return True
        event_start = _parse_iso(str(event.get("start", "")))
        event_end = _parse_iso(str(event.get("end", "")))
        if event_start is None or event_end is None:
            return True
        return event_start < window_end and event_end > window_start

    # ── the write ───────────────────────────────────────────────────────────

    def create_event(
        self,
        summary: str,
        start_iso: str,
        end_iso: str,
        attendees: Optional[list[str]] = None,
        description: str = "",
        calendar_id: str = "primary",
    ) -> str:
        self._counter += 1
        event_id = f"FAKE-EVT-{self._counter:04d}"
        record = {
            "id": event_id,
            "summary": summary,
            "start_iso": start_iso,
            "end_iso": end_iso,
            "attendees": list(attendees) if attendees else None,
            "description": description,
            "calendar_id": calendar_id,
        }
        self.created.append(record)
        # Visible to subsequent conflict checks, so a test can prove the second
        # booking of the same slot is caught by the first one having happened.
        self.events.append(
            {
                "id": event_id,
                "summary": summary,
                "start": start_iso,
                "end": end_iso,
            }
        )
        return event_id


class FakeNotion:
    """Notion stand-in. `pages` is the evidence ledger."""

    def __init__(self) -> None:
        self.pages: list[dict] = []
        self._counter = 0

    def create_page(self, parent_id: str, title: str, body_md: str = "") -> str:
        self._counter += 1
        page_id = f"FAKE-PAGE-{self._counter:04d}"
        self.pages.append(
            {
                "id": page_id,
                "parent_id": parent_id,
                "title": title,
                "body_md": body_md,
            }
        )
        return page_id

    def retrieve_page(self, page_id: str) -> dict:
        """Return the recorded page, or raise.

        Raises rather than returning None for the same reason the real client
        does: post-action verification that can quietly return nothing is not
        verification.
        """
        for page in self.pages:
            if page["id"] == page_id:
                return page
        raise KeyError(f"FakeNotion has no page {page_id!r}")
