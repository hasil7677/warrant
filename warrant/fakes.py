"""
fakes.py
────────
Stand-ins for all ten app clients, each of which records everything that
reaches it.

**If these ledgers are non-empty after a refused proposal, the gate was
bypassed.** That single assertion is the point of this module and of the demo:
a refusal is only real if nothing arrived at the boundary. `verdict.allowed is
False` proves the gate said no; `fake.sent == []` proves the send did not
happen anyway down some other path - a retry wrapper, an exception handler that
"recovers", a second call site that forgot to ask.

The method signatures here mirror their real counterpart in `warrant.apps.*`
exactly, keyword for keyword. That is not tidiness: the broker splats an
approved Proposal's params into whichever client it holds, so a fake that
accepted a looser signature would let a params bug pass every test and appear
for the first time against a real account.

For Gmail, Calendar and Notion that real account exists and has been run
against (`artifacts/smoke_*.json`). For the other seven it does not - see
`warrant.registry` for which apps carry which liveness status. Those seven
fakes are still written against each app's documented REST API as carefully
as the three that are proven, because a fake that tests nothing is worse than
an honest gap: it is a gap wearing a passing test suite as a disguise.

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

    `raises_after_write` simulates the failure mode no other fake here could:
    the server-side write landing and the client never learning it, because
    the response itself was lost (a timeout, a dropped connection) rather than
    the call never reaching the app. Every fake up to this point only ever
    modeled "the call failed" as "nothing happened" - `monkeypatch.setattr` a
    method to raise *before* it records anything, as
    `test_error_during_execution_is_journaled_not_swallowed` already does. That
    cannot exercise reliability finding 1 (an ambiguous external failure
    causing a duplicate on retry), because in that shape the write provably
    never happened - there is nothing ambiguous about it. `send()` here
    appends to `self.sent` FIRST - the write "landing" - and only then raises,
    so a test can tell the two failure shapes apart the same way a real retry
    bug would have to.
    """

    def __init__(self, raises_after_write: bool = False) -> None:
        self.sent: list[dict] = []
        self.threads: dict[str, ThreadFacts] = {}
        self.unread: list[dict] = []
        self._counter = 0
        # Consumed on first use: fires once (the "lost response"), then a
        # retry of the same or a different proposal succeeds normally - the
        # same shape a transient network failure actually has.
        self.raises_after_write = raises_after_write

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
        if self.raises_after_write:
            # The write above already happened - this models the response
            # never making it back, not the call never arriving. Fires once.
            self.raises_after_write = False
            raise ConnectionError(
                "simulated: the send landed but the response was lost (raises_after_write)"
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


# ── the seven fake-only apps ────────────────────────────────────────────────
# Everything below stands in for an app this project has no credentials for.
# Each fake's method signatures mirror `warrant/apps/<name>.py` exactly, for
# the same reason FakeGmail/FakeCalendar/FakeNotion's do - the broker splats a
# proposal's params into whichever client it holds, and a fake that accepted a
# looser signature would let a params bug pass every test and appear for the
# first time against a real account nobody has connected yet.
# `tests/test_registry.py::test_fakes_match_real_client_signatures_for_every_tool`
# checks this generically, the same way `test_structure.py` checked it by hand
# for the original three.


class FakeSlack:
    """Slack stand-in. `posted` and `uploaded` are the evidence ledgers."""

    def __init__(self) -> None:
        self.posted: list[dict] = []
        self.uploaded: list[dict] = []
        self._counter = 0

    def post_message(self, channel: str, text: str, thread_ts: Optional[str] = None) -> str:
        self._counter += 1
        ts = f"{1700000000 + self._counter}.000001"
        self.posted.append({"channel": channel, "text": text, "thread_ts": thread_ts, "ts": ts})
        return ts

    def upload_file(self, channel: str, filename: str, content: str, title: str = "") -> str:
        self._counter += 1
        file_id = f"FAKE-SLACK-FILE-{self._counter:04d}"
        self.uploaded.append(
            {"channel": channel, "filename": filename, "content": content, "title": title, "id": file_id}
        )
        return file_id


class FakeGitHub:
    """GitHub stand-in. Four ledgers, one per write the suite governs."""

    def __init__(self) -> None:
        self.issues: list[dict] = []
        self.pull_requests: list[dict] = []
        self.merges: list[dict] = []
        self.collaborators: list[dict] = []
        self._counter = 0

    def create_issue(
        self, repo: str, title: str, body: str = "", labels: Optional[list[str]] = None
    ) -> str:
        self._counter += 1
        number = self._counter
        self.issues.append(
            {"repo": repo, "title": title, "body": body, "labels": list(labels) if labels else [],
             "number": number}
        )
        return str(number)

    def create_pull_request(self, repo: str, title: str, head: str, base: str, body: str = "") -> str:
        self._counter += 1
        number = self._counter
        self.pull_requests.append(
            {"repo": repo, "title": title, "head": head, "base": base, "body": body, "number": number}
        )
        return str(number)

    def merge_pull_request(
        self,
        repo: str,
        number: int,
        merge_method: Optional[str] = None,
        commit_title: Optional[str] = None,
    ) -> str:
        self._counter += 1
        sha = f"FAKE-SHA-{self._counter:07d}"
        self.merges.append(
            {"repo": repo, "number": number, "merge_method": merge_method,
             "commit_title": commit_title, "sha": sha}
        )
        return sha

    def add_collaborator(self, repo: str, username: str, permission: Optional[str] = None) -> str:
        self.collaborators.append({"repo": repo, "username": username, "permission": permission})
        return f"invited:{username}"


class FakeLinear:
    """Linear stand-in. `issues` is the evidence ledger; `update_issue` mutates
    the same record in place, the way the real GraphQL mutation would."""

    def __init__(self) -> None:
        self.issues: list[dict] = []
        self._counter = 0

    def create_issue(
        self, team_id: str, title: str, description: str = "", priority: Optional[int] = None
    ) -> str:
        self._counter += 1
        issue_id = f"FAKE-LINEAR-{self._counter:04d}"
        self.issues.append(
            {"id": issue_id, "team_id": team_id, "title": title, "description": description,
             "priority": priority, "state_id": None}
        )
        return issue_id

    def update_issue(
        self,
        issue_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        state_id: Optional[str] = None,
    ) -> str:
        for issue in self.issues:
            if issue["id"] == issue_id:
                if title is not None:
                    issue["title"] = title
                if description is not None:
                    issue["description"] = description
                if state_id is not None:
                    issue["state_id"] = state_id
                return issue_id
        raise KeyError(f"FakeLinear has no issue {issue_id!r}")


class FakeStripe:
    """Stripe stand-in. `refunds` and `payouts` are the evidence ledgers.

    Amounts are minor units throughout (cents), matching the real API and
    `ToolSpec.amount_param` - a fake that accepted dollars would test a
    spend_cap comparison the real integration does not make.
    """

    def __init__(self) -> None:
        self.refunds: list[dict] = []
        self.payouts: list[dict] = []
        self._counter = 0

    def create_refund(
        self, payment_intent: str, amount: int, currency: str, reason: Optional[str] = None
    ) -> str:
        self._counter += 1
        refund_id = f"FAKE-RE-{self._counter:04d}"
        self.refunds.append(
            {"id": refund_id, "payment_intent": payment_intent, "amount": int(amount),
             "currency": currency, "reason": reason}
        )
        return refund_id

    def create_payout(
        self, amount: int, currency: str, description: str = "", destination: Optional[str] = None
    ) -> str:
        self._counter += 1
        payout_id = f"FAKE-PO-{self._counter:04d}"
        self.payouts.append(
            {"id": payout_id, "amount": int(amount), "currency": currency,
             "description": description, "destination": destination}
        )
        return payout_id


class FakeTwilio:
    """Twilio stand-in. `sent` is the evidence ledger."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self._counter = 0

    def send_sms(self, to: list[str], from_number: str, body: str) -> str:
        self._counter += 1
        sid = f"FAKE-SM-{self._counter:08d}"
        self.sent.append({"to": list(to), "from_number": from_number, "body": body, "sid": sid})
        return sid


class FakeDrive:
    """Google Drive stand-in. `uploaded` and `shares` are the evidence ledgers."""

    def __init__(self) -> None:
        self.uploaded: list[dict] = []
        self.shares: list[dict] = []
        self._counter = 0

    def upload_file(
        self, folder_id: str, name: str, content: str, mime_type: Optional[str] = None
    ) -> str:
        self._counter += 1
        file_id = f"FAKE-DRIVE-{self._counter:04d}"
        self.uploaded.append(
            {"id": file_id, "folder_id": folder_id, "name": name, "content": content,
             "mime_type": mime_type}
        )
        return file_id

    def share_file(
        self,
        file_id: str,
        email: Optional[str] = None,
        role: Optional[str] = None,
        audience: Optional[str] = None,
    ) -> str:
        self._counter += 1
        perm_id = f"FAKE-PERM-{self._counter:04d}"
        self.shares.append(
            {"id": perm_id, "file_id": file_id, "email": email, "role": role, "audience": audience}
        )
        return perm_id


class FakeSheets:
    """Google Sheets stand-in. `appended` and `cleared` are the evidence ledgers."""

    def __init__(self) -> None:
        self.appended: list[dict] = []
        self.cleared: list[dict] = []

    def append_row(self, spreadsheet_id: str, range_a1: str, values: list[str]) -> str:
        self.appended.append(
            {"spreadsheet_id": spreadsheet_id, "range_a1": range_a1, "values": list(values)}
        )
        return f"{range_a1}:appended"

    def clear_range(self, spreadsheet_id: str, range_a1: str) -> str:
        self.cleared.append({"spreadsheet_id": spreadsheet_id, "range_a1": range_a1})
        return f"{range_a1}:cleared"


class FakeKite:
    """Kite Connect stand-in. `orders` is the evidence ledger.

    Unlike every other fake in this module, this one is never what
    `Broker._client("kite")` actually returns in production - the platform
    always supplies a real, tenant-authenticated `KiteConnect` instance
    explicitly (see `registry.py`'s note on the `kite` AppSpec). This class
    exists for warrant's own tests: it stands in for that real instance in
    unit tests that construct `Broker(apps={"kite": FakeKite()})` without a
    live account, and it is what `test_fake_matches_real_client_signature_
    for_every_tool` compares against `warrant.apps.kite.place_order`'s real
    signature.
    """

    def __init__(self) -> None:
        self.orders: list[dict] = []
        self._counter = 0

    def place_order(
        self,
        variety: str,
        exchange: str,
        tradingsymbol: str,
        transaction_type: str,
        quantity: int,
        product: str,
        order_type: str,
        price: Optional[float] = None,
        trigger_price: Optional[float] = None,
    ) -> str:
        self._counter += 1
        order_id = f"FAKE-ORDER-{self._counter:04d}"
        self.orders.append(
            {
                "id": order_id,
                "variety": variety,
                "exchange": exchange,
                "tradingsymbol": tradingsymbol,
                "transaction_type": transaction_type,
                "quantity": quantity,
                "product": product,
                "order_type": order_type,
                "price": price,
                "trigger_price": trigger_price,
            }
        )
        return order_id
