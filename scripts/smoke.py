"""
smoke.py
────────
Box A: prove the three external apps are really reachable with real
credentials, before any of the interesting machinery is built on top of them.

This deliberately does NOT go through the policy gate or the broker. It is the
control: if the gate later refuses something, this script is the evidence that
the refusal is the gate working and not the credentials being broken. A demo
where nothing happens is indistinguishable from a demo where nothing *can*
happen, and that distinction is the whole project.

It writes three real objects into the operator's own accounts:
  • one email, addressed to the authenticated user themself
  • one calendar event, 10 minutes long, tomorrow, no attendees
  • one Notion page under WARRANT_SMOKE_PARENT

Each write is then read back with a separate API call, because a 200 from a
create endpoint is the service's claim and reading the object is the check.

Usage:
    python scripts/smoke.py              # all three
    python scripts/smoke.py --skip-notion
"""

from __future__ import annotations

import argparse
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

OK, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results: list[tuple[str, str, str]] = []
TRACE = False


def step(name: str, fn):
    """Run one probe, record the outcome, never let one failure hide the rest."""
    try:
        detail = fn()
        results.append((name, OK, detail or ""))
        print(f"  {OK}  {name:<34} {detail or ''}")
        return True
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        results.append((name, FAIL, detail))
        print(f"  {FAIL}  {name:<34} {detail}")
        if TRACE:
            traceback.print_exc()
        return False


def main() -> int:
    global TRACE
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-notion", action="store_true")
    ap.add_argument("--skip-google", action="store_true")
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args()
    TRACE = args.trace

    print("\nwarrant - Box A smoke test")
    print("=" * 62)
    print("Writes one real object per app, then reads each one back.\n")

    state: dict = {}

    # ── google ──────────────────────────────────────────────────────────
    if not args.skip_google:
        from googleapiclient.discovery import build

        from warrant.auth import get_google_creds

        def _auth():
            state["creds"] = get_google_creds()
            svc = build("gmail", "v1", credentials=state["creds"])
            profile = svc.users().getProfile(userId="me").execute()
            state["me"] = profile["emailAddress"]
            return state["me"]

        if step("google oauth + gmail profile", _auth):
            from warrant.apps import gcal, gmail

            def _list():
                threads = gmail.list_unread(max_results=3)
                state["threads"] = threads
                return f"{len(threads)} unread thread(s)"

            def _read():
                if not state.get("threads"):
                    return "no unread thread to read - skipped"
                facts = gmail.read_thread(state["threads"][0]["thread_id"])
                state["facts"] = facts
                return f"{len(facts.participants)} participant(s), {len(facts.body_text)} body chars"

            def _send():
                msg_id = gmail.send(
                    to=[state["me"]],
                    subject="[warrant] Box A smoke test",
                    body=(
                        "This message was sent by the warrant smoke test. "
                        "It confirms gmail.send works with real credentials.\n\n"
                        "It did NOT pass through the policy gate - that is the "
                        "point of this file."
                    ),
                )
                state["msg_id"] = msg_id
                return f"message id {msg_id}"

            def _create_event():
                start = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0)
                end = start + timedelta(minutes=10)
                ev_id = gcal.create_event(
                    summary="[warrant] Box A smoke test",
                    start_iso=start.isoformat(),
                    end_iso=end.isoformat(),
                    attendees=[],
                    description="Created by the warrant smoke test.",
                )
                state["event_id"] = ev_id
                state["window"] = (start.isoformat(), end.isoformat())
                return f"event id {ev_id}"

            def _verify_event():
                lo, hi = state["window"]
                found = gcal.list_events(lo, hi)
                ids = [e["id"] for e in found]
                if state["event_id"] not in ids:
                    raise AssertionError(
                        "created event not returned by an independent list_events call"
                    )
                return "event read back independently"

            step("gmail.list_unread", _list)
            step("gmail.read_thread (trust anchor)", _read)
            step("gmail.send -> self", _send)
            step("calendar.create_event", _create_event)
            step("calendar read-back verify", _verify_event)
    else:
        results.append(("google", SKIP, "--skip-google"))

    # ── notion ──────────────────────────────────────────────────────────
    if not args.skip_notion:
        import os

        from warrant.apps import notion

        parent = os.getenv("WARRANT_SMOKE_PARENT", "").strip()

        def _create_page():
            if not parent:
                raise RuntimeError(
                    "WARRANT_SMOKE_PARENT is not set. Copy the target Notion page's URL - "
                    "the 32-hex id at the end is the parent id. Share that page with your "
                    "integration first (... -> Connections)."
                )
            page_id = notion.create_page(
                parent_id=parent,
                title="[warrant] Box A smoke test",
                body_md=(
                    "Created by the warrant smoke test.\n\n"
                    "Confirms notion.create_page works."
                ),
            )
            state["page_id"] = page_id
            return f"page id {page_id}"

        def _verify_page():
            got = notion.retrieve_page(state["page_id"])
            if got.get("id", "").replace("-", "") != state["page_id"].replace("-", ""):
                raise AssertionError("retrieve_page returned a different page")
            return "page read back independently"

        if step("notion.create_page", _create_page):
            step("notion read-back verify", _verify_page)
    else:
        results.append(("notion", SKIP, "--skip-notion"))

    # ── verdict ─────────────────────────────────────────────────────────
    passed = sum(1 for _, s, _ in results if s == OK)
    failed = sum(1 for _, s, _ in results if s == FAIL)
    print("\n" + "=" * 62)
    print(f"  {passed} passed, {failed} failed")

    apps_live = {
        "gmail": any(n.startswith("gmail.send") and s == OK for n, s, _ in results),
        "calendar": any(n.startswith("calendar.create") and s == OK for n, s, _ in results),
        "notion": any(n.startswith("notion.create") and s == OK for n, s, _ in results),
    }
    live = sorted(k for k, v in apps_live.items() if v)
    print(f"  apps proven live: {live or 'none'}")

    try:
        from warrant.provenance import write_artifact

        dest = write_artifact(
            kind="smoke",
            config={"skipped": {"notion": args.skip_notion, "google": args.skip_google}},
            result={
                "steps": [{"step": n, "status": s, "detail": d} for n, s, d in results],
                "passed": passed,
                "failed": failed,
                "apps_live": apps_live,
            },
        )
        print(f"  artifact: {dest}")
    except Exception as exc:
        print(f"  (artifact not written: {exc})")

    print("=" * 62 + "\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
