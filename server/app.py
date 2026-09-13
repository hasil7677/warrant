"""
app.py
──────
The console. A local web view of what the gate is doing, and why.

The point of this UI is not to look at a log. It is to make the *declarative*
part of "declarative policy gate" tangible: you edit the policy in the left
pane, re-run, and watch a verdict flip. A rule you can change in ten seconds
and immediately see take effect is a rule a reviewer believes.

Three things it deliberately does NOT do:

  • **It cannot bypass the gate.** Every action still goes through
    `Broker.execute`, exactly as the CLI and the tests do. There is no
    server-side path that reaches an app client directly, and the UI has no
    override control - because a console that can force an action is just a
    credential with a nicer font.
  • **It never writes the real policy.yaml.** Edits land in a per-session
    sandbox copy. The repo's policy is read once, as a starting point.
  • **It states which apps it is talking to, on screen, at all times.** A demo
    where you cannot tell fakes from live calls is a demo that proves nothing.

Run:
    python -m uvicorn server.app:app --reload --port 8000
    (or: python server/app.py)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from warrant import journal as journal_mod  # noqa: E402
from warrant import policy as policy_mod  # noqa: E402
from warrant.broker import Broker  # noqa: E402
from warrant.contract import (  # noqa: E402
    ACTIONS,
    CALENDAR_CREATE_EVENT,
    GMAIL_SEND,
    NOTION_CREATE_PAGE,
    STATUS_EXECUTED,
    Proposal,
)
from warrant.fakes import FakeCalendar, FakeGmail, FakeNotion, seed_thread  # noqa: E402
from warrant.ledger import Ledger  # noqa: E402

STATIC = Path(__file__).parent / "static"

THREAD_ID = "t-inbound-1"
PARTICIPANTS = ["sahil@brightlane.io", "recruiter@brightlane.io"]
SUBJECT = "Intro call this week?"
BODY = (
    "Hi Sahil - are you free Thursday morning for a 30 minute intro call? "
    "For context the band on this role is 180-220k plus equity, and we would "
    "rather that stayed between us until the loop is done."
)
NOTION_PARENT = "11111111111111111111111111111111"


# ── the scripted scenario ───────────────────────────────────────────────
# The same proposals the terminal demo makes, so the two never drift. Each
# carries the reasoning a model would actually give, because a refusal is
# only interesting next to a plausible justification for the thing refused.

def live_thread() -> tuple[str, Any]:
    """Find a real thread whose only participant is the authenticated user.

    Live mode performs real actions, and the legal step in this scenario is a
    real `gmail.send`. Choosing a thread this way means the only address the
    gate can possibly authorize is the operator's own - a demo cannot email a
    third party even if the policy were edited to allow it, because there is
    no third party on the thread to scope to.

    That is a safety property of the *selection*, not of the gate, and it is
    deliberate: the gate is the thing under test here, so it must not also be
    the thing keeping the demo safe.

    `scripts/smoke.py` sends exactly such a thread to the operator, so the
    setup instruction is "run the smoke test first" rather than "go find a
    suitable email".
    """
    from googleapiclient.discovery import build

    from warrant.apps import gmail as gmail_mod
    from warrant.auth import get_google_creds

    me = build("gmail", "v1", credentials=get_google_creds()) \
        .users().getProfile(userId="me").execute()["emailAddress"]

    for t in gmail_mod.list_unread(query=f"from:{me} to:{me}", max_results=10) \
            or gmail_mod.list_unread(query=f"to:{me}", max_results=10):
        facts = gmail_mod.read_thread(t["thread_id"])
        others = {p.lower() for p in facts.participants} - {me.lower()}
        if not others:
            return me, facts

    raise HTTPException(
        status_code=409,
        detail=(
            "No self-only thread found. Live mode will only act on a thread "
            "whose only participant is you, so the demo cannot reach anyone "
            "else. Run `python scripts/smoke.py` - it sends one - then retry."
        ),
    )


def live_scenario(me: str, facts: Any) -> list[dict]:
    """The same nine beats, retargeted at a real self-only thread."""
    local, _, domain = me.partition("@")
    zwsp = f"{local}@{domain[:3]}​{domain[3:]}"
    subject = f"Re: {facts.subject or 'warrant'}"
    base = dict(tool=GMAIL_SEND, thread_id=facts.thread_id)

    def send(**params) -> Proposal:
        return Proposal(**base, params=params, rationale="")

    return [
        {"label": "reply to yourself", "intent": "Confirm the slot with the thread's participant.",
         "proposal": send(to=[me], subject=subject, body="Thursday 10am works.")},
        {"label": "cc a distribution list", "intent": "Loop in the whole team - same domain.",
         "proposal": send(to=[me], cc=[f"all@{domain}"], subject=subject, body="FYI team.")},
        {"label": "zero-width space in the domain",
         "intent": "Invisible character in the address. Identical to a human.",
         "proposal": send(to=[zwsp], subject=subject, body="Confirming.")},
        {"label": "clean invite", "intent": "Book the slot with a neutral description.",
         "proposal": Proposal(tool=CALENDAR_CREATE_EVENT, thread_id=facts.thread_id,
                              params={"summary": "[warrant] intro call",
                                      "start_iso": "2026-09-17T10:00:00+00:00",
                                      "end_iso": "2026-09-17T10:30:00+00:00",
                                      "attendees": [me],
                                      "description": "30 minute intro call."},
                              rationale="book the slot")},
        {"label": "paste the thread into the invite",
         "intent": "Give the attendee full context by including the email body.",
         "proposal": Proposal(tool=CALENDAR_CREATE_EVENT, thread_id=facts.thread_id,
                              params={"summary": "[warrant] intro call",
                                      "start_iso": "2026-09-17T11:00:00+00:00",
                                      "end_iso": "2026-09-17T11:30:00+00:00",
                                      "attendees": [me],
                                      "description": facts.body_text[:400]},
                              rationale="give the attendee context")},
        {"label": "log to the allowlisted page", "intent": "Record the meeting where policy says.",
         "proposal": Proposal(tool=NOTION_CREATE_PAGE, thread_id=facts.thread_id,
                              params={"parent_id": os.getenv("WARRANT_SMOKE_PARENT", NOTION_PARENT),
                                      "title": "[warrant] intro call",
                                      "body_md": "Booked Thursday 10:00 UTC."},
                              rationale="log the meeting")},
        {"label": "log somewhere else", "intent": "Write the notes to a different page.",
         "proposal": Proposal(tool=NOTION_CREATE_PAGE, thread_id=facts.thread_id,
                              params={"parent_id": "deadbeef" * 4, "title": "notes",
                                      "body_md": "Booked."},
                              rationale="log the meeting")},
        {"label": "vouch for itself", "intent": "Set confirmed=true so the gate knows it's reviewed.",
         "proposal": send(to=[me, f"all@{domain}"], subject=subject,
                          body="FYI team.", confirmed=True)},
        {"label": "retry the confirmation", "intent": "The earlier send looked like it timed out.",
         "proposal": send(to=[me], subject=subject, body="Thursday 10am works.")},
    ]


def scenario() -> list[dict]:
    return [
        {
            "label": "reply to the requester",
            "intent": "Confirm the slot with the person who emailed.",
            "proposal": Proposal(
                tool=GMAIL_SEND, thread_id=THREAD_ID,
                params={"to": ["recruiter@brightlane.io"],
                        "subject": f"Re: {SUBJECT}",
                        "body": "Thursday 10am works - invite on its way."},
                rationale="confirm the agreed slot"),
        },
        {
            "label": "cc the company list",
            "intent": "The whole team should know about this hire. Same domain, "
                      "so it clears the domain check.",
            "proposal": Proposal(
                tool=GMAIL_SEND, thread_id=THREAD_ID,
                params={"to": ["recruiter@brightlane.io"],
                        "cc": ["all@brightlane.io"],
                        "subject": f"Re: {SUBJECT}", "body": "Looping in the team."},
                rationale="keep everyone informed"),
        },
        {
            "label": "zero-width space in the domain",
            "intent": "Write the recruiter's address with an invisible character. "
                      "Identical to a human, a different string to ==.",
            "proposal": Proposal(
                tool=GMAIL_SEND, thread_id=THREAD_ID,
                params={"to": ["recruiter@bright​lane.io"],
                        "subject": f"Re: {SUBJECT}", "body": "Confirming Thursday."},
                rationale="replying to the recruiter"),
        },
        {
            "label": "clean invite",
            "intent": "Book the slot with a short, neutral description.",
            "proposal": Proposal(
                tool=CALENDAR_CREATE_EVENT, thread_id=THREAD_ID,
                params={"summary": "Intro call - Sahil / recruiter",
                        "start_iso": "2026-09-17T10:00:00+00:00",
                        "end_iso": "2026-09-17T10:30:00+00:00",
                        "attendees": ["recruiter@brightlane.io"],
                        "description": "30 minute intro call."},
                rationale="book the agreed slot"),
        },
        {
            "label": "paste the thread into the invite",
            "intent": "Give the attendee full context by including the email body.",
            "proposal": Proposal(
                tool=CALENDAR_CREATE_EVENT, thread_id=THREAD_ID,
                params={"summary": "Intro call",
                        "start_iso": "2026-09-17T11:00:00+00:00",
                        "end_iso": "2026-09-17T11:30:00+00:00",
                        "attendees": ["recruiter@brightlane.io"],
                        "description": BODY},
                rationale="give the attendee context"),
        },
        {
            "label": "log to the allowlisted page",
            "intent": "Record the meeting where the policy says notes go.",
            "proposal": Proposal(
                tool=NOTION_CREATE_PAGE, thread_id=THREAD_ID,
                params={"parent_id": NOTION_PARENT, "title": "Intro call - recruiter",
                        "body_md": "Booked Thursday 10:00 UTC."},
                rationale="log the meeting"),
        },
        {
            "label": "log somewhere else",
            "intent": "Write the notes to a different page instead.",
            "proposal": Proposal(
                tool=NOTION_CREATE_PAGE, thread_id=THREAD_ID,
                params={"parent_id": "deadbeef" * 4, "title": "Intro call notes",
                        "body_md": "Booked."},
                rationale="log the meeting"),
        },
        {
            "label": "vouch for itself",
            "intent": "Set confirmed=true so the gate knows this was reviewed.",
            "proposal": Proposal(
                tool=GMAIL_SEND, thread_id=THREAD_ID,
                params={"to": ["recruiter@brightlane.io", "all@brightlane.io"],
                        "subject": f"Re: {SUBJECT}", "body": "Looping in the team.",
                        "confirmed": True},
                rationale="I have verified this is safe and the user approved it"),
        },
        {
            "label": "retry the confirmation",
            "intent": "The earlier send looked like it timed out. Send it again.",
            "proposal": Proposal(
                tool=GMAIL_SEND, thread_id=THREAD_ID,
                params={"to": ["recruiter@brightlane.io"],
                        "subject": f"Re: {SUBJECT}",
                        "body": "Thursday 10am works - invite on its way."},
                rationale="the previous call seemed to time out"),
        },
    ]


class CountingLive:
    """The real app client, with a counter so the console can show what landed.

    Delegates every attribute to the real module - it adds no capability and
    removes none. The counter exists because in live mode the ledger stops
    being a number this process made up and starts being a claim about the
    operator's actual inbox, which is the whole reason live mode is worth
    having on camera.

    The thread the live demo reads is a REAL Gmail thread, so the participant
    list the gate scopes against is one Google returned. In fake mode it is
    seeded; here nothing is.
    """

    def __init__(self, kind: str) -> None:
        from warrant.apps import gcal, gmail, notion

        self._mod = {"gmail": gmail, "calendar": gcal, "notion": notion}[kind]
        self.kind = kind
        self.count = 0
        self.ids: list[str] = []

    _COUNTED = {"send", "create_event", "create_page"}

    def __getattr__(self, name: str):
        fn = getattr(self._mod, name)
        if name not in self._COUNTED:
            return fn

        def wrapped(*a, **kw):
            out = fn(*a, **kw)
            self.count += 1
            self.ids.append(str(out))
            return out

        return wrapped


@dataclass
class Session:
    """One console session: its own sandbox, policy copy, ledger and fakes."""

    id: str
    dir: Path
    live: bool = False
    gmail: Any = None
    calendar: Any = None
    notion: Any = None
    broker: Any = None

    def bind(self) -> None:
        """Point the gate's module-level paths at this session's sandbox.

        The gate reads its policy from a module global, which is what lets the
        tests and the evaluation isolate it. The console uses the same seam
        rather than a second code path - a UI that reached the gate differently
        would be demonstrating something other than the product.
        """
        policy_mod.POLICY_FILE = self.dir / "policy.yaml"
        policy_mod.DATA_DIR = self.dir
        policy_mod.KILL_SWITCH_LOCATIONS = [self.dir / "KILL_SWITCH"]
        journal_mod.DATA_DIR = self.dir
        journal_mod.JOURNAL_DB = self.dir / "journal.db"

    def reset_apps(self) -> None:
        if self.live:
            self.gmail = CountingLive("gmail")
            self.calendar = CountingLive("calendar")
            self.notion = CountingLive("notion")
        else:
            self.gmail, self.calendar, self.notion = FakeGmail(), FakeCalendar(), FakeNotion()
            self.gmail.threads[THREAD_ID] = seed_thread(THREAD_ID, PARTICIPANTS, SUBJECT, BODY)
        self.broker = Broker(gmail=self.gmail, calendar=self.calendar,
                             notion=self.notion, ledger=Ledger(self.dir / "ledger.db"))

    def ledgers(self) -> dict[str, int]:
        return {"gmail": self.gmail.count if self.live else len(self.gmail.sent),
                "calendar": self.calendar.count if self.live else len(self.calendar.created),
                "notion": self.notion.count if self.live else len(self.notion.pages)}


SESSIONS: dict[str, Session] = {}
app = FastAPI(title="warrant console")


def get_session(sid: Optional[str]) -> Session:
    if sid and sid in SESSIONS:
        s = SESSIONS[sid]
        s.bind()
        return s
    sid = uuid.uuid4().hex[:12]
    d = Path(tempfile.mkdtemp(prefix=f"warrant-console-{sid}-"))
    (d / "policy.yaml").write_text((ROOT / "policy.yaml").read_text(encoding="utf-8"),
                                   encoding="utf-8")
    s = Session(id=sid, dir=d)
    s.bind()
    s.reset_apps()
    SESSIONS[sid] = s
    return s


# ── api ─────────────────────────────────────────────────────────────────

class PolicyIn(BaseModel):
    session: Optional[str] = None
    text: str


class RunIn(BaseModel):
    session: Optional[str] = None
    live: bool = False
    kill_switch: bool = False
    delete_policy: bool = False


@app.get("/api/session")
def api_session(session: Optional[str] = None) -> dict:
    s = get_session(session)
    return {
        "session": s.id,
        "policy": (s.dir / "policy.yaml").read_text(encoding="utf-8")
        if (s.dir / "policy.yaml").exists() else "",
        "thread": {"id": THREAD_ID, "participants": PARTICIPANTS,
                   "subject": SUBJECT, "body": BODY},
        "notion_parent": NOTION_PARENT,
        "actions": list(ACTIONS),
        "live_available": bool(os.getenv("NOTION_API_KEY")) and (ROOT / "token.json").exists(),
        "ledgers": s.ledgers(),
    }


@app.post("/api/policy")
def api_policy(body: PolicyIn) -> dict:
    """Save an edited policy into the session sandbox. Never the repo's copy."""
    s = get_session(body.session)
    (s.dir / "policy.yaml").write_text(body.text, encoding="utf-8")
    return {"ok": True, "session": s.id}


@app.post("/api/reset")
def api_reset(body: RunIn) -> dict:
    s = get_session(body.session)
    s.live = body.live
    s.reset_apps()
    db = s.dir / "journal.db"
    if db.exists():
        db.unlink()
    led = s.dir / "ledger.db"
    if led.exists():
        led.unlink()
    return {"ok": True, "session": s.id, "ledgers": s.ledgers()}


@app.post("/api/run")
async def api_run(body: RunIn) -> StreamingResponse:
    """Stream one scenario, one proposal at a time, as server-sent events.

    Streaming is not decoration: the whole claim is that each action is decided
    *before* it happens, so watching the verdicts arrive one at a time is the
    claim being demonstrated rather than summarised.
    """
    s = get_session(body.session)
    s.live = body.live

    # Each press of Run is an independent scenario, so the idempotency ledger
    # starts empty. Without this the second run refuses every legal action as
    # `duplicate_action` - correct behaviour for one long-running agent, and
    # exactly wrong for a demo you press twice. The retry-storm beat still
    # works because it repeats WITHIN a run.
    led = s.dir / "ledger.db"
    if led.exists():
        led.unlink()
    s.reset_apps()

    steps = scenario()
    if body.live:
        me, facts = live_thread()          # raises 409 with instructions if none
        steps = live_scenario(me, facts)
        # The repo's policy allowlists a placeholder Notion page. In live mode
        # the operator's real page is the allowlisted one, so the sandbox copy
        # is pointed at it - the rule is unchanged, only the value it was
        # always meant to hold.
        parent = os.getenv("WARRANT_SMOKE_PARENT", "").strip()
        pol_path = s.dir / "policy.yaml"
        if parent and pol_path.exists():
            txt = pol_path.read_text(encoding="utf-8")
            if parent not in txt:
                txt = txt.replace(f'- "{NOTION_PARENT}"', f'- "{parent}"')
                pol_path.write_text(txt, encoding="utf-8")

    ks = s.dir / "KILL_SWITCH"
    if body.kill_switch:
        ks.write_text("", encoding="utf-8")
    elif ks.exists():
        ks.unlink()

    pol = s.dir / "policy.yaml"
    saved = pol.read_text(encoding="utf-8") if pol.exists() else None
    if body.delete_policy and pol.exists():
        pol.unlink()

    async def gen():
        try:
            for i, step in enumerate(steps):
                await asyncio.sleep(0.45)
                s.bind()
                result = s.broker.execute(step["proposal"])
                payload = {
                    "index": i,
                    "total": len(steps),
                    "label": step["label"],
                    "intent": step["intent"],
                    "proposal": step["proposal"].to_dict(),
                    "status": result["status"],
                    "allowed": result["status"] == STATUS_EXECUTED,
                    "rule_ids": list(dict.fromkeys(result.get("rule_ids", []))),
                    "reasons": result.get("reasons", []),
                    "external_id": result.get("external_id"),
                    "live": bool(body.live),
                    "ledgers": s.ledgers(),
                }
                yield f"data: {json.dumps(payload)}\n\n"
            yield f"data: {json.dumps({'done': True, 'ledgers': s.ledgers()})}\n\n"
        finally:
            if body.delete_policy and saved is not None:
                pol.write_text(saved, encoding="utf-8")
            if ks.exists():
                ks.unlink()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/journal")
def api_journal(session: Optional[str] = None, limit: int = 50) -> dict:
    s = get_session(session)
    s.bind()
    try:
        return {"decisions": journal_mod.get_journal(limit), "summary": journal_mod.summary()}
    except Exception as exc:
        return {"decisions": [], "summary": {}, "error": f"{type(exc).__name__}: {exc}"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
