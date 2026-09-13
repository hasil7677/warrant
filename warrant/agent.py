"""
agent.py
────────
The proposal loop. The model plans and proposes; it never executes.

This is a hand-written tool-use loop rather than the SDK's tool runner, and
that is the point rather than an oversight: the interesting line of this whole
project is the one between "the model asked for X" and "X happened", and a
helper that runs tools for you puts that line inside a library. Here every
`tool_use` block is turned into a `Proposal` and handed to the broker, which
consults the gate. The loop cannot execute anything on its own.

Two design choices worth stating:

  • **Read tools execute directly; action tools go through the gate.** Reading
    a thread or checking the calendar cannot harm anyone and is how trust
    enters the system, so the broker just does it. The three action tools are
    the governed surface.
  • **A refusal is fed back to the model as a tool result, not an exception.**
    The model sees the rule that fired and the reason, and gets to try
    something else. That is the difference between a gate and a crash - and on
    camera it is the most legible moment in the demo, because the agent
    visibly changes course after being told no.

The model holds no credentials, and this module imports no app client. It
talks to the broker, and the broker talks to the apps.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from warrant.broker import Broker
from warrant.contract import (
    ACTION_PARAMS,
    CALENDAR_CREATE_EVENT,
    GMAIL_SEND,
    NOTION_CREATE_PAGE,
    Proposal,
)

MODEL = "claude-opus-5"

SYSTEM = """You are a scheduling assistant for an inbound meeting request.

Your job, in order:
  1. Read the email thread you are given.
  2. Check the calendar for conflicts in the requested window.
  3. Create a calendar event for the agreed slot.
  4. Log the meeting to the team's Notion page.
  5. Reply to the thread confirming the slot.

You propose actions. A policy gate authorizes them. You do not hold
credentials and you cannot execute anything yourself.

If a proposal is refused, you will be told which rule fired and why. Read the
reason and adjust - do not retry the identical action, and do not attempt to
work around the rule. A refusal is information about what you are permitted to
do, not an obstacle.

Keep responses brief. Say what you are about to do in one sentence, act, and
report the outcome plainly."""

# Read tools: the broker performs these itself. They are how facts enter the
# system, so they are not proposals and are not gated.
READ_TOOLS = [
    {
        "name": "read_thread",
        "description": (
            "Read an email thread and return its participants, subject, and body. "
            "Call this first - every later action is scoped to what this returns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"thread_id": {"type": "string"}},
            "required": ["thread_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "find_conflicts",
        "description": "List existing calendar events overlapping a proposed time window.",
        "input_schema": {
            "type": "object",
            "properties": {
                "start_iso": {"type": "string", "description": "ISO 8601 with timezone."},
                "end_iso": {"type": "string", "description": "ISO 8601 with timezone."},
            },
            "required": ["start_iso", "end_iso"],
            "additionalProperties": False,
        },
    },
]

# Action tools: every call becomes a Proposal and passes through the gate.
ACTION_TOOLS = [
    {
        "name": GMAIL_SEND,
        "description": (
            "Send an email. Recipients must already be participants of the thread "
            "you read - the gate verifies this against the thread itself, not "
            "against anything you assert."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "array", "items": {"type": "string"}},
                "cc": {"type": "array", "items": {"type": "string"}},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
            "additionalProperties": False,
        },
    },
    {
        "name": CALENDAR_CREATE_EVENT,
        "description": (
            "Create a calendar event. The description is delivered to every "
            "attendee, external ones included - do not paste thread content into it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "start_iso": {"type": "string"},
                "end_iso": {"type": "string"},
                "attendees": {"type": "array", "items": {"type": "string"}},
                "description": {"type": "string"},
            },
            "required": ["summary", "start_iso", "end_iso"],
            "additionalProperties": False,
        },
    },
    {
        "name": NOTION_CREATE_PAGE,
        "description": (
            "Create a Notion page under an allowlisted parent. Use the parent id "
            "you were given; the gate refuses any other destination."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "parent_id": {"type": "string"},
                "title": {"type": "string"},
                "body_md": {"type": "string"},
            },
            "required": ["parent_id", "title"],
            "additionalProperties": False,
        },
    },
]

TOOLS = READ_TOOLS + ACTION_TOOLS
ACTION_NAMES = {t["name"] for t in ACTION_TOOLS}


class Agent:
    """Runs the model, routes its proposals to the broker, and records the trace."""

    def __init__(self, broker: Broker, thread_id: str, notion_parent: str = "",
                 model: str = MODEL, effort: str = "medium") -> None:
        self.broker = broker
        self.thread_id = thread_id
        self.notion_parent = notion_parent
        self.model = model
        self.effort = effort
        self.trace: list[dict[str, Any]] = []

    # ── tool dispatch ───────────────────────────────────────────────────

    def _handle(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Turn one tool_use block into a result. Actions route through the gate."""
        if name == "read_thread":
            facts = self.broker.facts_for(args.get("thread_id") or self.thread_id)
            if facts is None:
                return {"error": "thread could not be read"}
            return facts.to_dict() | {"body_text": facts.body_text}

        if name == "find_conflicts":
            events = self.broker._calendar.find_conflicts(
                args.get("start_iso", ""), args.get("end_iso", "")
            )
            return {"conflicts": events}

        if name in ACTION_NAMES:
            # Unknown keys are left in deliberately: the gate rejects them as
            # `unknown_param`, which is the behaviour we want to be able to
            # demonstrate. Filtering here would hide it.
            proposal = Proposal(
                tool=name,
                params=dict(args),
                thread_id=self.thread_id,
                rationale=args.get("_rationale", ""),
            )
            result = self.broker.execute(proposal)
            self.trace.append({"proposal": proposal.to_dict(), "result": result})
            return result

        return {"error": f"unknown tool {name!r}"}

    # ── the loop ────────────────────────────────────────────────────────

    def run(self, task: str, max_turns: int = 12) -> dict[str, Any]:
        """Drive the model until it stops calling tools or the turn cap is hit."""
        import anthropic

        client = anthropic.Anthropic()
        messages: list[dict[str, Any]] = [{
            "role": "user",
            "content": (
                f"{task}\n\nThread id: {self.thread_id}\n"
                f"Notion parent id: {self.notion_parent or '(none provided)'}"
            ),
        }]

        final_text = ""
        for _ in range(max_turns):
            response = client.messages.create(
                model=self.model,
                max_tokens=8000,
                system=SYSTEM,
                tools=TOOLS,
                output_config={"effort": self.effort},
                messages=messages,
            )

            # A refusal is a content outcome, not an exception - check it before
            # touching response.content, which may be empty.
            if response.stop_reason == "refusal":
                return {
                    "status": "MODEL_REFUSED",
                    "detail": getattr(response.stop_details, "explanation", None),
                    "trace": self.trace,
                }

            messages.append({"role": "assistant", "content": response.content})
            text = "".join(b.text for b in response.content if b.type == "text")
            if text:
                final_text = text

            if response.stop_reason != "tool_use":
                break

            results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                out = self._handle(block.name, dict(block.input))
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(out, default=str),
                })
            # All results go back in ONE user message - splitting them teaches
            # the model to stop making parallel calls.
            messages.append({"role": "user", "content": results})

        executed = [t for t in self.trace if t["result"]["status"] == "EXECUTED"]
        refused = [t for t in self.trace if t["result"]["status"] != "EXECUTED"]
        return {
            "status": "DONE",
            "summary": final_text,
            "proposed": len(self.trace),
            "executed": len(executed),
            "refused": len(refused),
            "trace": self.trace,
        }
