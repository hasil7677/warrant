"""
llm.py
──────
The model backend, behind one small interface.

The gate does not care which model proposes an action, and neither does the
evidence trail - so the choice of model lives here and nowhere else. Swapping
Mistral for Claude changes this file and nothing about what is enforced.

Bedrock's **Converse** API is the transport, because it normalises tool calling
across providers (Mistral, Anthropic, Cohere, Amazon). Borrowed from
`solari/solari-cookbook/code-agent/agent/bedrock_client.py`, where tool calling
was verified live against this account's actual Bedrock access rather than
assumed from the docs.

One property worth stating: **this module cannot execute anything.** It returns
the model's requested tool calls as plain data. The agent turns them into
proposals and the broker decides. A model backend that could act would put the
credential boundary inside a vendor SDK.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

# Verified working for tool use on Bedrock. Mistral Large is the default
# because the smaller instruct models in the family are inconsistent at
# emitting well-formed tool calls, and an agent that fumbles the tool schema
# makes the gate look like it is refusing things it is not.
DEFAULT_MISTRAL = "mistral.mistral-large-3-675b-instruct"
DEFAULT_CLAUDE = "anthropic.claude-opus-5"


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class Turn:
    """One model turn, normalised across backends."""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"
    raw: Any = None


class BedrockConverse:
    """Bedrock Converse. Works for Mistral and Claude alike."""

    def __init__(self, model_id: str, region: str) -> None:
        import boto3
        from botocore.config import Config

        self.model_id = model_id
        self.region = region
        # botocore's default 60s read timeout is too short for a large model's
        # first token on a cold endpoint - a demo should not fail on that.
        self._client = boto3.Session(region_name=region).client(
            "bedrock-runtime",
            config=Config(read_timeout=180, connect_timeout=10,
                          retries={"max_attempts": 2}),
        )

    @staticmethod
    def to_tool_spec(tools: list[dict]) -> list[dict]:
        """Anthropic-style tool dicts -> Converse toolSpec."""
        return [{
            "toolSpec": {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": {"json": t["input_schema"]},
            }
        } for t in tools]

    def send(self, system: str, messages: list[dict], tools: list[dict],
             max_tokens: int = 4096) -> Turn:
        kwargs: dict[str, Any] = {
            "modelId": self.model_id,
            "system": [{"text": system}],
            "messages": messages,
            "inferenceConfig": {"maxTokens": max_tokens},
        }
        if tools:
            kwargs["toolConfig"] = {"tools": self.to_tool_spec(tools)}

        resp = self._client.converse(**kwargs)
        blocks = resp["output"]["message"]["content"]
        text = "".join(b["text"] for b in blocks if "text" in b)
        calls = [
            ToolCall(id=b["toolUse"]["toolUseId"],
                     name=b["toolUse"]["name"],
                     input=b["toolUse"].get("input") or {})
            for b in blocks if "toolUse" in b
        ]
        return Turn(text=text, tool_calls=calls,
                    stop_reason=resp.get("stopReason", "end_turn"), raw=resp)

    @staticmethod
    def assistant_turn(turn: Turn) -> dict:
        """Echo the model's own turn back verbatim - Converse requires it."""
        return {"role": "assistant", "content": turn.raw["output"]["message"]["content"]}

    @staticmethod
    def tool_results(pairs: list[tuple[str, dict]]) -> dict:
        """All results in ONE user message; splitting them teaches the model
        to stop making parallel calls."""
        return {
            "role": "user",
            "content": [
                {"toolResult": {"toolUseId": tid,
                                "content": [{"json": result}]}}
                for tid, result in pairs
            ],
        }

    @staticmethod
    def user_turn(text: str) -> dict:
        return {"role": "user", "content": [{"text": text}]}


def build_backend() -> BedrockConverse:
    """Pick a backend from the environment. Bedrock + Mistral by default.

    `WARRANT_MODEL` overrides the model id, so switching from Mistral to Claude
    is an env var rather than a code change - which is the point: the gate's
    behaviour must not depend on who is proposing.
    """
    region = (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "").strip()
    if not region:
        raise RuntimeError(
            "AWS_REGION is not set, so the Bedrock backend cannot be reached.\n"
            "  Add to .env:  AWS_REGION=us-east-1\n"
            "  Plus either AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or AWS_PROFILE.\n"
            "\nThe demo, the 127 tests and the evaluation need none of this - they\n"
            "exercise the gate, and there is no model inside the gate."
        )
    # BEDROCK_MODEL_ID is accepted as an alias because it is the name people
    # already have in their AWS notes and .env files. Silently ignoring a
    # variable the operator clearly set, and then running a different model
    # than they asked for, is a worse outcome than either name being wrong.
    model = (
        os.getenv("WARRANT_MODEL")
        or os.getenv("BEDROCK_MODEL_ID")
        or DEFAULT_MISTRAL
    ).strip()
    return BedrockConverse(model_id=model, region=region)


def list_available_models(region: str) -> list[str]:
    """Model ids this account can actually invoke, for a clearer failure.

    Bedrock requires per-model access to be granted in the console, so the
    common failure is not a bad id but an id the account was never granted.
    Printing what IS available turns a ten-minute confusion into ten seconds.
    """
    import boto3

    try:
        bedrock = boto3.Session(region_name=region).client("bedrock")
        models = bedrock.list_foundation_models()["modelSummaries"]
        return sorted(
            m["modelId"] for m in models
            if "TEXT" in m.get("outputModalities", [])
            and m.get("modelLifecycle", {}).get("status") == "ACTIVE"
        )
    except Exception as exc:  # pragma: no cover - diagnostic path
        return [f"(could not list models: {type(exc).__name__}: {exc})"]
