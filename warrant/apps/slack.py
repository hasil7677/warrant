"""
apps/slack.py
─────────────
The Slack client. Plain `requests` against the Web API - no SDK, matching
`notion.py`'s reasoning: three calls do not need a dependency and an exception
hierarchy of their own.

Only the broker imports this module.

**Liveness: fake-only.** There is no workspace to install a bot into, so this
has never made a real call. It is written against Slack's documented API
exactly as carefully as the three proven clients - see `warrant.registry` for
what "fake-only" means and why the distinction is stated rather than implied.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

API_BASE = "https://slack.com/api"
TIMEOUT = 30


class SlackError(RuntimeError):
    """A non-2xx, or a 200 carrying `ok: false` - Slack's API returns 200 for
    almost everything and puts the real result in the body, so a caller that
    only checked the status code would call a rejected message a success."""

    def __init__(self, error: str, detail: str = "") -> None:
        self.error = error
        message = f"Slack API error: {error}"
        if detail:
            message = f"{message}\nFIX: {detail}"
        super().__init__(message)


def _headers() -> dict[str, str]:
    from warrant.auth import slack_token

    return {"Authorization": f"Bearer {slack_token()}", "Content-Type": "application/json; charset=utf-8"}


def _hint_for(error: str) -> str:
    if error in ("invalid_auth", "not_authed", "token_revoked"):
        return "SLACK_BOT_TOKEN is missing or invalid - check the app's OAuth token."
    if error == "channel_not_found":
        return "The bot is not in that channel, or the channel id is wrong. Invite the bot first."
    if error == "not_in_channel":
        return "The bot must be invited to the channel before it can post there."
    if error == "missing_scope":
        return "The bot token is missing a required OAuth scope (chat:write or files:write)."
    return ""


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(f"{API_BASE}/{path}", headers=_headers(), json=payload, timeout=TIMEOUT)
    response.raise_for_status()
    body = response.json()
    if not body.get("ok"):
        error = str(body.get("error", "unknown_error"))
        raise SlackError(error, _hint_for(error))
    return body


def post_message(channel: str, text: str, thread_ts: Optional[str] = None) -> str:
    """Post a message. Returns the message timestamp, Slack's id for a message."""
    payload: dict[str, Any] = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    body = _post("chat.postMessage", payload)
    return str(body.get("ts", ""))


def upload_file(channel: str, filename: str, content: str, title: str = "") -> str:
    """Upload a file and share it into a channel, via the newer external-upload
    flow (Slack deprecated the single-call `files.upload` in 2024)."""
    from warrant.auth import slack_token

    started = _post(
        "files.getUploadURLExternal", {"filename": filename, "length": len(content.encode("utf-8"))}
    )
    upload_url = started["upload_url"]
    file_id = started["file_id"]

    put = requests.post(upload_url, data=content.encode("utf-8"), timeout=TIMEOUT)
    put.raise_for_status()

    completed = _post(
        "files.completeUploadExternal",
        {"files": [{"id": file_id, "title": title or filename}], "channel_id": channel},
    )
    files = completed.get("files") or [{"id": file_id}]
    return str(files[0].get("id", file_id))
