"""
apps/drive.py
───────────────
The Google Drive client. Plain `requests` against Drive API v3 - the same
"REST, no SDK" choice as `notion.py`, made once more even though Google
provides a discovery-based client library, because two calls do not need one
either.

Only the broker imports this module.

**Liveness: fake-only, and the reason is specific.** This project already has
one working Google OAuth token (`token.json`), cached with `gmail.readonly`,
`gmail.send` and `calendar.events` scopes - the ones the live smoke run
exercises. Drive needs `drive.file` on top of those, and requesting it would
force a fresh consent and mint a new token, invalidating the one this repo has
evidence behind. So Drive stays fake rather than widening that grant for a
build note. `warrant.auth.google_drive_sheets_creds()` explains this in code,
not just here.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

API_BASE = "https://www.googleapis.com/drive/v3"
UPLOAD_BASE = "https://www.googleapis.com/upload/drive/v3"
TIMEOUT = 30


class DriveError(RuntimeError):
    def __init__(self, status: int, body: str, hint: str = "") -> None:
        self.status = status
        self.body = body
        message = f"Drive API returned {status}: {body}"
        if hint:
            message = f"{message}\nFIX: {hint}"
        super().__init__(message)


def _headers() -> dict[str, str]:
    # Always raises today - see the module docstring and
    # `warrant.auth.google_drive_sheets_creds` for why. Written as a real call
    # rather than a bare `raise` here so the day someone adds drive.file to
    # SCOPES and makes that function return real credentials, this file needs
    # no change to start working.
    from warrant.auth import google_drive_sheets_creds

    creds = google_drive_sheets_creds()
    return {"Authorization": f"Bearer {creds.token}"}


def _hint_for(status: int) -> str:
    if status == 401:
        return "The Google OAuth token lacks Drive scope - see google_drive_sheets_creds()."
    if status == 404:
        return "That folder_id or file_id does not exist, or is not visible to this account."
    return ""


def upload_file(folder_id: str, name: str, content: str, mime_type: Optional[str] = None) -> str:
    """Multipart upload into a folder the operator owns. Returns the file id."""
    import json as _json

    metadata = {"name": name, "parents": [folder_id]}
    boundary = "warrant-boundary"
    body = (
        f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
        f"{_json.dumps(metadata)}\r\n"
        f"--{boundary}\r\nContent-Type: {mime_type or 'text/plain'}\r\n\r\n"
        f"{content}\r\n--{boundary}--"
    )
    headers = dict(_headers())
    headers["Content-Type"] = f"multipart/related; boundary={boundary}"
    response = requests.post(
        f"{UPLOAD_BASE}/files?uploadType=multipart", headers=headers, data=body.encode("utf-8"), timeout=TIMEOUT
    )
    if not 200 <= response.status_code < 300:
        raise DriveError(response.status_code, response.text, _hint_for(response.status_code))
    return str(response.json().get("id", ""))


def share_file(
    file_id: str,
    email: Optional[str] = None,
    role: Optional[str] = None,
    audience: Optional[str] = None,
) -> str:
    """POST /files/{id}/permissions. Grants access; returns the permission id."""
    payload: dict[str, Any] = {"type": audience or "user", "role": role or "reader"}
    if email:
        payload["emailAddress"] = email
    response = requests.post(
        f"{API_BASE}/files/{file_id}/permissions", headers=_headers(), json=payload, timeout=TIMEOUT
    )
    if not 200 <= response.status_code < 300:
        raise DriveError(response.status_code, response.text, _hint_for(response.status_code))
    return str(response.json().get("id", ""))
