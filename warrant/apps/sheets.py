"""
apps/sheets.py
────────────────
The Google Sheets client. Plain `requests` against Sheets API v4.

Only the broker imports this module.

**Liveness: fake-only,** for the same scope reason as `drive.py` - see that
module's docstring and `warrant.auth.google_drive_sheets_creds`.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

API_BASE = "https://sheets.googleapis.com/v4/spreadsheets"
TIMEOUT = 30


class SheetsError(RuntimeError):
    def __init__(self, status: int, body: str, hint: str = "") -> None:
        self.status = status
        self.body = body
        message = f"Sheets API returned {status}: {body}"
        if hint:
            message = f"{message}\nFIX: {hint}"
        super().__init__(message)


def _headers() -> dict[str, str]:
    from warrant.auth import google_drive_sheets_creds

    creds = google_drive_sheets_creds()
    return {"Authorization": f"Bearer {creds.token}"}


def _hint_for(status: int) -> str:
    if status == 401:
        return "The Google OAuth token lacks Sheets scope - see google_drive_sheets_creds()."
    if status == 404:
        return "That spreadsheet_id does not exist, or is not visible to this account."
    return ""


def append_row(spreadsheet_id: str, range_a1: str, values: list[str]) -> str:
    """POST .../values/{range}:append. Returns the range Sheets actually wrote to."""
    encoded_range = quote(range_a1, safe="")
    response = requests.post(
        f"{API_BASE}/{spreadsheet_id}/values/{encoded_range}:append"
        "?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS",
        headers=_headers(),
        json={"values": [list(values)]},
        timeout=TIMEOUT,
    )
    if not 200 <= response.status_code < 300:
        raise SheetsError(response.status_code, response.text, _hint_for(response.status_code))
    updates: dict[str, Any] = response.json().get("updates", {})
    return str(updates.get("updatedRange", range_a1))


def clear_range(spreadsheet_id: str, range_a1: str) -> str:
    """POST .../values/{range}:clear. Returns the range that was cleared."""
    encoded_range = quote(range_a1, safe="")
    response = requests.post(
        f"{API_BASE}/{spreadsheet_id}/values/{encoded_range}:clear",
        headers=_headers(),
        json={},
        timeout=TIMEOUT,
    )
    if not 200 <= response.status_code < 300:
        raise SheetsError(response.status_code, response.text, _hint_for(response.status_code))
    return str(response.json().get("clearedRange", range_a1))
