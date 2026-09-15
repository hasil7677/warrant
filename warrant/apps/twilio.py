"""
apps/twilio.py
────────────────
The Twilio client. Plain `requests` against the REST API 2010-04-01, form
encoded, HTTP Basic auth - no SDK.

Only the broker imports this module.

**Liveness: fake-only.** No account. This is the one tool in the suite that
both spends money and reaches a stranger's phone in the same call, which is
why the registry gives it three hazard classes rather than one.
"""

from __future__ import annotations

from typing import Any

import requests

API_BASE = "https://api.twilio.com/2010-04-01"
TIMEOUT = 30


class TwilioError(RuntimeError):
    def __init__(self, status: int, body: str, hint: str = "") -> None:
        self.status = status
        self.body = body
        message = f"Twilio API returned {status}: {body}"
        if hint:
            message = f"{message}\nFIX: {hint}"
        super().__init__(message)


def _hint_for(status: int) -> str:
    if status == 401:
        return "TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN are missing or invalid."
    if status == 400:
        return "Twilio rejected the request - check the 'to' number is E.164 and 'from_number' is a number on this account."
    return ""


def send_sms(to: list[str], from_number: str, body: str) -> str:
    """POST /Accounts/{sid}/Messages.json. One recipient per call - Twilio has
    no native multi-recipient send, so a `to` list longer than one means the
    caller sent this once per number; `warrant.registry` prices that by
    counting the list rather than assuming one message."""
    from warrant.auth import twilio_credentials

    sid, token = twilio_credentials()
    recipients = list(to) if isinstance(to, (list, tuple)) else [to]
    last_sid = ""
    for number in recipients:
        response = requests.post(
            f"{API_BASE}/Accounts/{sid}/Messages.json",
            auth=(sid, token),
            data={"To": number, "From": from_number, "Body": body},
            timeout=TIMEOUT,
        )
        if not 200 <= response.status_code < 300:
            raise TwilioError(response.status_code, response.text, _hint_for(response.status_code))
        last_sid = str(response.json().get("sid", ""))
    return last_sid
