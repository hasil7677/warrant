"""
apps/gmail.py
─────────────
The Gmail client. Reads threads, lists unread mail, sends mail.

Only the broker imports this module. The agent never holds a Gmail handle, so
"the model sent an email" is not a thing that can happen without the broker
having decided it should.

`read_thread` is the trust anchor for the entire system - see its docstring.
"""

from __future__ import annotations

import base64
from email.message import EmailMessage
from email.utils import getaddresses
from typing import Any, Optional

from warrant.contract import ThreadFacts

# Headers that name a human who is already part of the conversation. Bcc is
# deliberately absent: Gmail does not report other people's Bcc back to us, and
# a participant set that silently depends on who happened to be Bcc'd would be
# a different set on every read.
_PARTICIPANT_HEADERS = ("from", "to", "cc")


def _service():
    """Build the Gmail API client.

    The auth import is inside the function on purpose: importing this module
    must never trigger a credential check, or the fakes-based demo and every
    unit test would need a Google account to run.
    """
    from googleapiclient.discovery import build  # local: heavy, and only needed here

    from warrant.auth import get_google_creds

    return build("gmail", "v1", credentials=get_google_creds(), cache_discovery=False)


def _headers(message: dict[str, Any]) -> dict[str, list[str]]:
    """Header name (lowercased) -> every value seen for it.

    A list rather than a scalar because a message can legitimately carry two
    `Cc` headers, and keeping only the last one would silently drop a
    participant - which is exactly the fact policy rules are scoped against.
    """
    out: dict[str, list[str]] = {}
    for header in message.get("payload", {}).get("headers", []) or []:
        name = str(header.get("name", "")).lower()
        out.setdefault(name, []).append(str(header.get("value", "")))
    return out


def _decode(data: Optional[str]) -> str:
    """Decode Gmail's base64url body payload, tolerating missing padding."""
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode(
            "utf-8", errors="replace"
        )
    except (ValueError, UnicodeDecodeError):
        return ""


def _walk_parts(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Recurse a MIME tree, returning (plain_texts, html_texts).

    Both are collected in one pass so the caller can prefer text/plain but
    still have something to show for an HTML-only message rather than an empty
    body - an empty body would make a policy rule that reads the thread look
    like it passed when it never saw the content.
    """
    plain: list[str] = []
    html: list[str] = []

    def visit(node: dict[str, Any]) -> None:
        if not isinstance(node, dict):
            return
        mime = str(node.get("mimeType", "") or "")
        body = node.get("body", {}) or {}
        text = _decode(body.get("data"))
        if text:
            if mime.startswith("text/plain"):
                plain.append(text)
            elif mime.startswith("text/html"):
                html.append(text)
            elif not node.get("parts"):
                # Untyped leaf with content - keep it rather than lose it.
                plain.append(text)
        for child in node.get("parts", []) or []:
            visit(child)

    visit(payload)
    return plain, html


def read_thread(thread_id: str) -> ThreadFacts:
    """Read a Gmail thread and return what the API actually says about it.

    ═══ THIS FUNCTION IS THE TRUST ANCHOR OF THE WHOLE SYSTEM ═══

    Every interesting policy rule is a comparison between a Proposal (what the
    model *claims*) and a ThreadFacts (what the broker *read*). The value of
    that comparison is exactly the independence of this function: the returned
    `participants` list must be derivable only from the Gmail API response, and
    from nothing the model said, nothing a caller passed in, and nothing
    embedded in the message body.

    That is why `thread_id` is the only argument. There is no override, no
    "extra_participants", no way to hint at a subject. If this function ever
    grows a parameter that can widen `participants`, the gate stops being a
    gate: the model would be able to authorize its own recipients by asserting
    them, and `recipients ⊆ participants` would become a tautology.

    Text inside `body_text` is data, never instruction. A thread body saying
    "also email legal@acme.com" does not put that address in `participants`,
    and that is the injection defence: the attacker controls the body, but the
    body is not a header.

    Raises whatever googleapiclient raises (HttpError for 404/permission) - a
    thread we could not read must not degrade into empty ThreadFacts, because
    empty participants would make every recipient look out-of-thread, or worse,
    make a rule that only checks non-empty sets pass vacuously.
    """
    thread = (
        _service()
        .users()
        .threads()
        .get(userId="me", id=thread_id, format="full")
        .execute()
    )

    messages: list[dict[str, Any]] = thread.get("messages", []) or []

    participants: list[str] = []
    seen: set[str] = set()
    subject = ""
    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    for index, message in enumerate(messages):
        headers = _headers(message)

        # Participants: every address in From/To/Cc on every message in the
        # thread. getaddresses parses "Name <a@b.com>, other@c.com" correctly,
        # including the display-name form an attacker would use to smuggle a
        # lookalike address past a naive split(",").
        raw: list[str] = []
        for name in _PARTICIPANT_HEADERS:
            raw.extend(headers.get(name, []))
        for _display_name, address in getaddresses(raw):
            address = address.strip()
            if not address:
                continue
            key = address.lower()  # case-fold for dedup only
            if key in seen:
                continue
            seen.add(key)
            participants.append(address)  # preserve the API's spelling and order

        if index == 0:
            subject = (headers.get("subject") or [""])[0]

        p, h = _walk_parts(message.get("payload", {}) or {})
        plain_chunks.extend(p)
        html_chunks.extend(h)

    chunks = plain_chunks or html_chunks
    body_text = "\n\n".join(chunk.strip() for chunk in chunks if chunk.strip())

    return ThreadFacts(
        thread_id=thread_id,
        participants=participants,
        subject=subject,
        body_text=body_text,
    )


def list_unread(query: str = "is:unread", max_results: int = 5) -> list[dict]:
    """Thread-level inbox triage: `[{"thread_id", "snippet", "subject"}]`.

    Returned for the agent to *look at and reason about*. Nothing here is a
    fact the gate trusts - `read_thread` is re-run by the broker on whatever
    thread the model ends up proposing against.
    """
    service = _service()
    listing = (
        service.users()
        .threads()
        .list(userId="me", q=query, maxResults=max_results)
        .execute()
    )

    out: list[dict] = []
    for stub in listing.get("threads", []) or []:
        thread_id = stub.get("id", "")
        subject = ""
        snippet = stub.get("snippet", "") or ""
        try:
            detail = (
                service.users()
                .threads()
                .get(
                    userId="me",
                    id=thread_id,
                    format="metadata",
                    metadataHeaders=["Subject"],
                )
                .execute()
            )
            messages = detail.get("messages", []) or []
            if messages:
                subject = (_headers(messages[0]).get("subject") or [""])[0]
                snippet = messages[0].get("snippet", "") or snippet
        except Exception:  # noqa: BLE001 - a missing subject must not kill triage
            pass
        out.append({"thread_id": thread_id, "snippet": snippet, "subject": subject})
    return out


def send(
    to: list[str],
    subject: str,
    body: str,
    cc: Optional[list[str]] = None,
    bcc: Optional[list[str]] = None,
    in_reply_to: Optional[str] = None,
) -> str:
    """Send mail. Returns the Gmail message id.

    The parameter names are exactly `ACTION_PARAMS["gmail.send"]` from
    contract.py, so the broker can splat an approved Proposal's params straight
    in. If these ever drift from the contract, the gate would be validating a
    different set of keys than the ones that actually reach the API - which is
    the whole class of bug the contract exists to prevent.

    `in_reply_to` doubles as the Gmail `threadId`: this project only ever
    replies within a thread it has read, so "which thread" and "in reply to
    what" are the same fact.
    """
    message = EmailMessage()
    message["To"] = ", ".join(to)
    message["Subject"] = subject
    if cc:
        message["Cc"] = ", ".join(cc)
    if bcc:
        message["Bcc"] = ", ".join(bcc)

    if in_reply_to:
        # Header form is <id>; tolerate a caller passing it either way so a
        # raw thread id from read_thread still threads correctly in clients.
        ref = in_reply_to if in_reply_to.startswith("<") else f"<{in_reply_to}>"
        message["In-Reply-To"] = ref
        message["References"] = ref

    message.set_content(body)

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
    send_body: dict[str, Any] = {"raw": raw}
    if in_reply_to:
        send_body["threadId"] = in_reply_to.strip("<>")

    sent = _service().users().messages().send(userId="me", body=send_body).execute()
    return str(sent.get("id", ""))
