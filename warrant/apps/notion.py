"""
apps/notion.py
──────────────
The Notion client. Plain `requests` against the REST API - no SDK, because the
official client adds a dependency and an exception hierarchy for three calls we
can write in full view.

Only the broker imports this module.

`retrieve_page` is here for post-action verification: after the broker creates
a page it re-reads it through an independent call, so "the page exists" is
established by a GET rather than by the fact that a POST returned 200. Provenance
that trusts the write path to describe itself proves nothing.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

API_BASE = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"  # pinned: Notion breaks payload shapes between versions
TIMEOUT = 30


class NotionError(RuntimeError):
    """Any non-2xx from Notion, carrying enough to act on.

    `status` and `body` are kept as attributes rather than only formatted into
    the message so callers (and the journal) can branch on the status without
    parsing English.
    """

    def __init__(self, status: int, body: str, hint: str = "") -> None:
        self.status = status
        self.body = body
        self.hint = hint
        message = f"Notion API returned {status}: {body}"
        if hint:
            message = f"{message}\n→ {hint}"
        super().__init__(message)


def _headers() -> dict[str, str]:
    """Auth headers. The token import is lazy so importing this module never
    requires NOTION_API_KEY to be set."""
    from warrant.auth import notion_token

    return {
        "Authorization": f"Bearer {notion_token()}",
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json",
    }


def _hint_for(status: int, body: str, path: str) -> str:
    """Turn a Notion status into the thing the user has to go do.

    Notion's 404 is the one that wastes the most time: it does not mean the
    page is missing, it usually means the integration was never invited to it.
    The API cannot tell those apart, so the message must name both.
    """
    lowered = body.lower()
    if status == 401:
        return "NOTION_API_KEY is missing or invalid - check the integration's secret."
    if status == 404:
        return (
            "Notion returns 404 both for a page that does not exist and for one "
            "your integration cannot see. If the page exists, open it in Notion "
            "and share the page with your integration "
            "(••• → Connections → add your integration), then retry."
        )
    if status == 403:
        return (
            "The integration lacks the capability for this call - check its "
            "read/insert content capabilities in the Notion integration settings."
        )
    if status == 400 and "validation" in lowered:
        return f"Notion rejected the request body sent to {path}."
    if status == 429:
        return "Rate limited by Notion - retry after the Retry-After interval."
    return ""


def _request(method: str, path: str, payload: Optional[dict] = None) -> dict[str, Any]:
    """One HTTP call, raising NotionError on anything that is not 2xx."""
    url = f"{API_BASE}{path}"
    response = requests.request(
        method, url, headers=_headers(), json=payload, timeout=TIMEOUT
    )
    if not 200 <= response.status_code < 300:
        raise NotionError(
            response.status_code, response.text, _hint_for(response.status_code, response.text, path)
        )
    try:
        return response.json()
    except ValueError as exc:
        raise NotionError(
            response.status_code, response.text, "Notion returned a non-JSON body."
        ) from exc


def _paragraph_blocks(body_md: str) -> list[dict[str, Any]]:
    """Split text into paragraph blocks on blank lines.

    Deliberately not a markdown parser. The body of a page created by an agent
    is model-authored text, and interpreting it as markup would let the model
    choose block types - a small privilege, but one nobody asked to grant. Plain
    paragraphs mean the content is visibly content.
    """
    blocks: list[dict[str, Any]] = []
    for chunk in body_md.split("\n\n"):
        text = chunk.strip()
        if not text:
            continue
        # Notion caps a single rich_text item at 2000 characters.
        for start in range(0, len(text), 2000):
            piece = text[start : start + 2000]
            blocks.append(
                {
                    "object": "block",
                    "type": "paragraph",
                    "paragraph": {
                        "rich_text": [{"type": "text", "text": {"content": piece}}]
                    },
                }
            )
    return blocks


def _page_payload(parent: dict[str, str], title: str, body_md: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "parent": parent,
        "properties": {
            "title": {"title": [{"type": "text", "text": {"content": title}}]}
        },
    }
    children = _paragraph_blocks(body_md)
    if children:
        payload["children"] = children
    return payload


def _looks_like_database_parent(body: str) -> bool:
    """Does this 400 mean 'that id is a database, not a page'?

    Notion phrases it several ways across versions, so match on the ideas
    rather than on one sentence.
    """
    lowered = body.lower()
    if "database_id" in lowered:
        return True
    return "parent" in lowered and "database" in lowered


def create_page(parent_id: str, title: str, body_md: str = "") -> str:
    """Create a page under `parent_id`. Returns the created page id.

    Parameter names match `ACTION_PARAMS["notion.create_page"]` exactly.

    The parent can be either a page or a database and the caller does not
    reliably know which - a Notion URL looks identical for both. Rather than
    spend a round trip probing on the happy path, this tries `page_id` first
    (the common case for a scratch parent) and retries as `database_id` only
    when Notion's 400 says that is the problem. Any other 400 is a real error
    and propagates unchanged instead of being retried into a second confusing
    failure.

    A database parent whose title property is not literally named "title" will
    still be rejected by Notion; that is a schema mismatch the caller has to
    fix, and the NotionError body names the offending property.
    """
    try:
        created = _request(
            "POST", "/pages", _page_payload({"page_id": parent_id}, title, body_md)
        )
    except NotionError as exc:
        if exc.status == 400 and _looks_like_database_parent(exc.body):
            created = _request(
                "POST",
                "/pages",
                _page_payload({"database_id": parent_id}, title, body_md),
            )
        else:
            raise
    return str(created.get("id", ""))


def retrieve_page(page_id: str) -> dict:
    """GET /pages/{id}. Raises NotionError if the page is not retrievable.

    Used for independent post-action verification, which only means anything if
    a missing page is loud. There is no "return None if absent" variant on
    purpose: a falsy return is the kind of thing a caller forgets to check, and
    a verification step that can be silently skipped is not a verification step.
    """
    return _request("GET", f"/pages/{page_id}")
