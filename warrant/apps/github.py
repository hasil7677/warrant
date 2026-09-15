"""
apps/github.py
────────────────
The GitHub client. Plain `requests` against the REST API v3 - no SDK.

Only the broker imports this module.

**Liveness: fake-only.** No fine-grained token was issued, because no
repository exists that this project is allowed to write to, and issuing a
token scoped to nothing would prove nothing either. Written against the
documented API, never run.

Four calls, because GitHub is the one app in the suite where `code` and
`identity` both show up: `merge_pull_request` changes what runs in production,
`add_collaborator` changes who can push to it.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
TIMEOUT = 30


class GitHubError(RuntimeError):
    def __init__(self, status: int, body: str, hint: str = "") -> None:
        self.status = status
        self.body = body
        message = f"GitHub API returned {status}: {body}"
        if hint:
            message = f"{message}\nFIX: {hint}"
        super().__init__(message)


def _headers() -> dict[str, str]:
    from warrant.auth import github_token

    return {
        "Authorization": f"Bearer {github_token()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }


def _hint_for(status: int, path: str) -> str:
    if status == 401:
        return "GITHUB_TOKEN is missing or invalid."
    if status == 403:
        return "The token lacks a required permission, or the repo is not in its fine-grained scope."
    if status == 404:
        return f"{path} was not found, or the token cannot see it - fine-grained tokens 404 on repos outside their scope rather than returning 403."
    if status == 422:
        return "GitHub rejected the request body - check for a duplicate branch name or an invalid field."
    return ""


def _request(method: str, path: str, payload: Optional[dict] = None) -> dict[str, Any]:
    response = requests.request(method, f"{API_BASE}{path}", headers=_headers(), json=payload, timeout=TIMEOUT)
    if not 200 <= response.status_code < 300:
        raise GitHubError(response.status_code, response.text, _hint_for(response.status_code, path))
    if not response.text:
        return {}
    return response.json()


def create_issue(repo: str, title: str, body: str = "", labels: Optional[list[str]] = None) -> str:
    """POST /repos/{repo}/issues. Returns the issue number as a string."""
    payload: dict[str, Any] = {"title": title, "body": body}
    if labels:
        payload["labels"] = list(labels)
    created = _request("POST", f"/repos/{repo}/issues", payload)
    return str(created.get("number", ""))


def create_pull_request(repo: str, title: str, head: str, base: str, body: str = "") -> str:
    """POST /repos/{repo}/pulls. Returns the PR number as a string."""
    created = _request(
        "POST", f"/repos/{repo}/pulls", {"title": title, "head": head, "base": base, "body": body}
    )
    return str(created.get("number", ""))


def merge_pull_request(
    repo: str, number: int, merge_method: Optional[str] = None, commit_title: Optional[str] = None
) -> str:
    """PUT /repos/{repo}/pulls/{number}/merge. Returns the merge commit sha."""
    payload: dict[str, Any] = {}
    if merge_method:
        payload["merge_method"] = merge_method
    if commit_title:
        payload["commit_title"] = commit_title
    result = _request("PUT", f"/repos/{repo}/pulls/{number}/merge", payload)
    return str(result.get("sha", ""))


def add_collaborator(repo: str, username: str, permission: Optional[str] = None) -> str:
    """PUT /repos/{repo}/collaborators/{username}. Grants repo access.

    Returns "invited" or "already-collaborator" rather than a GitHub id: the
    API returns 201 with an invitation object for a new collaborator and 204
    with an empty body for an existing one, and this project cares about
    which of those happened more than about the invitation's own id.
    """
    payload: dict[str, Any] = {}
    if permission:
        payload["permission"] = permission
    response = requests.put(
        f"{API_BASE}/repos/{repo}/collaborators/{username}", headers=_headers(), json=payload, timeout=TIMEOUT
    )
    if response.status_code == 204:
        return "already-collaborator"
    if response.status_code == 201:
        return "invited"
    raise GitHubError(response.status_code, response.text, _hint_for(response.status_code, "collaborators"))
