"""
apps/linear.py
────────────────
The Linear client. Plain `requests` against Linear's GraphQL endpoint - no
SDK, and no GraphQL client library either: two mutations do not need one.

Only the broker imports this module.

**Liveness: fake-only.** No workspace, no API key. Written against the
documented mutations, never run.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

API_URL = "https://api.linear.app/graphql"
TIMEOUT = 30

_CREATE_ISSUE = """
mutation($teamId: String!, $title: String!, $description: String, $priority: Int) {
  issueCreate(input: {teamId: $teamId, title: $title, description: $description, priority: $priority}) {
    success
    issue { id }
  }
}
"""

_UPDATE_ISSUE = """
mutation($issueId: String!, $title: String, $description: String, $stateId: String) {
  issueUpdate(id: $issueId, input: {title: $title, description: $description, stateId: $stateId}) {
    success
    issue { id }
  }
}
"""


class LinearError(RuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(f"Linear API error: {message}")


def _call(query: str, variables: dict[str, Any]) -> dict[str, Any]:
    from warrant.auth import linear_api_key

    response = requests.post(
        API_URL,
        headers={"Authorization": linear_api_key(), "Content-Type": "application/json"},
        json={"query": query, "variables": variables},
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    body = response.json()
    if body.get("errors"):
        raise LinearError("; ".join(str(e.get("message", e)) for e in body["errors"]))
    return body.get("data", {})


def create_issue(team_id: str, title: str, description: str = "", priority: Optional[int] = None) -> str:
    data = _call(
        _CREATE_ISSUE,
        {"teamId": team_id, "title": title, "description": description, "priority": priority},
    )
    result = data.get("issueCreate", {})
    if not result.get("success"):
        raise LinearError(f"issueCreate did not report success: {data}")
    return str(result.get("issue", {}).get("id", ""))


def update_issue(
    issue_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    state_id: Optional[str] = None,
) -> str:
    data = _call(
        _UPDATE_ISSUE,
        {"issueId": issue_id, "title": title, "description": description, "stateId": state_id},
    )
    result = data.get("issueUpdate", {})
    if not result.get("success"):
        raise LinearError(f"issueUpdate did not report success: {data}")
    return str(result.get("issue", {}).get("id", issue_id))
