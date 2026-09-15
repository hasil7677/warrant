"""
auth.py
───────
The credential boundary. This module, and the broker that calls it, are the
only places a token exists.

Two deliberate choices worth stating, because both are the kind of thing a
reviewer should be able to check rather than take on faith:

  • **User-consent OAuth, not a service account.** The agent acts as one
    specific human on their own mailbox. A service account with domain-wide
    delegation would be a standing grant over every mailbox in a workspace -
    a far larger blast radius than this demo needs, and one that cannot be
    revoked by the person actually affected.
  • **Least privilege, split read from write.** `gmail.readonly` and
    `gmail.send` are requested separately rather than taking `gmail.modify`,
    which would also let the agent delete mail. Nothing in this project
    deletes anything, so nothing in this project asks for the ability to.

The model never calls anything here. `get_google_creds()` is imported by the
app clients, which are importable only from the broker - and there is a test
that fails if any other module imports them.

Setup (once):
    1. console.cloud.google.com -> new project -> enable Gmail API + Calendar API
    2. OAuth consent screen -> External -> add yourself under "Test users"
    3. Credentials -> Create -> OAuth client ID -> Desktop app -> download JSON
    4. Save it as client_secret.json in this directory
    5. python -m warrant.auth
"""

from __future__ import annotations

import os
from pathlib import Path

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
]

CLIENT_SECRET_FILE = Path(os.getenv("WARRANT_CLIENT_SECRET", "client_secret.json"))
TOKEN_FILE = Path(os.getenv("WARRANT_TOKEN_FILE", "token.json"))

ENV_FILE = Path(os.getenv("WARRANT_ENV_FILE", ".env"))


def load_env(path: Path | None = None) -> dict[str, str]:
    """Read KEY=value lines from .env into the process environment.

    Hand-rolled rather than taking a dependency on python-dotenv: this is ten
    lines, and one fewer thing to install on a machine that is about to record
    a demo. Values already present in the real environment WIN - a shell
    export is a more deliberate act than a file someone edited last week, and
    silently overriding it is how you debug the wrong credential for an hour.

    Secrets live here and nowhere else. `.env` is gitignored; if you are
    reading this in a clone, the file is absent by design.
    """
    path = Path(path or ENV_FILE)
    loaded: dict[str, str] = {}
    if not path.exists():
        return loaded
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


# Load once on import so every entry point - auth, smoke, demo, the agent -
# sees the same credentials without each one remembering to ask.
load_env()


class AuthError(RuntimeError):
    """Credentials are missing or unusable. The message says what to fix.

    Raised rather than returning None: a caller that gets None tends to carry
    on and fail somewhere confusing, and a credential problem should stop the
    run at the point it is discoverable.
    """


def get_google_creds():
    """Return usable Google credentials, refreshing or minting them as needed.

    Order: cached token -> silent refresh -> browser consent. The browser step
    is interactive by necessity, so it only happens when there is no other way.
    """
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as exc:  # pragma: no cover - import guard
        raise AuthError(
            "Google client libraries are missing. Run:\n"
            "  pip install google-auth google-auth-oauthlib google-api-python-client"
        ) from exc

    creds = None
    if TOKEN_FILE.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
        except (ValueError, OSError):
            # A corrupt or scope-mismatched token is not worth guessing about -
            # drop it and re-consent rather than half-using it.
            creds = None

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")
            return creds
        except Exception:
            creds = None  # fall through to a fresh consent

    if not CLIENT_SECRET_FILE.exists():
        raise AuthError(
            f"No OAuth client at {CLIENT_SECRET_FILE.resolve()}.\n"
            "  1. console.cloud.google.com -> enable the Gmail API and the Calendar API\n"
            "  2. OAuth consent screen -> External -> add your own address under 'Test users'\n"
            "  3. Credentials -> Create credentials -> OAuth client ID -> Desktop app\n"
            f"  4. Download the JSON and save it as {CLIENT_SECRET_FILE}"
        )

    flow = InstalledAppFlow.from_client_secrets_file(str(CLIENT_SECRET_FILE), SCOPES)
    creds = flow.run_local_server(port=0)
    TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")
    return creds


def notion_token() -> str:
    """The Notion integration token, from the environment only.

    Never read from a file the package could write, and never accepted as a
    function argument - a credential that can be passed in is a credential the
    model can supply.
    """
    token = os.getenv("NOTION_API_KEY", "").strip()
    if not token:
        raise AuthError(
            "NOTION_API_KEY is not set.\n"
            "  1. notion.so/my-integrations -> New integration -> copy the Internal Integration Secret\n"
            "  2. Open the target Notion page -> ... -> Connections -> add your integration\n"
            "  3. set NOTION_API_KEY=<secret>   (PowerShell: $env:NOTION_API_KEY='<secret>')"
        )
    return token


# ── the seven fake-only apps ─────────────────────────────────────────────────
# None of these have ever been called with real credentials - see
# `warrant.registry` for the liveness table. The functions exist anyway,
# because the honest boundary is "no account was ever connected", not "the code
# to connect one does not exist". Each raises AuthError with the same shape as
# notion_token: which env var, where to get the value, one line to set it.


def _env_token(var: str, hint: str) -> str:
    """Shared shape for a single-env-var credential. Not exported - every
    caller below is a named function, because a name in this file's exports is
    what makes `grep AuthError` a way to enumerate every app that needs setup,
    not a generic helper nobody can find by app name."""
    value = os.getenv(var, "").strip()
    if not value:
        raise AuthError(f"{var} is not set.\n{hint}")
    return value


def slack_token() -> str:
    return _env_token(
        "SLACK_BOT_TOKEN",
        "  1. api.slack.com/apps -> your app -> OAuth & Permissions -> Bot User OAuth Token\n"
        "  2. set SLACK_BOT_TOKEN=xoxb-...   (PowerShell: $env:SLACK_BOT_TOKEN='xoxb-...')",
    )


def github_token() -> str:
    return _env_token(
        "GITHUB_TOKEN",
        "  1. github.com/settings/personal-access-tokens -> Fine-grained token,\n"
        "     scoped to the one repository this agent may touch\n"
        "  2. set GITHUB_TOKEN=github_pat_...",
    )


def linear_api_key() -> str:
    return _env_token(
        "LINEAR_API_KEY",
        "  1. linear.app -> Settings -> API -> Personal API keys -> Create key\n"
        "  2. set LINEAR_API_KEY=lin_api_...",
    )


def stripe_api_key() -> str:
    return _env_token(
        "STRIPE_API_KEY",
        "  1. dashboard.stripe.com/apikeys -> Secret key\n"
        "  2. set STRIPE_API_KEY=sk_...\n"
        "  A key that moves real money deserves more caution than an env var -\n"
        "  this project never wired one up, live or test-mode, for exactly that reason.",
    )


def twilio_credentials() -> tuple[str, str]:
    """Account SID and auth token - Twilio's REST API takes both, as HTTP Basic
    auth, so there is no single-token variant to fall back to."""
    sid = _env_token(
        "TWILIO_ACCOUNT_SID",
        "  1. console.twilio.com -> Account Info -> Account SID\n"
        "  2. set TWILIO_ACCOUNT_SID=AC...",
    )
    token = _env_token(
        "TWILIO_AUTH_TOKEN",
        "  1. console.twilio.com -> Account Info -> Auth Token\n"
        "  2. set TWILIO_AUTH_TOKEN=<token>",
    )
    return sid, token


def google_drive_sheets_creds():
    """Drive and Sheets would reuse `get_google_creds()` - same OAuth user, same
    cached token.json - except the cached token only carries the gmail and
    calendar scopes this project has actually run against. Requesting drive.file
    or spreadsheets scopes would force a fresh consent and invalidate that
    token, which would break the one live path this repo has evidence for. So
    this raises rather than silently widening the scope list nobody asked for.
    """
    raise AuthError(
        "Drive and Sheets need drive.file / spreadsheets scopes that token.json does "
        "not carry. Re-running `python -m warrant.auth` after adding those scopes to "
        "warrant/auth.py's SCOPES list would fetch a token that has them - deliberately "
        "not done automatically, because that is a live re-consent this project chose "
        "not to force on the one working credential it has."
    )


def anthropic_key() -> str:
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not key:
        raise AuthError("ANTHROPIC_API_KEY is not set.")
    return key


def main() -> int:
    print("\nwarrant - credential setup")
    print("-" * 52)
    try:
        creds = get_google_creds()
        print(f"  google   OK   token cached at {TOKEN_FILE}")
        print(f"           scopes: {len(SCOPES)} (gmail.readonly, gmail.send, calendar.events)")
        print(f"           valid={creds.valid}")
    except AuthError as exc:
        print(f"  google   FAIL\n{exc}")
        return 1

    for label, fn in (("notion", notion_token), ("anthropic", anthropic_key)):
        try:
            fn()
            print(f"  {label:<8} OK   key present in environment")
        except AuthError as exc:
            print(f"  {label:<8} FAIL {str(exc).splitlines()[0]}")

    print("\nNext: python scripts/smoke.py\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
