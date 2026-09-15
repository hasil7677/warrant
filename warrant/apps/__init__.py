"""
warrant.apps
────────────
Ten real clients: Gmail, Google Calendar, Notion - the three with live
credentials and a smoke artifact behind them - plus Slack, GitHub, Linear,
Stripe, Twilio, Google Drive and Google Sheets, written against each
provider's documented REST API and exercised through the gate against their
fakes in `warrant/fakes.py`, with no account connected. `warrant/registry.py`
is the table naming which is which.

One rule governs this package: **only the broker may import it.** The agent
side of the system never gets a handle to anything in here, which is the
mechanical reason it holds no credentials - not a convention, an import graph.

Nothing is re-exported at package level, and nothing is imported here eagerly.
`import warrant.apps` must never touch the network, never read a token file and
never raise AuthError. Each submodule imports `warrant.auth` lazily, inside the
function that needs a credential, so that merely loading the code - as tests,
linters and the demo's import of `fakes` all do - costs nothing and asks
nothing of the user's machine.
"""

from __future__ import annotations

__all__: list[str] = []
