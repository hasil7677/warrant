"""
warrant - an agent proposes, a declarative policy authorizes, and the gate
holds the credentials so the model never does.

Loading `.env` happens here, at package import, rather than inside `auth.py`.
It used to live in auth, which meant any entry point that did not import auth
never saw the file: `scripts/smoke.py --skip-google` skipped the auth import
and then reported WARRANT_SMOKE_PARENT as unset while it sat plainly in .env.
Credential loading must not depend on which branch of a script runs.
"""

from warrant.auth import load_env as _load_env

_load_env()
