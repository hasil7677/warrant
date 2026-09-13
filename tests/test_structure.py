"""
test_structure.py
-----------------
Tests about the SHAPE of the package rather than its behaviour.

Everything asserted here is a claim the README makes in prose - "the model never
holds credentials", "only the broker can reach an app", "there is no override
flag", "a fresh clone refuses everything". Prose drifts. A structural test is the
same sentence written so that it fails when it stops being true.

These read the source with `pathlib` and `ast` rather than importing and poking
at objects, because the properties are about what the code *can* reach, not what
it happened to do on one run. An import that only fires inside a rarely-taken
branch is still an import, and `ast` sees it.

Ported from finLM's `test_mandate_is_never_written_by_this_package` (grep the
package for a forbidden capability) and `test_tool_contract.py` (does what the
project says it exposes match what it actually exposes).
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import warrant
from warrant import contract as contract_mod
from warrant.broker import Broker

PKG = Path(warrant.__file__).parent
REPO_ROOT = PKG.parent

SOURCES = sorted(PKG.rglob("*.py"))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(PKG).as_posix()


def test_the_package_has_sources_to_scan():
    """Guard: every test below is vacuous if the glob finds nothing."""
    assert len(SOURCES) >= 5, f"only found {[_rel(p) for p in SOURCES]}"
    assert "broker.py" in {_rel(p) for p in SOURCES}


# -- 1. the credential boundary ------------------------------------------------


def _imports_apps(tree: ast.Module) -> bool:
    """True if this module can reach `warrant.apps` by any import spelling."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "warrant.apps" or alias.name.startswith("warrant.apps."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "warrant.apps" or module.startswith("warrant.apps."):
                return True
            # `from .apps import gmail` / `from ..apps.gmail import send`
            if node.level and (module == "apps" or module.startswith("apps.")):
                return True
            # `from . import apps`
            if node.level and not module:
                if any(alias.name == "apps" for alias in node.names):
                    return True
    return False


def test_only_the_broker_imports_app_clients():
    """THE structural test: the credential boundary is checked, not documented.

    `warrant.apps` is where the real Gmail, Calendar and Notion clients live, and
    `warrant.auth` is the only place a token is read. If any module other than
    broker.py can import an app client, then "the model never holds credentials"
    is a convention someone is maintaining by hand rather than a property of the
    import graph - and conventions are one refactor from being false.
    """
    importers = sorted(_rel(p) for p in SOURCES if _imports_apps(_tree(p)))
    assert importers == ["broker.py"], (
        f"modules importing warrant.apps: {importers}; only broker.py may."
    )


def test_fakes_reach_no_real_client():
    """The fakes are imported by tests, demos and eval harnesses, on machines with
    no credentials at all. An import of a real client there would make importing
    the test suite an auth event."""
    fakes = PKG / "fakes.py"
    assert not _imports_apps(_tree(fakes))


# -- 2. where credentials may be read ------------------------------------------

SECRET_NAMES = ("NOTION_API_KEY", "ANTHROPIC_API_KEY", "client_secret", "token.json")

# A credential is only *read* through one of these. The names appear in a couple
# of error-hint strings elsewhere ("NOTION_API_KEY is missing or invalid"), which
# is documentation, not access - so the test asks for the name AND an access verb
# on the same line before calling it a violation.
READ_VERBS = (
    "getenv",
    "environ",
    "open(",
    "read_text",
    "read_bytes",
    "load_dotenv",
    "from_client_secrets_file",
    "from_authorized_user_file",
)


def test_only_auth_reads_credentials():
    """Every secret in this system enters through auth.py or not at all.

    One module reading a token is a boundary. Two is a habit, and a habit has no
    edge you can point at in a review."""
    offenders: list[str] = []
    for path in SOURCES:
        if _rel(path) == "auth.py":
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(name in line for name in SECRET_NAMES) and any(
                verb in line for verb in READ_VERBS
            ):
                offenders.append(f"{_rel(path)}:{lineno}: {line.strip()}")
    assert not offenders, f"credentials are read outside auth.py: {offenders}"


# -- 3. what execute() is allowed to take --------------------------------------


def test_broker_execute_takes_only_a_proposal():
    """A caller who could pass `facts` could fabricate the very thing the gate
    checks proposals against.

    `recipients is a subset of participants` is only a safety property because
    the two sides come from different places: the proposal from the model, the
    participants from an API read the broker performed itself. Add a `facts=`
    parameter and it becomes a statement about two things the model wrote, which
    is always true and therefore worth nothing."""
    params = list(inspect.signature(Broker.execute).parameters)
    assert params == ["self", "proposal"], (
        f"Broker.execute signature is {params}; it must take one Proposal and "
        "nothing else - no facts, no policy, no override."
    )


# -- 4. no bypass parameter anywhere -------------------------------------------

FORBIDDEN_PARAMS = {
    "confirmed",
    "force",
    "override",
    "bypass",
    "skip_checks",
    "skip_policy",
    "unsafe",
    "ignore_limits",
    "admin",
    "allow_anyway",
}


def _arg_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    a = fn.args
    names = {arg.arg for arg in a.posonlyargs + a.args + a.kwonlyargs}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


def test_no_module_exposes_a_bypass_parameter():
    """The project's thesis, enforced: nothing in this package lets a caller
    vouch for itself.

    The caller of every function here is the layer being governed, so any
    argument it can set to soften the answer is an argument that makes the answer
    meaningless. This fails the moment someone adds a convenience flag."""
    offenders: list[str] = []
    for path in SOURCES:
        for node in ast.walk(_tree(path)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue
            bad = sorted(_arg_names(node) & FORBIDDEN_PARAMS)
            if bad:
                offenders.append(f"{_rel(path)}:{node.name}{bad}")
    assert not offenders, f"bypass-shaped parameters found: {offenders}"


# -- 5. the policy is the user's, and the repo does not ship one ---------------


def test_policy_file_is_gitignored():
    """A fresh clone must refuse every action until a human writes a policy.

    Shipping a default policy.yaml would be shipping consent nobody gave: the
    clone would arrive already authorized to email people, and whatever that file
    said would be a decision the user never made."""
    gitignore = REPO_ROOT / ".gitignore"
    assert gitignore.exists(), f"no .gitignore at {REPO_ROOT}"
    entries = {
        line.strip()
        for line in gitignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert "policy.yaml" in entries, (
        f".gitignore does not exclude policy.yaml (entries: {sorted(entries)})"
    )


# -- 6/7. the contract, the dispatch and the rules stay in step ----------------


def _constant_names_for(action: str) -> set[str]:
    """The UPPER_CASE names in contract.py that hold this action string."""
    return {
        name
        for name, value in vars(contract_mod).items()
        if isinstance(value, str) and value == action and name.isupper()
    }


def _referenced_tokens(path: Path) -> set[str]:
    """Every identifier and string literal a module mentions."""
    tokens: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Name):
            tokens.add(node.id)
        elif isinstance(node, ast.Attribute):
            tokens.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            tokens.add(node.value)
    return tokens


@pytest.mark.parametrize("action", contract_mod.ACTIONS)
def test_every_contract_action_has_a_broker_dispatch(action):
    """Catches a tool added to the contract with no way to perform it.

    `_perform` raises on an unknown tool rather than returning quietly, so the
    failure mode this guards against is loud at runtime - but only if someone
    runs that path. Here it is caught at the contract."""
    tokens = _referenced_tokens(PKG / "broker.py")
    expected = {action} | _constant_names_for(action)
    assert tokens & expected, (
        f"broker.py never mentions {action!r} (or any of {sorted(expected)}), so "
        "the contract advertises a tool the broker cannot dispatch."
    )


@pytest.mark.parametrize("action", contract_mod.ACTIONS)
def test_every_contract_action_has_a_policy_rule_covering_it(action):
    """Catches a new tool arriving silently ungoverned.

    A tool the policy module never names is a tool no rule was written against,
    and the gate would wave it through on the strength of rules that all decline
    to apply."""
    tokens = _referenced_tokens(PKG / "policy.py")
    expected = {action} | _constant_names_for(action)
    assert tokens & expected, (
        f"policy.py never mentions {action!r} (or any of {sorted(expected)}), so "
        "that action is in the contract but governed by nothing."
    )


# -- 8. the fakes have to be the real clients' shape ---------------------------

FAKE_REAL_PAIRS = [
    ("FakeGmail.send", "warrant.apps.gmail", "send", "FakeGmail", "send"),
    (
        "FakeCalendar.create_event",
        "warrant.apps.gcal",
        "create_event",
        "FakeCalendar",
        "create_event",
    ),
    (
        "FakeNotion.create_page",
        "warrant.apps.notion",
        "create_page",
        "FakeNotion",
        "create_page",
    ),
]


@pytest.mark.parametrize(
    "label,real_module,real_fn,fake_cls,fake_fn", FAKE_REAL_PAIRS, ids=[p[0] for p in FAKE_REAL_PAIRS]
)
def test_fakes_match_real_client_signatures(label, real_module, real_fn, fake_cls, fake_fn):
    """A fake that drifts from the real client makes every test that uses it a
    test of nothing.

    The broker splats an approved Proposal's params into whichever client it
    holds, so a fake with a looser signature would let a params bug pass the whole
    suite and appear for the first time against the live API. `calendar_id` is
    excluded because it is broker-side plumbing, not a model-settable param."""
    import importlib

    real = getattr(importlib.import_module(real_module), real_fn)
    fake = getattr(getattr(importlib.import_module("warrant.fakes"), fake_cls), fake_fn)

    real_params = set(inspect.signature(real).parameters) - {"calendar_id"}
    fake_params = set(inspect.signature(fake).parameters) - {"self"}

    missing = sorted(real_params - fake_params)
    assert not missing, (
        f"{label} is missing parameter(s) the real {real_module}.{real_fn} takes: "
        f"{missing}. The fake must accept everything the real client does."
    )
