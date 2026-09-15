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
from typing import Any

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
#
# These two tests used to grep broker.py and policy.py for each action's name
# or its UPPER_CASE constant - a token scan works when dispatch and coverage
# are `if proposal.tool == GMAIL_SEND:` blocks typed out per app. They stop
# working the moment dispatch and coverage become generic, which is the entire
# point of `warrant.registry`: a tool governed *because* it declares
# `recipient_kind="email"`, with no line of policy.py naming it, is the
# design working, not a hole in the test. So both tests were rewritten to
# check the properties the token scan was a proxy for, by exercising the real
# code path instead of grepping source:
#
#   - dispatch:  can the broker actually reach a callable for this tool, with
#                a client whose signature accepts every param the tool
#                declares? (proven the same way `test_fakes_match_real_
#                client_signatures` proves it for the original three, just
#                generalized to whichever app the registry names)
#   - coverage:  does *some* combination of rules a human could plausibly
#                enable actually refuse an unauthorized attempt at this tool?
#                (proven by running the real gate against every action with a
#                deliberately-unauthorized proposal, not by finding its name
#                in a source file)


def _placeholder_for(spec, param) -> Any:
    """One value for one required param, chosen to be plausible in shape and
    certain to be UNAUTHORIZED - an address nobody allowlisted, a destination
    nobody named. The coverage test below only needs "the gate has grounds to
    object"; it does not need a value realistic enough to reach a real API."""
    import warrant.registry as registry_mod

    if param.kind == "integer":
        scalar: Any = 1
    elif param.kind == "number":
        scalar = 1.0
    elif param.kind == "boolean":
        scalar = True
    elif param.name == spec.destination_param:
        scalar = "unapproved-destination"
    elif param.name in spec.recipient_params and spec.recipient_kind == registry_mod.PHONE:
        scalar = "+15550001111"
    elif param.name in spec.recipient_params:
        scalar = "nobody@unapproved.example"
    else:
        scalar = "x"
    return [scalar] if param.kind == "string_list" else scalar


@pytest.fixture
def registry_mod():
    import warrant.registry as m

    return m


@pytest.mark.parametrize("action", contract_mod.ACTIONS)
def test_every_contract_action_has_a_broker_dispatch(action, registry_mod):
    """Catches a tool added to the registry with no way to perform it.

    The broker dispatches generically: `Broker._perform` resolves
    `ToolSpec.app` to a client and calls `getattr(client, ToolSpec.function)`.
    So "can the broker dispatch this tool" is now the question "does the
    fake for this tool's app expose that function, with a signature that
    accepts every param the tool declares" - the exact check
    `test_fakes_match_real_client_signatures` already made for the original
    three, run here for all thirteen apps generically instead of by name.
    """
    import warrant.fakes as fakes_mod

    spec = registry_mod.tool_spec(action)
    assert spec is not None, f"{action!r} is in ACTIONS but registry.tool_spec found nothing"

    app_spec = registry_mod.app_spec(spec.app)
    assert app_spec is not None, f"{action!r} claims app {spec.app!r}, which is not in APP_LIST"

    fake_cls = getattr(fakes_mod, app_spec.fake, None)
    assert fake_cls is not None, f"warrant.fakes has no {app_spec.fake!r} for app {spec.app!r}"

    fn = getattr(fake_cls, spec.function, None)
    assert fn is not None, (
        f"{app_spec.fake}.{spec.function} does not exist, so the broker has nothing to call "
        f"for {action!r} even against a fake, let alone the real client."
    )
    fake_params = set(inspect.signature(fn).parameters) - {"self"}
    missing = spec.param_names - fake_params
    assert not missing, (
        f"{app_spec.fake}.{spec.function} is missing parameter(s) {missing} that {action!r} "
        "declares - the broker would splat them into a call the fake cannot accept."
    )


# A policy that authorizes NOTHING, built once from every allowlist-shaped
# rule this build implements, config left at its refuse-everything default.
# Not the shipped policy.yaml - a synthetic worst case, so this test does not
# quietly start passing because someone loosened the repo's real policy.
_NOTHING_AUTHORIZED_RULES = {
    "recipient_scope": {},
    "domain_allowlist": {"allowed_domains": ["nowhere.example"]},
    "no_distribution_lists": {"blocked_local_parts": ["all"]},
    "notion_parent_allowlist": {"allowed_parents": []},
    "destination_allowlist": {"allowed": {}},
    "irreversible_gate": {"allowed_tools": []},
}


@pytest.mark.parametrize("action", contract_mod.ACTIONS)
def test_every_contract_action_has_a_policy_rule_covering_it(action, registry_mod, tmp_path, monkeypatch):
    """Catches a new tool arriving silently ungoverned.

    Rather than grep policy.py for the tool's name - meaningless once rules
    reason about capability classes instead of app names - this builds the
    smallest proposal the tool's REQUIRED params allow, deliberately
    unauthorized (an address nobody allowlisted, a destination nobody named),
    and runs it through the real gate with every allowlist-shaped rule enabled
    at its refuse-everything default. A tool that sails through anyway is a
    tool no rule currently applies to - the exact hole this test existed to
    catch, just detected by running the gate instead of reading its source.
    """
    import yaml

    import warrant.policy as policy_mod
    from warrant.contract import Proposal

    spec = registry_mod.tool_spec(action)
    assert spec is not None

    params = {p.name: _placeholder_for(spec, p) for p in spec.params if p.required}
    proposal = Proposal(tool=action, params=params, thread_id="t-nonexistent")

    # `check()` takes a proposal, facts and a ledger - no override parameter,
    # by design (see policy.py's module docstring). So the "authorize
    # nothing" policy is written to an isolated tmp_path and pointed at via
    # the module globals, the same seam the adversarial suite and the console
    # both use to isolate the gate.
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        yaml.safe_dump({"version": 1, "rules": _NOTHING_AUTHORIZED_RULES}), encoding="utf-8"
    )
    monkeypatch.setattr(policy_mod, "POLICY_FILE", policy_file)
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])

    verdict = policy_mod.check(proposal, facts=None, ledger=None)

    assert not verdict.allowed, (
        f"{action!r} was ALLOWED against a policy that authorizes nothing "
        f"(reasons: {verdict.reasons}). No rule in {sorted(_NOTHING_AUTHORIZED_RULES)} "
        "applies to it - that tool is in the contract and governed by nothing."
    )
    assert verdict.rule_ids, (
        f"{action!r} was refused but named no rule_ids - a refusal has to trace back to a "
        "rule, or the journal cannot say what stopped it."
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
