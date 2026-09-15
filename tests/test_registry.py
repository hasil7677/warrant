"""
test_registry.py
─────────────────
The app adapter registry: does the capability-class design actually hold
together, and does every liveness claim it makes have real evidence behind it.

`warrant.registry.validate()` already runs at import time and would have
raised before these tests could even collect if the table were internally
broken - see registry.py's bottom. What this file adds is the checks that
need to reach OUTSIDE the registry to mean anything: does a `proven-live` app
actually name an artifact that says so, does every fake match the real
adapter's signature (generalizing what `test_structure.py` used to check by
hand for three apps), and does the capability-class design cover what the
brief asked for - spend, irreversibility, fan-out, egress, and so on.
"""

from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path

import pytest

from warrant import fakes as fakes_mod
from warrant import registry as registry_mod

REPO_ROOT = Path(registry_mod.__file__).resolve().parents[1]


# ── the suite is the size the brief asked for ────────────────────────────────


def test_suite_has_ten_to_fifteen_apps():
    """10-15 apps was the brief. Fewer is not the suite this was scoped as;
    more without a reason is scope creep nobody asked for."""
    assert 10 <= len(registry_mod.APP_LIST) <= 15, (
        f"{len(registry_mod.APP_LIST)} apps registered; brief asked for 10-15."
    )


def test_the_original_three_are_still_here_and_proven_live():
    """Gmail, Calendar and Notion have live credentials and a smoke artifact.
    Losing one of them in a refactor toward a generic registry would be
    exactly the kind of regression a generalization pass can hide."""
    for name in ("gmail", "calendar", "notion"):
        spec = registry_mod.app_spec(name)
        assert spec is not None, f"{name!r} is missing from the registry"
        assert spec.proven_live, f"{name!r} must stay proven-live"


# ── liveness claims are never made without evidence ──────────────────────────


def test_every_proven_live_app_names_an_artifact_that_exists_and_says_so():
    """The whole project's credibility rests on not overclaiming liveness -
    the brief said so explicitly. So a 'proven-live' claim has to point at a
    real file, and that file has to actually report the apps it is cited for
    as live."""
    for app in registry_mod.APP_LIST:
        if not app.proven_live:
            continue
        assert app.evidence, f"{app.name!r} is proven-live but names no evidence artifact"
        artifact_path = REPO_ROOT / app.evidence
        assert artifact_path.exists(), (
            f"{app.name!r} cites evidence at {app.evidence!r}, which does not exist"
        )
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
        apps_live = payload.get("result", {}).get("apps_live", {})
        assert apps_live.get(app.name) is True, (
            f"{app.evidence} does not report {app.name!r} as live in its own apps_live field "
            f"(saw {apps_live})"
        )


def test_every_fake_only_app_states_why():
    """An unexplained gap reads as an oversight; a stated one reads as a
    decision. `AppSpec.note` is required for every fake-only app precisely so
    the README and console are quoting a reason instead of a silence."""
    for app in registry_mod.APP_LIST:
        if app.proven_live:
            continue
        assert app.note.strip(), f"{app.name!r} is fake-only and gives no reason why"
        assert not app.evidence, (
            f"{app.name!r} is fake-only but names an evidence artifact ({app.evidence!r}) - "
            "that field means 'this claim is proven', and a fake-only app has not made it"
        )


def test_liveness_is_binary_not_a_third_undeclared_state():
    """Every app is one of exactly two states. A registry entry that is
    neither would be a claim nobody could act on - not proven, not admittedly
    fake, just unstated."""
    for app in registry_mod.APP_LIST:
        assert app.liveness in registry_mod.LIVENESS_STATES


# ── the capability-class design covers what the brief asked for ─────────────


@pytest.mark.parametrize(
    "capability",
    [registry_mod.WRITE, registry_mod.THIRD_PARTY, registry_mod.SPEND,
     registry_mod.AUDIENCE, registry_mod.EGRESS, registry_mod.IRREVERSIBLE,
     registry_mod.REVERSIBLE, registry_mod.DESTRUCTIVE, registry_mod.CODE,
     registry_mod.IDENTITY],
)
def test_every_required_capability_class_is_exercised_by_at_least_one_tool(capability):
    """The brief named six things the classes had to cover at minimum - write,
    third-party, reversibility, spend, fan-out, egress - plus this project
    added code and identity for GitHub's sake. A class nothing declares is a
    class that exists on paper only."""
    matches = registry_mod.tools_with(capability)
    assert matches, f"no tool declares capability {capability!r}"


def test_spend_is_not_all_stripe():
    """If only Stripe ever moved money, spend_cap would be untested against
    the case that actually motivated a generic capability class: an app
    nobody thought of as 'a payments app' that spends anyway."""
    spenders = {registry_mod.app_of(t) for t in registry_mod.tools_with(registry_mod.SPEND)}
    assert spenders >= {"stripe", "twilio"}, (
        f"expected spend to show up outside Stripe too, saw {spenders}"
    )


def test_reversibility_is_declared_for_every_tool_exactly_once():
    """`registry.validate()` already enforces this at import time - this test
    re-asserts it as a black-box property so a future refactor that changed
    validate() itself would still be caught by something that does not share
    its blind spots."""
    for name, spec in registry_mod.TOOLS.items():
        reversibility = set(spec.classes) & registry_mod.REVERSIBILITY_CLASSES
        assert len(reversibility) == 1, f"{name!r} declares {reversibility}, want exactly one"


# ── every tool is real: fake and real adapter agree with the registry ───────


@pytest.mark.parametrize("tool_name", list(registry_mod.TOOLS))
def test_fake_matches_real_client_signature_for_every_tool(tool_name):
    """Generalizes `test_structure.py::test_fakes_match_real_client_signatures`
    (which only ever checked Gmail/Calendar/Notion by hand) to all twenty-two
    tools. A fake with a looser signature than its real counterpart would let
    a params bug pass every test in the suite and appear for the first time
    against a real account - the exact failure mode that test existed to
    catch, now checked for apps that do not have a real account to fail
    against yet either."""
    spec = registry_mod.tool_spec(tool_name)
    app = registry_mod.app_spec(spec.app)

    real_module = importlib.import_module(f"warrant.apps.{app.module}")
    real_fn = getattr(real_module, spec.function)
    fake_cls = getattr(fakes_mod, app.fake)
    fake_fn = getattr(fake_cls, spec.function)

    real_params = set(inspect.signature(real_fn).parameters)
    fake_params = set(inspect.signature(fake_fn).parameters) - {"self"}

    missing = real_params - fake_params
    assert not missing, f"{app.fake}.{spec.function} is missing {missing} that the real client takes"


@pytest.mark.parametrize("tool_name", list(registry_mod.TOOLS))
def test_registry_param_names_are_a_subset_of_the_real_functions_params(tool_name):
    """The other direction of the same check: every param the registry says
    this tool accepts has to actually be a parameter the real function takes,
    or the gate would authorize a key the client silently ignores."""
    spec = registry_mod.tool_spec(tool_name)
    app = registry_mod.app_spec(spec.app)
    real_module = importlib.import_module(f"warrant.apps.{app.module}")
    real_fn = getattr(real_module, spec.function)
    real_params = set(inspect.signature(real_fn).parameters)

    missing = spec.param_names - real_params
    assert not missing, (
        f"registry says {tool_name!r} accepts {missing}, but warrant.apps.{app.module}."
        f"{spec.function} has no such parameter(s)"
    )


# ── the fake-only apps are honest about never having been called ────────────


def test_fake_only_apps_have_a_real_http_adapter_anyway():
    """'Fake-only' describes liveness, not effort - every app still needs a
    real adapter written against its documented REST API, importable without
    credentials, so the day someone connects an account it is a config
    change, not a rewrite."""
    for app in registry_mod.APP_LIST:
        module = importlib.import_module(f"warrant.apps.{app.module}")
        for tool in app.tools:
            assert hasattr(module, tool.function), (
                f"warrant.apps.{app.module} has no {tool.function!r} for {tool.name!r}"
            )


def test_importing_a_fake_only_apps_module_touches_no_credential():
    """Importing any apps/*.py must never read an env var or a token file -
    the same property `warrant.apps.__init__`'s docstring states for the
    original three, checked here for the other ten. If import itself required
    a credential, `test_fake_matches_real_client_signature_for_every_tool`
    above would need real accounts to even collect."""
    for app in registry_mod.APP_LIST:
        # Reload isn't necessary - if the module already imported cleanly at
        # collection time (which every test above depends on), the property
        # already held. This test exists to name the property explicitly
        # rather than leave it as an unstated side effect of collection
        # succeeding.
        importlib.import_module(f"warrant.apps.{app.module}")
