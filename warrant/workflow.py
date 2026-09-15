"""
workflow.py
───────────
The workflow runner: a YAML file names a sequence of steps across multiple
apps, and every step goes through `Broker.execute` exactly as a single
proposal does. This is the "n8n workflow of sorts" the project asked for - a
declarative multi-step run, governed the same way as everything else here.

## The one property that makes this safe to add

`run_workflow` never talks to an app client. It never imports `warrant.apps`.
It holds a `Broker` it was handed and calls `broker.execute(proposal)` once
per step, in order - the exact same call the console, the demo and the CLI
already make one proposal at a time. A workflow file cannot grant a step
anything a lone proposal for that tool would not also get: the file changes
*when* a proposal is made and *what feeds its params*, never *whether the gate
allows it*. There is no separate "workflow mode" in the gate, because there is
no separate gate to have one - `warrant/policy.py` was not touched to build
this.

## Shape of a workflow file

    name: incident-response
    description: page on-call, then post a status update once it is open.
    on_step_refused: halt        # halt | continue  (default: halt)

    steps:
      - id: page
        tool: twilio.send_sms
        params:
          to: ["+15550001111"]
          from_number: "+15550009999"
          body: "API error rate above threshold - paging on-call."

      - id: notify
        tool: slack.post_message
        params:
          channel: "C0ALLOWED"
          # ${steps.<id>.<field>} pulls a value out of an earlier step's
          # result - the external id an app handed back, mostly, so a later
          # step can reference what an earlier one created. This is data
          # plumbing between steps, not a decision the gate makes: the
          # substituted value still goes through the SAME policy check as
          # anything else in that field would.
          text: "Paged on-call: ${steps.page.external_id}"
        on_refused: continue     # this step's own override of the default

## Halt or continue - never silently continue

A refused step's default is `halt`: the run stops, and every step after it
never becomes a proposal at all - not refused, simply never attempted. That
default exists because a workflow that kept going past a refusal by default
would turn "the gate said no" into "the gate said no, and then something else
ran anyway on the assumption it was fine", which is the exact silent-continue
failure `Broker.execute` was built to make structurally impossible for a
single action. `continue` exists for the cases where a workflow's author has
actually decided that a refusal on this specific step is recoverable - and
that decision lives in the YAML, in plain sight, not in a default nobody
chose.

Branching (`goto:<step_id>`) was cut deliberately. A runner that can jump
between steps on a condition is most of the way to a state machine, and this
project's job is proving that a multi-step run stays governed by the same
Broker/policy/evidence layer as a lone proposal - not building a workflow
engine. `halt` and `continue` say everything that invariant needs said.

## The evidence trail

Every step already writes its own row to `journal.db` through
`Broker.execute` - allowed or refused, exactly as a lone proposal would.
`run_workflow_file` additionally writes ONE stamped artifact
(`warrant.provenance.write_artifact(kind="workflow", ...)`) naming every step,
its verdict, and the journal row id that decision produced - the single
signed evidence trail for the run the brief asked for, sitting on top of the
per-step rows rather than replacing them. Reading the artifact tells you what
the run did; reading the journal rows it names tells you, independently, that
the gate is what decided each one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from warrant import policy as policy_mod
from warrant.broker import Broker
from warrant.contract import STATUS_EXECUTED, Proposal
from warrant.provenance import write_artifact

ON_REFUSED_HALT = "halt"
ON_REFUSED_CONTINUE = "continue"

# ${steps.<id>.<field>} - deliberately just one substitution form, not an
# expression language. policy.yaml's docstring explains why this package
# keeps declining to build one: a format that can compute is a format that
# can be talked into computing something else. This substitutes a field of an
# earlier step's *result* (what the app returned, what the gate decided) into
# a later step's params; it cannot reach into params, cannot branch, cannot
# do arithmetic. What it substitutes still goes through policy.check() like
# any other value in that field.
_TEMPLATE_RE = re.compile(r"\$\{steps\.([A-Za-z0-9_\-]+)\.([A-Za-z0-9_]+)\}")


class WorkflowError(ValueError):
    """The workflow file itself is malformed - a bad step id, an unknown
    on_refused target, a step with no tool. Distinct from a step being
    refused: that is the gate working. This is the YAML being wrong."""


@dataclass
class StepResult:
    """One step's outcome - the same shape `Broker.execute` returns, plus the
    step id so a workflow-level report can name which step a verdict belongs
    to."""

    step_id: str
    tool: str
    status: str
    allowed: bool
    external_id: Optional[str] = None
    rule_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    journal_id: Optional[int] = None
    error: Optional[str] = None
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "tool": self.tool,
            "status": self.status,
            "allowed": self.allowed,
            "external_id": self.external_id,
            "rule_ids": self.rule_ids,
            "reasons": self.reasons,
            "journal_id": self.journal_id,
            "error": self.error,
            "params": self.params,
        }


@dataclass
class WorkflowResult:
    """The whole run: every step attempted, in order, and where it stopped."""

    name: str
    steps: list[StepResult] = field(default_factory=list)
    halted_at: Optional[str] = None
    skipped: list[str] = field(default_factory=list)

    @property
    def completed(self) -> bool:
        """True if every step in the file was attempted - halting on a
        refusal makes this False, which is the point: a workflow that hit a
        wall is a different outcome from one that ran end to end, and a
        caller checking only "did it crash" would conflate them."""
        return self.halted_at is None

    @property
    def all_allowed(self) -> bool:
        return bool(self.steps) and all(s.allowed for s in self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "completed": self.completed,
            "halted_at": self.halted_at,
            "all_allowed": self.all_allowed,
            "steps": [s.to_dict() for s in self.steps],
            "skipped": self.skipped,
        }


def load_workflow(path: Path) -> dict[str, Any]:
    """Read a workflow YAML file. Raises WorkflowError on anything unusable -
    a workflow file is authored by a human the same way policy.yaml is, and a
    malformed one should fail loudly rather than run a truncated DAG."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise WorkflowError(f"cannot read workflow file {path}: {exc}") from exc
    try:
        spec = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise WorkflowError(f"workflow file {path} is not valid YAML: {exc}") from exc
    if not isinstance(spec, dict):
        raise WorkflowError(f"workflow file {path} must be a YAML mapping, got {type(spec).__name__}")
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps:
        raise WorkflowError(f"workflow file {path} declares no steps")
    seen_ids: set[str] = set()
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise WorkflowError(f"step #{i} in {path} is not a mapping")
        sid = step.get("id")
        if not sid or not isinstance(sid, str):
            raise WorkflowError(f"step #{i} in {path} has no string 'id'")
        if sid in seen_ids:
            raise WorkflowError(f"step id {sid!r} is used twice in {path}")
        seen_ids.add(sid)
        if not step.get("tool"):
            raise WorkflowError(f"step {sid!r} in {path} has no 'tool'")
        on_refused = step.get("on_refused", spec.get("on_step_refused", ON_REFUSED_HALT))
        if on_refused not in (ON_REFUSED_HALT, ON_REFUSED_CONTINUE):
            raise WorkflowError(
                f"step {sid!r} in {path} has on_refused={on_refused!r}; must be "
                f"{ON_REFUSED_HALT!r} or {ON_REFUSED_CONTINUE!r}"
            )
    return spec


def _resolve(value: Any, results: dict[str, StepResult]) -> Any:
    """Walk a step's params, substituting ${steps.<id>.<field>} in any string.

    Recurses into dicts and lists so a `params:` block can nest a template
    inside a list value (a Slack message referencing an earlier event id
    inside its text, say) without the caller having to know that in advance.
    """
    if isinstance(value, str):
        def sub(match: "re.Match[str]") -> str:
            sid, field_name = match.group(1), match.group(2)
            if sid not in results:
                raise WorkflowError(
                    f"template ${{steps.{sid}.{field_name}}} references a step that has not "
                    "run yet (or does not exist) - steps can only reference earlier steps."
                )
            resolved = getattr(results[sid], field_name, None)
            if resolved is None:
                raise WorkflowError(
                    f"template ${{steps.{sid}.{field_name}}}: step {sid!r} has no {field_name!r} "
                    f"(it may have been refused - status was {results[sid].status})."
                )
            return str(resolved)

        return _TEMPLATE_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _resolve(v, results) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, results) for v in value]
    return value


@dataclass
class RunState:
    """Mutated in place by `iter_workflow_steps` as it goes, so a caller
    driving the generator by hand (the console, mostly - see server/app.py)
    can read `halted_at` and `skipped` once the generator is exhausted,
    without needing `run_workflow`'s synchronous wrapper to collect them."""

    halted_at: Optional[str] = None
    skipped: list[str] = field(default_factory=list)


def iter_workflow_steps(
    spec: dict[str, Any], broker: Broker, state: Optional[RunState] = None, resume: bool = False,
):
    """Generator form of the runner: yields one `StepResult` per step, in the
    order it was attempted, as it happens. `run_workflow` below just drains
    this into a list; the console drains it into server-sent events, one
    `yield` per verdict, so a workflow run looks the same on screen as the
    single-proposal scenario already does - decisions arriving one at a time,
    each one real before the next is even proposed.

    Every property `run_workflow`'s docstring claims lives here, because this
    is the actual loop; `run_workflow` has none of its own.

    `resume=True` is `resume_workflow()`'s seam - see that function. Before a
    step is proposed, its idempotency key is checked against
    `broker.ledger.external_id_for()`; a hit means this exact step already
    executed successfully in an earlier, crashed run, and it is reconstructed
    from that ledger row instead of being proposed again. `resume=False` (the
    default, what `run_workflow` uses) skips that check entirely, so a lone
    proposal's normal path costs nothing extra.
    """
    if state is None:
        state = RunState()
    steps = spec["steps"]
    default_on_refused = spec.get("on_step_refused", ON_REFUSED_HALT)

    results: dict[str, StepResult] = {}

    for i, step in enumerate(steps):
        sid = step["id"]
        params = _resolve(step.get("params") or {}, results)
        thread_id = _resolve(step.get("thread_id"), results) if step.get("thread_id") else None

        proposal = Proposal(
            tool=step["tool"],
            params=params,
            thread_id=thread_id,
            rationale=step.get("rationale", ""),
        )

        prior_external_id = (
            broker.ledger.external_id_for(policy_mod.idempotency_key(proposal)) if resume else None
        )
        if prior_external_id is not None:
            # Already happened, for real, in a run this process did not
            # finish - reconstructed from the ledger. The gate is never asked
            # about this step again and the app is never called again either;
            # both would be the exact re-execution resuming is meant to stop.
            result = StepResult(
                step_id=sid,
                tool=step["tool"],
                status=STATUS_EXECUTED,
                allowed=True,
                external_id=prior_external_id,
                params=params,
            )
        else:
            outcome = broker.execute(proposal)
            result = StepResult(
                step_id=sid,
                tool=step["tool"],
                status=outcome["status"],
                allowed=outcome["status"] == STATUS_EXECUTED,
                external_id=outcome.get("external_id"),
                rule_ids=list(outcome.get("rule_ids", [])),
                reasons=list(outcome.get("reasons", [])),
                journal_id=outcome.get("journal_id"),
                error=outcome.get("error"),
                params=params,
            )
        results[sid] = result
        yield result

        if result.allowed:
            continue

        # Refused (or errored - an execution error is treated the same as a
        # refusal for control flow: neither means "proceed as planned").
        on_refused = step.get("on_refused", default_on_refused)
        if on_refused == ON_REFUSED_CONTINUE:
            continue

        # halt: the default, and the safe one. Every remaining step was never
        # attempted - not refused, simply never proposed.
        state.halted_at = sid
        state.skipped = [s["id"] for s in steps[i + 1 :] if s["id"] not in results]
        return


def run_workflow(spec: dict[str, Any], broker: Broker) -> WorkflowResult:
    """Execute a loaded workflow spec against a broker, to completion. One
    `Broker.execute` call per step, in order - see the module docstring for
    why that single fact is what keeps this from being a second gate."""
    state = RunState()
    ordered = list(iter_workflow_steps(spec, broker, state))
    return WorkflowResult(
        name=spec.get("name", ""), steps=ordered, halted_at=state.halted_at, skipped=state.skipped
    )


def resume_workflow(spec: dict[str, Any], broker: Broker) -> WorkflowResult:
    """Run a workflow that may have already executed some of its steps in an
    earlier process that crashed or was killed mid-run.

    `RunState` and the generator driving it are both plain in-memory objects
    - nothing about a workflow run is persisted on its own, so a process that
    dies mid-run leaves no record of "how far it got" anywhere but the
    ledger, which already has one row per step that actually reached an app
    (see `warrant/ledger.py`). This function is the read side of that fact:
    before proposing each step, it checks whether the ledger already shows
    that EXACT step (by idempotency key, the same fingerprint `duplicate_action`
    uses) as successfully executed, and if so reconstructs the step's result
    from that row instead of proposing it again. A step the ledger has no
    record of is proposed completely normally - through the same
    `broker.execute()` call `run_workflow` makes - so a resumed run and a
    fresh run are indistinguishable for every step that has not, in fact,
    already happened.

    This is deliberately not automatic inside `run_workflow`: resuming
    changes what a step means (a step can now succeed without ever being
    proposed to the gate), and a caller should ask for that explicitly rather
    than have every workflow run implicitly capable of skipping steps.
    """
    state = RunState()
    ordered = list(iter_workflow_steps(spec, broker, state, resume=True))
    return WorkflowResult(
        name=spec.get("name", ""), steps=ordered, halted_at=state.halted_at, skipped=state.skipped
    )


def run_workflow_file(path: Path, broker: Broker, artifact_dir: Optional[Path] = None) -> tuple[WorkflowResult, Path]:
    """Load and run a workflow file, then write the single stamped artifact
    that ties its per-step journal rows into one signed evidence trail.

    Returns the result and the artifact's path - callers that only want the
    result (the workflow tests, mostly) can discard the second element.
    """
    spec = load_workflow(path)
    result = run_workflow(spec, broker)
    artifact = write_artifact(
        kind="workflow",
        config={"file": str(path), "name": spec.get("name", ""), "step_count": len(spec["steps"])},
        result=result.to_dict(),
        out_dir=artifact_dir,
    )
    return result, artifact


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Run a warrant workflow file.")
    ap.add_argument("workflow", type=Path, help="path to a workflow YAML file")
    ap.add_argument("--live", action="store_true", help="use real app clients instead of fakes")
    args = ap.parse_args()

    if args.live:
        broker = Broker()
    else:
        from warrant import fakes as fakes_mod
        from warrant import registry as registry_mod

        app_clients = {name: getattr(fakes_mod, spec.fake)() for name, spec in registry_mod.APPS.items()}
        broker = Broker(
            gmail=app_clients.pop("gmail"),
            calendar=app_clients.pop("calendar"),
            notion=app_clients.pop("notion"),
            apps=app_clients,
        )

    result, artifact = run_workflow_file(args.workflow, broker)
    for step in result.steps:
        mark = "ALLOWED " if step.allowed else "REFUSED "
        print(f"  {mark} {step.step_id:<20} {step.tool:<28} {step.status}")
        if not step.allowed and step.reasons:
            print(f"           -> {step.reasons[0]}")
    if not result.completed:
        print(f"\n  halted at step {result.halted_at!r}; skipped: {result.skipped}")
    print(f"\n  artifact: {artifact}")
    return 0 if result.completed else 1


if __name__ == "__main__":
    raise SystemExit(main())
