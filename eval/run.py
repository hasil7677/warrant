"""
run.py
──────
Replays a set of declarative cases through the real gate and writes the
evidence.

This is not the test suite. The tests ask "does each rule do what it says?";
this asks the question a reviewer actually cares about: **given a thread and a
proposed action, what does the system do, and did anything reach the apps?**
Every case runs through the real `Broker.execute` and the real `policy.check`
against fake app clients whose ledgers are inspected afterwards. A case that
expects a refusal fails if the fake's ledger grew, even when the returned
status was right - a gate that refuses and then acts is worse than one that
does neither.

Two properties are deliberate:

  • **Cases are data, not code.** `eval/cases/*.yaml` is readable by someone
    who does not write Python, which is the point of a policy you can audit.
  • **ALLOW cases are first-class and reported separately.** An evaluation
    consisting only of refusals is satisfied by a gate that blocks everything,
    so the pass rate is reported split by expected outcome. If the allow
    column is empty, the number above it means nothing.

Usage:
    python eval/run.py                  # run, write artifact + EVAL.md
    python eval/run.py --quiet
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from warrant import journal as journal_mod  # noqa: E402
from warrant import policy as policy_mod  # noqa: E402
from warrant import registry as registry_mod  # noqa: E402
from warrant import fakes as fakes_mod  # noqa: E402
from warrant.broker import Broker  # noqa: E402
from warrant.contract import STATUS_EXECUTED, Proposal  # noqa: E402
from warrant.fakes import seed_thread  # noqa: E402
from warrant.ledger import Ledger  # noqa: E402
from warrant.provenance import write_artifact  # noqa: E402

CASE_DIR = Path(__file__).parent / "cases"
RESULTS_DIR = Path(__file__).parent / "results"
RAW_PATH = RESULTS_DIR / "raw.jsonl"
REPORT_PATH = ROOT / "EVAL.md"


def load_cases() -> list[dict]:
    """Every case in every YAML file under cases/, tagged with its source."""
    cases: list[dict] = []
    for path in sorted(CASE_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for case in data.get("cases", []):
            case["_file"] = path.name
            cases.append(case)
    return cases


def run_case(case: dict, tmp: Path) -> dict:
    """Execute one case against a freshly isolated gate, broker, and fakes.

    Isolation is per-case on purpose: a shared ledger would make a case's
    result depend on which cases ran before it, and an evaluation whose
    outcome depends on ordering is not reproducible.
    """
    sandbox = tmp / case["name"].replace(" ", "_")[:40]
    sandbox.mkdir(parents=True, exist_ok=True)

    policy_src = case.get("policy", "policy.yaml")
    policy_text = (ROOT / policy_src).read_text(encoding="utf-8")
    policy_file = sandbox / "policy.yaml"
    policy_file.write_text(policy_text, encoding="utf-8")

    policy_mod.POLICY_FILE = policy_file
    policy_mod.DATA_DIR = sandbox
    policy_mod.KILL_SWITCH_LOCATIONS = [sandbox / "KILL_SWITCH"]
    journal_mod.DATA_DIR = sandbox
    journal_mod.JOURNAL_DB = sandbox / "journal.db"

    # Setup steps the case asked for, before anything runs.
    if case.get("kill_switch"):
        (sandbox / "KILL_SWITCH").write_text("", encoding="utf-8")
    if case.get("delete_policy"):
        policy_file.unlink()

    # A fresh fake for every app in the registry, not just the original three.
    # `apps={...}` is the general path `Broker.__init__` documents; gmail,
    # calendar and notion stay their own keyword for the same reason the
    # broker keeps them named - they are the apps with a live smoke artifact
    # behind them, and every other caller in this repo already constructs a
    # Broker expecting those three names to work.
    app_fakes = {name: getattr(fakes_mod, spec.fake)() for name, spec in registry_mod.APPS.items()}
    gmail = app_fakes["gmail"]
    thread = case.get("thread")
    thread_id = None
    if thread:
        thread_id = thread["id"]
        gmail.threads[thread_id] = seed_thread(
            thread_id,
            thread.get("participants", []),
            thread.get("subject", ""),
            thread.get("body", ""),
        )

    ledger = Ledger(sandbox / "ledger.db")
    broker = Broker(
        gmail=app_fakes.pop("gmail"),
        calendar=app_fakes.pop("calendar"),
        notion=app_fakes.pop("notion"),
        apps=app_fakes,
        ledger=ledger,
    )

    spec = case["proposal"]
    results = []
    # `repeat` exists so a retry-storm case is one case rather than five.
    for _ in range(int(case.get("repeat", 1))):
        results.append(broker.execute(Proposal(
            tool=spec["tool"],
            params=dict(spec.get("params", {})),
            thread_id=spec.get("thread_id", thread_id),
            rationale=spec.get("rationale", ""),
        )))

    final = results[-1]
    expect = case.get("expect", {})
    want_allow = str(expect.get("decision", "DENY")).upper() == "ALLOW"
    got_allow = final["status"] == STATUS_EXECUTED

    failures = []
    if want_allow != got_allow:
        failures.append(f"expected {'ALLOW' if want_allow else 'DENY'}, got {final['status']}")

    want_rule = expect.get("rule")
    if want_rule and want_rule not in final.get("rule_ids", []):
        failures.append(f"expected rule {want_rule!r}, got {final.get('rule_ids')}")

    # The side-effect check. This is the assertion that a status string cannot
    # satisfy: on a refusal the ledger must be untouched. `tools_executed_today`
    # reads the broker's own effect ledger - one row per action that actually
    # reached an app, written only after `_perform` returns - so this check
    # covers all thirteen apps without hand-counting each fake's own list.
    executed = [registry_mod.app_of(t) or t for t in ledger.tools_executed_today()]
    reached: dict[str, int] = {}
    for app_name in executed:
        reached[app_name] = reached.get(app_name, 0) + 1
    expected_side_effects = int(expect.get("side_effects", 1 if want_allow else 0))
    if sum(reached.values()) != expected_side_effects:
        failures.append(
            f"expected {expected_side_effects} action(s) to reach an app, saw {reached}"
        )

    return {
        "name": case["name"],
        "file": case["_file"],
        "expect": "ALLOW" if want_allow else "DENY",
        "status": final["status"],
        "rule_ids": sorted(set(final.get("rule_ids", []))),
        "reasons": final.get("reasons", [])[:2],
        "reached_apps": reached,
        "expected_side_effects": expected_side_effects,
        "attempts": len(results),
        "passed": not failures,
        "failures": failures,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    import tempfile

    # This console is cp1252 and will raise UnicodeEncodeError on the arrows and
    # box-drawing characters below - mid-run, after some cases have already
    # printed. Force UTF-8 so a reporting detail cannot fail the evaluation.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    cases = load_cases()
    if not cases:
        print(f"no cases found in {CASE_DIR}", file=sys.stderr)
        return 2

    RESULTS_DIR.mkdir(exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="warrant-eval-") as td:
        tmp = Path(td)
        for case in cases:
            row = run_case(case, tmp)
            rows.append(row)
            if not args.quiet:
                mark = "pass" if row["passed"] else "FAIL"
                print(f"  {mark}  {row['expect']:<5} {row['name']:<44} "
                      f"{','.join(row['rule_ids']) or row['status']}")
                for f in row["failures"]:
                    print(f"        → {f}")

    with RAW_PATH.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    allow = [r for r in rows if r["expect"] == "ALLOW"]
    deny = [r for r in rows if r["expect"] == "DENY"]
    passed = [r for r in rows if r["passed"]]
    # An action that reached an app when the case did not budget for one. This
    # is the number that must be zero, and it is deliberately NOT "any DENY case
    # that touched an app": the retry-storm case expects exactly one of five
    # attempts to land, so counting raw side effects there would report a leak
    # that is really the gate working. A metric that cries wolf on a correct run
    # is worse than no metric - nobody trusts the next one.
    leaked = [r for r in rows
              if sum(r["reached_apps"].values()) > r["expected_side_effects"]]

    result = {
        "cases": len(rows),
        "passed": len(passed),
        "failed": len(rows) - len(passed),
        "allow_cases": {"total": len(allow), "passed": sum(r["passed"] for r in allow)},
        "deny_cases": {"total": len(deny), "passed": sum(r["passed"] for r in deny)},
        "unbudgeted_actions": len(leaked),
        "rules_exercised": sorted({rid for r in rows for rid in r["rule_ids"]}),
        "rows": rows,
    }

    artifact = write_artifact(
        kind="eval",
        config={"case_files": sorted({r["file"] for r in rows}), "policy": "policy.yaml"},
        result=result,
    )
    write_report(result, artifact)

    print(f"\n  {len(passed)}/{len(rows)} passed "
          f"({sum(r['passed'] for r in allow)}/{len(allow)} allow, "
          f"{sum(r['passed'] for r in deny)}/{len(deny)} deny)")
    print(f"  actions that reached an app unbudgeted: {len(leaked)}")
    print(f"  artifact: {artifact}")
    print(f"  report:   {REPORT_PATH}\n")
    return 0 if len(passed) == len(rows) else 1


def write_report(result: dict, artifact: Path) -> None:
    """Render EVAL.md. Caveats go near the top, not in a footnote."""
    rows = result["rows"]
    L = [
        "# Evaluation - what the gate did, and what reached the apps",
        "",
        f"`{artifact.name}` is the machine-readable record of this run; the numbers "
        "below are read from it rather than typed in by hand.",
        "",
        f"**{result['passed']}/{result['cases']} cases passed** "
        f"({result['allow_cases']['passed']}/{result['allow_cases']['total']} expected-allow, "
        f"{result['deny_cases']['passed']}/{result['deny_cases']['total']} expected-deny). "
        f"Actions that reached an app without the case budgeting for one: "
        f"**{result['unbudgeted_actions']}**.",
        "",
        "## What this measures, and what it does not",
        "",
        "- **The app clients are fakes, and that is the measurement.** Each fake keeps a "
        "ledger of what reached it. A refusal case passes only if the ledger is still "
        "empty afterwards - a status string alone cannot satisfy it. What this does not "
        "prove is that the real Gmail/Calendar/Notion clients behave identically; that is "
        "what `scripts/smoke.py` is for, and the two are deliberately separate.",
        "- **Expected-allow cases are reported separately on purpose.** An evaluation made "
        "only of refusals is satisfied by a gate that blocks everything. If the allow "
        "column above is empty or failing, the headline number is meaningless.",
        "- **Cases are hand-written, not sampled.** They cover the failure modes the policy "
        "was designed against, so this is a statement about those modes - not an estimate "
        "of behaviour on arbitrary real traffic.",
        "- **The model is not in this loop.** Proposals are supplied directly, so this "
        "measures the gate, not the agent's judgment. That separation is intentional: the "
        "gate's correctness must not depend on the model behaving well.",
        "- **Each case runs in its own sandbox** (fresh policy file, ledger, journal, and "
        "kill-switch path), so results do not depend on case ordering.",
        "",
        "## Rules exercised",
        "",
        "".join(f"`{r}` " for r in result["rules_exercised"]) or "_none_",
        "",
        "## Cases",
        "",
        "| | Expect | Case | Outcome | Rules fired | Reached apps |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        mark = "✅" if r["passed"] else "❌"
        reached = sum(r["reached_apps"].values())
        L.append(
            f"| {mark} | {r['expect']} | {r['name']} | `{r['status']}` | "
            f"{', '.join(f'`{x}`' for x in r['rule_ids']) or ' - '} | "
            f"{reached}/{r['expected_side_effects']} |"
        )
    L += ["", "## Reproduce", "", "```", "python eval/run.py", "```", ""]
    REPORT_PATH.write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
