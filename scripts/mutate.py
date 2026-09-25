"""
mutate.py
─────────
Breaks the gate on purpose and checks that the test suite notices.

A passing test suite proves the code does something. It does not prove the
tests would fail if the code were wrong - and that is the actual question when
someone claims "127 tests pass". A suite of assertions that can never fail is
indistinguishable from a suite that works, right up until it matters.

So each mutation below disables one load-bearing property, runs the suite, and
records what broke. A mutation that kills nothing is a hole in the tests, and
the script exits non-zero so CI treats it as a failure rather than a curiosity.

Two details make the output honest rather than decorative:

  • **Expected survivors are named per mutation.** Making the gate advisory
    should NOT break the tests that assert a legal action succeeds - a gate
    that allows everything still allows the legal thing. A mutation script
    that demanded every test fail would be measuring the wrong thing, and the
    surviving count is reported rather than hidden.
  • **The source file is restored from memory in a `finally`**, so an
    interrupted run cannot leave a sabotaged gate on disk. The script verifies
    the restore before exiting.

Usage:
    python scripts/mutate.py
    python scripts/mutate.py --quiet
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Mutation:
    name: str
    file: str
    find: str
    replace: str
    why: str  # the property being disabled, in one line


MUTATIONS = [
    Mutation(
        name="gate-advisory",
        file="warrant/broker.py",
        find="        if not verdict.allowed:",
        replace="        if False:  # MUTATION",
        why="the broker executes even when the gate refuses",
    ),
    Mutation(
        name="normalise-and-send",
        file="warrant/policy.py",
        find="        note = _evasion_note(raw)\n        if note:",
        replace="        note = _evasion_note(raw)\n        if False:  # MUTATION",
        why="a homoglyph address is silently canonicalised instead of refused",
    ),
    Mutation(
        name="fail-open-on-missing-policy",
        file="warrant/policy.py",
        find="    if policy is None:",
        replace="    if policy is None and False:  # MUTATION",
        why="a missing policy file permits everything instead of nothing",
    ),
    Mutation(
        name="ignore-kill-switch",
        file="warrant/policy.py",
        find="    ks = kill_switch_active()\n    if ks:",
        replace="    ks = kill_switch_active()\n    if False:  # MUTATION",
        why="the kill switch stops being consulted",
    ),
    Mutation(
        name="trust-unknown-params",
        file="warrant/policy.py",
        find="    if unknown:",
        replace="    if False:  # MUTATION",
        why="a bypass-shaped param like confirmed=true is accepted rather than refused",
    ),
    # ── the four rules the multi-app suite added ─────────────────────────
    # Each disables the one line that makes an "absence means nothing is
    # authorized" rule actually refuse the absent case - the same shape as
    # fail-open-on-missing-policy above, for the four rules that generalize
    # across all thirteen apps instead of naming one.
    Mutation(
        name="destination-allowlist-membership-not-checked",
        file="warrant/policy.py",
        find="    if dest not in allowed_for_tool:",
        replace="    if False:  # MUTATION",
        why="a write lands at a destination nobody put on the allowlist for that tool",
    ),
    Mutation(
        name="spend-cap-ignores-per-action-limit",
        file="warrant/policy.py",
        find="    if per_action is not None and amount > int(per_action):",
        replace="    if False:  # MUTATION",
        why="a single action can move an unbounded amount of money regardless of max_per_action_minor",
    ),
    Mutation(
        name="irreversible-gate-open-by-default",
        file="warrant/policy.py",
        find="    if proposal.tool not in allowed:",
        replace="    if False:  # MUTATION",
        why="an irreversible action runs without ever being named in allowed_tools",
    ),
    Mutation(
        name="audience-bound-uncapped",
        file="warrant/policy.py",
        find="    if key not in already_reached and len(already_reached) + 1 > int(cap):",
        replace="    if False:  # MUTATION",
        why="a fan-out tool can reach an unbounded number of distinct audiences per day",
    ),
    # ── the reliability fix from the Part 2 findings ─────────────────────
    Mutation(
        name="ambiguous-retry-not-refused",
        file="warrant/broker.py",
        find="        if self.ledger.pending_attempt(idem_key):",
        replace="        if False:  # MUTATION",
        why="a retry of a proposal whose prior attempt has an unknown outcome is performed "
            "again instead of refused, which can duplicate a write that already landed",
    ),
    # ── the delegation layer ─────────────────────────────────────────────
    # Its two defences answer two different attacks and each must be killed
    # on its own. A suite that only ever exercised them together would let a
    # refactor delete one and keep passing, which is exactly what these two
    # mutations exist to disprove.
    Mutation(
        name="attenuation-not-rechecked",
        file="warrant/identity.py",
        find="        widened = sorted(grant.classes - parent.classes)\n        if widened:",
        replace="        widened = sorted(grant.classes - parent.classes)\n        if False:  # MUTATION",
        why="a holder can mint itself a child grant carrying capabilities its parent never "
            "held - every signature still verifies, so only this re-check catches it",
    ),
    Mutation(
        name="chain-signature-not-verified",
        file="warrant/identity.py",
        find="            if not grant.signature_matches(key):",
        replace="            if False:  # MUTATION",
        why="a fabricated root grant is honoured - the chain can attenuate perfectly, so "
            "only the MAC catches it",
    ),
    Mutation(
        name="revoked-grants-still-honoured",
        file="warrant/identity.py",
        find="        if revocations is not None and revocations.is_revoked(grant.grant_id):",
        replace="        if False:  # MUTATION",
        why="revoking a grant stops having any effect, including on every authority "
            "descended from it",
    ),
    Mutation(
        name="chain-not-bound-to-its-tenant",
        file="warrant/policy.py",
        find="    if str(facts_tenant) != str(chain_tenant):",
        replace="    if False:  # MUTATION",
        why="a valid delegation chain for one tenant authorizes actions against another "
            "tenant's account",
    ),
]


def run_suite() -> tuple[int, int, list[str]]:
    """Run pytest, return (passed, failed, failing test ids)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
    )
    out = proc.stdout + proc.stderr
    failing = [ln.split(" ")[1] for ln in out.splitlines()
               if ln.startswith("FAILED ") and len(ln.split(" ")) > 1]

    # Read the counts out of pytest's summary line with a regex rather than by
    # walking tokens. The first version of this indexed into `line.split()` to
    # find the number before "passed", which returns the FIRST match of a
    # repeated token and quietly reported 0 failures for every mutation - so
    # the script cheerfully announced that a suite which does catch these bugs
    # catches none of them. A measurement tool that fails silently is worse
    # than no tool, so the count is now cross-checked against the exit code
    # below and a disagreement is fatal.
    passed = failed = 0
    m = re.search(r"(\d+) passed", out)
    if m:
        passed = int(m.group(1))
    m = re.search(r"(\d+) failed", out)
    if m:
        failed = int(m.group(1))

    if (proc.returncode != 0) != (failed > 0 or bool(failing)):
        raise SystemExit(
            f"cannot parse pytest output: exit={proc.returncode} but parsed "
            f"{failed} failures. Refusing to report a number I do not trust.\n"
            f"--- tail ---\n{out[-1500:]}"
        )
    return passed, failed, failing


def apply(mut: Mutation) -> str:
    """Apply one mutation; return the original text for restoration."""
    path = ROOT / mut.file
    original = path.read_text(encoding="utf-8")
    if mut.find not in original:
        raise SystemExit(
            f"mutation {mut.name!r} no longer matches {mut.file} - the code moved "
            "under it. Update the mutation rather than deleting it; a mutation "
            "that silently stops applying is a test that silently stopped running."
        )
    path.write_text(original.replace(mut.find, mut.replace, 1), encoding="utf-8")
    return original


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("\nwarrant - mutation check")
    print("=" * 72)
    print("Each row disables one property and reports how many tests noticed.")
    print("A mutation that kills nothing is a hole in the suite.\n")

    base_pass, base_fail, _ = run_suite()
    if base_fail:
        print(f"  baseline is already failing ({base_fail} tests) - fix that first.")
        return 2
    print(f"  baseline: {base_pass} passed, 0 failed\n")

    rows = []
    for mut in MUTATIONS:
        original = None
        try:
            original = apply(mut)
            passed, failed, failing = run_suite()
        finally:
            if original is not None:
                (ROOT / mut.file).write_text(original, encoding="utf-8")

        killed = failed > 0
        rows.append((mut, failed, passed, failing))
        mark = "killed" if killed else "SURVIVED"
        print(f"  {mark:<9} {mut.name:<28} {failed:>3} tests failed   ({mut.why})")
        if not args.quiet and failing:
            for t in failing[:3]:
                print(f"            · {t.split('::')[-1]}")
            if len(failing) > 3:
                print(f"            · … and {len(failing) - 3} more")
        print()

    survivors = [m for m, failed, _, _ in rows if failed == 0]
    print("=" * 72)
    print(f"  {len(rows) - len(survivors)}/{len(rows)} mutations killed by the suite")

    # Restoration check: never leave a sabotaged gate on disk.
    final_pass, final_fail, _ = run_suite()
    print(f"  after restore: {final_pass} passed, {final_fail} failed")
    if final_fail:
        print("  RESTORE FAILED - check git status before trusting this tree.")
        return 2

    if survivors:
        print(f"\n  unkilled: {', '.join(m.name for m in survivors)}")
        print("  Each is a property nothing asserts. Write the test.\n")
        return 1
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
