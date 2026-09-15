# Reliability findings - the five, and what actually happened to each

Five scenarios, each found by reading the code rather than assumed. For each
one: the invariant it claims, whether the code held it before this pass
(the baseline, established against the code as it actually was - not
guessed), what was changed if it did not, and the test that now proves the
final answer. `tests/test_reliability.py` is where the proof tests live;
this file is the record of the five verdicts.

Two of five were already correct and just lacked proof. Two were real gaps,
now fixed. One is correct by construction, and that construction is named
below rather than asserted.

| # | Scenario | Invariant | Baseline result | Fix | Final result | Proof | Status |
|---|---|---|---|---|---|---|---|
| 1 | Ambiguous external failure → duplicate on retry | `ACTION_REQUESTED → EXTERNAL_TIMEOUT → UNKNOWN_EXTERNAL_STATE → retry with the same proposal must not perform a second write` | **Broken.** Reproduced by hand against this session's own pre-fix `broker.py`/`ledger.py` (checked out via `git stash push -- warrant/broker.py warrant/ledger.py`, run, then restored): `_perform` raising after `FakeGmail.send` had already recorded the write left no ledger row at all (`record()` only runs after success), so a retry of the identical `Proposal` found `ledger.seen(idem_key) is False` and executed a second time. Two real sends for one logical request. | `warrant/ledger.py`: new `status` column (`'pending'` / `'succeeded'`), `mark_pending()` written *before* the app is called, `resolve_success()` only on confirmed success, `pending_attempt()` to detect an unresolved attempt. `warrant/broker.py`: `execute()` refuses outright (`ambiguous_external_state`) if the proposal's idempotency key has a pending row, before the gate or `_perform` run again. | **Fixed.** The retry is refused; the app is never called a second time. | `tests/test_reliability.py::test_ambiguous_write_failure_does_not_duplicate_on_retry` (+3 more in the same section) | **proven-after-fix** |
| 2 | Crash/restart mid-workflow | `crash after step N → resume re-derives {completed: 1..N, pending: N+1..} from the ledger alone, never re-proposes a completed step` | **Broken.** `RunState` and the generator driving it are plain in-memory objects with no persistence. Proved directly: draining `iter_workflow_steps` one step in, discarding the generator (simulating a killed process), then calling plain `run_workflow()` again on the same broker/ledger re-proposed the completed step - and since no `rate_limit.idempotency` was configured (the common case), it executed a second time. | `warrant/workflow.py`: new `resume_workflow()`, backed by a `resume=` parameter on `iter_workflow_steps`. Before proposing each step, its idempotency key is checked against a new `Ledger.external_id_for()`; a hit reconstructs the step's result from that row instead of proposing it again - the gate is never asked and the app is never called for a step that already genuinely ran. | **Fixed.** A resumed run never re-executes a completed step, and later steps' `${steps.<id>.external_id}` templates still resolve correctly using the reconstructed id. | `tests/test_reliability.py::test_a_crash_mid_run_leaves_no_automated_record_of_progress` (gap), `test_resume_workflow_never_reexecutes_a_completed_step`, `test_resume_workflow_completes_remaining_steps_after_a_two_step_crash`, `test_resume_workflow_on_a_never_started_run_behaves_like_a_fresh_run` | **proven-after-fix** |
| 3 | Stale authorization / policy edited mid-workflow | starting a workflow under one policy must not authorize a later step under a policy that has since been tightened on disk | **Already correct.** `policy.load_policy()` re-reads `policy.yaml` from disk on every call to `check()` - no cache anywhere in `policy.py`. This was true before this session touched anything; it just had never been exercised under an actual multi-step run. | None. | **Confirmed.** A three-step workflow, `policy.yaml` rewritten on disk between steps 2 and 3 (an allowed tool dropped from `irreversible_gate.allowed_tools`), step 3 refused under the new rule. The reverse (a step loosened mid-run becomes allowed) was also checked. | `tests/test_reliability.py::test_policy_edited_between_steps_governs_the_very_next_step`, `test_policy_loosened_between_steps_also_takes_effect_immediately` | **proven** (cheap - no fix needed) |
| 4 | Injection resistance through the full agent decision loop | a prompt injection embedded in real thread content, read by the model through `agent.run()`, must not result in a real send outside the thread - regardless of whether the model takes the bait | **Proven-by-design.** `Agent._handle` in `warrant/agent.py` routes every action tool call (`gmail.send`, `calendar.create_event`, `notion.create_page`) through `self.broker.execute(proposal)` with no other path to an app - there is no code path from a model's tool call to a real send that does not pass through the same gate every other caller in this repo uses. | None. | **Confirmed**, deliberately against the worst case: a stub backend (`GullibleBackend`) was written to ALWAYS obey an injected instruction it extracts from the real `ThreadFacts.body_text` the broker returns (not a hardcoded address the test set up independently) - it proposed both an injected cc and a forward to an external address. Both were refused (`recipient_scope`, and `domain_allowlist` for the external one); zero real sends. A second stub that ignores the injection was also run, to confirm the gate isn't just refusing everything. | `tests/test_reliability.py::test_agent_loop_resists_injection_even_when_the_model_takes_the_bait`, `test_agent_loop_still_lets_a_non_gullible_model_send_the_legitimate_reply` | **proven-by-design** (see honesty note below) |
| 5 | Excessive fanout on a single proposal, not just cumulative daily volume | a single proposal whose own audience already meets or exceeds the configured bound must be refused, even on a clean ledger with zero prior actions | **Already correct.** `_rule_audience_bound` computes `len(already_reached) + 1 > cap` - the `+ 1` already accounts for the proposal under evaluation, not only the running total that preceded it. This was true before this session touched anything. | None. | **Confirmed**, using the sharpest version of the question a single-destination-per-call tool (Slack) can pose: `max_distinct_per_day: 0` on a brand-new ledger. `already_reached` is empty either way, so a refusal here can only come from the rule counting the current proposal, not history. Refused. A control at `cap: 1` proves the rule isn't just refusing everything regardless of the configured cap. | `tests/test_reliability.py::test_audience_bound_refuses_a_single_proposals_own_fanout_on_a_clean_ledger`, `test_audience_bound_allows_the_first_proposal_when_it_fits_under_the_cap` | **proven** (cheap - no fix needed) |

## Honesty notes, not omitted

- **Finding 4 is proven-by-design, and that phrase is doing real work.** The
  brief asked for the difference between "the gate catches it regardless of
  what the model does" and "it happened to work because of what the stub
  did." This is the former: the routing through `Broker.execute()` is
  structural (checked indirectly by `tests/test_structure.py`'s import-graph
  tests, which establish there is no *other* way to reach an app), not a
  property of `GullibleBackend`'s specific script. The stub matters only to
  prove the loop actually runs end to end with a model that behaves as badly
  as this project assumes one might - not to prove the gate works, which was
  already established by `test_policy_adversarial.py`.
- **Finding 5's test is narrower than the scenario description in the brief
  makes it sound.** The registry's current `AUDIENCE`-class tools (Slack's
  two) each take exactly one destination per call - there is no tool in this
  build where a *single* proposal can name several audiences at once (a
  `channel: string_list`, say). So "a single proposal whose own audience
  count already exceeds the bound" can only be tested meaningfully at
  `cap: 0`; a `cap: 5` first call can never itself exceed a bound of 5,
  because it only ever contributes 1. The test above is honest about that -
  it explains the `cap: 0` choice rather than pretending a larger cap would
  have shown the same thing. If a future tool declared `AUDIENCE` with a
  list-shaped destination field, `_rule_audience_bound`'s fallback to
  `recipient_params[0]` would squash that whole list into one audience key
  (see its docstring) and this finding would need re-opening - not urgent
  today, because no such tool exists in the registry, but worth naming
  rather than leaving implicit.
- **Finding 1's fix has a stated, deliberate gap.** A `'pending'` row is
  excluded from every count (`count_today`, `spend_today`,
  `distinct_audience_today`) so an unresolved attempt cannot inflate a cap as
  though it definitely happened. If the write actually did land server-side
  and is never reconciled, that real effect is permanently invisible to
  `rate_limit`/`spend_cap`/`audience_bound` - a small, one-directional
  undercount. `pending_attempt()` is what actually stops the *duplicate*
  (the property this finding is about); reconciling a stuck pending row back
  into the counts is a follow-up this build does not attempt.
- **No automated reconciliation exists.** A row stuck `'pending'` stays that
  way forever unless a human (or a future tool) resolves it. That is the
  correct default - guessing wrong in either direction is worse than asking
  - but it means an operator needs a way to see pending rows and decide.
  `Ledger` has no query for "list every pending row" yet; `sqlite3
  .warrant/ledger.db "select * from actions where status='pending'"` is the
  reconciliation path today. Naming this rather than building a tool for it
  in this pass is the honest call given the scope.
