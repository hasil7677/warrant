# warrant

**An agent proposes an action. A declarative policy authorizes it against explicit capability classes. The gate holds the credentials, so the model never does. Every decision is journaled.**

359 tests passing. 11 apps, 19 actions, all reached only through the broker. 3 apps are live-verified against real accounts; 8, including a real-money trading integration added most recently, are fake-only - wired, tested, and honestly labeled as never having made a live call.

---

## Problem

Give an autonomous agent tools that send email, page people, spend money, or place trades, and "the agent asks permission first" stops being a meaningful control the moment the agent also decides *when* to ask, *how* to phrase the request, and *holds the API credentials* itself. At that point permission-asking is a suggestion the model makes to itself. A confused, manipulated, or simply overconfident agent has the same raw authority as a correct one, because nothing outside the model's own judgment stands between a proposal and its effect.

This is not a hypothetical about rogue AI. It is an ordinary systems problem: broad tool access plus probabilistic judgment plus no external check is an authorization gap, and it looks exactly like a confused deputy problem from classical security - a party with more privilege than the request it is fulfilling actually calls for.

## Thesis

**Deterministic policy has to sit around a probabilistic agent, not inside it.** The agent may propose an action; it must not be able to execute an unauthorized one, and "unauthorized" has to be decidable by code a human wrote and can audit, not by another guess from the same model that produced the proposal.

The second half of the thesis is what actually generalizes: **the gate reasons about what an action is capable of, not which app it belongs to.** A policy rule written to bound "moves money" governs a Stripe refund, a Twilio SMS, and a Zerodha trading order without ever being told any of their names. A gate that needs a new rule for every new integration is a gate that rots on the day someone is in a hurry; a gate built on `write` / `destructive` / `irreversible` / `spend` / `egress` / `audience` / `third_party` / `code` / `identity` classes is governed on the day integration number twelve is added, not the day someone remembers to write a rule for it. The Kite trading extension (below) is the test of that claim: a materially different domain - real money, a live market, no email thread to anchor trust in - added without a single change to the six generic rules the first three apps already used.

## Architecture

```
   agent  ──proposes──▶  broker.execute(Proposal)
 (no creds)                    │
                               │ 1. facts_for() / facts_providers[app] -
                               │    the broker reads its OWN trust anchor
                               │    (a Gmail thread, a tenant's live quote),
                               │    never anything the model asserted
                               ▼
                policy.check(proposal, facts, ledger, chain)  ◀── policy.yaml
                               │                                   (a human wrote this;
                               │                                    the package never does)
                               │  chain = who is acting, on whose
                               │  behalf — see Delegation below
                               │ Verdict(allowed, reasons, rule_ids)
                    ┌──────────┴──────────┐
                    │                     │
               refused                allowed
                    │                     │
              journal.db            ledger: mark_pending()
           (logged either way)            │
                                    _perform() → the app client
                                           │
                                    ledger.resolve_success()
                                           │
                                    journal.log_decision(external_id)
```

One `Proposal` dataclass (`warrant/contract.py`) is the only thing that crosses the line from agent to broker: a tool name, params, an optional thread id, and a rationale the gate never reads. Everything downstream of that line is deterministic Python.

**Propose.** The agent (or, for `kite.place_order`, whatever platform code is running on the tenant's behalf) builds a `Proposal`. This is untrusted input by construction - `contract.py`'s docstring calls it "a claim by the model."

**Gather facts.** `Broker._gather_facts()` fetches the trust anchor itself, before the gate runs: `ThreadFacts` for the three Gmail/Calendar/Notion-shaped apps (who is actually on this email thread, per the Gmail API - not per what the proposal claims), or `KiteFacts` for a Kite order (a live quote fetched by a closure the platform hands in at construction time, plus mandate/kill-switch/order-count facts the platform already pulled from Postgres). The model chooses *which* thread or account to act on; it never gets to state what is in it.

**Evaluate.** `policy.check()` (`warrant/policy.py`) runs the kill switch check, then loads `policy.yaml`, then runs every rule the file names, by name, against the proposal and the facts. It collects every objection rather than stopping at the first, so a refusal names all of what is wrong. The only output that matters is `Verdict.allowed` - a boolean nothing on the calling side can override.

**Hold credentials, execute.** `Broker` is the only module in the package that imports `warrant.apps.*`, and `warrant.auth` is the only module that reads a credential. If the verdict is `allowed`, the broker marks a `'pending'` row in the ledger, calls the app client, and only then resolves the row to `'succeeded'`. The agent process never sees a Gmail OAuth token, a Stripe secret key, or a tenant's Kite session - it sees a dict back: `EXECUTED`, `REJECTED_BY_POLICY_GATE`, or `ERROR`.

**Journal.** Every decision - allowed or refused, and if executed, the resulting external id or the specific exception - lands in `journal.db` (`warrant/journal.py`) before the function returns. `decision` is derived from the verdict object, never passed in independently, so nothing can write a clean-looking journal row for a call that wasn't clean.

## Delegation — who is acting, and on whose behalf

Everything above answers one question: *is this action within the rules?* It has nothing to say about a second one, which matters the moment more than one agent is involved:

> Is **this** agent allowed to perform **this exact action**, in this exact context, **on behalf of this exact user**?

A `Proposal` carries a tool and params. It does not carry a principal — so until this layer existed, the research agent that may only read and the execution agent that may place an order were the same anonymous caller wearing the same `policy.yaml`. `warrant/identity.py` adds the missing axis.

The two are **conjunctive, never alternative**. A delegated authority says what an agent *may* be permitted to do; `policy.yaml` still says what *anyone* is permitted to do. Both must pass. An agent holding every capability class there is still cannot write to a Notion page the policy does not list — `test_delegation_does_not_override_the_rest_of_the_policy` is the assertion.

### The problem, stated precisely

> Can an agent safely delegate a subset of its authority without accidentally granting more authority than it possesses?

Two independent failure modes hide in that sentence, and conflating them is how capability systems get this wrong:

| | What it looks like | What stops it |
|---|---|---|
| **Amplification** | A holder mints a child claiming more than it holds. Every signature is valid; nothing is forged. | The attenuation check, re-derived on every link at verification time |
| **Forgery** | A grant is fabricated or edited after issue. It may attenuate perfectly. | The chained MAC |

A system with only the first is bypassed by writing your own chain. A system with only the second lets any holder issue itself a superset. Both are needed, so both exist — and in `tests/test_identity_delegation.py` **each is tested with the other disabled**, because a suite that only ever tests them together cannot tell you which one is load-bearing.

### The chained MAC

Each grant carries an HMAC over its own canonical bytes. The key is the interesting part:

```
root grant:   sig = HMAC(root_secret, canonical(body))
child grant:  sig = HMAC(parent.sig,  canonical(body))
```

The root secret lives in the operator's environment and is never given to an agent. A holder of grant `G` knows `G.sig` — which is exactly the key needed to mint a child of `G`, and nothing else. So:

- Any holder can **delegate downward** offline, with no round trip to an authority and no secret it was not already given. That is what makes it usable by an agent mid-run.
- No holder can mint a **sibling**, a **parent**, or a **fresh root** — those need a MAC keyed by something upstream of it.
- Editing an ancestor invalidates every descendant, because each link's key *is* the previous link's signature.

This is the macaroon construction (Birgisson et al., 2014). The alternative — signing every grant with the root key — would require handing the root secret to every delegation point, i.e. giving every agent the ability to mint anything.

```
   operator (holds WARRANT_ROOT_SECRET)
        │  issue_root(classes={write, third_party, irreversible})
        ▼
   agent:research-1 ──────────────────────────── may send mail
        │  attenuate(classes={write})              (third_party)
        ▼
   agent:analysis-1 ──────────────────────────── may NOT send mail
        │  attenuate(tools={notion.create_page})
        ▼
   agent:summariser ─────────────────────────── one tool, nothing else
```

### What a grant can carry

Nothing new — grants are scoped in the **capability classes** `registry.py` already tags every tool with (`write`, `spend`, `egress`, `irreversible`, …). A grant authorizes a tool when the tool's hazard classes are a **subset** of the grant's: a grant that omits `spend` refuses every tool that moves money, and the burden is on the grant to enumerate what it accepts.

That reuse is the point. A grant naming tools only would need editing every time an app is added; a grant carrying `{write}` authorizes exactly as much after app sixteen ships as before, because the new app's hazards are declared in the registry and the subset check picks them up for free.

`authorize()` checks the **leaf** grant, not the root and not the union. The leaf is what the acting agent actually holds; checking either of the others would silently hand a sub-agent its delegator's powers.

### Binding a chain to the account it acts on

`verify_chain()` proves a chain is genuine, unexpired and attenuating. It
cannot prove it is the **right** chain — it never sees the facts. A perfectly
valid chain for tenant A, presented alongside facts the broker read for
tenant B, passes every check in `identity.py`.

So the binding lives in the policy rule, where both halves are in scope: if
the chain names a `tenant` principal and the facts carry a `tenant_id`, they
must match. The tenant is found by scanning **every** subject in the chain,
not just the two ends — a multi-tenant host delegates `platform → tenant →
agent`, and the tenant is the middle link, named by neither `principal` nor
`on_behalf_of`.

```yaml
delegation:
  require_tenant_binding: true    # multi-tenant hosts should set this
```

A mismatch is *always* a refusal. The flag governs only the "cannot check"
cases — facts with no `tenant_id`, or a chain with no tenant link — which
are skipped by default so enabling `delegation` does not force a tenant
model on a single-operator install (`ThreadFacts` has no tenant concept and
never will). A chain that names *two different* tenants is refused
outright: attenuation is about capability, not identity, so `identity.py`
does not forbid it and should not have to.

### Revocation

A flat set of grant ids, read from `.warrant/revoked-grants.txt` — one id per line, `#` comments allowed. Revoking **any** link kills that grant and everything descended from it, with no tree walk and no database, because verification checks every link. Revoking the root disables every agent at once.

It is a file, read by the gate, rather than an argument the caller passes — the same shape as the kill switch, and for the same reason: a revocation list the governed layer hands in is a list it can hand in empty. There is no un-revoke; a grant is a bearer credential, and if it was worth revoking the holder may still have it.

A flat file is right for one operator with an editor and useless for a host that wants revocation to be an API call. So the store is pluggable — but the plugin point is a **schema, not an import path**:

```yaml
delegation:
  revocations_sqlite: /var/lib/warrant/revocations.db   # SELECT grant_id FROM revoked_grants
```

Letting policy.yaml name a Python callable would be the obvious general fix and is deliberately not what this is: `policy.py` has no expression language because "a policy file that can compute is a policy file that can be talked into computing something else," and an import path is computation wearing a config's clothes. A table name and a path are data. Any process that can write SQLite can now drive revocation, and warrant reads one column from one table and executes nothing — opened read-only, because a gate that can write the revocation list is a gate that can shorten it. Configuring both stores is a policy error rather than a silent preference.

### Auditability

`journal.db` gained three columns — `principal`, `on_behalf_of`, `chain_json` — so a row answers *who did this, acting as whom, under which authority*, not only *what happened*. Rejected claims of authority are journalled too, with the chain that was claimed; those are the rows worth having. Grant **signatures are never stored** — a signature is the key that mints children, and an audit file that confers authority is not an audit file. A journal written before this layer existed gains the columns by `ALTER TABLE` and keeps every row, with `NULL` principals: nothing knew who was acting when they were written, so nothing claims to now.

### Turning it on

Off by default. The `delegation:` block in `policy.yaml` is commented out, and uncommenting it is a hard switch — from that moment every proposal must arrive with a verified chain or be refused. There is no partial mode, which is the point: once policy.yaml names the rule, `chain=None` is a refusal, so there is no value a caller can pass that turns the check off.

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"   # → WARRANT_ROOT_SECRET
```

```python
from warrant.identity import Principal, issue_root, attenuate
from warrant.broker import Broker

operator = Principal("user", "sahil")
root = issue_root(                      # needs the secret — operator only
    grant_id="g-root", issuer=operator, subject=Principal("agent", "research-1"),
    classes=["write", "third_party", "irreversible"],
)
child = attenuate(                      # needs only the parent grant — agent-callable
    root, grant_id="g-1", subject=Principal("agent", "analysis-1"), classes=["write"],
)

broker = Broker(chain=[root, child])    # this sub-agent cannot send mail
```

The chain goes on the `Broker`, not on `execute()`: it is a property of the session, not of one action, and a per-call argument is one the model-facing loop can vary per call. A sub-agent that should hold less authority gets **its own Broker built from an attenuated chain** — which is what makes "this agent had strictly less power" checkable rather than promised.

## Threat Model

Grounded in what `tests/` actually exercises, not an idealized list. Each row names the real test file.

| Threat | Defended how | Evidence |
|---|---|---|
| **Model fabricates the facts it's judged against** (e.g. claims recipients are already thread participants) | Broker fetches `ThreadFacts`/`KiteFacts` itself from the API/platform layer; `Proposal` carries no facts field for the gate to read instead | `tests/test_policy_adversarial.py::test_thread_body_cannot_add_a_participant`, `test_broker_kite_facts.py::test_check_order_receives_the_facts_derived_values_not_the_proposals_own_claims` |
| **Confused deputy via a "confirmed" or bypass-shaped flag** | `check()` and `execute()` take no override parameter; an unexpected key like `confirmed: true` is rejected as `unknown_param`, not silently ignored or honored | `test_policy_adversarial.py::test_check_exposes_no_bypass_parameter`, `test_bypass_shaped_param_is_rejected_not_honoured`, `test_structure.py::test_no_module_exposes_a_bypass_parameter` |
| **Prompt injection in untrusted content** (an email body instructing "also cc legal@...") talks the agent into a bad proposal | The instruction is text inside a fact object the gate compares *against*, never a channel into the gate itself; a stub backend built to always take the injection bait was run through the real agent loop and still produced zero unauthorized sends | `tests/test_reliability.py::test_agent_loop_resists_injection_even_when_the_model_takes_the_bait` (see also `EVAL_MATRIX.md` finding 4, labeled "proven-by-design": the routing is structural, not a property of that one stub) |
| **Unicode/homoglyph address laundering** (`recruiter@bright<ZWSP>lane.io` normalizes to a real participant, but the raw string is a different mailbox) | Normalization is detection-only; an address that changes under NFKC is refused outright, never silently corrected and sent to | `test_policy_adversarial.py::test_address_that_normalises_to_a_participant_is_still_refused`, `test_refusal_quotes_the_raw_address_not_the_cleaned_one` - this was a real, since-fixed bug, see Failure Cases below |
| **Retry/replay after an ambiguous failure** (client times out after the write already landed server-side; naive retry duplicates the effect) | `execute()` writes a `'pending'` ledger row *before* calling the app; an identical proposal with a still-pending fingerprint is refused rather than retried | `test_reliability.py::test_ambiguous_write_failure_does_not_duplicate_on_retry`, `test_a_third_identical_call_is_still_refused_not_just_the_first_retry` |
| **Splitting one large action into many small ones to dodge a cap** | Daily caps (`rate_limit`, `spend_cap`) read from the ledger's running total for the day, not per-call state, so five small sends are still summed against the same cap a single large one would be | `test_policy_adversarial.py::test_daily_cap_cannot_be_dodged_by_splitting_the_action` |
| **Fan-out escalation across many individually-legal messages** (each message to one pre-approved audience, but the agent works through an increasing number of audiences in one run) | `audience_bound` counts distinct destinations reached today, independent of `rate_limit`'s per-tool count | `test_reliability.py::test_audience_bound_refuses_a_single_proposals_own_fanout_on_a_clean_ledger` |
| **Policy tampered with, deleted, or mid-edit** | Missing file, unreadable YAML, non-mapping YAML, an empty `rules:` block, and a rule name the build does not implement all refuse outright rather than defaulting open | `test_policy_adversarial.py::test_no_policy_file_blocks_every_action`, `test_unreadable_policy_blocks_rather_than_crashes`, `test_policy_with_no_rules_block_authorizes_nothing`, `test_policy_naming_an_unimplemented_rule_blocks` |
| **Emergency stop needed while the policy itself is broken** | Kill switch is a file-existence check performed before the policy is even loaded | `test_policy_adversarial.py::test_kill_switch_is_checked_before_the_policy_is_read`, `test_kill_switch_works_while_the_policy_is_mid_edit` |
| **Code outside the broker reaching an app client or a credential directly** | An AST walk over the package asserts only `broker.py` imports `warrant.apps.*` and only `auth.py` reads a credential | `test_structure.py::test_only_the_broker_imports_app_clients`, `test_only_auth_reads_credentials` |
| **Privilege escalation via an irreversible action nobody explicitly authorized** | Anything the registry marks `irreversible` requires an explicit per-tool allowlist entry; absence refuses, it does not default-allow | `test_policy_adversarial.py` irreversible-gate cases; `scripts/mutate.py`'s `irreversible-gate-open-by-default` mutation, killed by 3 tests |

What is **not** in this list because it is not tested: multi-agent collusion, a compromised dependency in `google-api-python-client`/`kiteconnect` itself, a compromised host machine reading the process's environment variables directly (the gate assumes the boundary between "the agent's reasoning" and "the credentials" is real - if that boundary is broken by something outside this package, the gate has nothing to say about it), and adversarial fuzzing of the YAML parser beyond the malformed/list/unreadable cases above. These are honestly out of scope rather than silently assumed solved.

## Security Model

**Capability classes, not app names.** Every `ToolSpec` in `warrant/registry.py` declares which of ten hazard classes it carries - `write`, `destructive`, exactly one of `reversible`/`irreversible`, `third_party`, `audience`, `spend`, `egress`, `code`, `identity` - and the ten policy rules read those classes instead of an app name. `registry.validate()` runs at import time and refuses to let the package load at all if any tool skips the reversibility pair, declares an unknown class, or is missing the plumbing (`destination_param`, `amount_param`, `idempotency_params`, …) a rule needs to actually grade it. A misconfigured capability is a load-time crash, not a silent gap.

**Fail closed, structurally, not by convention.** Every branch in `policy.check()` that cannot positively establish authorization returns `Verdict(False, ...)`:

- No `policy.yaml` on disk -> refused (`policy_missing`). Nothing in the package writes this file - `test_policy_adversarial.py::test_policy_file_is_never_written_by_the_package` walks the source and fails if any module does, and `policy.yaml` is gitignored so a fresh clone starts with zero authority.
- Unreadable or malformed YAML -> refused (`policy_unreadable` / `policy_malformed`), not "treated as empty and therefore permissive."
- A rule the policy names that this build does not implement -> refused (`unknown_rule`), rather than silently enforcing less than the file claims.
- A ledger that cannot be read to check a spend/rate/audience cap -> refused, not "assume zero and allow."
- Missing or wrong-shaped trust-anchor facts (`ThreadFacts` for email, `KiteFacts` for Kite) -> refused, never treated as "nothing to object to."
- An unresolved prior attempt at the identical action (see the retry threat above) -> refused, not retried.

**No override parameter exists anywhere in the call chain.** `Broker.execute(proposal)` and `policy.check(proposal, facts, ledger)` take exactly those arguments - no `confirmed`, `force`, `dry_run`, or `admin`. This isn't a documented convention the code happens to follow; `test_structure.py::test_no_module_exposes_a_bypass_parameter` and `test_policy_adversarial.py::test_check_exposes_no_bypass_parameter` assert it directly, and a proposal carrying a `confirmed: true` param is rejected as `unknown_param` rather than accepted and ignored.

**The kill switch is checked first, before the policy is even parsed**, so "stop everything now" still works when the policy file is the thing that's broken.

**Idempotency is a property of effect, not of the call.** `idempotency_key()` hashes the tool, thread, and a canonicalized subset of params drawn from each tool's `ToolSpec.idempotency_params` - address lists sorted and normalized, so `to: [a, b]` and `to: [b, a]` collapse to the same key, and a reworded `rationale` never changes it.

## Evaluation / Benchmarks

- **359 tests passing**, verified by running `python -m pytest tests/ -q` against this checkout at the time this README was written (`359 passed in 8.79s`, re-run 2026-09-26). This spans structural invariants (`test_structure.py`), the full adversarial policy suite (`test_policy_adversarial.py`), the five reliability findings (`test_reliability.py`), registry self-consistency (`test_registry.py`), and the new Kite mandate rule specifically (`test_policy_kite_mandate.py`, `test_broker_kite_facts.py`).
- **Mutation testing: 23/23 mutations killed** (`scripts/mutate.py`), one per load-bearing property: ten for the original rule set (gate-advisory, normalise-and-send, fail-open-on-missing-policy, ignore-kill-switch, trust-unknown-params, destination-allowlist-membership-not-checked, spend-cap-ignores-per-action-limit, irreversible-gate-open-by-default, audience-bound-uncapped, ambiguous-retry-not-refused), four for the delegation layer, and nine for `_rule_kite_mandate` - which proposals it claims, missing facts, the kill switch, a missing llmfin, a discarded verdict, and each fact it must take from `KiteFacts` rather than the proposal (price, today's value, today's count, the mandate). **Honestly noted:** six of the nine kite mutants are each killed by exactly one test, four of them by the same argument-capture test, so that coverage is real but thin.
- **55/55 hand-written evaluation cases passed** (`eval/cases/*.yaml` -> `EVAL.md`, artifact `artifacts/eval_20260926T100055Z.json`): 10/10 expected-allow, 45/45 expected-deny, 0 actions reaching a fake app client without the case budgeting for one. Eleven are the delegation cases (`eval/cases/delegation.yaml`), which declare their chain as data - `agent_classes: [write]` against `expect.rule: delegation_capability` is readable without opening any Python. Fifteen are the Kite cases (`eval/cases/kite.yaml`), which run the **real** `llmfin.risk.check_order` rather than a stand-in: warrant does not depend on llmfin, so the harness loads `risk.py` from finLM's source with only its data-store import stubbed, and fails the cases (never skips them) if no usable copy exists. Each Kite refusal is pinned to its reason with `reason_contains`, since the rule reports every mandate breach under the one id `kite_mandate`.
- **Live integration: 8/8** against real Gmail, Calendar, and Notion, each write independently read back (`artifacts/smoke_20260913T194858Z.json`, via `scripts/smoke.py`). This is the only number in this section backed by a real external service; every other number above runs against fakes.
- **The evaluation checks ledger state, not status strings.** A refusal case fails if an action reached a fake app client even when the returned status string was correct - a gate that refuses and then acts anyway is worse than one that does neither.

## Failure Cases

Two real, since-fixed bugs are documented directly in the source and covered by regression tests - not retrofitted from memory, both are in the git history and in `policy.py`'s own comments:

**Unicode/homoglyph laundering (fixed).** `recruiter@bright<ZWSP>lane.io` (a zero-width space embedded in the local part) normalized under NFKC to `recruiter@brightlane.io`, which *is* a legitimate thread participant - so a membership check against the normalized form passed, and the broker then sent to the **raw** string, a different, attacker-controlled mailbox. The fix, documented in `_rule_recipient_scope`'s own comment block, was to make normalization detection-only: an address that changes under normalization is refused rather than repaired-and-sent. Regression tests: `test_policy_adversarial.py::test_address_that_normalises_to_a_participant_is_still_refused` and three related cases.

**`body_containment`'s window was unreachable for short threads (fixed).** The verbatim-quote detector compared a fixed 120-character sliding window against the thread body; a body shorter than 120 characters could never trip the rule at all, meaning a *short* email pasted wholesale into a calendar invite description was allowed while a long one was refused - backwards, since a short pasted line like "comp band is 180-220k, keep this confidential" is exactly the leak this rule exists to catch. Fixed by clamping the window to `min(configured_window, len(body))`. Regression test: `test_policy_adversarial.py::test_short_thread_pasted_wholesale_is_still_refused`.

Beyond these two, and the five items tracked formally in `EVAL_MATRIX.md` (ambiguous-retry duplication, workflow-crash resume, policy-edit-mid-run, injection resistance, single-proposal audience fanout - two were real gaps and are now fixed, two were already correct and only lacked proof, one is correct by construction), failure discovery here is **not systematically documented**. There is no changelog of every bug found during development; what's stated above is what is actually traceable to a comment, a test name, or `EVAL_MATRIX.md` - not a claim that these are the only two bugs this project ever had.

## Design Decisions

**Kite's spend/risk logic delegates to `llmfin.risk.check_order()` instead of being reimplemented natively in `policy.py`.** `_rule_kite_mandate` is a thin adapter: it builds `KiteFacts` into the exact keyword arguments `check_order()` expects and returns its verdict's reasons. The alternative - porting NFKC symbol normalization, the `PRICE_BINDING_ORDER_TYPES` carve-out (a MARKET order's value isn't a real number until fill, so a caller-claimed price for one can't be trusted the way a Stripe refund amount can), and the empty-mandate-means-unrestricted semantics into a second, warrant-native implementation - was rejected because it would re-derive logic that has already been adversarially tested once, in a different codebase, and every future fix to that logic would then need to land in two places or drift. The cost of this decision is real: warrant's own test suite cannot exercise the actual risk arithmetic, only that delegation happens correctly with the right inputs (see `test_check_order_receives_the_facts_derived_values_not_the_proposals_own_claims`, which pins exactly what crosses the boundary).

**The Kite rule fails closed if `llmfin` isn't installed**, rather than falling back to some local approximation. `warrant`'s own dependency list (`pyproject.toml`) does not include `llmfin` - it is deliberately not a hard dependency of this package - and `test_llmfin_not_importable_fails_closed` pins the *actual* current behavior of this repository's own test environment: `llmfin` genuinely is not importable here, and the rule refuses every kite proposal as a result rather than silently no-opping. The alternative (treating an ImportError as "no rule configured, allow") would turn a missing dependency into an open trading gate.

**Kite credentials are never resolved through the same lazy-import path every other app uses.** For the other ten apps, `Broker._client()` falls back to `importlib.import_module(f"warrant.apps.{module}")` on first use if no client was passed in. Kite credentials are tenant-scoped and live in per-tenant Postgres rows, not a static module-level session the way `warrant.auth`'s other functions read one shared env var - so there is no valid default Kite client, and `warrant/apps/kite.py::place_order` exists only to keep the registry's signature-consistency checks (`test_registry.py::test_registry_param_names_are_a_subset_of_the_real_functions_params`) honest for kite the same way they are for the other ten; the function itself raises loudly if ever actually reached. The platform layer is required to construct `Broker(apps={"kite": <tenant's authenticated client>})` explicitly - a decision to fail loudly on a missing explicit wiring rather than silently succeed with the wrong tenant's session, or no session at all.

**`journal.py` and `ledger.py` are two separate stores, not one.** The journal records *decisions* (a claim about intent, including every refusal); the ledger records *effects* (a fact about the outside world, used only for rows the broker actually executed). Two rules need facts, not claims: a daily rate cap is unanswerable from "the gate approved a send" if a crash between approval and execution would otherwise inflate the count forever, and idempotency needs a record of what actually happened, not what was decided. Collapsing these into one table would make it impossible to tell "refused ten times" from "executed ten times" by querying decision rows alone.

**No expression language in `policy.yaml`.** Rules are dispatched by name from a fixed table (`RULES` in `policy.py`) rather than the YAML containing conditions the code evaluates generically. A policy file that can compute is a policy file that can be talked into computing something its author didn't intend; a fixed vocabulary of named rules stays legible to the human who has to sign off on it without reading Python.

## Running Locally

Verified against this checkout (Python 3.10+, per `pyproject.toml`'s `requires-python`):

```bash
pip install -r requirements.txt
python -m pytest tests/ -q          # 359 passed, ~5s, no credentials or network needed
```

Everything above runs with no external account: the tests construct their own `Ledger`/`Journal` against `tmp_path`, monkeypatch `policy.POLICY_FILE` to a scratch file per test, and exercise the app layer through `warrant.fakes`, never a real client.

To go further:

```bash
python scripts/mutate.py            # break the gate on purpose, confirm the tests notice (23/23 currently)
python eval/run.py                  # 55 hand-written cases -> EVAL.md + a stamped artifact in artifacts/
python demo/demo.py                 # ~70s scripted scenario, no credentials, no network
python scripts/serve.py             # local console at http://127.0.0.1:8000 (requires the `console` extra: pip install -e ".[console]")
```

For the three live-verified apps (optional, requires real credentials):

```bash
cp .env.example .env                # fill in NOTION_API_KEY, WARRANT_SMOKE_PARENT, and the Bedrock/AWS vars
python -m warrant.auth               # one-time OAuth consent flow for Gmail + Calendar (writes token.json)
python scripts/smoke.py              # exercises real Gmail/Calendar/Notion, reads every write back independently
```

Nothing in the package will create `policy.yaml` for you - write one by hand (start from the rule tables in `warrant/policy.py`'s docstrings, or the shapes exercised in `tests/test_policy_adversarial.py`) before proposals can be authorized at all; a fresh clone refuses every action until you do.

**What I did not independently re-verify for this README:** the live Gmail/Calendar/Notion smoke path (`scripts/smoke.py`) and the console (`scripts/serve.py`) require real credentials (a Google OAuth token, a Notion integration secret, AWS Bedrock access) that were not exercised while writing this document. The pip-install-and-test path above *was* run against this exact checkout. The `google`/`console` extras in `pyproject.toml` were read but not installed and smoke-tested here.

## Roadmap

Honesty first: **`liveness` in `warrant/registry.py` is a field every other layer reads, not a marketing claim made once in this file.** `PROVEN_LIVE` requires a named evidence artifact (`registry.validate()` fails the build otherwise); `FAKE_ONLY` requires a stated reason. Both are enforced at import time, not just written in this document.

### Implemented and live-verified
- **Gmail** (`gmail.send`) - proven-live, `artifacts/smoke_20260913T194858Z.json`, 8/8 writes read back independently.
- **Google Calendar** (`calendar.create_event`) - proven-live, same artifact.
- **Notion** (`notion.create_page`) - proven-live, same artifact.

### Implemented, tested, and honestly fake-only (real HTTP/SDK adapter exists, real signature-matching fake exists, never run against a live account)
- **Slack** (`slack.post_message`, `slack.upload_file`) - no workspace to install a bot into.
- **GitHub** (`create_issue`, `create_pull_request`, `merge_pull_request`, `add_collaborator`) - no repository this project is allowed to write to.
- **Linear** (`create_issue`, `update_issue`) - no workspace.
- **Stripe** (`create_refund`, `create_payout`) - deliberately not even wired to a test-mode sandbox key; a spend cap exercised only against a sandbox is untested against the thing it bounds.
- **Twilio** (`send_sms`) - no account; the one tool that both spends money and reaches a stranger's phone in the same call.
- **Google Drive** (`upload_file`, `share_file`) - the cached OAuth token carries only Gmail/Calendar scopes; widening it for Drive would invalidate the one live-verified Google token this repo has.
- **Google Sheets** (`append_row`, `clear_range`) - same scope reason as Drive.
- **Kite / Zerodha** (`place_order`) - **the newest addition (commit `36991a2`)**. Real capability classes (`write`, `spend`, `irreversible`), a real registry entry, a real gate rule (`_rule_kite_mandate`) that delegates to `llmfin.risk.check_order()`, and dedicated end-to-end tests through the real `Broker.execute()` with a fake Kite client. **This has never been exercised through warrant's own gate against a real Kite Connect account or a real market.** `llmfin`'s own Kite OAuth/order-placement path is separately claimed live-verified for a single operator in a different project (finLM), but that is a different codebase and a different evidence trail from this one - it does not make `kite.place_order` in *this* registry live-tested. Treat this integration as proof the capability-class abstraction extends cleanly to a domain with no email thread, real money, and externally-fetched live pricing - not as proof the trading path works end to end against a live broker.

### Implemented, and off by default until an operator turns it on
- **Delegated authority** (`warrant/identity.py`) - principals, macaroon-style chained-HMAC grants, offline attenuation, expiry, and revocation over the existing capability classes, with 80 adversarial tests. Everything about it is exercised in-process: the amplification defence is tested against correctly-signed widening chains and the forgery defence against perfectly-attenuating forged ones, so neither can pass by leaning on the other. It reaches the real gate (`policy.check`) and the real journal through `Broker.execute()`.

  **It now has a real caller.** [`finLM-platform`](https://github.com/hasil7677/finlm-platform) delegates `service:finlm-platform -> tenant:<id> -> agent:execution:<id>` on every order it gates, with the execution agent attenuated to the single tool `kite.place_order` and a research-scoped role that structurally cannot trade (its grant omits `spend`, which `kite.place_order` requires). That closes the "verified mechanism, no demonstrated caller" gap this entry used to record.

  What is still *not* demonstrated: nothing in **this** repo's own demo/workflow/agent path builds a chain, and the platform's agents are processes the platform itself spawns rather than independent ones holding their grants over time. So "a holder can delegate downward offline, mid-run" remains an argument from the construction (delegation needs only the parent grant, never the root secret) rather than something a long-lived multi-agent system has exercised. `delegation:` stays opt-in in `policy.yaml` accordingly.

### Experimental / partially proven
- **The five reliability findings** (`EVAL_MATRIX.md`): ambiguous-retry handling and workflow-crash resume were real gaps that are now fixed and covered by targeted tests; two others were already correct and only lacked proof; one (injection resistance) is correct by construction rather than by a specific test scenario. All five are narrower than a general reliability guarantee - see the honesty notes at the bottom of `EVAL_MATRIX.md` for the specific limits of finding 4 and finding 5.
- **The evaluation harness (`eval/`)** covers delegation (11 cases, including a forged chain and a correctly-signed amplifying one) and `kite_mandate` (15 cases against the real llmfin arithmetic) as well as the original rule set. What it cannot say about Kite is anything about a real Kite account - the client under the gate is still `FakeKite`.
- **Mutation testing (`scripts/mutate.py`)** covers twenty-three load-bearing properties, 23/23 killed. Four are the delegation layer's, and they are separate mutations on purpose: `attenuation-not-rechecked` and `chain-signature-not-verified` disable the two defences independently, so a refactor that deleted either could not hide behind the other. Nine are the Kite adapter's; the arithmetic behind it is llmfin's and is mutation-tested there, not here.

### Planned / not built
- An agent in *this* repo that holds and attenuates a grant. `finLM-platform` is now a real caller (it delegates `service:finlm-platform → tenant:<id> → agent:execution:<id>` on every order), but nothing in warrant's own demo/workflow path builds a chain yet.
- Persistent, revocable *sessions* as first-class principals - `session` is a valid principal kind today, but nothing mints session-scoped grants or expires them on logout.
- Live verification of `kite.place_order` against a real Kite Connect sandbox or account, with an independent read-back the way `scripts/smoke.py` does for Gmail/Calendar/Notion.
- Anything beyond the eleven apps currently in `registry.py` - adding app twelve is meant to require a `ToolSpec` and a client, not a new policy rule, but that claim itself is only as strong as the next integration that actually tests it.

## What this is not

- **Not a guarantee about real API behavior from the test suite alone.** 359 tests and 55 eval cases run against fakes whose method signatures are asserted to match the real clients (`test_registry.py::test_fake_matches_real_client_signature_for_every_tool`). That proves the fakes are shaped like the real clients; it does not prove the real clients behave as expected under real network conditions, rate limits, or partial outages. Only `scripts/smoke.py`'s 8/8 (Gmail, Calendar, Notion) is evidence about a real API.
- **Eight of eleven apps have never made a real call**, Kite included. Each has a real adapter written against its documented API and a fake with an asserted-matching signature - neither is a substitute for a live run, and this README does not claim otherwise.
- **Not a model evaluation.** The eval harness supplies proposals directly with no model in the loop, by design - the gate's correctness must not depend on the model behaving well, so it is measured without one. `test_reliability.py`'s injection tests are the one place a (stubbed) model backend runs through the loop, and only to prove the gate holds regardless of what it does.
- **Not an estimate of behavior on arbitrary traffic.** Every adversarial and eval case is hand-written against a specific failure mode the policy was designed for. That is a statement about those modes, not a statistical sample.
