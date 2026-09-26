# warrant handoff — 2026-09-25 (Warrant 2.0 §4: the delegation layer)

Read this whole file before touching anything. It exists so a fresh session
(new machine, no chat history) can pick this repo up cold.

`README.md` is the argument — what this project claims and why. This file is
the state: what changed last, where it is published, and the three things
that will waste your time if you don't know them.

**One-line status:** the Warrant 2.0 delegation layer is built, tested
(359 passing, 55/55 eval cases, 23/23 mutations killed), pushed, and in real
use by finLM-platform. It is off by default — `policy.yaml` decides whether a
chain is required.

---

## Read these three gotchas first

1. **`policy.yaml` is gitignored and untracked.** A commented-out
   `delegation:` block was added to the local copy on this machine
   documenting how to turn the layer on. **It is not in the repo and a
   clone will not have it** — that is by design (a fresh clone must refuse
   every action until a human writes a policy), but it means the
   turn-it-on instructions live in `README.md` §Delegation, not in a file
   anyone inherits. If you rewrite `policy.yaml`, you will silently lose
   that block.

2. **No root secret exists on this machine.** `WARRANT_ROOT_SECRET` is not
   set and is not in `.env`. Nothing is broken by this — with the
   `delegation` rule commented out, the layer is never consulted — but if
   you uncomment it without generating a secret first, every action starts
   refusing with `delegation_unconfigured`. That is the intended
   fail-closed behaviour, not a bug.

3. **Nothing in THIS repo uses the delegation layer — but finLM-platform
   does.** No agent, workflow, demo, or server route here builds or
   attenuates a grant (`grep -rn "attenuate" warrant/agent.py
   warrant/workflow.py server/ demo/` → nothing). The real caller lives in
   [`finlm-platform`](https://github.com/hasil7677/finlm-platform), at
   `api/src/finlm_api/delegation.py`: it delegates
   `service:finlm-platform → tenant:<id> → agent:execution:<id>` on every
   order it gates. If you change `identity.py`'s public surface, that is
   what breaks.

---

## What was built (commit `9a2e7f5`)

Roadmap §4 of `../FinLM_2_Warrant_2_Flagship_Roadmap.md` asks Warrant to
become the security layer of FinLM 2.0, answering:

> Is **this** agent allowed to perform **this exact action**, in this exact
> context, **on behalf of this exact user**?

Before this commit, `policy.check()` could answer the first half and had no
vocabulary at all for the second. A `Proposal` carries a tool and params,
not a principal — so the research agent that may only read and the
execution agent that may place an order were the same anonymous caller
wearing the same `policy.yaml`.

### What of §4 already existed, and was left alone

Worth knowing so you don't rebuild it. `registry.py` already had the
**capability-class taxonomy** (`write`, `destructive`, `irreversible`,
`third_party`, `audience`, `spend`, `egress`, `code`, `identity`) tagged
onto every tool, and the policy rules already reasoned about classes rather
than app names. §4's "Capabilities" bullet was substantially already done.
`journal.py` covered auditability; fail-closed was already the house style
throughout.

What was genuinely absent: **Identity, Delegation, Revocation**, and the
"who → acting as whom" half of auditability. That is the scope of this
commit. Grants are scoped in the *existing* class vocabulary rather than a
parallel one — a grant carrying `{write}` authorizes exactly as much after
app sixteen ships as before, because the new app's hazards are declared in
the registry and the subset check picks them up for free.

### The two mechanisms, and why there are two

Two distinct failure modes hide in "delegate without accidentally granting
more than you possess", and they need different defences. Conflating them
is how capability systems get this wrong:

| | What it looks like | What stops it |
|---|---|---|
| **Amplification** | A holder mints a child claiming more than it holds. Every signature valid, nothing forged. | The attenuation check, re-derived on **every link at verification time** |
| **Forgery** | A grant fabricated or edited after issue. May attenuate perfectly. | The chained MAC |

A system with only the first is bypassed by writing your own chain. A system
with only the second lets any holder issue itself a superset.

**In `tests/test_identity_delegation.py`, each is tested with the other
disabled.** The `resign()` helper re-seals a hand-built malicious chain so
every MAC verifies — which removes the forgery defence entirely, leaving
attenuation as the only thing that can refuse it. The forgery tests use
chains that would sail through every attenuation check. This is deliberate
and load-bearing: a suite that only ever tests them together cannot tell you
which one is doing the work, and a refactor that silently removed one would
keep passing. **Do not "simplify" `resign()` away.**

### The MAC construction

```
root grant:   sig = HMAC(root_secret, canonical(body))
child grant:  sig = HMAC(parent.sig,  canonical(body))
```

Macaroons (Birgisson et al., 2014). A holder of grant `G` knows `G.sig`,
which is exactly the key needed to mint a child of `G` — so delegation is
offline, with no round trip and no secret the holder was not already given.
It cannot mint a sibling, a parent, or a fresh root, and editing an ancestor
invalidates every descendant because each link's key *is* the previous
link's signature.

The alternative — signing everything with the root key — would require the
root secret at every delegation point, i.e. giving every agent the ability
to mint anything.

`authorize()` checks the **leaf** grant, never the root and never the union.
Checking either would silently hand a sub-agent its delegator's powers,
which is the entire thing being prevented.

### Files

| File | Change |
|---|---|
| `warrant/identity.py` | **new**, 881 lines. Principals, `Grant`, `attenuate`, `verify_chain`, `authorize`, `Revocations`, `load_revocations` |
| `tests/test_identity_delegation.py` | **new**, 65 tests in eight sections (§A amplification … §H integration) |
| `warrant/policy.py` | `check()` gains `chain`; `_evaluate_delegation`; `CHECK_LEVEL_RULES` |
| `warrant/journal.py` | three new columns by `ALTER TABLE`; `_chain_fields` |
| `warrant/broker.py` | `Broker(chain=...)`, threaded to `policy.check` and every `log_decision` |
| `tests/test_policy_adversarial.py` | the parameter-guard test updated, plus one new guard |
| `warrant/policy.py` (later) | `_bind_chain_to_facts` — a verified chain must be the chain for the account the facts describe |
| `warrant/identity.py` (later) | `AuthorityVerdict.subjects` — the two ends aren't enough; a multi-tenant chain names its tenant in the middle |
| `warrant/identity.py` (later) | `load_revocations_sqlite` — a revocation store a host can drive from an API, without a code-execution plugin point |
| `eval/cases/delegation.yaml` | 11 declarative cases, including `tamper: forge` and `tamper: amplify` |
| `scripts/mutate.py` | 4 delegation mutations, each disabling one defence independently |
| `README.md` | new §Delegation; roadmap and test count updated |

---

## Decisions that will look wrong until you know why

**`chain` is a parameter of `check()`, and `check()`'s whole thesis is that
it has no parameters a caller can use to soften the answer.**
`test_check_exposes_no_bypass_parameter` failed when this was added, and it
was updated deliberately rather than loosened. `chain` is admissible on
exactly one ground: it can only ever **narrow**. When `policy.yaml` does not
name `delegation` it is never read; when it does, `chain=None` is a refusal
— so there is no value, the default included, that switches the check off.
Two tests assert that property directly rather than leaving it to a
docstring.

**The root secret, the clock, and the revocation list are deliberately NOT
parameters.** A `secret=` would let the governed layer verify against a key
it chose; a `now=` would let it claim an expired grant is current; a
`revocations=` would let it pass an empty list and have every revoked agent
work again. All three are read from the operator's environment and files.
`test_no_operator_authority_is_a_parameter` is what keeps that true — it
exists because each one is individually tempting (they all make testing
easier) and each one individually voids the guarantee.

**`delegation` is evaluated inline in `check()`, not through the `RULES`
table.** Every rule in that table takes `(proposal, facts, cfg, ledger)` and
none of those carries a chain; widening the signature for one rule would
make every other rule's parameter list a lie about what it reads.
`CHECK_LEVEL_RULES` records the exemption so the "policy names a rule this
build does not implement" guard doesn't fire, and
`test_check_level_rules_are_all_handled_by_check` asserts the set stays in
sync — a name added there without a matching branch would become a policy
rule the operator wrote and the gate silently skipped.

**Revocation is a file, not an argument.** Same shape as the kill switch,
same reason: a revocation list the governed layer hands in is a list it can
hand in empty. `.warrant/revoked-grants.txt`, one id per line, `#` comments
allowed, `WARRANT_REVOCATIONS_FILE` to relocate. A *missing* file means
nothing revoked; an *unreadable* one raises, because "this exists and I
couldn't read it" must never round down to "nothing is revoked".

**Grant signatures are never written to the journal.** A sig is the key that
mints children — a journal holding them would be an audit file that confers
authority. Only ids are stored, and there is a test asserting the raw sig
bytes do not appear in the DB file.

**`reversible`/`irreversible` are excluded from the grant/tool comparison.**
They are properties of an action, not hazards to be conferred, and
`irreversible_gate` already governs them. Including them would mean every
grant had to list `reversible` to permit anything at all, which teaches
holders to list classes they haven't thought about.

---

## Verify it yourself

```bash
cd warrant
python -m pytest -q                              # 344 passed
python -m pytest tests/test_identity_delegation.py -q   # 65 passed
```

The mutation worth re-running if you touch `verify_chain` — delete the
class-subset re-check and confirm §A fails:

```bash
# in verify_chain(), remove the `widened = sorted(grant.classes - parent.classes)` block
python -m pytest tests/test_identity_delegation.py -q
```

Run on 2026-09-25, this gives **3 failed, 62 passed**:

```
test_a_hand_built_wider_child_is_refused_even_though_it_is_correctly_signed
test_a_grandchild_cannot_recover_a_class_its_parent_dropped
test_a_refused_delegation_is_journalled_with_the_chain_that_was_claimed
```

The third is the §H integration test and it failing is correct — it drives
an amplifying chain through `Broker.execute()` and asserts the app is never
reached, so it depends on the same check.

If those still pass after the deletion, the suite has stopped being
load-bearing and something has gone wrong with `resign()`.

The equivalent mutation was also run against `finLM-platform`'s
`onboarding.py` (deleting the `tenant_id = :tenant_id` predicate from
`revoke_key`, which fails 2 tests) — see that repo's handoff.

---

## What is NOT done

- **No in-repo caller.** See gotcha 3. "Usable by an agent mid-run" is an
  argument from the construction (delegation needs only the parent grant,
  never the root secret) — not something a running system has demonstrated.
- **The kite mutations are thinly killed.** All nine die, but six of them
  (`kite-kill-switch-ignored`, `-fails-open-without-llmfin`,
  `-prices-from-the-proposal`, `-daily-value-not-carried`,
  `-daily-count-not-carried`, `-mandate-not-the-tenants`) are each killed by
  exactly one test - four of them by the same capture test in
  `test_policy_kite_mandate.py`. The eval cases catch them too, but
  `mutate.py` only runs pytest, so that second net is not what the 23/23
  counts.
- **The SQLite revocation store is read-only and local.** A host on Postgres
  has to project its revocations into a SQLite file warrant reads
  (finLM-platform does exactly this). That works, and it means a
  multi-instance deployment needs the projection on each instance or a
  shared volume — there is no networked revocation store and no cache
  invalidation protocol.
- **Sessions are a principal kind with no implementation.** `session` is
  valid in `PRINCIPAL_KINDS`, but nothing mints session-scoped grants or
  expires them on logout.
- **§4's "context-aware authorization" bullet is only partly addressed.**
  Tenant, agent identity, parent agent, delegation chain, tool, action and
  requested parameters are all now reachable by the gate. *Risk level* and
  *environment* as first-class policy inputs are not built.
- **No key/secret rotation story for `WARRANT_ROOT_SECRET`.** Rotating it
  invalidates every outstanding chain at once, which is correct but abrupt;
  there is no dual-secret grace window.

---

## 2026-09-26 — kite_mandate coverage

`_rule_kite_mandate` was the one load-bearing rule with no eval cases and no
mutation. It now has both:

| File | Change |
|---|---|
| `eval/cases/kite.yaml` | **new**, 15 cases (2 allow, 13 deny): every cap, the kill switch, no quote, no mandate row, no facts, llmfin absent, and a MARKET order claiming price 1 to fit the cap. Each deny pins its reason with `reason_contains`, because the rule reports every mandate breach under one rule id |
| `eval/fixtures/kite_policy.yaml` | **new**, `kite_mandate: {}` and nothing else |
| `eval/run.py` | `kite:` block → `facts_providers["kite"]`; `llmfin: absent`; `expect.reason_contains`; loads the **real** `llmfin.risk` |
| `scripts/mutate.py` | 9 kite mutations - which proposals the rule claims, missing facts, kill switch, missing llmfin, a discarded verdict, and each fact the adapter must take from `KiteFacts` rather than the proposal |

**How the eval gets a real `check_order` without warrant depending on
llmfin.** An installed llmfin is used as-is. Otherwise `risk.py` is loaded from
`../finLM-platform/finLM/src` (override: `WARRANT_EVAL_LLMFIN_SRC`) with only
`llmfin.data_store` stubbed - it exists to locate the operator's own order
ledger, which every case bypasses by injecting the tenant's counters, and the
real one imports pandas. A copy that predates the `injected_mandate` family of
parameters is refused, since it would silently read the global mandate file.
No copy found → the kite cases **fail**, they are not skipped. The origin is
written into the artifact and `EVAL.md`.

Checked by breaking it: making the rule discard `check_order`'s verdict took
the eval from 55/55 to 45/55 with 10 orders reaching the fake Kite client.

---

## Publish state — all published 2026-09-25

**One local commit is not pushed:** the kite_mandate coverage above
(2026-09-26). Everything before it is on the remote.

| repo | remote | state |
|---|---|---|
| `warrant` | `github.com/hasil7677/warrant` | `main` at `b080bd4` |
| `finLM` | `github.com/hasil7677/finLM` | `main` at `6a2ee73` |
| `finLM-platform` | `github.com/hasil7677/finlm-platform` | `main`, 4 commits |

`warrant` has no ordering dependency on the other two and went last. The
other two did — `finLM-platform` pins `finLM/` as a submodule at `6a2ee73`,
so `finLM` had to be pushed first or the reference would dangle. It was, and
a clean `git clone --recurse-submodules` afterwards confirmed the submodule
registers, clones, and checks out `6a2ee73`.

That constraint returns any time those repos are re-created or re-pointed.

Note the platform's remote is spelled **`finlm-platform`** (all lowercase)
while the local directory is `finLM-platform`.

---

## Related work in the same session

`finLM-platform` got tenant onboarding / key rotation / revocation
endpoints, an a11y fix, and a documentation pass — see
`../finLM-platform/handoff.md`, which has its own 2026-09-25 section.
Nothing there consumes this delegation layer yet, but it is the natural next
integration: the platform already builds a per-tenant `Broker`, which is
exactly where a chain would go.
