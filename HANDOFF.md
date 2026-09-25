# warrant handoff — 2026-09-25 (Warrant 2.0 §4: the delegation layer)

Read this whole file before touching anything. It exists so a fresh session
(new machine, no chat history) can pick this repo up cold.

`README.md` is the argument — what this project claims and why. This file is
the state: what changed last, what is unpushed, and the three things that
will waste your time if you don't know them.

**One-line status:** the Warrant 2.0 delegation layer is built, tested
(344 passing), committed as `9a2e7f5`, and **not pushed**. It is off by
default and nothing in this repo calls it yet.

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

3. **Nothing in this repo actually uses the delegation layer.** No agent,
   workflow, demo, or server route builds or attenuates a grant
   (`grep -rn "attenuate" warrant/agent.py warrant/workflow.py server/ demo/`
   → nothing). The mechanism is verified; a caller is not. The README's
   roadmap says this explicitly and it should stay said.

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
- **`eval/run.py` and `scripts/mutate.py` do not cover `identity.py`**
  (verified: no reference to `identity` or `delegation` in either
  directory). So the layer inherits the same caveat the Kite rule has — the
  tests would catch a broken attenuation check because they were written
  to, not because a surviving mutant proved they would. The eval harness's
  29/29 headline number says nothing about delegation.
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

## Publish state — nothing is pushed

Sahil holds the publish moment himself. As of the end of this session:

| repo | state |
|---|---|
| `warrant` | **1 commit ahead** of `origin/main` (`9a2e7f5`). Remote: `github.com/hasil7677/warrant` |
| `finLM` | `6a2ee73` unpushed (remote is at `838f47d`) |
| `finLM-platform` | 4 local commits, **no remote configured** |

**Order matters for the other two.** `finLM-platform` pins `finLM/` as a
submodule at `6a2ee73`, so `finLM` must be pushed first or the submodule
reference won't resolve for anyone cloning it. `finLM-platform` needs a
**new** repo — it cannot be pushed into `finLM`'s, since that would be a
repo containing itself as a submodule.

```bash
cd finLM && git push origin main
cd .. && gh repo create finLM-platform --public --source=. --push
cd ../warrant && git push origin main          # independent of the other two
```

`warrant` has no ordering dependency on the others and can go any time.

---

## Related work in the same session

`finLM-platform` got tenant onboarding / key rotation / revocation
endpoints, an a11y fix, and a documentation pass — see
`../finLM-platform/handoff.md`, which has its own 2026-09-25 section.
Nothing there consumes this delegation layer yet, but it is the natural next
integration: the platform already builds a per-tenant `Broker`, which is
exactly where a chain would go.
