# warrant

**An agent proposes. A declarative policy authorizes. The gate holds the credentials, so the model never does.**

Give an agent tools that send email, page people, spend money, or touch code, and you have a problem no prompt fixes. The standard answer is "the agent asks permission first" - but the agent decides when to ask, phrases the request, and holds the API tokens. That is not a control, it is a request.

`warrant` sits in between. It started as one scenario across three apps: an inbound meeting request gets read, scheduled, logged, and answered across Gmail, Google Calendar, and Notion. It now governs a suite of ten apps - the three above plus Slack, GitHub, Linear, Stripe, Twilio, Google Drive, and Google Sheets - through one policy that reasons about what an action *can do* rather than which app it belongs to. **The gate and the evidence trail are the product.**

## Demo

**▶ [Two-minute demo](https://youtu.be/lKqEVJ_mBDs)** (the original three-app scenario)

Or run it yourself - no credentials, no network, 70 seconds:

```
python demo/demo.py
```

## The suite, and which parts of it are proven

Ten apps, eighteen actions, all reached only through the broker. **Three are proven live**; **seven are fake-only**, and that distinction is load-bearing, not a footnote - it is stated in `warrant/registry.py` as a field every other module reads, not just written here.

| App | Liveness | Evidence / reason |
|---|---|---|
| **Gmail** | proven-live | 8/8 against the real API, every write read back independently - `artifacts/smoke_20260913T194858Z.json` |
| **Google Calendar** | proven-live | same artifact |
| **Notion** | proven-live | same artifact |
| **Slack** | fake-only | no workspace to install a bot into |
| **GitHub** | fake-only | no repository this project is allowed to write to |
| **Linear** | fake-only | no workspace |
| **Stripe** | fake-only, deliberately not even test-mode | a spend cap exercised only against a sandbox is a spend cap nobody has tested against the thing it bounds |
| **Twilio** | fake-only | no account; this is the one tool that both spends money and reaches a stranger's phone in the same call |
| **Google Drive** | fake-only | would need `drive.file` scope, which is not on the one live Google token this repo has evidence behind - widening it would invalidate that token |
| **Google Sheets** | fake-only | same scope reason as Drive |

Every fake-only app still has a real HTTP adapter (`warrant/apps/*.py`, plain `requests`, no SDK, matching how `notion.py` was already written) and a high-fidelity fake (`warrant/fakes.py`) whose method signatures are asserted against the real client's - `tests/test_registry.py::test_fake_matches_real_client_signature_for_every_tool` checks this generically for all eighteen tools, the same property `test_structure.py` used to check by hand for three. What none of the seven has is an account anyone connected. `GET /api/suite` in the console and `warrant.registry.suite_summary()` in code are the two places that table is read from - never re-typed, so the claim in this README, the claim on screen, and the claim the gate acts on cannot drift apart.

```
python scripts/serve.py      # the console -> http://127.0.0.1:8000
python demo/demo.py          # 70 seconds, no credentials, no network
python -m pytest tests/ -q   # 261 tests
python eval/run.py           # 29 cases -> EVAL.md + a stamped artifact
python scripts/mutate.py     # break the gate on purpose, check the tests notice
python scripts/smoke.py      # prove the three real APIs are reachable
python -m warrant.workflow workflows/incident_response.yaml   # run a multi-app workflow
```

## The capability classes

Ten hazards, not ten app names. Each `ToolSpec` in `warrant/registry.py` declares which of these it carries, and the policy rules read the classes instead of the app:

| Class | Means |
|---|---|
| `write` | changes state in the application at all |
| `destructive` | removes or overwrites state that existed before |
| `reversible` / `irreversible` | exactly one is required on every tool - see below |
| `third_party` | the effect lands in front of someone outside the operator's control |
| `audience` | delivers to a set of people the proposal does not enumerate |
| `spend` | moves money |
| `egress` | moves data outside the tenant |
| `code` | changes source, CI, or what runs in production |
| `identity` | changes who can access what |

`reversible`/`irreversible` is the strict pair worth explaining: a tool counts as irreversible if there is no undo that restores the prior state *as observed by everyone who could already have seen it*. A Slack message can be deleted; it cannot be un-read, so posting one is irreversible under this definition - the lenient reading would have let "technically deletable" cover most of the damage an agent can do. `warrant/registry.py::validate()` runs at import time and refuses to let the package load if any tool skips this pair, declares an unknown class, or is missing the plumbing (`destination_param`, `amount_param`, `idempotency_params`, …) a rule needs to actually grade it.

A gate that must learn a new rule for every new app is a gate that rots. `destination_allowlist`, `spend_cap`, `irreversible_gate` and `audience_bound` have never heard of Slack, Stripe or Twilio by name - they read `ToolSpec.classes` - which is what makes app number eleven governed on the day it is added rather than the day someone remembers to write a rule for it.

## The console

`server/` is a local web view of the gate deciding, one proposal - or now, one workflow step - at a time.

The point is not to look at a log. It is to make the *declarative* half of
"declarative policy gate" tangible: **edit a rule in the left pane, save, re-run,
and watch a verdict flip.** Delete `all` from `blocked_local_parts` and the
company-wide cc stops being refused; put it back and it is refused again. No
prompt changed, no redeploy, no model involved - a human edited one line and the
agent's permissions changed. Two header toggles turn on the kill switch or delete
the policy file, and both turn the entire run red, legal actions included.

A **live toggle** points Gmail, Calendar and Notion at real accounts instead of fakes; the header says which set is in use at all times. The other ten apps stay fakes regardless of the toggle - there is no live credential for the toggle to point them at, and the console does not pretend otherwise. In live mode the scripted scenario only acts on a thread whose sole participant is you, so it cannot reach a third party even if the policy were edited to allow it.

**The suite panel** lists all ten apps with a liveness dot - green for proven-live, amber for fake-only - read straight from `GET /api/suite`, which returns `warrant.registry.suite_summary()` unmodified.

**The workflow runner** lets you pick one of the shipped example workflows and watch it run step by step, the same SSE-streamed one-verdict-at-a-time view the scripted scenario already had, generalized to a multi-step, multi-app run. A halted or branched workflow is shown as such - a step after a halt is marked "never attempted", not folded into the ones that were refused.

You can also **describe a rule change in plain English** and a model drafts the
YAML. It lands in the editor with a diff, and it is not saved. You read it and
press Save: the model proposes, a human authorizes, exactly like the agent and
the gate one level down. A policy the agent can write for itself is not consent.

That review step is not a formality. Asked to block a domain the rules cannot
express, `mistral-7b` added it to `allowed_domains` and labelled the line
"block emails to this domain" - the exact opposite, stated confidently.
`mistral-large-3` left the policy alone and named the rule that would actually
be needed. The diff is what makes the difference visible.

The console cannot bypass the gate. Every action - and every workflow step -
goes through `Broker.execute` exactly as the CLI and the tests do, there is no
override control, and edits land in a per-session sandbox rather than the
repo's `policy.yaml`.

Start it with `scripts/serve.py` rather than bare `uvicorn`: uvicorn will not
replace a process already holding the port, and silently leaves the old one
serving while every health check still returns 200.

---

## The shape

```
   agent  ──proposes──▶  broker  ──asks──▶  policy.yaml        (a human wrote this)
 (no creds)                 │                    │
                            │              Verdict(allowed, reasons, rule_ids)
                            │                    │
                            ▼                    ▼
                     holds the tokens      journal.db  (every decision, refused or not)
                            │
                            ▼
              Gmail / Calendar / Notion / ...ten more, same boundary
```

Three properties carry the whole design, and each one is a test rather than a claim:

**1. `Broker.execute()` takes a `Proposal` and nothing else.** There is no `facts` parameter, no `policy` parameter, no override flag. A caller who could supply facts could fabricate the very thing the gate checks proposals against - which would turn `recipients ⊆ participants` into a statement about two things the model wrote. The broker reads the thread itself, from the `thread_id`, before the gate runs. The model chooses *which* thread to act on; it does not get to say what is in it. This holds for a workflow step exactly as it holds for a lone proposal - `warrant/workflow.py` never talks to an app client, it calls `broker.execute()` once per step.
→ `tests/test_structure.py::test_broker_execute_takes_only_a_proposal`

**2. Only the broker can reach an app client.** `warrant/auth.py` is the only module that reads a credential, and `warrant/broker.py` is the only module that imports `warrant.apps.*` - all ten of them, real or never-yet-called. Every other module is checked by an AST walk over the package. Without that check, "the model never holds credentials" would be a convention someone breaks in a hurry at 2am.
→ `tests/test_structure.py::test_only_the_broker_imports_app_clients`

**3. It fails closed.** No `policy.yaml` → every action refused. Unreadable YAML → refused. A thread that cannot be read → refused, because "I could not verify" and "it is fine" are different answers and only one of them is safe. `policy.yaml` is **gitignored**: a fresh clone of this repo refuses everything until a human writes one. Shipping a default policy would be shipping consent nobody gave.

There is no parameter anywhere in the package that lets the model vouch for itself. A proposal carrying `confirmed: true` is refused as `unknown_param` - the flag is not disabled, it was never a field.

---

## The policy

Ten rules, dispatched by name from `policy.yaml`. Not an expression language - a rule is a named Python function the YAML switches on, so the file stays readable by someone who does not write Python. Six generalize across every tool the registry declares a matching shape for; two stayed narrow because the thing they govern (an email thread's text, a Notion parent this project has live credentials for) is genuinely app-specific; four are new and reason about a capability class rather than an app.

| Rule | Catches | Reasons about |
|---|---|---|
| `recipient_scope` | recipients not on the thread the broker read | any tool with `scope="thread"` and email recipients |
| `domain_allowlist` | addresses outside the permitted domains | any tool with `recipient_kind="email"` |
| `no_distribution_lists` | `all@`, `everyone@`, `team@` | any tool with `recipient_kind="email"` |
| `body_containment` | thread text pasted into a calendar invite that goes to external attendees | `calendar.create_event` specifically - see its docstring for why this one stayed narrow |
| `notion_parent_allowlist` | writes to any Notion page but the allowlisted one | `notion.create_page` - grandfathered from before the registry existed |
| `destination_allowlist` | writes to any Slack channel, GitHub repo, Stripe payment intent, … that nobody named | any tool with `destination_param` set, except Notion |
| `spend_cap` | a single action, or a day's total, moving more than the configured amount | any tool the registry marks `spend` |
| `irreversible_gate` | an irreversible action that was never explicitly opted into | any tool the registry marks `irreversible` |
| `audience_bound` | the same fan-out tool reaching more distinct audiences in a day than the cap allows | any tool the registry marks `audience` |
| `rate_limit` | per-day caps, plus idempotency so a retry storm sends once | any tool, keyed by name in the policy's `max_actions_per_day` |

Plus the states that are not rules: `policy_missing`, `policy_unreadable`, `policy_malformed`, `unknown_tool`, `unknown_param`, `unknown_rule`, `kill_switch`, `duplicate_action`. All refuse.

## The workflow runner

`warrant/workflow.py` runs a declarative YAML file naming a sequence of steps across multiple apps - the "n8n workflow of sorts" this project was asked for. It is not a second gate: `run_workflow` never imports `warrant.apps` and never talks to a client directly, it calls `broker.execute(proposal)` once per step, the exact call a lone proposal makes. A workflow file changes *when* a proposal happens and *what feeds its params* (via `${steps.<id>.<field>}`, a single substitution form - not an expression language, for the same reason `policy.yaml` does not have one); it never changes *whether the gate allows it*.

A refused step's default is `halt`: every step after it is never attempted, not refused - the distinction matters because a workflow that silently kept going past a refusal by default would be exactly the failure `Broker.execute` was built to make impossible for a single action. `on_refused: continue` exists for the cases where a workflow's author has decided a specific step's refusal is recoverable, and that decision is visible in the YAML, not buried in a default nobody chose. Branching (`goto:<step_id>`) was considered and cut: a runner that can jump between steps on a condition is most of the way to a workflow engine, and proving "multi-step stays governed by the same gate" needs only `halt` and `continue` to say.

Every step still writes its own row to `journal.db` through `Broker.execute`, exactly as before. `run_workflow_file` additionally writes one stamped artifact naming every step, its verdict, and the journal row id that produced it - the single signed evidence trail for the run, sitting on top of the per-step rows rather than replacing them.

`resume_workflow(spec, broker)` runs a workflow that may have already executed some of its steps in a process that crashed mid-run: before proposing each step, it checks the ledger for a KNOWN-successful row with that step's idempotency key, and reconstructs the step's result from that row instead of proposing it again if one exists. `RunState` itself is not persisted - the ledger's per-step rows are the only durable record a resumed run reads. See `EVAL_MATRIX.md` finding 2.

Three example workflows ship in `workflows/`, each crossing multiple apps and runnable as-is against the shipped `policy.yaml`:

| File | Crosses | Demonstrates |
|---|---|---|
| `meeting_intake.yaml` | Gmail, Calendar, Notion | the original scenario, as a workflow; `${steps.book.external_id}` threaded into the logged note |
| `incident_response.yaml` | Twilio, Slack, Linear | chaining a real id through two later steps; `on_refused: continue` on the optional ticket step |
| `broadcast_bound.yaml` | Slack, Notion | `audience_bound` halting a run mid-broadcast once the daily distinct-channel cap is hit |

```
python -m warrant.workflow workflows/broadcast_bound.yaml
```

---

## How reliability was tested

Five independent checks, each answering a question the others cannot.

| | |
|---|---|
| **261 tests** | `tests/` - covering the original three-app scenario, the four capability-class rules, the registry's own consistency, the workflow runner, and the five reliability findings in [`EVAL_MATRIX.md`](EVAL_MATRIX.md) |
| **29 evaluation cases** | `eval/cases/*.yaml` → [`EVAL.md`](EVAL.md), including the multi-app `multi_app.yaml` |
| **10/10 mutations killed** | `scripts/mutate.py` - one per load-bearing property, including one per capability-class rule and one for the finding-1 fix |
| **Stamped artifacts** | `artifacts/` - git SHA, dirty flag, environment, full config; workflow runs get their own `kind: workflow` artifacts |
| **Live integration** | 8/8 against real Gmail, Calendar, Notion - each write read back independently. The other seven apps have no equivalent number, and the suite table above says so rather than implying otherwise. |

**The evaluation does not check status strings.** Each case runs through the real broker and gate against fake app clients, then inspects what the ledger recorded. A refusal case fails if an action reached an app, even when the returned status was right - a gate that refuses and then acts is worse than one that does neither.

**Expected-allow cases are reported separately**, because an evaluation made only of refusals is satisfied by a gate that blocks everything.

**Mutation testing is why the test count means anything.** A passing suite proves the code does something; it does not prove the tests would fail if it were wrong. `scripts/mutate.py` disables each load-bearing property one at a time:

```
killed  gate-advisory                          21 tests   broker executes despite a refusal
killed  normalise-and-send                     16 tests   homoglyph canonicalised, not refused
killed  fail-open-on-missing-policy              2 tests   missing policy permits everything
killed  ignore-kill-switch                       4 tests   kill switch stops being consulted
killed  trust-unknown-params                     6 tests   confirmed=true accepted as permission
killed  destination-allowlist-membership-not-checked  3 tests   a write lands somewhere nobody allowlisted for that tool
killed  spend-cap-ignores-per-action-limit       2 tests   a single action can spend an unbounded amount
killed  irreversible-gate-open-by-default        3 tests   an irreversible action runs unlisted
killed  audience-bound-uncapped                  3 tests   a fan-out tool reaches unlimited distinct audiences/day
killed  ambiguous-retry-not-refused              2 tests   a retry of an unknown-outcome attempt duplicates it
```

## Five reliability findings

Each was found by reading the actual code, then baselined against it before anything changed - not assumed. Two were real gaps and are now fixed; two were already correct and just lacked proof; one is correct by construction. Full detail, including how each baseline was actually established, is [`EVAL_MATRIX.md`](EVAL_MATRIX.md); the tests are `tests/test_reliability.py`.

| # | Finding | Result |
|---|---|---|
| 1 | A client error after a server-side write already landed left no trace - a retry duplicated the write | **fixed** - `warrant/broker.py`, `warrant/ledger.py` |
| 2 | A workflow crash mid-run left no durable record of which steps had executed - a restart could repeat one | **fixed** - `warrant/workflow.py::resume_workflow` |
| 3 | Policy edited on disk between workflow steps might not govern the next step | **already correct** - `load_policy()` has no cache |
| 4 | A prompt injection in real thread content might talk the model into a bad proposal | **correct by construction** - every action call routes through `Broker.execute()` |
| 5 | `audience_bound` might only check a cumulative total, missing an oversized single proposal | **already correct** - the check includes the current proposal |

---

## Two bugs this found in itself

Both were live, both were found by running the stack rather than reading it, and both are in the git history.

**Unicode laundering.** `recruiter@bright<ZWSP>lane.io` normalises to a real thread participant, passed the membership check - and the broker then sent to the **raw** string, a different mailbox. The gate was canonicalising an attacker-controlled identifier and acting on the original. Normalisation is now **detection only**: an address that changes under NFKC is refused, never repaired and used.

**`body_containment` could not fire on short threads.** The window was 120 characters, so a body shorter than that could never match - meaning pasting a *short* email wholesale into an invite was allowed while a long one was refused. Exactly backwards: "comp band is 180-220k, keep this confidential" is the leak you care about most.

---

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env        # fill in Notion + Bedrock; the ten fake-only apps' vars are optional and unused by anything live
```

Then write a `policy.yaml` (start from the one in the repo history, or the tables above). **Nothing in the package will create it for you** - `tests/test_policy_adversarial.py::test_policy_file_is_never_written_by_the_package` walks the source and fails if any module writes that path.

Google uses OAuth (`python -m warrant.auth`), not a service account: the agent acts as one specific human on their own mailbox, and domain-wide delegation would be a standing grant over every mailbox in a workspace. Scopes are `gmail.readonly` + `gmail.send` separately rather than `gmail.modify` - nothing here deletes mail, so nothing here asks for the ability to.

The model backend is Bedrock Converse, Mistral Large by default. `WARRANT_MODEL=anthropic.claude-opus-5` switches families - an env var, not a code change, because the gate does not care who proposes.

---

## What this is not

- **Not a guarantee about real API behaviour from the test suite alone.** The tests and evaluation run against fakes whose signatures are asserted to match the real clients - for all ten apps, not just the original three. The integration is proven separately by `scripts/smoke.py`, and only for the three apps it has ever run against: latest run 8/8 against real Gmail, Calendar and Notion, every write read back with an independent call (`artifacts/smoke_20260913T194858Z.json`). The two are deliberately not the same artifact: one proves the gate decides correctly, the other proves the apps are real - and for seven of the ten apps, nothing here proves the second thing at all.
- **Seven of ten apps have never made a real call.** Slack, GitHub, Linear, Stripe, Twilio, Drive and Sheets are real HTTP adapters against documented APIs, exercised only against fakes. `warrant.registry` marks each one `fake-only` and names the reason (no account, a scope conflict with the one working Google token, or - for Stripe specifically - a deliberate choice not to even use a sandbox key). Overclaiming here would be the exact failure this project's credibility depends on not making.
- **The workflow runner's control flow (halt/continue) is new, not years of production use.** It reuses the gate unmodified, which is the property that matters most, but the runner itself - template substitution, the artifact it writes - is new code with a correspondingly smaller evidence base than the three-app scenario has. Branching (`goto:<step_id>`) was cut rather than hardened: a workflow engine was never the point, and fewer control-flow shapes is less to have gotten wrong.
- **Not an estimate of behaviour on arbitrary traffic.** The cases are hand-written against the failure modes the policy was designed for. That is a statement about those modes, not a sample.
- **Not a model evaluation.** The eval supplies proposals directly, with no model in the loop. The gate's correctness must not depend on the model behaving well, so it is measured without one.
