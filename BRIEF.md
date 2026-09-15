# System & reliability brief

## The problem

An agent that takes real actions has no real authorization. The standard pattern is "the agent asks permission first," but the agent decides when to ask, writes the request, and holds the tokens. Every part of the control is inside the thing being controlled. Ask *"who authorized this action, and what stopped it from being different?"* and the only available answer is the model's own word.

### "Asks permission" is not a control

Most human-in-the-loop agent products - including good ones - mean *the agent asks nicely*. A review step, an approval queue, a confirmation modal. Those are worth having, but they are conventions: the agent still holds the token, and the only thing standing between a confused model and a sent email is that it chose to ask first.

Warrant means something narrower and stronger: **the agent has no path to the credential at all.** Not a prompt instruction, not a UI review step - a structural property, checked by an AST walk over the package (`test_only_the_broker_imports_app_clients`). One module reads credentials, one module can reach an app client, and a test fails the moment a third one does. That is the difference between a control that holds under a deadline and one that holds until someone is in a hurry at 2am.

The distinction matters because the failure it prevents is **silent**. Nothing crashes, no exception is thrown, no status code goes red. The wrong mailbox just gets the email.

## The system

Three parts, one boundary.

**The agent** (`warrant/agent.py`) plans and proposes. It holds no credentials and imports no app client. Its output is a structured `Proposal` - `gmail.send(to=…, body=…)` - and nothing more. It runs on Bedrock Converse (Mistral Large by default); swapping model families is an environment variable.

**The registry** (`warrant/registry.py`) is new: a table of every app and tool this build knows about, and - the part that matters - what each tool is *capable of*, as a set of capability classes rather than an app name. This replaced two hardcoded tuples in `contract.py` that named three apps by hand. The reason is scale: a policy rule written as `if proposal.tool == GMAIL_SEND` has to be rewritten for every new app; a rule written as `if registry_mod.SPEND in spec.classes` governs app number fourteen the day it is added. `registry.validate()` runs at import time and refuses to let the package load if the table is internally inconsistent - an unknown capability class, a tool missing the reversibility pair, a `spend` tool with no way to price it.

**The gate** (`warrant/policy.py`) authorizes proposals against `policy.yaml`, a file a human writes and no code path in the package may create. Ten rules dispatched by name, six of them reading the registry generically and four reasoning about capability classes (`destination_allowlist`, `spend_cap`, `irreversible_gate`, `audience_bound`) rather than being written against one app. A missing, unreadable, or malformed policy refuses everything.

**The broker** (`warrant/broker.py`) is the only module that holds credentials and the only one that can reach an app - all ten of them now, not three. It executes solely on an `allowed` verdict. Dispatch is generic too: `_perform` resolves a tool's app and function from the registry and splats the proposal's params at it, rather than one `if proposal.tool == X:` block per app.

**The workflow runner** (`warrant/workflow.py`) is also new: a declarative YAML file names a sequence of steps across multiple apps, and each one goes through `Broker.execute` exactly as a lone proposal would - the runner never imports `warrant.apps` and never talks to a client directly. See "The workflow runner" below for the design.

The load-bearing detail is **where facts come from**. `Proposal` is what the model claims; `ThreadFacts` is what the broker read from the Gmail API itself. Every interesting rule compares the two. `Broker.execute()` therefore takes a `Proposal` and nothing else - a caller who could pass facts could fabricate the thing the gate checks against.

**The evidence trail** is not a byproduct, it is half the deliverable. `journal.py` writes every decision - allowed *and* refused - with the proposal, the rule ids that fired, the reason text, and the resulting external id. `decision` is derived from the verdict rather than passed in, so a caller cannot log an outcome that did not happen. `provenance.py` stamps every run with the git SHA, a dirty-tree flag, interpreter and library versions, and the full config, so a number in this document can be traced to the run that produced it instead of being transcribed off a terminal.

**The console** (`server/`) is a local web view of the gate deciding, one proposal at a time over SSE. Its purpose is to make the *declarative* half tangible: edit a rule, save, re-run, watch a verdict flip. It cannot bypass the gate - every action goes through `Broker.execute` exactly as the CLI and tests do, there is no override control, and policy edits land in a per-session sandbox rather than the repo's file. A live toggle points it at real Gmail, Calendar and Notion; the header states which set of apps is in use at all times, because a demo where you cannot tell fakes from live calls proves nothing.

The console also drafts policy from plain English. That is the one place a model
touches the rules file, and it is deliberately the weakest possible touch: the
endpoint returns a string into the editor alongside a diff and writes nothing. A
human reads it and saves. The same relationship the agent has with the gate,
applied one level up to the rules themselves - because a policy the agent can
author for itself is not consent. The diff earns its place: asked to block a
domain the rules cannot express, a small model added it to the allowlist and
annotated the line as a block, while the larger one declined and named the rule
that would be needed. Handed ninety lines of YAML nobody catches that; handed one
red line and one green line, everybody does.

In live mode the scenario only acts on a thread whose sole participant is the operator, so it cannot reach a third party even if the policy were edited to allow it - there is nobody else on the thread to scope to. That safety property is in the *selection*, deliberately: the gate is the thing under test, so it must not also be the thing keeping the demo safe.

### The original scenario

Inbound meeting request → read the thread → check the calendar → create the event → log to Notion → reply. Five steps, three apps. Boring on purpose: nobody is impressed by scheduling software, and the failure modes have to be real for the gate to mean anything. It is still governed exactly as before - nothing about generalizing the gate to ten apps changed how this scenario behaves, which is itself asserted (`tests/test_broker_boundary.py`, `tests/test_policy_adversarial.py` are unmodified in their assertions about this scenario).

### The workflow runner

A declarative YAML file names a sequence of steps across apps; each step is a `Broker.execute()` call, in order. Three design choices carry the whole thing:

1. **The runner is not a second gate.** `run_workflow`/`iter_workflow_steps` never import `warrant.apps` and never construct a client - they hold a `Broker` handed to them and call `.execute()`. A workflow step gets exactly what a lone proposal for that tool would get, never more.
2. **`${steps.<id>.<field>}` is data plumbing, not computation.** It substitutes one field of an earlier step's *result* into a later step's param - the same single-substitution-only stance `policy.yaml` takes on rules, for the same reason: a format that can compute is a format that can be talked into computing something else. What gets substituted still goes through `policy.check()` like any other value in that field; referencing a field a refused step never produced (`.external_id` on a step with no external id) raises rather than substituting `"None"` into a live param.
3. **Halt is the default, and silence is not an option.** A refused step stops the run by default - every step after it is marked "never attempted," a state distinct from "refused." `on_refused: continue` is opt-in per step, so a workflow that tolerates a specific refusal says so in the file rather than relying on the runner's default to happen to be permissive. Branching (`on_refused: goto:<step_id>`) was built, then cut: it added loop-detection code and its own failure mode (an infinite goto cycle) in service of a feature nobody asked this project to have - a workflow engine. `halt` and `continue` say everything the "stays governed by the same gate" invariant needs said.

Every step's decision lands in `journal.db` exactly as a lone proposal's would - the runner adds no second logging path. `run_workflow_file` additionally writes one `kind: workflow` artifact naming every step, its verdict, and the journal row id, via the same `provenance.write_artifact` the eval runner and smoke test use.

Three example workflows ship in `workflows/` and are runnable as-is against the shipped `policy.yaml` (verified: see README's table). `tests/test_workflow.py` covers the happy path, halt, continue, template resolution failure, malformed-file rejection, and the artifact's shape.

### Failure modes the gate catches

| | Rule |
|---|---|
| Recipient escalation - cc'ing `all@company` | `no_distribution_lists`, `recipient_scope` |
| Unicode laundering - a zero-width space in the domain | `recipient_scope` |
| PII leak - thread text pasted into an invite that goes to external attendees | `body_containment` |
| Wrong destination - writing to a non-allowlisted Notion page, Slack channel, GitHub repo, … | `notion_parent_allowlist`, `destination_allowlist` |
| An irreversible action nobody explicitly opted into (a merge, a payout) | `irreversible_gate` |
| Unbounded spend on a single action or across a day | `spend_cap` |
| One legal message broadcast to more distinct channels than the daily cap | `audience_bound` |
| Retry storm - the same confirmation sent five times | `duplicate_action` |
| Self-authorization - `confirmed: true` on the proposal | `unknown_param` |
| No policy / kill switch / unreadable thread | fail closed |

---

### Where this sits

Agent observability tells you an agent misbehaved - after it did. That is necessary and it is not the same job as this one. Warrant is the layer that makes the misbehaviour structurally impossible to execute in the first place: the complement to monitoring, not a competitor to it.

The two compose cleanly, and the seam is already here. `journal.db` records every decision - allowed and refused - with the proposal, the rule that fired, the reason, and the resulting external id. That is an audit trail, and audit trails, approvals and RBAC are what teams ask for once monitoring tells them something went wrong and they want it to stop happening. A monitoring layer answers *what did the agent do*; this answers *what was it permitted to do, and who said so*.

## Reliability

### What is measured

**261 tests**, structured as a red-team suite: the gate may only fail in one direction, so nearly every assertion is a refusal. The exceptions are the control tests - a legal proposal must pass - without which every other assertion would be satisfied by a gate that blocks everything. The growth is not just volume: `tests/test_registry.py` (55 tests) checks the capability-class design and every liveness claim against its cited evidence; `tests/test_policy_multi_app.py` (21 tests) red-teams the four capability-class rules against apps the original suite never mentions; `tests/test_workflow.py` (14 tests) covers the runner; `tests/test_reliability.py` (14 tests) covers the five findings below; the rest is the original suite plus two tests in `test_structure.py` rewritten from grepping source for app names to actually running the gate, because that grep stopped meaning anything once rules stopped naming apps.

**29 evaluation cases** (`eval/cases/*.yaml`) replay proposals through the real broker and gate against fake app clients, then **inspect what the ledger recorded**. A refusal case fails if an action reached an app, even when the status string was correct. Each case runs in its own sandbox - fresh policy, ledger, journal, kill-switch path - so results do not depend on ordering. `eval/cases/multi_app.yaml` is the multi-app addition: `destination_allowlist`, `irreversible_gate` and `spend_cap` each get an ALLOW and a DENY case against apps (Slack, GitHub, Stripe) the original three cases never touch.

**10/10 mutations killed.** This is the number that makes the other two mean something. A passing suite proves the code does something, not that the tests would notice if it were wrong. `scripts/mutate.py` disables one property at a time and records what breaks:

| Mutation | Tests killed |
|---|---|
| broker executes despite a refusal | 21 |
| homoglyph canonicalised instead of refused | 16 |
| missing policy permits everything | 2 |
| kill switch stops being consulted | 4 |
| `confirmed=true` accepted as permission | 6 |
| a write lands where nobody allowlisted it for that tool | 3 |
| a single action spends an unbounded amount | 2 |
| an irreversible action runs without being opted into | 3 |
| a fan-out tool reaches unlimited distinct audiences/day | 3 |
| a retry of an ambiguous-outcome attempt is performed again instead of refused | 2 |

Each of the non-original mutations targets a specific line chosen to be a genuine bypass rather than a redundant one - the first attempt at the `destination_allowlist` mutation targeted a line that a second check downstream still caught, which would have reported "killed: 0" and revealed nothing. Finding that required actually running the mutation and reading what survived, not assuming the target line mattered because it looked load-bearing.

Every run emits a stamped artifact - git SHA, dirty flag, interpreter and library versions, full config - so a number in a document can be traced to the run that produced it instead of being transcribed by hand.

### The live control

The tests and the evaluation run against fakes. That is a deliberate choice, and on its own it would be a hole - a green suite against stand-ins can imply a working integration that does not exist. So the integration is proven separately, by `scripts/smoke.py`, which writes one real object per app and then **reads each one back with an independent call**, because a 200 from a create endpoint is the service's claim and not proof.

Latest run - `artifacts/smoke_20260913T194858Z.json`, git `297782c`:

```
PASS  google oauth + gmail profile      dtomsahil@gmail.com
PASS  gmail.list_unread                 3 unread thread(s)
PASS  gmail.read_thread (trust anchor)  2 participants, 5669 body chars
PASS  gmail.send -> self                message id 1a09c50cbb721fd8
PASS  calendar.create_event             event id j9anerthokc1uch5umd8fj2dtg
PASS  calendar read-back verify         event read back independently
PASS  notion.create_page                page 3dacd088-d5e2-81d5-94d5-f4688ca82463
PASS  notion read-back verify           page read back independently

8 passed, 0 failed · apps proven live: gmail, calendar, notion
```

The two artifacts are deliberately kept apart: the suite proves the gate decides correctly, the smoke run proves the apps are real. Neither is asked to stand in for the other.

### Five reliability findings

Each was found by reading the code, not assumed - and each was baselined against the actual code before anything was changed, not guessed at. Full detail, including the baseline evidence and the honesty notes, is [`EVAL_MATRIX.md`](EVAL_MATRIX.md); the short version:

| # | Finding | Baseline | Status |
|---|---|---|---|
| 1 | A client-side failure after a server-side write already landed left no trace, so a retry duplicated the write | broken - reproduced by hand | **proven-after-fix** |
| 2 | A workflow run has no durable state; a restart after a crash had no way to know which steps already executed | broken - reproduced directly | **proven-after-fix** |
| 3 | Policy edited on disk mid-workflow might not govern the next step if `policy.yaml` were cached anywhere | already correct - `load_policy()` has no cache | **proven** |
| 4 | A prompt injection in real thread content might talk the model into a bad proposal the gate does not catch | correct by construction - every action tool call routes through `Broker.execute()` | **proven-by-design** |
| 5 | `audience_bound` might only check a cumulative running total, missing a single oversized first proposal | already correct - the check includes the current proposal | **proven** |

Two of five were real gaps and are now fixed (`warrant/broker.py`, `warrant/ledger.py`, `warrant/workflow.py`). Two were already correct and needed proof, not code. One is correct because of how `agent.py` is structured, not because of anything the test's stub model happened to do - `EVAL_MATRIX.md` explains that distinction rather than eliding it.

### What is still not measured, and why

- **The smoke run does not go through the gate.** It is the control, not a demonstration - if the gate later refuses something, the smoke artifact is the evidence that the refusal is the gate working rather than the credentials being broken. A run that proved both at once would prove neither.
- **The fakes are signature-matched, not full-fidelity.** `test_fakes_match_real_client_signatures` asserts each fake's parameters are a superset of the real client's, so a fake cannot silently drift into testing nothing. What that does not give is realistic *behaviour* - Gmail's threading quirks, Notion's database-vs-page parent split, partial failures, rate limits. Running these same cases against high-fidelity service twins instead of our own hand-written fakes is the obvious next step, and the honest characterisation is that hand-written fakes test the gate's logic while a twin would test the integration's reality. Those are different claims and this repo only makes the first.
- **One live run is one data point.** It shows the clients work against these three accounts, at that commit. It is not a statement about rate limits, pagination, quota behaviour, or a second workspace.
- **The `dirty: true` flag on that artifact is real.** The tree had uncommitted changes when the run happened. The artifact records it rather than hiding it, which is the entire reason the field exists.
- **Cases are hand-written, not sampled.** They cover the failure modes the policy was designed against. That is a statement about those modes, not an estimate of behaviour on arbitrary real traffic.
- **The model is not in the evaluation loop.** Proposals are supplied directly. The gate's correctness must not depend on the model behaving well, so it is measured without one. The agent is exercised separately.
- **Sample size is small.** 29 cases and 10 mutations is a smoke-scale statement, not a powered benchmark. Read it as "these specific failures are held shut," not "the gate is safe."
- **One rule is shallower than it looks.** `body_containment` is a verbatim-substring test. It catches paste, not paraphrase - a model that *summarised* the salary band into the invite would pass. A semantic check was out of scope, and a threshold on "how similar" is a number nobody can defend in review, whereas "N consecutive characters appear verbatim" is a fact.
- **Seven apps' worth of adapters have never made a real HTTP call.** They are written against documented APIs, signature-checked against their fakes, and exercised through the same gate as the three proven apps - but "the fake matches the real function's signature" is not "the real function works." That gap is real and stated, not papered over with a passing test suite that only ever calls the fake.

### Two bugs found in this system, by this system

Both were live, both surfaced from running the stack rather than reading it, and both are in the git history with the reasoning.

**Unicode laundering - a silent failure, and the reason this project exists.** `recruiter@bright<ZWSP>lane.io` normalises to a real thread participant, so a membership test on the normalised form said yes - and the broker then sent to the **raw** string, a different mailbox. The gate was canonicalising an attacker-controlled identifier and then acting on the original: a homoglyph check operating as a homoglyph laundering service.

Note what this looked like from the outside while it was broken. **Every status was green.** The gate returned `allowed`. The send returned a message id. The tests passed. No exception, no error log, no red anywhere - the email simply went to the wrong person. A monitoring layer watching return codes would have seen a healthy system. The only thing that caught it was running the stack end to end and reading the address that actually reached the client.

Normalisation is now detection only: an address that changes under NFKC is refused, never repaired. And the reason every check in this project asserts on a *side effect* rather than a status string - the eval inspects the fake's ledger, the smoke test re-reads each object - is this bug. A 200 is the service's claim, not proof.

**`body_containment` could not fire on a short thread.** The window was 120 characters and the code required the body to be at least that long, so pasting a *short* email wholesale into an invite was allowed while a long one was refused - exactly backwards, since a two-line message containing a salary band is the leak that matters most.

A third was caught in the tooling itself: the first mutation-check parser reported zero failures for every mutation, which would have certified a suite that does catch these bugs as catching none of them. Counts are now cross-checked against pytest's exit code and a disagreement is fatal.

### Known gaps

- OAuth consent for Gmail/Calendar is interactive, so the live path requires a human once per machine. That is a property of the grant being user-scoped rather than a workspace-wide service account, and it is the trade accepted on purpose.
- `notion.create_page` handles a plain-page parent on the first call and retries as a database parent only on a 400 that names one. The database path is the least-exercised code in the repo.
- The per-day caps - `rate_limit`, `spend_cap`, `audience_bound` - are all enforced from the same local SQLite ledger. A second process with its own ledger would not see the first one's count. Single-operator assumption, stated rather than hidden, and it now applies to three rules instead of one.
- **`spend_cap` has never been exercised against a real payments API, sandbox or otherwise.** The arithmetic is tested (per-action, cumulative daily, currency mismatch, flat-cost-times-recipient-count), but "does Stripe actually charge in the units and shape this code assumes" is untested by construction, because no Stripe credential - live or test-mode - was ever wired in. Deliberate, stated in the registry's own note field on the Stripe entry, not discovered by a reader.
- **The seven fake-only adapters are real code with no live evidence.** Each is written against its provider's documented REST API and matches its fake's signature (checked generically in `tests/test_registry.py`), but none has been pointed at a real account. The gap between "written correctly against documentation" and "actually works" is exactly the gap `scripts/smoke.py` exists to close for the original three, and it remains open for the other seven.
- **The workflow runner is new code.** It reuses the gate unmodified - the property that actually matters for safety - but its own logic (template substitution, the per-run artifact) has a much smaller evidence base than the original scenario's longer exercise. `${steps.<id>.<field>}` was deliberately kept to one substitution form with no arithmetic capability, for the same reason `policy.yaml` has no expression language - and branching (`goto:<step_id>`) was cut outright rather than hardened, on the same reasoning - but "deliberately limited" is a design argument, not a substitute for time-in-production.
- **Google Drive and Sheets stay fake for a specific, checkable reason**: the one live OAuth token this repo has evidence behind (`token.json`) does not carry `drive.file` or `spreadsheets` scope, and requesting those scopes would force a fresh consent that invalidates it. `warrant.auth.google_drive_sheets_creds()` raises rather than silently requesting a wider grant than the smoke-tested token has.
- **A ledger row stuck `'pending'` (finding 1) has no automated reconciliation.** If the write it represents actually landed and nobody resolves the row, that real effect stays permanently invisible to `rate_limit`/`spend_cap`/`audience_bound`'s counts, and the row itself never clears on its own. The correct default - refuse rather than guess - is in place; a way to list and resolve stuck rows is not. See `EVAL_MATRIX.md`'s honesty notes.
