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

**The gate** (`warrant/policy.py`) authorizes proposals against `policy.yaml`, a file a human writes and no code path in the package may create. Six rules dispatched by name. A missing, unreadable, or malformed policy refuses everything.

**The broker** (`warrant/broker.py`) is the only module that holds credentials and the only one that can reach an app. It executes solely on an `allowed` verdict.

The load-bearing detail is **where facts come from**. `Proposal` is what the model claims; `ThreadFacts` is what the broker read from the Gmail API itself. Every interesting rule compares the two. `Broker.execute()` therefore takes a `Proposal` and nothing else - a caller who could pass facts could fabricate the thing the gate checks against.

**The evidence trail** is not a byproduct, it is half the deliverable. `journal.py` writes every decision - allowed *and* refused - with the proposal, the rule ids that fired, the reason text, and the resulting external id. `decision` is derived from the verdict rather than passed in, so a caller cannot log an outcome that did not happen. `provenance.py` stamps every run with the git SHA, a dirty-tree flag, interpreter and library versions, and the full config, so a number in this document can be traced to the run that produced it instead of being transcribed off a terminal.

**The console** (`server/`) is a local web view of the gate deciding, one proposal at a time over SSE. Its purpose is to make the *declarative* half tangible: edit a rule, save, re-run, watch a verdict flip. It cannot bypass the gate - every action goes through `Broker.execute` exactly as the CLI and tests do, there is no override control, and policy edits land in a per-session sandbox rather than the repo's file. A live toggle points it at real Gmail, Calendar and Notion; the header states which set of apps is in use at all times, because a demo where you cannot tell fakes from live calls proves nothing.

In live mode the scenario only acts on a thread whose sole participant is the operator, so it cannot reach a third party even if the policy were edited to allow it - there is nobody else on the thread to scope to. That safety property is in the *selection*, deliberately: the gate is the thing under test, so it must not also be the thing keeping the demo safe.

### Workflow

Inbound meeting request → read the thread → check the calendar → create the event → log to Notion → reply. Five steps, three apps. Boring on purpose: nobody is impressed by scheduling software, and the failure modes have to be real for the gate to mean anything.

### Failure modes the gate catches

| | Rule |
|---|---|
| Recipient escalation - cc'ing `all@company` | `no_distribution_lists`, `recipient_scope` |
| Unicode laundering - a zero-width space in the domain | `recipient_scope` |
| PII leak - thread text pasted into an invite that goes to external attendees | `body_containment` |
| Wrong destination - writing to a non-allowlisted Notion page | `notion_parent_allowlist` |
| Retry storm - the same confirmation sent five times | `duplicate_action` |
| Self-authorization - `confirmed: true` on the proposal | `unknown_param` |
| No policy / kill switch / unreadable thread | fail closed |

---

### Where this sits

Agent observability tells you an agent misbehaved - after it did. That is necessary and it is not the same job as this one. Warrant is the layer that makes the misbehaviour structurally impossible to execute in the first place: the complement to monitoring, not a competitor to it.

The two compose cleanly, and the seam is already here. `journal.db` records every decision - allowed and refused - with the proposal, the rule that fired, the reason, and the resulting external id. That is an audit trail, and audit trails, approvals and RBAC are what teams ask for once monitoring tells them something went wrong and they want it to stop happening. A monitoring layer answers *what did the agent do*; this answers *what was it permitted to do, and who said so*.

## Reliability

### What is measured

**127 tests**, 91 of them adversarial across nine attack classes, structured as a red-team suite: the gate may only fail in one direction, so nearly every assertion is a refusal. The exceptions are the control tests - a legal proposal must pass - without which every other assertion would be satisfied by a gate that blocks everything.

**20 evaluation cases** (`eval/cases/*.yaml`) replay proposals through the real broker and gate against fake app clients, then **inspect the fakes' ledgers**. A refusal case fails if the ledger grew, even when the status string was correct. Each case runs in its own sandbox - fresh policy, ledger, journal, kill-switch path - so results do not depend on ordering.

**5/5 mutations killed.** This is the number that makes the other two mean something. A passing suite proves the code does something, not that the tests would notice if it were wrong. `scripts/mutate.py` disables one property at a time and records what breaks:

| Mutation | Tests killed |
|---|---|
| broker executes despite a refusal | 13 |
| homoglyph canonicalised instead of refused | 16 |
| missing policy permits everything | 2 |
| kill switch stops being consulted | 4 |
| `confirmed=true` accepted as permission | 6 |

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

### What is still not measured, and why

- **The smoke run does not go through the gate.** It is the control, not a demonstration - if the gate later refuses something, the smoke artifact is the evidence that the refusal is the gate working rather than the credentials being broken. A run that proved both at once would prove neither.
- **The fakes are signature-matched, not full-fidelity.** `test_fakes_match_real_client_signatures` asserts each fake's parameters are a superset of the real client's, so a fake cannot silently drift into testing nothing. What that does not give is realistic *behaviour* - Gmail's threading quirks, Notion's database-vs-page parent split, partial failures, rate limits. Running these same 20 cases against high-fidelity service twins instead of our own hand-written fakes is the obvious next step, and the honest characterisation is that hand-written fakes test the gate's logic while a twin would test the integration's reality. Those are different claims and this repo only makes the first.
- **One live run is one data point.** It shows the clients work against these three accounts, at that commit. It is not a statement about rate limits, pagination, quota behaviour, or a second workspace.
- **The `dirty: true` flag on that artifact is real.** The tree had uncommitted changes when the run happened. The artifact records it rather than hiding it, which is the entire reason the field exists.
- **Cases are hand-written, not sampled.** They cover the failure modes the policy was designed against. That is a statement about those modes, not an estimate of behaviour on arbitrary real traffic.
- **The model is not in the evaluation loop.** Proposals are supplied directly. The gate's correctness must not depend on the model behaving well, so it is measured without one. The agent is exercised separately.
- **Sample size is small.** 20 cases and 5 mutations is a smoke-scale statement, not a powered benchmark. Read it as "these specific failures are held shut," not "the gate is safe."
- **One rule is shallower than it looks.** `body_containment` is a verbatim-substring test. It catches paste, not paraphrase - a model that *summarised* the salary band into the invite would pass. A semantic check was out of scope, and a threshold on "how similar" is a number nobody can defend in review, whereas "N consecutive characters appear verbatim" is a fact.

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
- The per-day caps are enforced from a local SQLite ledger. A second process with its own ledger would not see the first one's count. Single-operator assumption, stated rather than hidden.
