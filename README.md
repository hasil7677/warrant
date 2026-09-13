# warrant

**An agent proposes. A declarative policy authorizes. The gate holds the credentials, so the model never does.**

Give an agent tools that send email and book time with other people, and you have a problem no prompt fixes. The standard answer is "the agent asks permission first" - but the agent decides when to ask, phrases the request, and holds the API tokens. That is not a control, it is a request.

`warrant` sits in between. The workflow it governs is deliberately boring: an inbound meeting request gets read, scheduled, logged, and answered across Gmail, Google Calendar, and Notion. **The gate and the evidence trail are the product.**

## Demo

**▶ Two-minute demo: _(link)_**

Or run it yourself - no credentials, no network, 70 seconds:

```
python demo/demo.py
```

## External apps

Three, all reached only through the broker, all proven live (8/8, every write read back with an independent call - `artifacts/smoke_20260913T194858Z.json`):

| App | Used for | Scopes / auth |
|---|---|---|
| **Gmail** | read the thread (the trust anchor), send the reply | OAuth user consent - `gmail.readonly` + `gmail.send`, deliberately not `gmail.modify` |
| **Google Calendar** | check conflicts, create the event | OAuth user consent - `calendar.events` |
| **Notion** | log the meeting to an allowlisted page | Internal integration token, REST (no SDK) |

The model backend is **Mistral Large via AWS Bedrock** (Converse API); `WARRANT_MODEL` switches families.

```
python server/app.py         # the console -> http://127.0.0.1:8000
python demo/demo.py          # 70 seconds, no credentials, no network
python -m pytest tests/ -q   # 127 tests
python eval/run.py           # 20 cases -> EVAL.md + a stamped artifact
python scripts/mutate.py     # break the gate on purpose, check the tests notice
python scripts/smoke.py      # prove the three real APIs are reachable
```

## The console

`server/` is a local web view of the gate deciding, one proposal at a time.

The point is not to look at a log. It is to make the *declarative* half of
"declarative policy gate" tangible: **edit a rule in the left pane, save, re-run,
and watch a verdict flip.** Delete `all` from `blocked_local_parts` and the
company-wide cc stops being refused; put it back and it is refused again. No
prompt changed, no redeploy, no model involved - a human edited one line and the
agent's permissions changed. Two header toggles turn on the kill switch or delete
the policy file, and both turn the entire run red, legal actions included.

The console cannot bypass the gate. Every action goes through `Broker.execute`
exactly as the CLI and the tests do, there is no override control, and edits land
in a per-session sandbox rather than the repo's `policy.yaml`.

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
                   Gmail / Calendar / Notion
```

Three properties carry the whole design, and each one is a test rather than a claim:

**1. `Broker.execute()` takes a `Proposal` and nothing else.** There is no `facts` parameter, no `policy` parameter, no override flag. A caller who could supply facts could fabricate the very thing the gate checks proposals against - which would turn `recipients ⊆ participants` into a statement about two things the model wrote. The broker reads the thread itself, from the `thread_id`, before the gate runs. The model chooses *which* thread to act on; it does not get to say what is in it.
→ `tests/test_structure.py::test_broker_execute_takes_only_a_proposal`

**2. Only the broker can reach an app client.** `warrant/auth.py` is the only module that reads a credential, and `warrant/broker.py` is the only module that imports `warrant.apps.*`. Every other module is checked by an AST walk over the package. Without that check, "the model never holds credentials" would be a convention someone breaks in a hurry at 2am.
→ `tests/test_structure.py::test_only_the_broker_imports_app_clients`

**3. It fails closed.** No `policy.yaml` → every action refused. Unreadable YAML → refused. A thread that cannot be read → refused, because "I could not verify" and "it is fine" are different answers and only one of them is safe. `policy.yaml` is **gitignored**: a fresh clone of this repo refuses everything until a human writes one. Shipping a default policy would be shipping consent nobody gave.

There is no parameter anywhere in the package that lets the model vouch for itself. A proposal carrying `confirmed: true` is refused as `unknown_param` - the flag is not disabled, it was never a field.

---

## The policy

Six rules, dispatched by name from `policy.yaml`. Not an expression language - a rule is a named Python function the YAML switches on, so the file stays readable by someone who does not write Python.

| Rule | Catches |
|---|---|
| `recipient_scope` | recipients not on the thread the broker read |
| `domain_allowlist` | addresses outside the permitted domains |
| `no_distribution_lists` | `all@`, `everyone@`, `team@` |
| `body_containment` | thread text pasted into a calendar invite that goes to external attendees |
| `notion_parent_allowlist` | writes to any page but the allowlisted one |
| `rate_limit` | per-day caps, plus idempotency so a retry storm sends once |

Plus the states that are not rules: `policy_missing`, `policy_unreadable`, `policy_malformed`, `unknown_tool`, `unknown_param`, `unknown_rule`, `kill_switch`, `duplicate_action`. All refuse.

---

## How reliability was tested

Four independent checks, each answering a question the others cannot.

| | |
|---|---|
| **127 tests** | `tests/` - 91 of them adversarial, nine attack classes |
| **20 evaluation cases** | `eval/cases/*.yaml` → [`EVAL.md`](EVAL.md) |
| **5/5 mutations killed** | `scripts/mutate.py` |
| **Stamped artifacts** | `artifacts/` - git SHA, dirty flag, environment, full config |
| **Live integration** | 8/8 against real Gmail, Calendar, Notion - each write read back independently |

**The evaluation does not check status strings.** Each case runs through the real broker and gate against fake app clients, then inspects the fakes' ledgers. A refusal case fails if the ledger grew, even when the returned status was right - a gate that refuses and then acts is worse than one that does neither.

**Expected-allow cases are reported separately**, because an evaluation made only of refusals is satisfied by a gate that blocks everything.

**Mutation testing is why the test count means anything.** 127 passing tests prove the code does something; they do not prove the tests would fail if it were wrong. `scripts/mutate.py` disables five load-bearing properties one at a time:

```
killed  gate-advisory                 13 tests   broker executes despite a refusal
killed  normalise-and-send            16 tests   homoglyph canonicalised, not refused
killed  fail-open-on-missing-policy    2 tests   missing policy permits everything
killed  ignore-kill-switch             4 tests   kill switch stops being consulted
killed  trust-unknown-params           6 tests   confirmed=true accepted as permission
```

---

## Two bugs this found in itself

Both were live, both were found by running the stack rather than reading it, and both are in the git history.

**Unicode laundering.** `recruiter@bright<ZWSP>lane.io` normalises to a real thread participant, passed the membership check - and the broker then sent to the **raw** string, a different mailbox. The gate was canonicalising an attacker-controlled identifier and acting on the original. Normalisation is now **detection only**: an address that changes under NFKC is refused, never repaired and used.

**`body_containment` could not fire on short threads.** The window was 120 characters, so a body shorter than that could never match - meaning pasting a *short* email wholesale into an invite was allowed while a long one was refused. Exactly backwards: "comp band is 180-220k, keep this confidential" is the leak you care about most.

---

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env        # fill in Notion + Bedrock
```

Then write a `policy.yaml` (start from the one in the repo history, or the table above). **Nothing in the package will create it for you** - `tests/test_policy_adversarial.py::test_policy_file_is_never_written_by_the_package` walks the source and fails if any module writes that path.

Google uses OAuth (`python -m warrant.auth`), not a service account: the agent acts as one specific human on their own mailbox, and domain-wide delegation would be a standing grant over every mailbox in a workspace. Scopes are `gmail.readonly` + `gmail.send` separately rather than `gmail.modify` - nothing here deletes mail, so nothing here asks for the ability to.

The model backend is Bedrock Converse, Mistral Large by default. `WARRANT_MODEL=anthropic.claude-opus-5` switches families - an env var, not a code change, because the gate does not care who proposes.

---

## What this is not

- **Not a guarantee about real API behaviour from the test suite alone.** The tests and evaluation run against fakes whose signatures are asserted to match the real clients. The integration is proven separately by `scripts/smoke.py` - latest run 8/8 against real Gmail, Calendar and Notion, every write read back with an independent call (`artifacts/smoke_20260913T194858Z.json`). The two are deliberately not the same artifact: one proves the gate decides correctly, the other proves the apps are real.
- **Not an estimate of behaviour on arbitrary traffic.** The cases are hand-written against the failure modes the policy was designed for. That is a statement about those modes, not a sample.
- **Not a model evaluation.** The eval supplies proposals directly, with no model in the loop. The gate's correctness must not depend on the model behaving well, so it is measured without one.
