"""
test_workflow.py
─────────────────
The workflow runner, end to end: does a multi-step YAML file actually run
through the real gate one step at a time, does a refusal halt (or let the run
continue) exactly as the file declares, and - the same invariant
`test_broker_boundary.py` checks for a single proposal - does a step that was
never reached leave every fake ledger it would have touched untouched.

`run_workflow` never talks to an app client and never imports `warrant.apps`;
it calls `broker.execute()` once per step, the same call a lone proposal makes.
So every test here is really asking one question in different shapes: is a
workflow just N proposals through the same gate, or did adding a runner quietly
create a second one?
"""

from __future__ import annotations

import yaml

import pytest

from warrant import journal as journal_mod
from warrant import policy as policy_mod
from warrant.broker import Broker
from warrant.contract import STATUS_EXECUTED, STATUS_REJECTED
from warrant.fakes import (
    FakeCalendar,
    FakeGitHub,
    FakeGmail,
    FakeLinear,
    FakeNotion,
    FakeSlack,
    FakeTwilio,
    seed_thread,
)
from warrant.ledger import Ledger
from warrant.workflow import (
    ON_REFUSED_CONTINUE,
    WorkflowError,
    load_workflow,
    run_workflow,
    run_workflow_file,
)

REPO_ROOT_WORKFLOWS = __import__("pathlib").Path(__file__).resolve().parents[1] / "workflows"

PARENT = "11111111111111111111111111111111"
OWNER = "sahil@brightlane.io"
RECRUITER = "recruiter@brightlane.io"

# A policy covering every rule the three example workflows exercise. Not the
# repo's own policy.yaml - a fixture, isolated per test the same way
# test_policy_adversarial.py's `governed` fixture is, so these tests do not
# depend on the shipped policy's exact channel ids staying what they are today.
POLICY = {
    "version": 1,
    "rules": {
        "recipient_scope": {},
        "domain_allowlist": {"allowed_domains": ["brightlane.io"]},
        "no_distribution_lists": {"blocked_local_parts": ["all", "everyone"]},
        "body_containment": {"max_quoted_chars": 120},
        "notion_parent_allowlist": {"allowed_parents": [PARENT]},
        "destination_allowlist": {
            "allowed": {
                # Same channel ids the shipped example workflows use, so this
                # fixture governs them the way policy.yaml actually does
                # rather than a fixture-only set that happens to look similar.
                "slack.post_message": ["C0WARRANTOPS", "C0WARRANTALERTS", "C0WARRANTSTATUS"],
                "linear.create_issue": ["team_warrant"],
                "github.create_pull_request": ["brightlane/warrant-ops"],
                # github.merge_pull_request has NO entry - refused outright.
            }
        },
        "irreversible_gate": {
            "allowed_tools": [
                "gmail.send",
                "calendar.create_event",
                "slack.post_message",
                "twilio.send_sms",
            ]
        },
        "audience_bound": {"max_distinct_per_day": {"slack.post_message": 2}},
        "rate_limit": {
            "max_actions_per_day": {
                "gmail.send": 10, "calendar.create_event": 10, "notion.create_page": 10,
                "slack.post_message": 10, "twilio.send_sms": 10,
                "linear.create_issue": 10, "github.create_pull_request": 10,
                "github.merge_pull_request": 10,
            },
            "idempotency": True,
        },
    },
}


@pytest.fixture
def governed(tmp_path, monkeypatch):
    """An isolated gate with POLICY in place - policy file, data dir and kill
    switch all under tmp_path, so no test here depends on or mutates the
    repo's real policy.yaml or .warrant directory."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml.safe_dump(POLICY), encoding="utf-8")
    monkeypatch.setattr(policy_mod, "POLICY_FILE", policy_file)
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "KILL_SWITCH_LOCATIONS", [tmp_path / "KILL_SWITCH"])
    monkeypatch.setattr(journal_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(journal_mod, "JOURNAL_DB", tmp_path / "journal.db")
    return tmp_path


@pytest.fixture
def wired(governed, tmp_path):
    """A Broker over fakes for every app the example workflows touch, plus a
    thread the gmail/calendar steps can be scoped against."""
    gmail, cal, notion = FakeGmail(), FakeCalendar(), FakeNotion()
    slack, twilio, linear, github = FakeSlack(), FakeTwilio(), FakeLinear(), FakeGitHub()
    gmail.threads["t-inbound-1"] = seed_thread(
        "t-inbound-1", [OWNER, RECRUITER], "Intro call this week?",
        "Are you free Thursday morning for a 30 minute intro call?",
    )
    broker = Broker(
        gmail=gmail, calendar=cal, notion=notion,
        apps={"slack": slack, "twilio": twilio, "linear": linear, "github": github},
        ledger=Ledger(tmp_path / "ledger.db"),
    )
    return broker, {"gmail": gmail, "calendar": cal, "notion": notion, "slack": slack,
                     "twilio": twilio, "linear": linear, "github": github}


def load(name: str) -> dict:
    return load_workflow(REPO_ROOT_WORKFLOWS / name)


# ── the example files parse and are internally consistent ───────────────────


@pytest.mark.parametrize(
    "name", ["meeting_intake.yaml", "incident_response.yaml", "broadcast_bound.yaml"]
)
def test_every_example_workflow_loads(name):
    """The three shipped examples are the evidence the runner works on more
    than a hand-picked test fixture - if one fails to parse, the README's
    claim about them is false."""
    spec = load(name)
    assert spec["steps"], f"{name} has no steps"
    assert len({s["id"] for s in spec["steps"]}) == len(spec["steps"]), f"{name} reuses a step id"


# ── the happy path: N steps, N proposals, same gate ──────────────────────────


def test_meeting_intake_runs_end_to_end(wired):
    """Three apps, three steps, all allowed - and the Notion step's body
    carries the REAL calendar event id via template substitution, not a
    string the workflow author guessed at write time."""
    broker, fakes = wired
    result = run_workflow(load("meeting_intake.yaml"), broker)

    assert result.completed
    assert result.all_allowed
    assert [s.step_id for s in result.steps] == ["reply", "book", "log"]

    assert len(fakes["gmail"].sent) == 1
    assert len(fakes["calendar"].created) == 1
    assert len(fakes["notion"].pages) == 1

    real_event_id = fakes["calendar"].created[0]["id"]
    assert real_event_id in fakes["notion"].pages[0]["body_md"], (
        "the logged note should carry the calendar step's own external_id, not a "
        "hand-typed placeholder"
    )


def test_incident_response_chains_three_apps(wired):
    """Twilio -> Slack -> Linear, with the Twilio message sid threaded into
    both later steps' text via template substitution."""
    broker, fakes = wired
    result = run_workflow(load("incident_response.yaml"), broker)

    assert result.completed
    assert result.all_allowed
    sid = fakes["twilio"].sent[0]["sid"]
    assert sid in fakes["slack"].posted[0]["text"]
    assert sid in fakes["linear"].issues[0]["title"]


# ── halt is the default, and it means "never even proposed" ─────────────────


def test_a_refused_step_halts_and_later_steps_are_never_proposed(wired):
    """The core safety property: a step after a refusal is not refused, it is
    never attempted at all - and the fake ledger it would have touched stays
    empty, the same invariant test_broker_boundary.py checks for one proposal."""
    broker, fakes = wired
    spec = {
        "name": "halt-demo",
        "steps": [
            {"id": "bad_send", "tool": "gmail.send", "thread_id": "t-inbound-1",
             "params": {"to": ["stranger@evil.example"], "subject": "x", "body": "y"}},
            {"id": "would_log", "tool": "notion.create_page",
             "params": {"parent_id": PARENT, "title": "should never happen"}},
        ],
    }
    result = run_workflow(spec, broker)

    assert not result.completed
    assert result.halted_at == "bad_send"
    assert result.skipped == ["would_log"]
    assert [s.step_id for s in result.steps] == ["bad_send"]
    assert result.steps[0].status == STATUS_REJECTED

    assert fakes["gmail"].sent == []
    assert fakes["notion"].pages == [], (
        "would_log must never reach the app - it was skipped, not refused"
    )


def test_on_refused_continue_lets_the_workflow_proceed(wired):
    """A step marked on_refused: continue does not stop the run - the next
    step still gets its own, independent gate decision."""
    broker, fakes = wired
    spec = {
        "name": "continue-demo",
        "steps": [
            {"id": "bad_ticket", "tool": "linear.create_issue", "on_refused": ON_REFUSED_CONTINUE,
             "params": {"team_id": "not-allowlisted", "title": "x"}},
            {"id": "notify", "tool": "slack.post_message",
             "params": {"channel": "C0WARRANTOPS", "text": "proceeding anyway"}},
        ],
    }
    result = run_workflow(spec, broker)

    assert result.completed
    assert [s.step_id for s in result.steps] == ["bad_ticket", "notify"]
    assert result.steps[0].status == STATUS_REJECTED
    assert result.steps[1].status == STATUS_EXECUTED
    assert fakes["linear"].issues == []
    assert len(fakes["slack"].posted) == 1


def test_audience_bound_halts_the_broadcast(wired):
    """broadcast_bound.yaml's third post is the third DISTINCT slack channel
    of the day against a cap of 2 - audience_bound refuses it, the run halts
    there by default, and the summary log is never attempted."""
    broker, fakes = wired
    result = run_workflow(load("broadcast_bound.yaml"), broker)

    assert not result.completed
    assert result.halted_at == "post_status"
    assert result.skipped == ["log_summary"]
    assert "audience_bound" in result.steps[-1].rule_ids
    assert len(fakes["slack"].posted) == 2
    assert fakes["notion"].pages == []


# ── malformed workflows fail loudly, not partially ───────────────────────────


def test_load_workflow_rejects_duplicate_step_ids(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        yaml.safe_dump({"steps": [
            {"id": "x", "tool": "slack.post_message", "params": {}},
            {"id": "x", "tool": "slack.post_message", "params": {}},
        ]}),
        encoding="utf-8",
    )
    with pytest.raises(WorkflowError, match="used twice"):
        load_workflow(bad)


def test_load_workflow_rejects_an_unknown_on_refused_value(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        yaml.safe_dump({"steps": [
            {"id": "x", "tool": "slack.post_message", "on_refused": "shrug", "params": {}},
        ]}),
        encoding="utf-8",
    )
    with pytest.raises(WorkflowError, match="on_refused"):
        load_workflow(bad)


def test_load_workflow_rejects_no_steps(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"name": "empty"}), encoding="utf-8")
    with pytest.raises(WorkflowError, match="no steps"):
        load_workflow(bad)


def test_template_cannot_reference_a_refused_steps_missing_field(wired):
    """A template pulling `.external_id` off a step that never executed must
    fail loudly - substituting "None" into a live param would silently send
    a broken value to whatever app is next, instead of stopping the run."""
    broker, _ = wired
    spec = {
        "name": "bad-template",
        "steps": [
            {"id": "refused", "tool": "linear.create_issue",
             "params": {"team_id": "not-allowlisted", "title": "x"}, "on_refused": ON_REFUSED_CONTINUE},
            {"id": "next", "tool": "slack.post_message",
             "params": {"channel": "C0WARRANTOPS", "text": "ticket was ${steps.refused.external_id}"}},
        ],
    }
    with pytest.raises(WorkflowError, match="external_id"):
        run_workflow(spec, broker)


# ── the evidence trail ────────────────────────────────────────────────────


def test_every_step_is_journaled_like_a_lone_proposal(wired):
    """A workflow step's decision lands in journal.db exactly like a proposal
    made outside a workflow - the runner adds no second logging path."""
    broker, _ = wired
    before = journal_mod.summary()["total"]
    run_workflow(load("meeting_intake.yaml"), broker)
    after = journal_mod.summary()["total"]
    assert after - before == 3


def test_run_workflow_file_writes_one_artifact_naming_every_step(wired, tmp_path):
    """The single signed evidence trail the brief asked for: one artifact per
    run, naming every step's verdict and journal row id."""
    broker, _ = wired
    artifact_dir = tmp_path / "artifacts"
    result, path = run_workflow_file(
        REPO_ROOT_WORKFLOWS / "meeting_intake.yaml", broker, artifact_dir=artifact_dir
    )
    assert path.exists()
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["kind"] == "workflow"
    assert payload["result"]["completed"] is True
    step_ids = [s["step_id"] for s in payload["result"]["steps"]]
    assert step_ids == ["reply", "book", "log"]
    assert all(s["journal_id"] is not None for s in payload["result"]["steps"])
    # git SHA / dirty flag / environment - the same provenance stamp eval and
    # smoke artifacts carry, so a workflow run is traceable the same way.
    assert "git" in payload and "environment" in payload
