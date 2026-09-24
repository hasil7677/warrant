"""
registry.py
───────────
The app adapter registry: every application this gate governs, every action
those applications expose, and - the part that matters - what each action is
*capable of*.

Nothing here imports anything else in the package and nothing here executes
anything. It is a table. The clients that hold credentials live in
`warrant.apps` and only the broker may reach them; what lives here is the
description of those clients, which every layer is allowed to read.

## Why a registry replaced three hardcoded tuples

The first version of this project governed three apps and five actions, and the
policy rules were named after them: `notion_parent_allowlist` knew the word
"notion". That is fine at three apps and indefensible at thirteen. A gate that
must learn a new rule for every new app is a gate that rots, because the day
someone is in a hurry the app ships and the rule does not.

So a tool does not tell the policy which app it belongs to. It tells the policy
what it can do:

    slack.post_message   write, third_party, audience, irreversible

The rules read those classes. `audience_bound` has never heard of Slack and
bounds it anyway, which is the only property that makes app number sixteen
governed on the day it is added rather than on the day someone remembers.

## The capability classes

Ten, and they are hazards rather than categories. Each one names a way an
action can be worse than the person who authorized it expected:

  write         changes state in the application at all. Every action here has
                it; it is stated rather than assumed so that a future read-only
                tool is distinguishable from one nobody classified.
  destructive   removes or overwrites state that existed before. Distinct from
                `write`, because creating a row and clearing a range are not the
                same risk even though both are writes.
  reversible    the tool surface offers an undo that restores the prior state
                *as observed by everyone who could already have seen it*.
  irreversible  it does not. A Slack message can be deleted; it cannot be
                un-read, so posting is irreversible under that definition. This
                is the strict reading on purpose: the lenient one would let
                "technically deletable" cover most of the damage an agent can do.
  third_party   the effect lands in front of somebody outside the operator's
                control. The operator can clean up their own workspace; they
                cannot clean up a stranger's inbox.
  audience      it delivers to a set of people the proposal does not enumerate.
                `to: [a@b.com, c@d.com]` is two recipients. `channel: #general`
                is however many people are in #general, and the proposal does
                not say how many.
  spend         it moves money. Includes per-message telephony charges, which
                are small until a loop sends forty thousand of them.
  egress        it moves data to a place the tenant does not control. Sharing a
                Drive file with an outside address is egress; writing a row into
                the tenant's own sheet is not.
  code          it changes source, CI, or what runs in production.
  identity      it changes who can access what.

`reversible` and `irreversible` are mutually exclusive and exactly one is
required on every tool. That is a validation error rather than a default,
because a default would mean the safest-sounding answer is what you get for
forgetting to think about it.

## Liveness, stated in the data

Three apps in this table have credentials and a smoke artifact behind them. Ten
do not: they are real HTTP clients written against the documented REST API, with
no account to run them against. `liveness` records which is which and
`evidence` names the artifact that backs a live claim, so the README, the
console and the test suite all read the same field instead of three people
remembering the same thing. `tests/test_registry.py::test_proven_live_apps_name_an_artifact_that_says_so`
opens the artifact and checks it agrees.

Overclaiming here would cost more than it bought. The whole project is an
argument about evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

# ── capability classes ──────────────────────────────────────────────────────

WRITE = "write"
DESTRUCTIVE = "destructive"
REVERSIBLE = "reversible"
IRREVERSIBLE = "irreversible"
THIRD_PARTY = "third_party"
AUDIENCE = "audience"
SPEND = "spend"
EGRESS = "egress"
CODE = "code"
IDENTITY = "identity"

CAPABILITY_CLASSES: tuple[str, ...] = (
    WRITE,
    DESTRUCTIVE,
    REVERSIBLE,
    IRREVERSIBLE,
    THIRD_PARTY,
    AUDIENCE,
    SPEND,
    EGRESS,
    CODE,
    IDENTITY,
)

# The two classes that answer "can this be undone". They are handled by their
# own policy rule rather than by the class allowlist, because reversibility is a
# property of an action and the other eight are hazards it carries.
REVERSIBILITY_CLASSES = frozenset({REVERSIBLE, IRREVERSIBLE})

CLASS_DESCRIPTIONS: dict[str, str] = {
    WRITE: "changes state in the application",
    DESTRUCTIVE: "removes or overwrites state that existed before",
    REVERSIBLE: "can be undone through this tool surface",
    IRREVERSIBLE: "cannot be undone by anything this gate can reach",
    THIRD_PARTY: "the effect is visible to someone outside the operator's control",
    AUDIENCE: "delivers to a set of people the proposal does not enumerate",
    SPEND: "moves money",
    EGRESS: "moves data outside the tenant",
    CODE: "changes source, CI, or what runs in production",
    IDENTITY: "changes who can access what",
}

# ── liveness ────────────────────────────────────────────────────────────────

PROVEN_LIVE = "proven-live"
FAKE_ONLY = "fake-only"
LIVENESS_STATES = (PROVEN_LIVE, FAKE_ONLY)


# ── recipient and destination kinds ─────────────────────────────────────────
# What shape a recipient is, so a rule written for email addresses does not
# quietly apply itself to a phone number and pass because a phone number has no
# domain to check.

EMAIL = "email"
PHONE = "phone"
CHANNEL = "channel"


@dataclass(frozen=True)
class ParamSpec:
    """One parameter of one tool.

    `kind` is a shape, not a validator - the gate refuses unknown params and
    reasons about the ones it knows, and a type system in the policy file is the
    expression language this project keeps declining to build.
    """

    name: str
    kind: str = "string"  # string | string_list | integer | number | boolean
    required: bool = False
    description: str = ""


@dataclass(frozen=True)
class ToolSpec:
    """One action, and what it is capable of.

    Every field below exists because some rule needs to ask a question without
    knowing which app it is looking at:

      classes             what the policy reasons about instead of app names
      destination_param   where the write lands, for `destination_allowlist`
      recipient_params    who it reaches, for scope / domain / fanout rules
      recipient_kind      whether those recipients are addresses, numbers or
                          channels, so an email rule does not grade a phone
      audience_param      the single destination that stands for a crowd
      amount_param        how much money moves, read from the proposal, for
                          `spend_cap` - used when the caller states an amount
      flat_cost_minor     for a `spend` tool with no caller-stated amount (an
                          SMS has a per-message carrier cost the proposal
                          never names): a fixed minor-unit cost `spend_cap`
                          charges per call instead. Exactly one of
                          amount_param / flat_cost_minor is required on a
                          `spend` tool - a spend class backed by neither is a
                          cap nothing can enforce.
      scope               "thread" when the action must stay inside the thread
                          the broker read for itself
    """

    name: str
    app: str
    function: str
    summary: str
    params: tuple[ParamSpec, ...]
    classes: frozenset[str]
    destination_param: Optional[str] = None
    destination_kind: str = ""
    recipient_params: tuple[str, ...] = ()
    recipient_kind: str = ""
    audience_param: Optional[str] = None
    amount_param: Optional[str] = None
    currency_param: Optional[str] = None
    flat_cost_minor: Optional[int] = None
    flat_cost_currency: str = "usd"
    idempotency_params: tuple[str, ...] = ()
    scope: str = ""
    spend_enforced_externally: bool = False
    """True only for a SPEND tool whose cap is enforced by a dedicated policy
    rule reading a broker-verified fact (e.g. a live quote fetched at gate
    time), instead of `_rule_spend_cap` reading the model's own claimed
    `amount_param`. This is a STRONGER guarantee than amount_param/
    flat_cost_minor, not a weaker one - the model's claimed order value for a
    MARKET order is not a real number until the order fills, so trusting it
    the way a Stripe refund amount can be trusted would reintroduce the exact
    unverified-number problem `llmfin.risk.PRICE_BINDING_ORDER_TYPES` exists
    to avoid. Set this only when a named rule (see policy.py) actually
    enforces spend for this tool some other way - it is not a way to skip
    enforcement, only to point at where it lives. See kite.place_order and
    _rule_kite_mandate."""

    @property
    def param_names(self) -> set[str]:
        return {p.name for p in self.params}

    def has(self, capability: str) -> bool:
        return capability in self.classes

    @property
    def hazards(self) -> frozenset[str]:
        """Classes minus the reversibility pair. What `capability_allowlist` grades."""
        return frozenset(self.classes) - REVERSIBILITY_CLASSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "app": self.app,
            "summary": self.summary,
            "classes": sorted(self.classes),
            "params": [
                {"name": p.name, "kind": p.kind, "required": p.required,
                 "description": p.description}
                for p in self.params
            ],
            "destination_param": self.destination_param,
            "destination_kind": self.destination_kind,
            "recipient_params": list(self.recipient_params),
            "recipient_kind": self.recipient_kind,
            "audience_param": self.audience_param,
            "amount_param": self.amount_param,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class AppSpec:
    """One application: how it authenticates, and whether we have ever run it.

    `module` is the name under `warrant.apps`, `fake` the class in
    `warrant.fakes`. Both are strings rather than imports so that reading this
    table costs nothing and asks nothing of the machine - the broker resolves
    them when it actually needs a client.
    """

    name: str
    module: str
    fake: str
    title: str
    api: str
    auth: str
    liveness: str
    tools: tuple[ToolSpec, ...]
    evidence: str = ""
    note: str = ""

    @property
    def proven_live(self) -> bool:
        return self.liveness == PROVEN_LIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "api": self.api,
            "auth": self.auth,
            "liveness": self.liveness,
            "evidence": self.evidence,
            "note": self.note,
            "classes": sorted({c for t in self.tools for c in t.classes}),
            "tools": [t.to_dict() for t in self.tools],
        }


def _p(name: str, kind: str = "string", required: bool = False, description: str = "") -> ParamSpec:
    return ParamSpec(name=name, kind=kind, required=required, description=description)


# ═══════════════════════════════════════════════════════════════════════════
# The suite
# ═══════════════════════════════════════════════════════════════════════════
# Ordered live-first, because that is the order the honesty matters in: the
# reader should meet the three apps with evidence before the ten without.

APP_LIST: tuple[AppSpec, ...] = (

    # ── proven live ─────────────────────────────────────────────────────────

    AppSpec(
        name="gmail",
        module="gmail",
        fake="FakeGmail",
        title="Gmail",
        api="Gmail API v1 (google-api-python-client)",
        auth="OAuth user consent - gmail.readonly + gmail.send, deliberately not gmail.modify",
        liveness=PROVEN_LIVE,
        evidence="artifacts/smoke_20260913T194858Z.json",
        tools=(
            ToolSpec(
                name="gmail.send",
                app="gmail",
                function="send",
                summary="Send an email in reply to a thread the broker read.",
                params=(
                    _p("to", "string_list", True, "Recipients. Must be thread participants."),
                    _p("cc", "string_list"),
                    _p("bcc", "string_list"),
                    _p("subject"),
                    _p("body"),
                    _p("in_reply_to", description="Thread id to reply within."),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, IRREVERSIBLE}),
                recipient_params=("to", "cc", "bcc"),
                recipient_kind=EMAIL,
                idempotency_params=("to", "cc", "bcc", "subject", "body"),
                scope="thread",
            ),
        ),
    ),

    AppSpec(
        name="calendar",
        module="gcal",
        fake="FakeCalendar",
        title="Google Calendar",
        api="Calendar API v3 (google-api-python-client)",
        auth="OAuth user consent - calendar.events",
        liveness=PROVEN_LIVE,
        evidence="artifacts/smoke_20260913T194858Z.json",
        tools=(
            ToolSpec(
                name="calendar.create_event",
                app="calendar",
                function="create_event",
                summary="Create an event and invite the people already on the thread.",
                params=(
                    _p("summary"),
                    _p("start_iso", required=True),
                    _p("end_iso", required=True),
                    _p("attendees", "string_list"),
                    _p("description", description="Delivered verbatim to every attendee."),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, IRREVERSIBLE}),
                recipient_params=("attendees",),
                recipient_kind=EMAIL,
                idempotency_params=("attendees", "start_iso", "end_iso", "summary"),
                scope="thread",
            ),
        ),
    ),

    AppSpec(
        name="notion",
        module="notion",
        fake="FakeNotion",
        title="Notion",
        api="Notion REST v1, 2022-06-28 (plain requests, no SDK)",
        auth="Internal integration token",
        liveness=PROVEN_LIVE,
        evidence="artifacts/smoke_20260913T194858Z.json",
        tools=(
            ToolSpec(
                name="notion.create_page",
                app="notion",
                function="create_page",
                summary="File a note under an allowlisted page.",
                params=(
                    _p("parent_id", required=True, description="Page or database id."),
                    _p("title"),
                    _p("body_md"),
                ),
                classes=frozenset({WRITE, REVERSIBLE}),
                destination_param="parent_id",
                destination_kind="notion-parent",
                idempotency_params=("parent_id", "title"),
            ),
        ),
    ),

    # ── fake only ───────────────────────────────────────────────────────────

    AppSpec(
        name="slack",
        module="slack",
        fake="FakeSlack",
        title="Slack",
        api="Slack Web API (chat.postMessage, files.*ExternalUpload)",
        auth="Bot token, SLACK_BOT_TOKEN",
        liveness=FAKE_ONLY,
        note="No workspace to install a bot into. The client is written against "
             "the documented API and has never made a real call.",
        tools=(
            ToolSpec(
                name="slack.post_message",
                app="slack",
                function="post_message",
                summary="Post a message into a channel.",
                params=(
                    _p("channel", required=True, description="Channel id, e.g. C0123ABCD."),
                    _p("text", required=True),
                    _p("thread_ts", description="Reply inside an existing message thread."),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, AUDIENCE, IRREVERSIBLE}),
                destination_param="channel",
                destination_kind="slack-channel",
                recipient_params=("channel",),
                recipient_kind=CHANNEL,
                audience_param="channel",
                idempotency_params=("channel", "text"),
            ),
            ToolSpec(
                name="slack.upload_file",
                app="slack",
                function="upload_file",
                summary="Upload a file and share it into a channel.",
                params=(
                    _p("channel", required=True),
                    _p("filename", required=True),
                    _p("content", required=True, description="File bytes as text."),
                    _p("title"),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, AUDIENCE, EGRESS, IRREVERSIBLE}),
                destination_param="channel",
                destination_kind="slack-channel",
                recipient_params=("channel",),
                recipient_kind=CHANNEL,
                audience_param="channel",
                idempotency_params=("channel", "filename"),
            ),
        ),
    ),

    AppSpec(
        name="github",
        module="github",
        fake="FakeGitHub",
        title="GitHub",
        api="REST v3, X-GitHub-Api-Version 2022-11-28",
        auth="Fine-grained PAT, GITHUB_TOKEN",
        liveness=FAKE_ONLY,
        note="A token exists for no repository this project is allowed to write to, "
             "so none was issued. Written against the documented API, never run.",
        tools=(
            ToolSpec(
                name="github.create_issue",
                app="github",
                function="create_issue",
                summary="Open an issue on a repository.",
                params=(
                    _p("repo", required=True, description="owner/name"),
                    _p("title", required=True),
                    _p("body"),
                    _p("labels", "string_list"),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, CODE, REVERSIBLE}),
                destination_param="repo",
                destination_kind="github-repo",
                idempotency_params=("repo", "title"),
            ),
            ToolSpec(
                name="github.create_pull_request",
                app="github",
                function="create_pull_request",
                summary="Open a pull request from one branch to another.",
                params=(
                    _p("repo", required=True),
                    _p("title", required=True),
                    _p("head", required=True),
                    _p("base", required=True),
                    _p("body"),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, CODE, REVERSIBLE}),
                destination_param="repo",
                destination_kind="github-repo",
                idempotency_params=("repo", "head", "base", "title"),
            ),
            ToolSpec(
                name="github.merge_pull_request",
                app="github",
                function="merge_pull_request",
                summary="Merge a pull request into its base branch.",
                params=(
                    _p("repo", required=True),
                    _p("number", "integer", True),
                    _p("merge_method", description="merge | squash | rebase"),
                    _p("commit_title"),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, CODE, IRREVERSIBLE}),
                destination_param="repo",
                destination_kind="github-repo",
                idempotency_params=("repo", "number"),
            ),
            ToolSpec(
                name="github.add_collaborator",
                app="github",
                function="add_collaborator",
                summary="Grant a GitHub user access to a repository.",
                params=(
                    _p("repo", required=True),
                    _p("username", required=True),
                    _p("permission", description="pull | triage | push | maintain | admin"),
                ),
                classes=frozenset({WRITE, THIRD_PARTY, CODE, IDENTITY, IRREVERSIBLE}),
                destination_param="repo",
                destination_kind="github-repo",
                idempotency_params=("repo", "username", "permission"),
            ),
        ),
    ),

    AppSpec(
        name="linear",
        module="linear",
        fake="FakeLinear",
        title="Linear",
        api="GraphQL, https://api.linear.app/graphql",
        auth="Personal API key, LINEAR_API_KEY",
        liveness=FAKE_ONLY,
        note="No workspace. Written against the documented mutations, never run.",
        tools=(
            ToolSpec(
                name="linear.create_issue",
                app="linear",
                function="create_issue",
                summary="Create an issue on a team's board.",
                params=(
                    _p("team_id", required=True),
                    _p("title", required=True),
                    _p("description"),
                    _p("priority", "integer"),
                ),
                classes=frozenset({WRITE, REVERSIBLE}),
                destination_param="team_id",
                destination_kind="linear-team",
                idempotency_params=("team_id", "title"),
            ),
            ToolSpec(
                name="linear.update_issue",
                app="linear",
                function="update_issue",
                summary="Change the title, description or state of an existing issue.",
                params=(
                    _p("issue_id", required=True),
                    _p("title"),
                    _p("description"),
                    _p("state_id"),
                ),
                classes=frozenset({WRITE, DESTRUCTIVE, REVERSIBLE}),
                destination_param="issue_id",
                destination_kind="linear-issue",
                idempotency_params=("issue_id", "title", "state_id"),
            ),
        ),
    ),

    AppSpec(
        name="stripe",
        module="stripe",
        fake="FakeStripe",
        title="Stripe",
        api="REST v1, form-encoded (no SDK)",
        auth="Secret key, STRIPE_API_KEY",
        liveness=FAKE_ONLY,
        note="Deliberately not wired to a test-mode key either. A spend cap that has "
             "only ever been exercised against a sandbox is a spend cap nobody has "
             "tested, and pretending otherwise is the failure this project is about.",
        tools=(
            ToolSpec(
                name="stripe.create_refund",
                app="stripe",
                function="create_refund",
                summary="Refund a payment back to a customer.",
                params=(
                    _p("payment_intent", required=True),
                    _p("amount", "integer", True, "Minor units, e.g. cents."),
                    _p("currency", required=True),
                    _p("reason", description="duplicate | fraudulent | requested_by_customer"),
                ),
                classes=frozenset({WRITE, SPEND, THIRD_PARTY, IRREVERSIBLE}),
                destination_param="payment_intent",
                destination_kind="stripe-payment-intent",
                amount_param="amount",
                currency_param="currency",
                idempotency_params=("payment_intent", "amount", "currency"),
            ),
            ToolSpec(
                name="stripe.create_payout",
                app="stripe",
                function="create_payout",
                summary="Move money from the Stripe balance to the connected bank account.",
                params=(
                    _p("amount", "integer", True, "Minor units."),
                    _p("currency", required=True),
                    _p("description"),
                    _p("destination", description="Bank account or card id."),
                ),
                classes=frozenset({WRITE, SPEND, IRREVERSIBLE}),
                destination_param="destination",
                destination_kind="stripe-payout-destination",
                amount_param="amount",
                currency_param="currency",
                idempotency_params=("amount", "currency", "destination"),
            ),
        ),
    ),

    AppSpec(
        name="twilio",
        module="twilio",
        fake="FakeTwilio",
        title="Twilio",
        api="REST 2010-04-01, form-encoded, HTTP Basic",
        auth="Account SID + auth token, TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN",
        liveness=FAKE_ONLY,
        note="No account. Note that this one both spends and reaches a stranger's "
             "phone, which is why it carries three hazard classes rather than one.",
        tools=(
            ToolSpec(
                name="twilio.send_sms",
                app="twilio",
                function="send_sms",
                summary="Send an SMS. Costs money per message and arrives on a phone.",
                params=(
                    _p("to", "string_list", True, "E.164 numbers."),
                    _p("from_number", required=True),
                    _p("body", required=True),
                ),
                classes=frozenset({WRITE, SPEND, THIRD_PARTY, IRREVERSIBLE}),
                recipient_params=("to",),
                recipient_kind=PHONE,
                idempotency_params=("to", "body"),
                # Twilio bills a fixed carrier cost per message segment and the
                # proposal never states a dollar figure, unlike a refund or a
                # payout - so spend_cap prices this call at a flat cost rather
                # than reading an amount param that does not exist.
                flat_cost_minor=1,
                flat_cost_currency="usd",
            ),
        ),
    ),

    AppSpec(
        name="drive",
        module="drive",
        fake="FakeDrive",
        title="Google Drive",
        api="Drive API v3 over plain REST",
        auth="OAuth bearer from the same Google consent, plus drive.file scope",
        liveness=FAKE_ONLY,
        note="The cached token.json carries gmail and calendar scopes only. Adding "
             "drive scopes invalidates that token and would break the one live path "
             "this repo has evidence for, so it was not done.",
        tools=(
            ToolSpec(
                name="drive.upload_file",
                app="drive",
                function="upload_file",
                summary="Upload a file into a folder the operator owns.",
                params=(
                    _p("folder_id", required=True),
                    _p("name", required=True),
                    _p("content", required=True),
                    _p("mime_type"),
                ),
                classes=frozenset({WRITE, REVERSIBLE}),
                destination_param="folder_id",
                destination_kind="drive-folder",
                idempotency_params=("folder_id", "name"),
            ),
            ToolSpec(
                name="drive.share_file",
                app="drive",
                function="share_file",
                summary="Grant someone access to a file.",
                params=(
                    _p("file_id", required=True),
                    _p("email", description="Leave empty with audience=anyone for a public link."),
                    _p("role", description="reader | commenter | writer"),
                    _p("audience", description="user | domain | anyone"),
                ),
                classes=frozenset({WRITE, EGRESS, IDENTITY, THIRD_PARTY, IRREVERSIBLE}),
                destination_param="file_id",
                destination_kind="drive-file",
                recipient_params=("email",),
                recipient_kind=EMAIL,
                idempotency_params=("file_id", "email", "role", "audience"),
            ),
        ),
    ),

    AppSpec(
        name="sheets",
        module="sheets",
        fake="FakeSheets",
        title="Google Sheets",
        api="Sheets API v4 over plain REST",
        auth="OAuth bearer from the same Google consent, plus spreadsheets scope",
        liveness=FAKE_ONLY,
        note="Same scope problem as Drive.",
        tools=(
            ToolSpec(
                name="sheets.append_row",
                app="sheets",
                function="append_row",
                summary="Append a row to a sheet.",
                params=(
                    _p("spreadsheet_id", required=True),
                    _p("range_a1", required=True, description="e.g. Sheet1!A:D"),
                    _p("values", "string_list", True),
                ),
                classes=frozenset({WRITE, REVERSIBLE}),
                destination_param="spreadsheet_id",
                destination_kind="sheets-spreadsheet",
                idempotency_params=("spreadsheet_id", "range_a1", "values"),
            ),
            ToolSpec(
                name="sheets.clear_range",
                app="sheets",
                function="clear_range",
                summary="Erase the values in a range.",
                params=(
                    _p("spreadsheet_id", required=True),
                    _p("range_a1", required=True),
                ),
                classes=frozenset({WRITE, DESTRUCTIVE, IRREVERSIBLE}),
                destination_param="spreadsheet_id",
                destination_kind="sheets-spreadsheet",
                idempotency_params=("spreadsheet_id", "range_a1"),
            ),
        ),
    ),

    AppSpec(
        name="kite",
        module="kite",
        fake="FakeKite",
        title="Zerodha Kite Connect",
        api="Kite Connect v3 (kiteconnect)",
        auth="Per-tenant OAuth (BYO Kite Connect app) - see finLM-platform/api/kite_gateway.py",
        liveness=FAKE_ONLY,
        note=(
            "finLM's own Kite OAuth/order-placement path (llmfin.session_manager, "
            "llmfin.risk) is separately proven live for a single operator - see "
            "finLM's CLAUDE.md. As of 2026-09-24 this tool HAS been exercised "
            "through warrant's own gate end to end, in paper mode: "
            "finLM-platform/api/tests/test_full_pipeline_integration.py runs a "
            "real finlmjr.pipeline.run_symbol() proposal through "
            "finlm_api.execution.propose_and_execute() -> this real Broker.execute() "
            "-> the real _rule_kite_mandate -> real (adversarially-tested) "
            "llmfin.risk.check_order() - against a fake, non-network KiteConnect "
            "standing in for the tenant's account, reached through the real "
            "tenant_auth bearer-key HTTP path (deps.get_tenant_id), not a shortcut. "
            "Both outcomes were proven and journaled: an ALLOW that actually calls "
            "the fake client's place_order() (decision=ALLOWED in the tenant's own "
            "warrant journal.db), and a mandate-exceeding DENY that is refused "
            "before the client is ever called (decision=REFUSED, rule_id "
            "kite_mandate). What remains unexercised is a REAL Kite account/API "
            "call - no tenant has registered a Kite Connect app yet, so liveness "
            "stays FAKE_ONLY: that label is specifically about a live broker call, "
            "and none has ever been made for this app. Unlike every other app in "
            "this registry, the client for 'kite' is never lazily resolved from "
            "warrant.apps - credentials are tenant-scoped and live in Postgres, "
            "not a static module-level session, so the platform layer MUST always "
            "construct Broker(apps={'kite': <tenant's authenticated KiteConnect>}) "
            "explicitly. warrant.apps.kite / FakeKite do not exist; a Broker that "
            "reaches this app without one supplied fails loudly on import, which "
            "is the correct behaviour - there is no valid default kite client."
        ),
        tools=(
            ToolSpec(
                name="kite.place_order",
                app="kite",
                function="place_order",
                summary=(
                    "Place a real order on the tenant's own Kite trading account. "
                    "Gated by _rule_kite_mandate (policy.py), which delegates to "
                    "llmfin.risk.check_order() - the same mandate/kill-switch logic "
                    "finLM's own single-operator gate uses, evaluated per-tenant."
                ),
                params=(
                    _p("tradingsymbol", required=True),
                    _p("transaction_type", required=True, description="BUY | SELL"),
                    _p("quantity", "integer", True),
                    _p("order_type", description="MARKET | LIMIT | SL | SL-M"),
                    _p("price", "number", description="Only binding for a BUY LIMIT/SL - see PRICE_BINDING_ORDER_TYPES."),
                    _p("trigger_price", "number"),
                    _p("product", description="CNC | MIS | NRML"),
                    _p("exchange", description="e.g. NSE"),
                ),
                # Not THIRD_PARTY: the tenant is trading their own account, there
                # is no recipient/thread this action lands in front of. Not
                # DESTRUCTIVE: an order adds/reduces a position, it does not
                # overwrite prior state. No amount_param/flat_cost_minor: a
                # MARKET order's value is unknown until fill, and the model's own
                # claimed price is exactly the unverified number risk.py's
                # PRICE_BINDING_ORDER_TYPES exists to distrust - spend/mandate
                # enforcement happens entirely inside _rule_kite_mandate via
                # KiteFacts, not via Broker._effect_fields()'s generic spend path.
                classes=frozenset({WRITE, SPEND, IRREVERSIBLE}),
                spend_enforced_externally=True,  # see _rule_kite_mandate, policy.py
                idempotency_params=(
                    "tradingsymbol", "transaction_type", "quantity",
                    "order_type", "product", "exchange",
                ),
            ),
        ),
    ),

)


# ── derived views ───────────────────────────────────────────────────────────
# Everything below is computed from APP_LIST. Nothing is typed twice, so a tool
# cannot exist in one table and be missing from another.

APPS: dict[str, AppSpec] = {a.name: a for a in APP_LIST}
TOOLS: dict[str, ToolSpec] = {t.name: t for a in APP_LIST for t in a.tools}

ACTIONS: tuple[str, ...] = tuple(TOOLS)

# Param keys each action accepts. The gate rejects unknown keys outright rather
# than ignoring them: an unknown key is either a typo or an attempt to reach a
# code path the policy was never written against.
ACTION_PARAMS: dict[str, set[str]] = {name: spec.param_names for name, spec in TOOLS.items()}

PROVEN_LIVE_APPS: tuple[str, ...] = tuple(a.name for a in APP_LIST if a.proven_live)
FAKE_ONLY_APPS: tuple[str, ...] = tuple(a.name for a in APP_LIST if not a.proven_live)


def tool_spec(tool: str) -> Optional[ToolSpec]:
    """The descriptor for a tool name, or None if this build does not have it."""
    return TOOLS.get(str(tool))


def app_spec(app: str) -> Optional[AppSpec]:
    return APPS.get(str(app))


def app_of(tool: str) -> str:
    spec = TOOLS.get(str(tool))
    return spec.app if spec else ""


def tools_with(capability: str) -> tuple[str, ...]:
    """Every tool carrying a capability class. This is how a policy rule written
    against `spend` finds the tools it governs without naming Stripe."""
    return tuple(name for name, spec in TOOLS.items() if capability in spec.classes)


def classes_in_use() -> frozenset[str]:
    return frozenset(c for spec in TOOLS.values() for c in spec.classes)


def suite_summary() -> dict[str, Any]:
    """What the console and the README both read, so they cannot disagree."""
    return {
        "apps": [a.to_dict() for a in APP_LIST],
        "counts": {
            "apps": len(APP_LIST),
            "tools": len(TOOLS),
            "proven_live": len(PROVEN_LIVE_APPS),
            "fake_only": len(FAKE_ONLY_APPS),
        },
        "capability_classes": {c: CLASS_DESCRIPTIONS[c] for c in CAPABILITY_CLASSES},
    }


# ── validation ──────────────────────────────────────────────────────────────


def validate(apps: Iterable[AppSpec] = APP_LIST) -> list[str]:
    """Every internal consistency rule this table has to satisfy.

    Returned as a list rather than raised one at a time so a broken registry
    reports all of its problems at once, the same way `check()` collects every
    policy objection instead of sending the caller round the loop.
    """
    problems: list[str] = []
    seen_tools: set[str] = set()
    seen_apps: set[str] = set()

    for app in apps:
        if app.name in seen_apps:
            problems.append(f"duplicate app {app.name!r}")
        seen_apps.add(app.name)

        if app.liveness not in LIVENESS_STATES:
            problems.append(
                f"app {app.name!r} has liveness {app.liveness!r}; must be one of "
                f"{list(LIVENESS_STATES)}"
            )
        if app.proven_live and not app.evidence:
            problems.append(
                f"app {app.name!r} claims {PROVEN_LIVE} but names no evidence artifact. "
                "A liveness claim with nothing behind it is the claim this project exists "
                "to stop making."
            )
        if not app.proven_live and not app.note:
            problems.append(
                f"app {app.name!r} is {FAKE_ONLY} and says nothing about why. The reason "
                "there is no live run is the interesting part."
            )
        if not app.tools:
            problems.append(f"app {app.name!r} declares no tools")

        for tool in app.tools:
            if tool.name in seen_tools:
                problems.append(f"duplicate tool {tool.name!r}")
            seen_tools.add(tool.name)

            if tool.app != app.name:
                problems.append(f"tool {tool.name!r} claims app {tool.app!r}, listed under {app.name!r}")
            if not tool.name.startswith(f"{app.name}."):
                problems.append(f"tool {tool.name!r} is not namespaced under {app.name!r}")

            unknown = sorted(set(tool.classes) - set(CAPABILITY_CLASSES))
            if unknown:
                problems.append(f"tool {tool.name!r} declares unknown capability class(es) {unknown}")

            reversibility = set(tool.classes) & REVERSIBILITY_CLASSES
            if len(reversibility) != 1:
                problems.append(
                    f"tool {tool.name!r} declares {sorted(reversibility) or 'no'} reversibility "
                    f"class; exactly one of {sorted(REVERSIBILITY_CLASSES)} is required. There is "
                    "no default, because the default would be whatever nobody thought about."
                )
            if WRITE not in tool.classes:
                problems.append(
                    f"tool {tool.name!r} is an action and does not declare {WRITE!r}. Reads are "
                    "performed by the broker and are not proposals."
                )
            if DESTRUCTIVE in tool.classes and WRITE not in tool.classes:
                problems.append(f"tool {tool.name!r} is {DESTRUCTIVE} but not {WRITE}")

            names = tool.param_names
            if len(names) != len(tool.params):
                problems.append(f"tool {tool.name!r} declares a parameter twice")
            for attr in ("destination_param", "audience_param", "amount_param", "currency_param"):
                value = getattr(tool, attr)
                if value and value not in names:
                    problems.append(
                        f"tool {tool.name!r} points {attr} at {value!r}, which is not one of its params"
                    )
            for rp in tool.recipient_params:
                if rp not in names:
                    problems.append(
                        f"tool {tool.name!r} lists recipient param {rp!r}, which is not one of its params"
                    )
            for ip in tool.idempotency_params:
                if ip not in names:
                    problems.append(
                        f"tool {tool.name!r} lists idempotency param {ip!r}, which is not one of its params"
                    )
            if tool.recipient_params and tool.recipient_kind not in (EMAIL, PHONE, CHANNEL):
                problems.append(
                    f"tool {tool.name!r} has recipients of unstated kind {tool.recipient_kind!r}. A "
                    "rule written for email addresses must not silently grade a phone number."
                )
            if AUDIENCE in tool.classes and not (tool.audience_param or tool.recipient_params):
                problems.append(
                    f"tool {tool.name!r} is {AUDIENCE} but names nothing the fanout bound can read"
                )
            if (
                SPEND in tool.classes
                and not (tool.amount_param or tool.flat_cost_minor)
                and not tool.spend_enforced_externally
            ):
                problems.append(
                    f"tool {tool.name!r} is {SPEND} but names neither an amount_param nor a "
                    "flat_cost_minor, so no cap can be enforced against it (or, if enforcement "
                    "genuinely lives in a dedicated policy rule instead, set "
                    "spend_enforced_externally=True and name that rule in a comment)"
                )
            if tool.amount_param and tool.flat_cost_minor:
                problems.append(
                    f"tool {tool.name!r} sets both amount_param and flat_cost_minor; a call is "
                    "priced one way or the other, not both"
                )
            if not tool.idempotency_params:
                problems.append(
                    f"tool {tool.name!r} names no idempotency params, so a retry storm has nothing "
                    "to collapse on"
                )

    return problems


_PROBLEMS = validate()
if _PROBLEMS:  # a broken registry is a programming error and must be loud
    raise RuntimeError(
        "warrant.registry is internally inconsistent:\n  - " + "\n  - ".join(_PROBLEMS)
    )
