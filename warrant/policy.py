"""
policy.py
─────────
The gate. Every Proposal the model produces passes through `check()` before the
broker is allowed to touch any of the thirteen apps in the suite - and
`check()` answers out of a file this package cannot write.

The shape of the argument, ported from the trading gate this is modelled on:

  • policy.yaml    - the authorization, written by the USER. A missing file means
    every action is refused, not defaulted open. Nothing in this package creates
    it, because a consent the software can author is not a consent.
  • KILL_SWITCH    - create a file named KILL_SWITCH beside the policy (or in
    WARRANT_DATA_DIR) and every proposal is refused until it is deleted. It is
    checked before the policy is even read, so it still works when the policy is
    broken, missing, or half-written by an editor.
  • No override    - `check()` takes a proposal, the facts the broker read for
    itself, and a ledger. There is no `confirmed=`, no `force=`, no `dry_run=`.
    A flag the model can set is a flag the model controls, and a gate the model
    controls is decoration.

Rules are dispatched BY NAME from the `rules:` block of policy.yaml into the
`RULES` table below. There is deliberately no expression language: a policy file
that can compute is a policy file that can be talked into computing something
else, and the set of things this gate can be asked to do is meant to be legible
to the human who signed it.

`check()` collects every failure rather than returning on the first one, so a
refusal names all of what is wrong with a proposal instead of sending the model
round the loop to discover the objections one at a time.

## What changed for the multi-app suite

The original six rules were written against three apps' worth of field names:
`recipient_scope` knew `to` / `cc` / `bcc` / `attendees`, `notion_parent_allowlist`
knew `parent_id`. That does not extend to thirteen apps - a rule that has to be
taught a new field name for every app is a rule that is one release behind the
app list, forever.

So the field names came out of this file and into `warrant.registry`, which is
the only new import below. `_RECIPIENT_FIELDS` and `_IDEMPOTENCY_PARAMS` are now
*computed* from every tool's `ToolSpec` instead of typed out per app - which
means `recipient_scope`, `domain_allowlist` and `no_distribution_lists` apply to
a new tool the moment it declares `recipient_kind="email"`, with no change to
this file at all. That is the whole thesis of the registry, demonstrated in the
two module-level dicts just below the imports.

Four rules are new, and each reasons about a capability class rather than an
app: `destination_allowlist` generalizes `notion_parent_allowlist` to every
other tool that writes to a named place; `spend_cap` bounds anything the
registry marks `spend`; `irreversible_gate` requires an explicit allowlist for
anything marked `irreversible`; `audience_bound` caps how many distinct
fan-out destinations a tool may reach in a day. None of the four mention an
app by name in their implementation - only in the policy.yaml a human writes.
"""

from __future__ import annotations

import hashlib
import json
import os
import unicodedata
from pathlib import Path
from itertools import zip_longest
from typing import Any, Callable, Optional

import yaml

try:  # imported as `warrant.policy` - the normal case
    from .contract import (
        ACTION_PARAMS,
        ACTIONS,
        CALENDAR_CREATE_EVENT,
        GMAIL_SEND,
        NOTION_CREATE_PAGE,
        Proposal,
        KiteFacts,
        ThreadFacts,
        Verdict,
    )
    from . import identity, registry as registry_mod
except ImportError:  # imported as a bare module from inside the package directory
    from contract import (  # type: ignore[no-redef]
        ACTION_PARAMS,
        ACTIONS,
        CALENDAR_CREATE_EVENT,
        GMAIL_SEND,
        NOTION_CREATE_PAGE,
        Proposal,
        KiteFacts,
        ThreadFacts,
        Verdict,
    )
    import identity  # type: ignore[no-redef]
    import registry as registry_mod  # type: ignore[no-redef]

DATA_DIR = Path(os.getenv("WARRANT_DATA_DIR", ".warrant"))
POLICY_FILE = Path(os.getenv("WARRANT_POLICY_FILE", "policy.yaml"))

KILL_SWITCH_LOCATIONS = [
    Path("KILL_SWITCH"),
    DATA_DIR / "KILL_SWITCH",
]

# Which params of an action identify "the same action done twice", for every
# tool in the registry. Deliberately a subset of each tool's params:
# re-sending the identical mail with a reworded rationale is still the same
# mail arriving in someone's inbox twice, so `rationale` is never in here and
# neither is anything else the model can vary for free - see
# `ToolSpec.idempotency_params` for where each tool draws that line.
_IDEMPOTENCY_PARAMS: dict[str, tuple[str, ...]] = {
    name: spec.idempotency_params for name, spec in registry_mod.TOOLS.items()
}

# Where each action's outbound EMAIL recipients live, for every tool the
# registry marks `recipient_kind="email"`. A tool with no recipient params (a
# Notion page, a GitHub issue) is absent on purpose - it has a destination, not
# a recipient list, which `destination_allowlist` governs instead.
_RECIPIENT_FIELDS: dict[str, tuple[str, ...]] = {
    name: spec.recipient_params
    for name, spec in registry_mod.TOOLS.items()
    if spec.recipient_kind == registry_mod.EMAIL and spec.recipient_params
}

# The subset of _RECIPIENT_FIELDS where the recipients must additionally be
# scoped to a thread the broker read for itself. Only tools the registry marks
# `scope="thread"` get that check - a Drive share invite has no email thread to
# scope against, so it goes through domain_allowlist / no_distribution_lists
# but not recipient_scope.
_THREAD_SCOPED_TOOLS: frozenset[str] = frozenset(
    name for name, spec in registry_mod.TOOLS.items()
    if spec.scope == "thread" and name in _RECIPIENT_FIELDS
)


# ── canonicalisation ────────────────────────────────────────────────────────


def _norm_principal(s: Any) -> str:
    """Canonicalise an email address for allowlist/membership matching.

    An allowlist is only as good as the comparison behind it, and an address on a
    proposal is attacker-controlled text - it arrives from a model that just read
    an email a stranger wrote. Three classes of evasion have to die here:

      "alice@corp.com "  / "ali ce@corp.com"  - ordinary whitespace
      "alice<ZWSP>@corp.com"                  - zero-width space, word joiner,
                                                soft hyphen: invisible in a diff,
                                                invisible in a log, defeats ==
      "ａlice@corp.com"                        - full-width and other
                                                compatibility forms, which
                                                .lower() leaves full-width so
                                                they never match the ASCII entry

    NFKC folds compatibility forms (full-width -> ASCII); stripping the space,
    format and control categories removes the invisibles. Lower-case, not upper:
    these are addresses, and every provider anyone actually uses treats them
    case-insensitively, so folding down is the conservative direction for a
    membership test.

    Note what this does NOT do: it does not make a lookalike Cyrillic 'а' equal
    an ASCII 'a'. That is a different attack, and it is the domain allowlist that
    catches it.
    """
    s = unicodedata.normalize("NFKC", str(s))
    s = "".join(
        c for c in s
        if not c.isspace() and unicodedata.category(c) not in ("Cf", "Cc", "Zs", "Zl", "Zp")
    )
    return s.lower()


def _domain_of(addr: Any) -> str:
    """Domain of an address, split on the LAST '@' of the normalized form.

    The last one, because "alice@trusted.com@evil.com" is a real trick and the
    mail that leaves actually goes to evil.com. Splitting on the first '@' would
    have this gate reading "trusted.com" while the MTA reads "evil.com" - exactly
    the kind of disagreement a policy gate exists to not have.
    """
    norm = _norm_principal(addr)
    if "@" not in norm:
        return ""
    return norm.rsplit("@", 1)[1]


def _local_part_of(addr: Any) -> str:
    """Local part of an address - everything before the last '@'. Same reasoning."""
    norm = _norm_principal(addr)
    if "@" not in norm:
        return norm
    return norm.rsplit("@", 1)[0]


def _evasion_note(raw: Any) -> str:
    """If normalising changed more than case and outer whitespace, say so out loud.

    A refusal that prints the normalized address hides the attack: the log shows a
    clean-looking string and nobody ever learns the model wrote one with a
    zero-width joiner in it. Every reason below quotes the RAW string and appends
    this note, so the evasion attempt is what ends up on the record.
    """
    raw_s = str(raw)
    if _norm_principal(raw_s) != raw_s.strip().lower():
        return (
            " - the address as written contains non-printing or compatibility "
            f"characters; it normalises to {_norm_principal(raw_s)!r}"
        )
    return ""


def _as_list(value: Any) -> list[Any]:
    """Coerce a recipient field to a list without silently dropping anything.

    A model that writes `to: "a@b.com"` instead of `to: ["a@b.com"]` is making a
    formatting mistake, not a request to skip the recipient checks - so a bare
    string becomes a one-element list rather than being ignored. Anything that is
    neither string nor sequence is wrapped too, so it still reaches the rules and
    gets refused there instead of vanishing on the way.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _outbound_addresses(proposal: Proposal) -> list[Any]:
    """Every address this proposal would send something to, raw and in order."""
    params = proposal.params if isinstance(proposal.params, dict) else {}
    out: list[Any] = []
    for field in _RECIPIENT_FIELDS.get(proposal.tool, ()):
        out.extend(_as_list(params.get(field)))
    return out


def _squash(text: Any) -> str:
    """Collapse whitespace runs to single spaces and lower-case.

    Used for the body-containment comparison. Quoting a thread back with the line
    breaks re-flowed is still quoting the thread back, so the comparison must not
    be sensitive to how the text happened to be wrapped.
    """
    return " ".join(str(text).split()).lower()


def _norm_notion_id(value: Any) -> str:
    """Notion ids are the same id with or without dashes. Compare without."""
    return _norm_principal(value).replace("-", "")


# ── kill switch and policy loading ──────────────────────────────────────────


def kill_switch_active() -> Optional[str]:
    for loc in KILL_SWITCH_LOCATIONS:
        if loc.exists():
            return str(loc.resolve())
    return None


def load_policy() -> Optional[dict[str, Any]]:
    """Read policy.yaml, or return None if it does not exist.

    Read-only by construction, and there is no counterpart to this function:
    nothing in this package writes POLICY_FILE, creates it from a template, or
    fills in defaults for a missing key. If you are about to add one, re-read the
    module docstring first.
    """
    if not POLICY_FILE.exists():
        return None
    return yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))


def idempotency_key(proposal: Proposal) -> str:
    """Stable fingerprint of an action's *effect*, for duplicate suppression.

    Hashes the tool, the thread, and a canonical subset of the params - address
    lists normalized and sorted, because `to: [a, b]` and `to: [b, a]` deliver the
    identical mail, and a duplicate check that can be defeated by reordering a
    list is not a duplicate check.

    Which fields count, and how each is canonicalized, comes from the tool's
    `ToolSpec` rather than a hardcoded list of field names: a recipient field
    (declared in `recipient_params`) is sorted address-wise, the Notion
    destination is dash-insensitive, and everything else is whitespace-squashed
    text. A tool the registry has never heard of - unreachable in practice,
    since `check()` refuses an unknown tool before this is ever called - falls
    back to hashing every param key it was given, so a fingerprint is always
    produced rather than silently omitting fields nobody thought to list.
    """
    params = proposal.params if isinstance(proposal.params, dict) else {}
    spec = registry_mod.tool_spec(proposal.tool)
    fields = _IDEMPOTENCY_PARAMS.get(proposal.tool) or tuple(sorted(str(k) for k in params))
    recipient_fields = set(spec.recipient_params) if spec else set()
    notion_field = (
        spec.destination_param
        if spec and spec.destination_kind == "notion-parent"
        else None
    )
    canonical: dict[str, Any] = {}
    for field in fields:
        value = params.get(field)
        if field in recipient_fields:
            canonical[field] = sorted(_norm_principal(v) for v in _as_list(value))
        elif field == notion_field:
            canonical[field] = _norm_notion_id(value)
        else:
            canonical[field] = _squash(value) if value is not None else None
    blob = "\x1f".join(
        [
            str(proposal.tool),
            str(proposal.thread_id or ""),
            json.dumps(canonical, sort_keys=True, ensure_ascii=True, default=str),
        ]
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ── the rules ───────────────────────────────────────────────────────────────
# Each rule is (proposal, facts, cfg, ledger) -> list[(rule_id, reason)]. An
# empty list means "nothing to say", which is not the same as "approved" - a rule
# that does not apply to this tool and a rule that passed both return []. Only
# the absence of ALL objections is an approval, and only check() gets to decide
# that.


def _rule_recipient_scope(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Outbound recipients must already be in the thread the broker read.

    This is the rule the whole design exists for. The model's job is to reply to a
    thread; the set of people it may reply to is therefore a fact about that
    thread, and that fact comes from ThreadFacts - read from the API by the broker
    - never from the proposal. An instruction buried in an email body saying "also
    cc legal@..." is a string in someone else's message, and it cannot add a
    member to a set it did not come from.

    Scoped to `_THREAD_SCOPED_TOOLS` rather than every email-recipient tool:
    a tool the registry marks `recipient_kind="email"` but not `scope="thread"`
    (sharing a Drive file, say) has no email thread to scope against, and
    running this check against it would refuse on a `facts is None` it has no
    way to fix. `domain_allowlist` and `no_distribution_lists` still apply to
    it - they do not need a thread, only an address.
    """
    if proposal.tool not in _THREAD_SCOPED_TOOLS:
        return []

    if facts is None:
        # No facts means no trust anchor. There is nothing to scope against, so
        # the honest answer is a refusal - not "allow, since we found nothing".
        return [
            (
                "recipient_scope",
                "Cannot verify recipient scope: no ThreadFacts were supplied, so there is no "
                "authoritative participant list to check against. The broker must read the "
                "thread itself before an outbound action can be authorized.",
            )
        ]

    allowed = {_norm_principal(p) for p in (facts.participants or [])}
    if not allowed:
        return [
            (
                "recipient_scope",
                f"Thread {facts.thread_id!r} has no known participants, so no outbound "
                "recipient can be authorized against it.",
            )
        ]

    reasons: list[tuple[str, str]] = []
    for raw in _outbound_addresses(proposal):
        # Normalisation is for DETECTION, never for silent correction.
        #
        # This ordering is load-bearing and was a live bypass before it existed.
        # `recruiter@bright<ZWSP>lane.io` normalises to `recruiter@brightlane.io`,
        # which IS a thread participant - so a membership test on the normalised
        # form said yes, and the broker then sent to the RAW string, which is a
        # different mailbox nobody in the thread controls. Canonicalising an
        # attacker-controlled identifier and then acting on the original is how a
        # homoglyph check becomes a homoglyph laundering service.
        #
        # So: if an address is not already in its own canonical form, that is the
        # refusal. We do not repair it and proceed - a repaired address is
        # indistinguishable from one that was honest to begin with, which is
        # exactly the evidence a reviewer needs to keep.
        note = _evasion_note(raw)
        if note:
            reasons.append(
                (
                    "recipient_scope",
                    f"Recipient {str(raw)!r} is not in canonical form{note}. An address "
                    "that changes under Unicode normalisation is refused rather than "
                    "rewritten: the gate will not send to a string it had to correct.",
                )
            )
            continue
        if _norm_principal(raw) not in allowed:
            reasons.append(
                (
                    "recipient_scope",
                    f"Recipient {str(raw)!r} is not a participant of thread "
                    f"{facts.thread_id!r} (participants: {sorted(allowed)}).",
                )
            )
    return reasons


def _rule_domain_allowlist(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Second fence: even an in-thread address must sit on an allowed domain.

    Redundant with recipient_scope on purpose. recipient_scope trusts the
    participant list; this rule does not - which is what catches the case where
    the attacker WAS a participant, having mailed in from a domain nobody
    authorized, so the thread legitimately contains their address.
    """
    allowed_domains = {
        _norm_principal(d) for d in _as_list(cfg.get("allowed_domains")) if str(d).strip()
    }
    if not allowed_domains:
        # Absent list = rule not configured = rule inactive. This is the one
        # allowlist in the file where empty means "off" rather than "nothing",
        # because a domain list is an optional narrowing on top of
        # recipient_scope, not a standalone authorization.
        return []

    reasons: list[tuple[str, str]] = []
    for raw in _outbound_addresses(proposal):
        domain = _domain_of(raw)
        if not domain:
            reasons.append(
                (
                    "domain_allowlist",
                    f"Recipient {str(raw)!r} has no domain - it is not a deliverable address"
                    f"{_evasion_note(raw)}.",
                )
            )
        elif domain not in allowed_domains:
            reasons.append(
                (
                    "domain_allowlist",
                    f"Recipient {str(raw)!r} is on domain {domain!r}, which is not in "
                    f"allowed_domains ({sorted(allowed_domains)}){_evasion_note(raw)}.",
                )
            )
    return reasons


def _rule_no_distribution_lists(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Refuse addresses that fan out to a crowd.

    all@, everyone@, team@ are one recipient to this gate and several hundred to
    the mail server. What is being capped here is the blast radius of a single
    mistake, and it is capped by local part because that is the part an attacker
    picks when they stand up a list on a domain you already allowed.
    """
    blocked_locals = {
        _norm_principal(p) for p in _as_list(cfg.get("blocked_local_parts")) if str(p).strip()
    }
    blocked_addrs = {
        _norm_principal(a) for a in _as_list(cfg.get("blocked_addresses")) if str(a).strip()
    }
    if not blocked_locals and not blocked_addrs:
        return []

    reasons: list[tuple[str, str]] = []
    for raw in _outbound_addresses(proposal):
        norm = _norm_principal(raw)
        local = _local_part_of(raw)
        if norm in blocked_addrs:
            reasons.append(
                (
                    "no_distribution_lists",
                    f"Recipient {str(raw)!r} is on blocked_addresses{_evasion_note(raw)}.",
                )
            )
        elif local in blocked_locals:
            reasons.append(
                (
                    "no_distribution_lists",
                    f"Recipient {str(raw)!r} has local part {local!r}, a blocked "
                    "distribution-list name - it delivers to an unbounded set of people"
                    f"{_evasion_note(raw)}.",
                )
            )
    return reasons


def _rule_body_containment(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """A calendar invite must not carry the thread's text into its description.

    An invite is the leakiest surface in this tool set: the description is
    delivered verbatim to every attendee, lands in their calendar app, and is
    routinely synced onto phones and into third-party assistants. So a "helpful"
    agent that pastes the email thread in as context is exfiltrating whatever was
    in that thread - a salary figure, a home address, a medical detail, someone
    else's quoted reply - to people who were only ever invited to a meeting.

    Implemented as a long-substring test rather than a similarity score, because a
    threshold on "how similar" is a number nobody can defend in a review, while "N
    consecutive characters of the thread appear verbatim" is a fact.
    """
    if proposal.tool != CALENDAR_CREATE_EVENT:
        return []
    if facts is None:
        # Nothing read means nothing this rule can compare against.
        # recipient_scope already refuses the whole proposal when facts are
        # missing, so this is not a hole - it is just not this rule's objection.
        return []

    params = proposal.params if isinstance(proposal.params, dict) else {}
    description = _squash(params.get("description") or "")
    body = _squash(facts.body_text or "")
    try:
        window = int(cfg.get("max_quoted_chars", 120))
    except (TypeError, ValueError):
        window = 120
    # Clamp the window to the body we actually have. Without this, a thread
    # shorter than `max_quoted_chars` could never trip the rule - so pasting a
    # SHORT email wholesale into an invite was allowed while pasting a long one
    # was refused, which is precisely backwards: a two-line message saying
    # "comp band is 180-220k, keep this confidential" is the leak you care
    # about most. A quote is a quote at any length.
    window = min(window, len(body))
    if window <= 0 or not description or not body:
        return []

    for i in range(0, len(body) - window + 1):
        chunk = body[i : i + window]
        if chunk in description:
            return [
                (
                    "body_containment",
                    f"Event description reproduces at least {window} consecutive characters of "
                    f"the email thread verbatim (starting {chunk[:48]!r}...). Invite "
                    "descriptions are delivered to every attendee, external ones included - "
                    "thread content, and any PII inside it, must not travel that way.",
                )
            ]
    return []


def _rule_notion_parent_allowlist(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """A page may only be created under a parent the user named in the policy.

    An empty or missing `allowed_parents` REFUSES. The asymmetry with
    domain_allowlist is deliberate: writing into a workspace is an authorization
    the user grants to a specific location, so "the user listed nowhere" means
    nowhere is writable - not that everywhere is.

    This rule predates the registry and is grandfathered rather than folded
    into `destination_allowlist` below: Notion was one of the three apps this
    project shipped with evidence for, its policy shape (`allowed_parents:` as
    a bare list) is what every existing test and the shipped policy already
    read, and there was no reason to break either just to prove the new
    mechanism could subsume the old one. `destination_allowlist` is what every
    app added afterwards uses; a narrow per-app rule stayed exactly where it
    already worked.
    """
    if proposal.tool != NOTION_CREATE_PAGE:
        return []

    allowed = {_norm_notion_id(p) for p in _as_list(cfg.get("allowed_parents")) if str(p).strip()}
    if not allowed:
        return [
            (
                "notion_parent_allowlist",
                "No allowed_parents are configured in policy.yaml, so there is no Notion page "
                "this agent may write under. An empty allowlist allows nothing.",
            )
        ]

    params = proposal.params if isinstance(proposal.params, dict) else {}
    raw_parent = params.get("parent_id")
    parent = _norm_notion_id(raw_parent) if raw_parent is not None else ""
    if not parent:
        return [
            (
                "notion_parent_allowlist",
                "notion.create_page requires a parent_id; none was given, so the destination "
                "cannot be checked against the allowlist.",
            )
        ]
    if parent not in allowed:
        return [
            (
                "notion_parent_allowlist",
                f"Notion parent {str(raw_parent)!r} is not in allowed_parents. Pages may only be "
                "created under the parents the user listed in policy.yaml.",
            )
        ]
    return []


def _rule_destination_allowlist(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Generalizes `notion_parent_allowlist` to every other app with a place to
    write.

    A GitHub repo, a Slack channel, a Stripe payment intent, a Linear team -
    every one of these is "the named place this write lands",
    and the registry already says which param on which tool carries it
    (`ToolSpec.destination_param`). This rule reads that instead of a per-app
    field name, which is the property that makes it apply to app number
    fourteen without a code change.

    Configured per tool, because "the allowlisted place" means something
    different for every tool and a single flat list would conflate a Slack
    channel with a GitHub repo:

        destination_allowlist:
          allowed:
            slack.post_message: ["C0123ABCD"]
            github.create_issue: ["myorg/myrepo"]

    A tool with a `destination_param` that is not named under `allowed` at all
    is refused outright - same asymmetry as notion_parent_allowlist: the user
    listing nowhere for a tool means nowhere is writable, not everywhere. Only
    `notion.create_page` is exempt, because `notion_parent_allowlist` already
    governs it and a write should not need two rules to name the same parent
    twice under two different keys.
    """
    spec = registry_mod.tool_spec(proposal.tool)
    if spec is None or not spec.destination_param:
        return []
    if spec.destination_kind == "notion-parent":
        # notion.create_page is governed by notion_parent_allowlist above; see
        # that rule's docstring for why it was grandfathered rather than
        # folded into this one.
        return []

    params = proposal.params if isinstance(proposal.params, dict) else {}
    raw_dest = params.get(spec.destination_param)
    dest = _squash(raw_dest) if raw_dest is not None else ""

    allowed_cfg = cfg.get("allowed") or {}
    if not isinstance(allowed_cfg, dict):
        allowed_cfg = {}
    allowed_for_tool = {
        _squash(v) for v in _as_list(allowed_cfg.get(proposal.tool)) if str(v).strip()
    }

    if not allowed_for_tool:
        return [
            (
                "destination_allowlist",
                f"No destinations are configured for {proposal.tool!r} under "
                "destination_allowlist.allowed in policy.yaml, so there is nowhere this tool "
                "may write. An empty or missing allowlist allows nothing.",
            )
        ]
    if not dest:
        return [
            (
                "destination_allowlist",
                f"{proposal.tool} requires {spec.destination_param!r}; none was given, so the "
                "destination cannot be checked against the allowlist.",
            )
        ]
    if dest not in allowed_for_tool:
        return [
            (
                "destination_allowlist",
                f"Destination {str(raw_dest)!r} for {proposal.tool} is not in the allowlist "
                f"configured for it. Writes may only land where the user listed in policy.yaml.",
            )
        ]
    return []


def _rule_spend_cap(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Bound anything the registry marks `spend`, regardless of which app it is.

    Two numbers, both optional and both in minor units (cents, not dollars -
    the registry's `amount_param` is minor units for the same reason a payment
    processor's API is: floating point has no business anywhere near money):

        spend_cap:
          currency: usd
          max_per_action_minor: {stripe.create_refund: 50000}
          max_per_day_minor: {stripe.create_refund: 200000}

    The amount for THIS proposal comes from `amount_param` when the tool
    states one (a refund names its own amount), or from `flat_cost_minor`
    multiplied by the recipient count when it does not (an SMS costs a fixed
    amount per message and the proposal never states a dollar figure - see
    `ToolSpec.flat_cost_minor`). The running total comes from the ledger,
    which only ever contains amounts for actions that actually executed, so a
    refused or crashed attempt never inflates the day's spend.

    A tool the config's currency does not match is refused rather than
    summed - converting currencies inside a policy gate would be exactly the
    kind of computation this file's docstring says the format cannot do.
    """
    if ledger is None:
        return []
    spec = registry_mod.tool_spec(proposal.tool)
    if spec is None or registry_mod.SPEND not in spec.classes:
        return []

    params = proposal.params if isinstance(proposal.params, dict) else {}
    currency = str(cfg.get("currency", spec.flat_cost_currency or "usd")).lower()

    amount = 0
    if spec.amount_param:
        raw_amount = params.get(spec.amount_param)
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError):
            return [
                (
                    "spend_cap",
                    f"{proposal.tool} requires a numeric {spec.amount_param!r} in minor units; "
                    f"got {raw_amount!r}. Refusing rather than guessing an amount.",
                )
            ]
        proposal_currency = str(params.get(spec.currency_param) or currency).lower() if spec.currency_param else currency
        if proposal_currency != currency:
            return [
                (
                    "spend_cap",
                    f"{proposal.tool} proposes currency {proposal_currency!r}, which does not "
                    f"match the spend_cap currency {currency!r}. Refusing rather than converting.",
                )
            ]
    elif spec.flat_cost_minor:
        count = max(1, len(_as_list(params.get(spec.recipient_params[0]))) if spec.recipient_params else 1)
        amount = int(spec.flat_cost_minor) * count

    if amount <= 0:
        return []

    reasons: list[tuple[str, str]] = []
    per_action = (cfg.get("max_per_action_minor") or {}).get(proposal.tool) if isinstance(cfg.get("max_per_action_minor"), dict) else None
    if per_action is not None and amount > int(per_action):
        reasons.append(
            (
                "spend_cap",
                f"{proposal.tool} proposes {amount} minor {currency} units, over the per-action "
                f"cap of {per_action}.",
            )
        )

    per_day = (cfg.get("max_per_day_minor") or {}).get(proposal.tool) if isinstance(cfg.get("max_per_day_minor"), dict) else None
    if per_day is not None:
        try:
            spent = int(ledger.spend_today(proposal.tool, currency))
        except Exception as exc:
            return reasons + [
                (
                    "spend_cap",
                    f"Could not read the ledger to enforce the daily spend cap ({exc}). Actions "
                    "are refused while spend cannot be verified.",
                )
            ]
        if spent + amount > int(per_day):
            reasons.append(
                (
                    "spend_cap",
                    f"{proposal.tool} would bring today's {currency} spend to {spent + amount} "
                    f"minor units, over the daily cap of {per_day} ({spent} already moved today).",
                )
            )
    return reasons


def _rule_irreversible_gate(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """An action the registry marks `irreversible` needs an explicit opt-in.

    Every other rule in this file bounds WHO, WHERE or HOW MUCH; this one
    bounds a different axis entirely - whether the action can be walked back
    at all if it turns out to be wrong. `gmail.send` and `calendar.create_event`
    are irreversible by the registry's strict definition (see its docstring)
    and are exactly the actions this project was built to allow, so this rule
    is an allowlist rather than a blanket ban: name the irreversible tools the
    agent may use, and everything else irreversible is refused by default.

        irreversible_gate:
          allowed_tools: [gmail.send, calendar.create_event]

    Missing or empty `allowed_tools` refuses every irreversible action - the
    same "absence authorizes nothing" shape as the two allowlists above,
    applied to the one hazard that has no undo button regardless of app.
    """
    spec = registry_mod.tool_spec(proposal.tool)
    if spec is None or registry_mod.IRREVERSIBLE not in spec.classes:
        return []

    allowed = {str(t).strip() for t in _as_list(cfg.get("allowed_tools")) if str(t).strip()}
    if proposal.tool not in allowed:
        return [
            (
                "irreversible_gate",
                f"{proposal.tool} cannot be undone through this tool surface, and it is not "
                "listed in irreversible_gate.allowed_tools. An irreversible action requires an "
                "explicit, per-tool opt-in - there is no default permission for something that "
                "cannot be taken back.",
            )
        ]
    return []


def _rule_audience_bound(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Cap how many DISTINCT fan-out destinations a tool may reach in a day.

    `no_distribution_lists` bounds the blast radius of one message by refusing
    the address that would fan it out. This rule bounds a different failure:
    every individual message going to one pre-approved, small audience, but
    the agent working through five, then ten, then all fifty allowlisted Slack
    channels in a single run. Each message is legal on its own; the pattern is
    not, and only a count across the day catches it.

        audience_bound:
          max_distinct_per_day:
            slack.post_message: 3

    Reads `ToolSpec.audience_param` for which field names the destination that
    counts as "one more audience reached" - `channel` for Slack. A tool with
    no audience_param and no recipients is not scoped by this rule at all, the
    same as every other rule here returning `[]` for a tool it was never
    written to grade.
    """
    if ledger is None:
        return []
    spec = registry_mod.tool_spec(proposal.tool)
    if spec is None or registry_mod.AUDIENCE not in spec.classes:
        return []

    caps = cfg.get("max_distinct_per_day") or {}
    cap = caps.get(proposal.tool) if isinstance(caps, dict) else None
    if cap is None:
        return []

    params = proposal.params if isinstance(proposal.params, dict) else {}
    field = spec.audience_param or (spec.recipient_params[0] if spec.recipient_params else None)
    if not field:
        return []
    raw = params.get(field)
    key = _squash(raw) if raw is not None else ""
    if not key:
        return [
            (
                "audience_bound",
                f"{proposal.tool} requires {field!r} to identify its audience; none was given, "
                "so the daily fan-out bound cannot be checked.",
            )
        ]

    try:
        already_reached = ledger.distinct_audience_today(proposal.tool)
    except Exception as exc:
        return [
            (
                "audience_bound",
                f"Could not read the ledger to enforce the daily audience bound ({exc}). "
                "Actions are refused while the fan-out count cannot be verified.",
            )
        ]

    if key not in already_reached and len(already_reached) + 1 > int(cap):
        nth = len(already_reached) + 1
        suffix = "th" if 11 <= nth % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(nth % 10, "th")
        return [
            (
                "audience_bound",
                f"{proposal.tool} would reach a {nth}{suffix} distinct audience "
                f"today ({str(raw)!r}), over the cap of {cap}. Already reached today: "
                f"{sorted(already_reached)}.",
            )
        ]
    return []


def _rule_rate_limit(
    proposal: Proposal, facts: Optional[ThreadFacts], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Daily caps and duplicate suppression - the bound on a loop gone wrong.

    Every other rule bounds WHO and WHAT. This one bounds HOW MANY, which is the
    only defence against a correct-looking action repeated a thousand times: each
    individual send passes every other rule, and the mailbox is destroyed anyway.

    Skipped when `ledger is None`, so the rules above stay unit-testable without a
    database. That is the one place in this file where absence means "not checked"
    rather than "refused", and it is only safe because the broker always passes a
    ledger - look at the call site for that, not at this comment.
    """
    if ledger is None:
        return []

    reasons: list[tuple[str, str]] = []
    caps = cfg.get("max_actions_per_day") or {}
    cap = caps.get(proposal.tool) if isinstance(caps, dict) else None

    if cap is not None:
        try:
            used = int(ledger.count_today(proposal.tool))
        except Exception as exc:  # an unreadable ledger is an unverifiable cap
            return [
                (
                    "rate_limit",
                    f"Could not read the action ledger to enforce the daily cap ({exc}). "
                    "Actions are refused while the cap cannot be verified.",
                )
            ]
        if used >= int(cap):
            reasons.append(
                (
                    "rate_limit",
                    f"Daily cap reached for {proposal.tool}: {used} of {cap} already performed "
                    "today.",
                )
            )

    if cfg.get("idempotency"):
        key = idempotency_key(proposal)
        try:
            already = bool(ledger.seen(key))
        except Exception as exc:
            return reasons + [
                (
                    "duplicate_action",
                    f"Could not read the action ledger to check for a duplicate ({exc}). "
                    "Actions are refused while duplicates cannot be ruled out.",
                )
            ]
        if already:
            reasons.append(
                (
                    "duplicate_action",
                    f"This exact action has already been performed (idempotency key "
                    f"{key[:16]}...). Repeating it would duplicate a real-world effect.",
                )
            )

    return reasons


def _rule_kite_mandate(
    proposal: Proposal, facts: Optional[Any], cfg: dict[str, Any], ledger: Any
) -> list[tuple[str, str]]:
    """Authorize a kite.place_order proposal by delegating to llmfin.risk's
    already-adversarially-tested mandate logic, evaluated per-tenant.

    Deliberately does NOT reimplement finLM's mandate semantics (NFKC symbol
    normalization, the PRICE_BINDING_ORDER_TYPES carve-out, empty-allowlist-
    means-unrestricted) as native warrant rules - re-deriving already-red-teamed
    logic in a second place is how it quietly drifts from what was actually
    tested. This is a thin adapter, not a reimplementation.

    Only applies to the kite app; every other tool returns [] (not
    applicable), same shape as `_rule_notion_parent_allowlist`.
    """
    if registry_mod.app_of(proposal.tool) != "kite":
        return []

    # Fail closed if the platform layer forgot to wire a facts_providers
    # closure for kite - this is the same "no facts, no trust anchor, refuse"
    # posture _rule_recipient_scope takes when ThreadFacts is None, applied to
    # a proposal type where None is never a valid state to check against at
    # all (unlike Gmail, where "no thread" is a real, refusable case).
    if not isinstance(facts, KiteFacts):
        return [
            (
                "kite_mandate",
                "No broker-verified KiteFacts were supplied for a kite proposal - refusing "
                "rather than evaluating against anything the proposal itself claims.",
            )
        ]

    # Checked before the mandate delegation below, mirroring both check()'s
    # own kill-switch-before-policy ordering and risk.py's own
    # kill-switch-first check inside check_order() itself - belt and braces,
    # not redundant: this short-circuits before even importing llmfin.
    if facts.kill_switch_reason:
        return [("kite_kill_switch", facts.kill_switch_reason)]

    try:
        from llmfin.risk import check_order as _llmfin_check_order
    except ImportError:
        return [
            (
                "kite_mandate",
                "llmfin is not installed in this environment, so the kite mandate rule "
                "cannot be evaluated. Fails closed rather than allowing an unauthorized order.",
            )
        ]

    params = proposal.params if isinstance(proposal.params, dict) else {}
    verdict = _llmfin_check_order(
        symbol=params.get("tradingsymbol"),
        transaction_type=params.get("transaction_type"),
        quantity=params.get("quantity"),
        exchange=params.get("exchange", "NSE"),
        product=params.get("product", "CNC"),
        est_price=facts.live_quote,
        order_type=params.get("order_type", "MARKET"),
        est_price_source=facts.quote_source,
        injected_mandate=facts.mandate,
        kill_switch_reason=facts.kill_switch_reason,
        orders_today=facts.orders_today,
        value_today=facts.value_today,
    )
    if verdict.allowed:
        return []
    return [("kite_mandate", reason) for reason in verdict.reasons]


RULES: dict[
    str, Callable[[Proposal, Optional[ThreadFacts], dict[str, Any], Any], list[tuple[str, str]]]
] = {
    "recipient_scope": _rule_recipient_scope,
    "domain_allowlist": _rule_domain_allowlist,
    "no_distribution_lists": _rule_no_distribution_lists,
    "body_containment": _rule_body_containment,
    "notion_parent_allowlist": _rule_notion_parent_allowlist,
    "destination_allowlist": _rule_destination_allowlist,
    "spend_cap": _rule_spend_cap,
    "irreversible_gate": _rule_irreversible_gate,
    "audience_bound": _rule_audience_bound,
    "rate_limit": _rule_rate_limit,
    "kite_mandate": _rule_kite_mandate,
}

# `delegation` is named in policy.yaml like any other rule, but it is not in
# RULES and cannot be: every rule above is called with
# (proposal, facts, cfg, ledger), and none of those four carries a delegation
# chain. Widening that signature for one rule would make every other rule's
# parameter list a lie about what it reads.
#
# So `check()` evaluates it inline, before the RULES loop, and this set is what
# keeps the "policy names a rule this build does not implement" guard from
# firing on it. A name here is a promise that `check()` handles it by hand -
# `tests/test_identity_delegation.py` asserts the two stay in sync.
CHECK_LEVEL_RULES: frozenset[str] = frozenset({"delegation"})


def _evaluate_delegation(
    proposal: Proposal, cfg: dict[str, Any], chain: Any
) -> list[tuple[str, str]]:
    """The `delegation:` rule: this action must be backed by a verified,
    attenuating chain of authority that covers the tool being proposed.

    Note what is NOT a parameter: the root secret, the clock, and the
    revocation list. All three are read by `warrant.identity` from the
    operator's environment and the operator's files. If any of them were
    arguments, the layer being governed could supply a secret it chose, a
    time it liked, or an empty revocation list - and the rule would still
    report that it had run.

    `chain` IS a parameter, and it is the one thing a caller can hand in.
    That is safe in exactly one direction: presenting a chain can only ever
    narrow what is permitted. Presenting none is a refusal (below), so
    there is no value of `chain` - including `None` - that turns this rule
    off once the policy has named it.
    """
    roots = cfg.get("roots")
    if roots is not None and not isinstance(roots, list):
        return [
            (
                "policy_malformed",
                f"delegation.roots must be a list of principal ids, got {type(roots).__name__}.",
            )
        ]

    max_depth = cfg.get("max_depth", identity.MAX_CHAIN_DEPTH)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        return [
            (
                "policy_malformed",
                f"delegation.max_depth must be a positive integer, got {max_depth!r}.",
            )
        ]

    if chain is None:
        return [
            (
                "delegation",
                "This policy requires every action to carry a delegation chain naming who is "
                "acting and on whose behalf, and this proposal carried none. There is no "
                "anonymous caller to fall back to - remove the `delegation:` rule from "
                f"{POLICY_FILE} if that is genuinely what you want.",
            )
        ]

    revocations_file = cfg.get("revocations_file")
    try:
        revocations = identity.load_revocations(
            Path(revocations_file) if revocations_file else None
        )
    except identity.IdentityError as exc:
        return [("delegation", str(exc))]

    try:
        grants = (
            identity.chain_from_dicts(chain)
            if not all(isinstance(g, identity.Grant) for g in chain)
            else list(chain)
        )
    except (identity.IdentityError, TypeError) as exc:
        # A chain that will not even parse is refused rather than skipped.
        return [("delegation", f"Delegation chain could not be read ({exc}); refusing.")]

    verdict = identity.authorize(
        grants,
        proposal.tool,
        revocations=revocations,
        roots=roots,
        max_depth=max_depth,
    )
    if verdict.allowed:
        return []
    # A refusing AuthorityVerdict carries one rule_id per reason, by
    # construction (`identity._deny`). `zip_longest` rather than `zip` so a
    # future verdict shape that breaks that pairing degrades to a generic
    # "delegation" id instead of silently dropping the reason - a refusal
    # that vanishes because two lists were different lengths would read as
    # an allow.
    return [
        (rule_id or "delegation", reason)
        for rule_id, reason in zip_longest(
            verdict.rule_ids, verdict.reasons, fillvalue="delegation"
        )
        if reason != "delegation"
    ]


# ── the gate ────────────────────────────────────────────────────────────────


def check(
    proposal: Proposal,
    facts: Optional[ThreadFacts] = None,
    ledger: Any = None,
    chain: Any = None,
) -> Verdict:
    """Authorize a proposal against policy.yaml. Fails closed.

    Four parameters, and none of them is an override. There is no `confirmed`,
    `force`, `bypass`, `dry_run` or `admin` here and there never will be: the
    caller of this function is the layer being governed, so any argument it can
    set to soften the answer is an argument that makes the answer meaningless. To
    allow something, edit policy.yaml - outside the conversation, as the person
    who is accountable for it.

    `facts` is optional in the signature only so the rules can say WHY its absence
    is a problem. Absent facts do not skip a check; they fail recipient_scope,
    which is the entire outbound surface.

    `chain` is the delegation chain (see `warrant.identity`) proving who is
    acting and on whose behalf. It is an argument, unlike the root secret and the
    revocation list, and it is worth being precise about why that is not a hole:
    it can only ever NARROW the answer. When policy.yaml does not name the
    `delegation` rule, it is ignored entirely. When policy.yaml DOES name it,
    `chain=None` is a refusal - so there is no value a caller can pass, including
    the default, that switches the check off. The worst a caller can do with it
    is present a weaker authority than it holds and be refused more often.
    """
    # 1. Kill switch, before anything else is read. It has to work when the policy
    #    file is missing, malformed, or mid-edit, because "stop everything now" is
    #    exactly the moment when other things are broken.
    ks = kill_switch_active()
    if ks:
        return Verdict(
            False,
            [f"KILL SWITCH is active at {ks} - delete the file to re-enable this agent."],
            ["kill_switch"],
        )

    # 2. A policy that exists but will not parse is the dangerous case: a typo
    #    saved mid-edit must never read as "no restrictions".
    try:
        policy = load_policy()
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        return Verdict(
            False,
            [
                f"Policy at {POLICY_FILE} exists but could not be read ({exc}). "
                "All actions are refused until it is valid YAML."
            ],
            ["policy_unreadable"],
        )

    # 3. No policy, no authority. The package will not write one for you.
    if policy is None:
        return Verdict(
            False,
            [
                f"No policy found at {POLICY_FILE.resolve()}. All actions are refused until the "
                "USER creates that file by hand. This is deliberate: the policy is your consent, "
                "and consent has to originate outside the agent - no part of this package will "
                "create, template, or default it for you."
            ],
            ["policy_missing"],
        )

    if not isinstance(policy, dict):
        return Verdict(
            False,
            [f"Policy at {POLICY_FILE} must be a YAML mapping, got {type(policy).__name__}."],
            ["policy_malformed"],
        )

    # 4. Tool surface. An action the policy was never written against cannot be
    #    authorized by it, however harmless the name looks.
    if proposal.tool not in ACTIONS:
        return Verdict(
            False,
            [f"Unknown tool {proposal.tool!r}. Known actions: {list(ACTIONS)}."],
            ["unknown_tool"],
        )

    if not isinstance(proposal.params, dict):
        return Verdict(
            False,
            [f"Proposal params must be a mapping, got {type(proposal.params).__name__}."],
            ["unknown_param"],
        )

    # 5. Unknown keys are refused, not ignored. An extra key is either a typo -
    #    in which case the param the policy checks is silently absent - or a reach
    #    for a code path nobody wrote a rule against. Both are refusals.
    unknown = sorted({str(k) for k in proposal.params} - ACTION_PARAMS[proposal.tool])
    if unknown:
        return Verdict(
            False,
            [
                f"Unknown params for {proposal.tool}: {unknown}. "
                f"Allowed: {sorted(ACTION_PARAMS[proposal.tool])}."
            ],
            ["unknown_param"],
        )

    # 6. The rules the user actually asked for. Iterating the POLICY's keys rather
    #    than the RULES table is what makes the YAML the source of behaviour: a
    #    rule this file implements but the policy never names does not run.
    rules_cfg = policy.get("rules")
    if not isinstance(rules_cfg, dict) or not rules_cfg:
        return Verdict(
            False,
            [
                f"Policy at {POLICY_FILE.resolve()} declares no `rules:` block, so it authorizes "
                "nothing. An empty policy is a refusal, not a permission."
            ],
            ["policy_malformed"],
        )

    reasons: list[str] = []
    rule_ids: list[str] = []

    for name, cfg in rules_cfg.items():
        rule_name = str(name)
        fn = RULES.get(rule_name)
        if fn is None and rule_name not in CHECK_LEVEL_RULES:
            # The policy asks for a check this build cannot perform. Running the
            # remaining rules and allowing would enforce less than the signed
            # policy says, so the only honest answer is to stop here.
            return Verdict(
                False,
                [
                    f"Policy names rule {rule_name!r}, which this build does not implement. "
                    f"Implemented rules: {sorted(RULES)}. Refusing rather than enforcing less "
                    "than the policy asks for."
                ],
                ["unknown_rule"],
            )
        if cfg is None:
            cfg = {}
        if not isinstance(cfg, dict):
            return Verdict(
                False,
                [f"Config for rule {rule_name!r} must be a mapping, got {type(cfg).__name__}."],
                ["policy_malformed"],
            )
        try:
            if rule_name == "delegation":
                # Evaluated here rather than through RULES - see
                # CHECK_LEVEL_RULES for why it cannot share that signature.
                found = _evaluate_delegation(proposal, cfg, chain)
            else:
                assert fn is not None  # guaranteed by the CHECK_LEVEL_RULES guard above
                found = fn(proposal, facts, cfg, ledger)
        except Exception as exc:  # a rule that crashed has not passed
            return Verdict(
                False,
                [f"Rule {rule_name!r} failed to evaluate ({exc!r}); refusing."],
                ["rule_error"],
            )
        for rule_id, reason in found:
            rule_ids.append(rule_id)
            reasons.append(reason)

    if reasons:
        return Verdict(False, reasons, rule_ids)
    return Verdict(True, ["All policy checks passed."], [])
