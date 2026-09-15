"""
apps/stripe.py
────────────────
The Stripe client. Plain `requests` against the REST API v1 - no SDK.
Stripe's API is form-encoded, not JSON, which is the one surprise for anyone
used to the other adapters in this package.

Only the broker imports this module.

**Liveness: fake-only, deliberately not even test-mode.** Every other
fake-only app in this suite has the honest excuse of "no account exists".
Stripe has test-mode keys that cost nothing and move no real money, and this
project still did not wire one up. That is worth stating plainly rather than
folding into the same sentence as the other nine: a spend cap that has only
ever been exercised against a sandbox is a spend cap nobody has tested against
the thing it is supposed to bound, and claiming otherwise would be exactly the
overclaiming this project's credibility depends on not doing.

All amounts are minor units (cents) throughout, matching Stripe's own API and
`warrant.registry`'s `amount_param` convention - never floating-point dollars.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

API_BASE = "https://api.stripe.com/v1"
TIMEOUT = 30


class StripeError(RuntimeError):
    def __init__(self, status: int, body: str, hint: str = "") -> None:
        self.status = status
        self.body = body
        message = f"Stripe API returned {status}: {body}"
        if hint:
            message = f"{message}\nFIX: {hint}"
        super().__init__(message)


def _hint_for(status: int) -> str:
    if status == 401:
        return "STRIPE_API_KEY is missing or invalid."
    if status == 402:
        return "Stripe declined the request - check the payment_intent or destination is valid and has funds."
    if status == 404:
        return "That payment_intent, or destination, does not exist on this account."
    return ""


def _post(path: str, form: dict[str, Any]) -> dict[str, Any]:
    from warrant.auth import stripe_api_key

    # Stripe wants form-encoded bodies, not JSON - `data=`, not `json=`.
    response = requests.post(
        f"{API_BASE}{path}",
        auth=(stripe_api_key(), ""),
        data={k: v for k, v in form.items() if v is not None},
        timeout=TIMEOUT,
    )
    if not 200 <= response.status_code < 300:
        raise StripeError(response.status_code, response.text, _hint_for(response.status_code))
    return response.json()


def create_refund(payment_intent: str, amount: int, currency: str, reason: Optional[str] = None) -> str:
    """POST /v1/refunds. `amount` is minor units; Stripe infers currency from
    the payment intent, so `currency` here is carried for spend_cap's
    comparison rather than sent on the wire."""
    created = _post(
        "/refunds",
        {"payment_intent": payment_intent, "amount": int(amount), "reason": reason},
    )
    return str(created.get("id", ""))


def create_payout(
    amount: int, currency: str, description: str = "", destination: Optional[str] = None
) -> str:
    """POST /v1/payouts. Moves money from the Stripe balance to the connected
    bank account or debit card. `amount` is minor units."""
    created = _post(
        "/payouts",
        {"amount": int(amount), "currency": currency, "description": description, "destination": destination},
    )
    return str(created.get("id", ""))
