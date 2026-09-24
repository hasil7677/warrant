"""
apps/kite.py
─────────────
Kite Connect's real `place_order` surface, mirrored here purely so the
registry's own signature-consistency checks (test_registry.py) hold for
`kite` exactly as they hold for the other twelve apps - this module's
function is never actually reached in production.

See `registry.py`'s note on the `kite` AppSpec: Kite credentials are
tenant-scoped and live in encrypted Postgres rows, not a static
module-level session the way `warrant.auth.stripe_api_key()` reads one env
var for every caller. The platform layer therefore always constructs
`Broker(apps={"kite": <tenant's authenticated KiteConnect>})` explicitly,
and `Broker._perform()` dispatches straight to that real `KiteConnect`
instance's own bound `place_order` method - `Broker._client("kite")` never
falls back to lazily importing this module in practice. It exists so "every
app has a real adapter, importable without credentials" and "the registry's
declared params are a real function's params" (test_registry.py) hold for
kite too, rather than kite being a silent, undocumented exception to
conventions this whole suite otherwise enforces for the other twelve apps.

Mirrors pykiteconnect's own `KiteConnect.place_order` signature. `variety`
is deliberately not a registry-declared param - same treatment as
`gmail.send`'s `in_reply_to` in `broker.py`'s `_perform` (domain behaviour a
proposal never sets); `_perform` injects it as the literal string
`"regular"` (`KiteConnect.VARIETY_REGULAR`'s real value) rather than this
module importing `kiteconnect` to reference the constant, which would
violate "only kite_gateway.py imports kiteconnect".
"""

from __future__ import annotations

from typing import Optional


def place_order(
    variety: str,
    exchange: str,
    tradingsymbol: str,
    transaction_type: str,
    quantity: int,
    product: str,
    order_type: str,
    price: Optional[float] = None,
    trigger_price: Optional[float] = None,
) -> str:
    """Never actually reached - see module docstring."""
    raise RuntimeError(
        "warrant.apps.kite.place_order was reached via lazy app resolution, which should "
        "never happen: Kite credentials are tenant-scoped, so the platform must always "
        "construct Broker(apps={'kite': <tenant's authenticated KiteConnect>}) explicitly "
        "rather than relying on this module."
    )
