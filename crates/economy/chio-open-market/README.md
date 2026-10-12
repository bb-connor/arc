# chio-open-market

`chio-open-market` implements Chio capability bid/ask/accept contracts,
fee and governance penalty checks, and finding-market admission, purchase,
audit, slash allocation, and recovery verification. It combines signed
listings with explicit authority and caller-supplied state. The host owns
reservations, durable activation, settlement, and runtime admission.

## Usage

Authenticate a reservation statement under a selected reservation authority.
This local example creates its own statement; a deployed buyer obtains one
from its trusted funds-reservation service before calling `accept`.

```rust
use chio_open_market::{
    bidding::{ReservationReceipt, SignedReservationReceipt,
              VerifiedReservationReceipt, RESERVATION_RECEIPT_SCHEMA},
    capability::scope::MonetaryAmount,
    crypto::Keypair,
};

let authority = Keypair::from_seed(&[7; 32]);
let signed = SignedReservationReceipt::sign(ReservationReceipt {
    schema: RESERVATION_RECEIPT_SCHEMA.into(),
    receipt_id: "reservation/example".into(),
    agent_id: "agent/example".into(),
    listing_id: "listing/example".into(),
    ask_digest: "a".repeat(64),
    reserved_amount: MonetaryAmount { units: 100, currency: "USD".into() },
}, &authority)?;
let verified = VerifiedReservationReceipt::from_signed(
    &signed, &authority.public_key(),
)?;
assert_eq!(verified.receipt_id(), "reservation/example");
assert_eq!(verified.reserved_amount().units, 100);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `kani` | Off | Empty marker for proof invocations. The harness module compiles only under the `cfg(kani)` supplied by cargo-kani; normal builds add no runtime behavior. |

There is no declared `default` feature set.

## Guarantees

- `bid` checks bid/listing/pricing signatures, owner and provider bindings,
  active and fresh listing state, price/currency, scope, and bounded arithmetic
  before signing a capability offer.
- `accept` requires a verified reservation, buyer subject equality, signed
  ask/token consistency, a live acceptance window, and sufficient currency-matched
  funds for the offered total liability.
- `verify_finding_admission` checks a pinned venue, exact constituent envelope
  digests, current allocation state, backing size, fee authority, penalty
  posture, and expiry bounds before producing a private-construction witness.
- `evaluate_open_market_penalty_with_trusted_signers` evaluates signed
  governance and economics inputs under the supplied governing keys.

## Status

The crate implements pure checks, capability offers, and signed market
records. Admission and recovery verifiers rely on trusted snapshots and
authority inputs supplied by the host. They have no persistent allocation
ledger, reservation ledger, status resolver, or settlement dispatcher.
The Cargo package is marked `publish = false`.

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding market envelopes](../../../spec/PROTOCOL.md#6471-market-envelope-discipline)
- [Listing discovery](../chio-listing/README.md)
- [Finding artifacts](../chio-finding/README.md)
- [License](../../../LICENSE)
