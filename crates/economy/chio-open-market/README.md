# chio-open-market

`chio-open-market` defines Chio's open capability marketplace: the bid/ask/accept
protocol that mints scoped capability tokens against published listings, and the
fee-schedule and penalty state machines (bond holds, slashes, reverse slashes)
that back it. It builds on `chio-listing` for listings and pricing hints and
`chio-governance` for the charters and cases that authorize penalties.

## Responsibilities

- Run the bid/ask/accept flow (`bidding`): validate a signed bid, apply
  fail-closed checks against the resolved listing and pricing hint, mint a
  scoped `CapabilityToken`, and record settlement acceptance against a
  verified funds reservation.
- Define open-market economics (`fee_schedule`): economics scopes, bond
  requirements, and signed fee schedules.
- Define the penalty state machine (`penalty`): abuse classes, penalty
  actions and states, signed penalty artifacts, and reverse-slash
  supersession.
- Evaluate penalties (`evaluation`): verify governance, activation, and
  fee-schedule evidence and derive the effective state, downgrading failures
  to a structured finding instead of an `Err`.
- Carry the evidence references and finding codes evaluation reports use
  (`evidence`).

## Public API

- `bidding::{bid, accept, verify_acceptance}` - mint an offer, sign acceptance,
  and verify received acceptance under locally selected buyer/provider keys,
  plus `BidRequest`, `RequestedScope`, `BidMintContext`, `AskResponse`,
  `AcceptedBid`, `ReservationReceipt`, `VerifiedReservationReceipt`, and
  `BiddingError`. Signed envelopes: `SignedBidRequest`, `SignedAskResponse`,
  `SignedAcceptedBid`, `SignedReservationReceipt`.
- `fee_schedule::{build_open_market_fee_schedule_artifact,
  OpenMarketFeeScheduleArtifact, OpenMarketFeeScheduleIssueRequest,
  OpenMarketEconomicsScope, OpenMarketBondRequirement, OpenMarketBondClass,
  OpenMarketCollateralReferenceKind}` and `SignedOpenMarketFeeSchedule`.
- `penalty::{build_open_market_penalty_artifact,
  build_open_market_penalty_artifact_with_trusted_signers,
  OpenMarketPenaltyArtifact, OpenMarketPenaltyIssueRequest,
  OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyState}` and
  `SignedOpenMarketPenalty`.
- `evaluation::{evaluate_open_market_penalty,
  evaluate_open_market_penalty_with_trusted_signers,
  OpenMarketPenaltyEvaluationRequest, OpenMarketPenaltyEvaluation}`.
- `evidence::{OpenMarketEvidenceReference, OpenMarketEvidenceKind,
  OpenMarketFinding, OpenMarketFindingCode}`.
- Re-exported: `canonical_json_bytes`, `capability`, `crypto`, `receipt`
  (from `chio-core-types`), `governance` (`chio-governance`), `listing`
  (`chio-listing`).

`verify_acceptance` checks the received buyer signature and reconstructs the
exact accepted body from the signed offer and verified reservation. Its caller
selects the reservation authority before constructing the witness. It does not
reserve funds, check the original job's application policy, authorize execution,
establish current funds availability, or settle a purchase. Those decisions
belong to the receiving runtime and selected payment service.

## Testing

`cargo test -p chio-open-market`

## See also

- `chio-listing` - listings and pricing hints that bids resolve against.
- `chio-governance` - charters and cases that authorize penalties.
- `chio-core-types` - capability tokens, signing, and the signed-envelope
  type every artifact in this crate uses.
