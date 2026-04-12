# Post-v2.28 Maximal Endgame Roadmap

## Purpose

`v2.28` closes ARC's bounded endgame claim: standards-native authorization,
portable trust, workload attestation, underwriting, credit, live-capital
orchestration, open registry, portable reputation, market-discipline
economics, and adversarial multi-operator qualification all exist locally with
explicit non-goals.

This document captures the remaining **maximal-endgame** deltas for the
strongest possible reading of `docs/research/DEEP_RESEARCH_1.md`:

- real external capital dispatch rather than custody-neutral instructions only
- bounded autonomous insurer-grade pricing and capital automation
- cross-operator trust federation and more open market admission
- broader public identity, wallet, and credential-network interop

These items started as the **planned-only** maximal-endgame ladder. They are
now activated into executable phase detail in the main planning stack.

## Current Explicit Boundaries

The current shipped boundary still says ARC does **not** claim:

- automatic external capital dispatch
- autonomous insurer pricing outside documented delegated envelopes
- permissionless mirror/indexer publication as trust or sanction authority
- portable reputation as a universal trust oracle
- generic DID/VC/public-wallet compatibility beyond ARC's bounded interop lane

Those current non-goals are recorded in:

- `docs/release/RELEASE_CANDIDATE.md`
- `docs/release/RELEASE_AUDIT.md`
- `docs/release/PARTNER_PROOF.md`
- `spec/PROTOCOL.md`

## Planned Ladder

### v2.29 Official Stack and Extension SDK

Freeze ARC's extension boundary before the web3/live-money lane hardens.

Target outcomes:

- one explicit inventory of canonical vs replaceable surfaces
- one official ARC stack package over first-party implementations
- machine-readable extension manifests, version negotiation, and compatibility
  contracts
- qualification rules that prove extensions cannot redefine ARC truth or widen
  trust silently

### v2.30 Web3 Settlement Rail Dispatch and External Capital Execution

Move from signed capital, payout, reserve, and settlement instructions into
real external rail execution with cryptographically reconcilable dispatch
proofs, built on the extension substrate defined in `v2.29`.

Target outcomes:

- at least one real rail adapter for capital and claims execution
- dispatch receipts that reconcile external settlement back to ARC truth
- explicit reversal, chargeback, partial-settlement, and rail-failure state
- custody and regulated-role boundaries that remain machine-readable

### v2.31 Autonomous Pricing, Capital Pools, and Insurance Automation

Move from delegated pricing and bounded bind logic into bounded autonomous
pricing, capital optimization, and insurer-grade automation.

Target outcomes:

- model-governed autonomous pricing artifacts
- reserve and capital-pool optimization policy
- automatic reprice, renew, decline, and bind execution within approved limits
- simulation, drift detection, rollback, and human override controls

### v2.32 Federated Trust Activation, Open Admission, and Shared Reputation Network

Move from local trust activation and local weighting into cross-operator trust
federation, more open admission, and shared portable-reputation networking.

Target outcomes:

- cross-operator trust-activation federation contracts
- mirror/indexer quorum, conflict, and anti-eclipse semantics
- bounded open-admission or stake/bond participation classes
- shared reputation clearing with anti-sybil and anti-ambient-trust controls

### v2.33 Public Identity/Wallet Network and Maximal Endgame Qualification

Move from ARC's bounded public identity and wallet interop into broader
multi-network identity and wallet compatibility, then close the strongest
possible reading of the research thesis.

Target outcomes:

- broader DID/VC method and credential-family support
- wallet directory, routing, and public discovery semantics
- multi-wallet, multi-issuer, cross-operator interoperability qualification
- final boundary rewrite for the maximal endgame claim

## Proposed Requirement Families

- `EXTMAX-*`: official-stack and extension-boundary contracts
- `RAILMAX-*`: real external dispatch and settlement truth
- `INSMAX-*`: autonomous pricing and capital automation
- `TRUSTMAX-*`: federated trust activation, open admission, and shared
  reputation networking
- `IDMAX-*`: broad public identity, credential, and wallet interop

## Sequencing Rationale

The order is intentional:

1. freeze the extension contract before web3 execution, because later rail,
   oracle, anchor, and identity work should plug into named ARC-owned
   extension points rather than bake one vendor stack into the trust kernel
2. real dispatch before autonomous pricing, because model-driven automation is
   weak if ARC still only issues neutral instructions
3. autonomous pricing before federated open admission, because open markets
   need explicit economic policy rather than manual delegated envelopes
4. federated trust and shared reputation before broad public wallet routing,
   because ecosystem-scale identity only matters once cross-operator trust
   semantics are explicit
5. final maximal qualification only after all stronger non-goals have been
   converted into qualified claims

## Non-Roadmap Procedural Follow-Ons

These are still important, but they are not product milestones in this ladder:

- hosted `CI` and hosted `Release Qualification` observation
- Nyquist validation backfill for recently completed phases
- historical planning-tree cleanup
