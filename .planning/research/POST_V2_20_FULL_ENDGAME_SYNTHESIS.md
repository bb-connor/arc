# Post-v2.20 Full Endgame Synthesis

**Date:** 2026-03-29
**Purpose:** Normalize the remaining post-`v2.20` research gaps into one
authoritative roadmap that is comprehensive enough for ARC to eventually claim
the full endgame described in `docs/research/DEEP_RESEARCH_1.md`.

## Inputs

- `docs/research/DEEP_RESEARCH_1.md`
- `docs/release/RELEASE_CANDIDATE.md`
- `spec/PROTOCOL.md`
- `docs/AGENT_ECONOMY.md`
- `.planning/research/POST_V2_20_CAPITAL_AND_LIABILITY_EXECUTION_ENDGAME.md`
- `.planning/research/POST_V2_20_PORTABLE_IDENTITY_AND_WALLET_ENDGAME.md`
- `.planning/research/POST_V2_20_ATTESTATION_AND_APPRAISAL_FEDERATION_ENDGAME.md`
- `.planning/research/POST_V2_20_OPEN_TRUST_MARKET_GOVERNANCE_ENDGAME.md`
- `.planning/research/POST_V2_20_OAUTH_OIDC_TRANSACTION_FABRIC_ENDGAME.md`

## Current Boundary After v2.20

ARC has now completed the bounded control-plane ladder implied by the original
research:

- governed rights, budgets, approvals, and settlement truth
- portable trust, wallet distribution, and a bounded OID4VP verifier bridge
- multi-cloud attestation appraisal and runtime-assurance rebinding
- enterprise IAM review surfaces and a governed public certification market
- underwriting, credit, bond, facility, and liability-market orchestration

That is enough to claim a strong bounded ARC control plane, but it is not yet
enough to claim the full endgame in the research. The remaining gaps are no
longer "missing core ARC." They are the broader standards fabric, vendor-
neutral verifier ecosystem, live capital execution, and open governed market
layers that sit on top of the current substrate.

## Synthesis Decision

The five post-`v2.20` planning tracks overlap heavily. They should not become
five parallel `v2.21` ladders. The authoritative sequence should be:

1. complete the standards-native authorization and credential fabric
2. widen wallet, identity-assertion, and sender-constrained live flows
3. externalize appraisal semantics and external verifier-result interop
4. federate verifier trust and broaden cross-issuer portability and discovery
5. convert bounded capital policy into live capital and escrow execution
6. add reserve control, auto-pricing, and automatic claims payment
7. widen from curated market surfaces into open registry, trust activation,
   and governance network semantics
8. close with portable reputation, market economics, abuse resistance, and
   full endgame qualification

That order is the smallest one that lets ARC widen its claim honestly:

- standards-facing identity and authorization come before broader market claims
- common appraisal semantics come before verifier federation
- live money movement comes after standards, trust, and assurance surfaces are
  stable enough to bind real authority
- open market governance comes after ARC can already represent the regulated
  and economic primitives it wants to expose

## Approved Milestone Sequence

### v2.21 Standards-Native Authorization and Credential Fabric

Close the gap between ARC's current narrow projected credential profile and its
review-oriented OAuth-family profile by aligning portable claim catalogs,
subject or issuer binding, multi-format credential projection, request-time
authorization mapping, and live metadata/status surfaces.

### v2.22 Wallet Exchange, Identity Assertions, and Sender-Constrained Authorization

Add a transport-neutral wallet exchange model, optional identity assertions for
session continuity, and a live sender-constrained contract over DPoP, mTLS,
and one explicitly bounded attestation-bound profile.

### v2.23 Common Appraisal Vocabulary and External Result Interop

Evolve ARC's appraisal bridge from an internal adapter boundary into a
versioned external result contract with normalized claims, reason taxonomy, and
import or export semantics that remain separated from local ARC policy.

### v2.24 Verifier Federation, Cross-Issuer Portability, and Discovery

Add cross-issuer trust packs and migration semantics, federated verifier
descriptors and trust bundles, public issuer or verifier discovery, and
assurance-aware policy that uses the common appraisal and portable identity
layers without creating auto-trust.

### v2.25 Live Capital Allocation and Escrow Execution

Convert bounded facility and bond policy into live capital books, custody-
neutral escrow or reserve instructions, governed-action allocation, and
regulated-role baseline profiles.

### v2.26 Reserve Control, Autonomous Pricing, and Claims Payment

Turn reserve posture into executable impairment, release, and slash controls,
then add delegated pricing authority, automatic coverage binding, automatic
claims payment, and recovery or reinsurance clearing under explicit role
topology.

### v2.27 Open Registry, Trust Activation, and Governance Network

Generalize ARC's current curated public discovery surfaces into a generic open
registry with mirrors, indexers, trust-activation artifacts, admission lanes,
governance charters, dispute escalation, sanctions, and appeals.

### v2.28 Portable Reputation, Marketplace Economics, and Endgame Qualification

Close the loop with portable reputation and negative-event exchange, fee and
bond economics, slashing-backed abuse resistance, adversarial multi-operator
qualification, and the public partner-proof and release-boundary rewrite needed
to claim the full research endgame honestly.

## Phase Numbering

- `v2.21`: phases `93` through `96`
- `v2.22`: phases `97` through `100`
- `v2.23`: phases `101` through `104`
- `v2.24`: phases `105` through `108`
- `v2.25`: phases `109` through `112`
- `v2.26`: phases `113` through `116`
- `v2.27`: phases `117` through `120`
- `v2.28`: phases `121` through `124`

## Claim Boundary

ARC can only honestly claim the full research endgame after `v2.28` closes,
and only if all of the following are true:

1. ARC's live authorization and portable credential surfaces are standards-
   native at request time, not only in post-execution evidence.
2. Wallet, identity assertion, sender-constrained, and transaction-propagation
   lanes are bounded, replay-safe, and qualification-backed.
3. Runtime attestation results can move through a common appraisal vocabulary,
   federated trust bundles, and assurance-aware downstream policy without
   widening trust from raw foreign evidence.
4. Capital, reserve, bond, pricing, claim payment, recovery, and reinsurance
   state can execute and reconcile against real counterparties without
   mutating canonical receipt truth.
5. Open discovery, trust activation, portable reputation, and governance
   network semantics exist without turning visibility into automatic runtime
   trust or collapsing into a universal trust oracle.
6. Partner proof, release boundary, qualification evidence, and protocol docs
   are rewritten to match the widened truth, including the regulated-role and
   non-goal boundaries that still remain.

## Persistent Guardrails

- Canonical ARC receipts remain the execution ground truth.
- Portable identity, OAuth/OIDC, and wallet flows derive from ARC truth rather
  than creating a second mutable authority system.
- `runtimeAttestation` remains the carried evidence input; stronger decisions
  still come from local policy rebinding, not raw foreign claims.
- Discovery visibility never equals runtime admission.
- Imported appraisal, reputation, governance, and listing evidence always keeps
  issuer or origin provenance and local policy remains authoritative.
- Live money movement always has both intent-state artifacts and reconciled
  external-state artifacts.
- Regulated authority is explicit; ARC must not silently imply that a generic
  operator is automatically a carrier, lender, custodian, TPA, MGA, or broker.
- Simulation, shadow mode, and qualification come before every new live-money
  or open-market widening step.
- ARC still does not target a universal trust score, universal wallet
  compatibility claim, or permissionless auto-trusting market.

## Crosswalk From Source Tracks

- `v2.21` and `v2.22` absorb the portable identity and OAuth/OIDC transaction-
  fabric agent plans.
- `v2.23` and `v2.24` absorb the attestation/appraisal federation plan plus
  the cross-issuer and discovery-heavy portable identity work.
- `v2.25` and `v2.26` absorb the capital and liability execution plan.
- `v2.27` and `v2.28` absorb the open trust market, governance, reputation,
  fee, bond, and abuse-resistance plan.

## Execution Decision

`v2.21` should be activated immediately. The later milestones should be kept
fully defined at the roadmap and requirements level, but only the active
milestone needs phase directories and executable plan files on disk.
