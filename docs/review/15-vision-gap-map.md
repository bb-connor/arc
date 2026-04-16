# ARC Vision Gap Map

Date: 2026-04-15
Authority: Full-vision truth assessment

## Purpose

This memo maps ARC's strongest vision claims to:

- the strongest evidence currently present in the repo
- the exact gap between that evidence and the stronger claim
- the concrete work required to make the stronger claim literally true

Use this with:

- [13-ship-blocker-ladder.md](./13-ship-blocker-ladder.md)
- [14-bounded-arc-pre-ship-checklist.md](./14-bounded-arc-pre-ship-checklist.md)
- [STRATEGIC-VISION.md](../protocols/STRATEGIC-VISION.md)

## Interpretation Rule

A claim is not "almost true." One of three things must happen:

- implement the missing machinery
- gate or demote the affected surface
- narrow the public claim until it matches the evidence boundary

This memo is about the first option: what must exist for the stronger claim to
be literally true rather than rhetorically attractive.

## Claim Map

### 1. ARC is a cryptographically signed, fail-closed, intent-aware governance control plane across qualified authoritative surfaces

**Status:** literal now, but only on the qualified authoritative HTTP, MCP,
OpenAI, A2A, and ACP surfaces.

**Current evidence**

- [STRATEGIC-VISION.md](../protocols/STRATEGIC-VISION.md) already names this as
  the current defensible claim.
- [universal-control-plane qualification](../../target/release-qualification/universal-control-plane/qualification-report.md)
  records this claim as qualified.
- [407-01-SUMMARY.md](../../.planning/phases/407-universal-binding-resolution-and-executor-registry/407-01-SUMMARY.md),
  [409-01-SUMMARY.md](../../.planning/phases/409-dynamic-intent-aware-governance-control-plane/409-01-SUMMARY.md),
  and
  [410-01-SUMMARY.md](../../.planning/phases/410-shared-lifecycle-contract-and-runtime-fidelity-closure/410-01-SUMMARY.md)
  show the shared registry, signed route-selection evidence, and shared
  lifecycle contract are real.

**Exact work required to keep it literally true**

- keep the qualified-surface list explicit and narrow
- keep authoritative and compatibility paths separate in docs and tests
- fail qualification when route-selection, lifecycle, or registry behavior drifts
- avoid collapsing this bounded control-plane claim into broader market,
  federation, or transparency claims

### 2. Capability tokens are programmable spending authorizations

**Status:** bounded now; not yet literally true in the strong economic sense.

**Current evidence**

- [VISION.md](../VISION.md) frames capability tokens as programmable spending
  authorizations.
- [10-economic-authorization-remediation.md](./10-economic-authorization-remediation.md)
  shows the runtime already has monetary ceilings, governed intent fields, one
  external payment-authorization hop, and signed financial metadata.

**Exact work required to make it literally true**

- define a first-class economic-party model:
  payer account, payee settlement destination, merchant of record,
  beneficiary of funds, rail, asset, and settlement mode
- cryptographically bind approval to those economic parties plus quote or tariff
- require verifiable ex ante rail authorization, hold, prepayment, or equivalent
  reservation before execution when strong payment claims are made
- model authorization, hold, capture, release, reversal, and settlement as
  distinct states rather than one mutable budget counter
- keep local budget truth, rail truth, and legal or liability truth as separate
  evidence classes

### 3. Delegation chains are cost-responsibility chains

**Status:** not yet literally true.

**Current evidence**

- [VISION.md](../VISION.md) treats delegation chains as the structure for cost
  responsibility.
- [02-delegation-enforcement-remediation.md](./02-delegation-enforcement-remediation.md)
  and [04-provenance-call-chain-remediation.md](./04-provenance-call-chain-remediation.md)
  show ARC now has stronger recursive delegation admission, capability lineage,
  and signed receipt attribution.

**Exact work required to make it literally true**

- authenticate delegation provenance end to end rather than preserving caller
  assertions inside signed receipts
- bind delegation edges to authenticated session or runtime identity continuity
- represent economic responsibility separately from mere authorization lineage
- link each economic authorization, hold, and capture event to the exact
  delegation edge or chain segment that authorized it
- enforce all declared chain limits at runtime, including the configured
  delegation-depth ceiling

### 4. ARC can prove who authorized what across recursive, cross-kernel, cross-protocol execution

**Status:** bounded now; receipts and reports distinguish `asserted`,
`observed`, and `verified`, local session anchors and request-lineage records
ship, but receipt-to-receipt and cross-kernel continuity are still incomplete.

**Current evidence**

- governed receipts now carry `GovernedCallChainProvenance` with evidence class
  and evidence-source fields rather than one undifferentiated `call_chain`
  truth claim
- the kernel upgrades caller-supplied `call_chain` metadata from `asserted` to
  `observed` when local parent request or parent receipt lineage, or
  capability-lineage subjects, corroborate the claim
- the kernel upgrades to `verified` only when a signed upstream delegator proof
  also validates against the asserted context and the executing capability
  lineage
- the authorization-context report preserves evidence class and does not count
  asserted-only call-chain provenance as delegated sender-bound truth
- local session anchors and durable request-lineage records now exist for local
  continuity and nested flows
- [04-provenance-call-chain-remediation.md](./04-provenance-call-chain-remediation.md)
  describes the remaining boundary: signed receipt-lineage statements are still
  incomplete, outward lineage references are not yet uniform, and replay-safe
  continuation qualification remains open

**Exact work required to make it literally true**

- finish the current execution order with signed receipt-lineage statements for
  local child edges and replay-safe continuation tokens for cross-kernel
  `verified` edges
- require signed parent receipts plus parent receipt hashes and replay-safe
  continuation artifacts before ARC upgrades remote provenance to `verified`
- unify governed `call_chain`, child-request lineage, and capability lineage
  into one durable provenance DAG rather than correlated receipt-local views
- bind provenance subjects to the authenticated caller and capability subject
  across auth rotation, restart, and failover
- keep reviewer packs and authorization-context exports evidence-class-aware and
  fail closed whenever a lineage edge cannot clear the `asserted` boundary

### 5. ARC is an attested rights channel with verifier-backed runtime assurance

**Status:** not yet literally true end to end.

**Current evidence**

- [03-runtime-attestation-remediation.md](./03-runtime-attestation-remediation.md)
  shows ARC already ships real Azure, AWS Nitro, Google, and enterprise verifier
  adapters plus appraisal and trust-policy layers
- the kernel and issuance paths already have runtime-assurance policy hooks

**Exact work required to make it literally true**

- introduce a first-class verified attestation record type
- make verifier output the sole authority for runtime-assurance admission
- cut issuance and governed execution over so they accept only a signed verified
  record or a local verified-record ID
- bind verified records to the authenticated caller, workload identity, or
  session identity that is actually using the capability
- make trust roots explicit and auditable per verifier
- require imported appraisal results to be locally re-admitted before they
  affect runtime assurance

### 6. ARC receipts are a pre-audited, cryptographically signed, append-only ledger with non-repudiation

**Status:** bounded local audit plane plus one bounded trust-anchored
publication path; append-only public-proof language is still not literally
true.

**Current evidence**

- [VISION.md](../VISION.md) uses append-only-ledger and non-repudiation language
- [05-non-repudiation-remediation.md](./05-non-repudiation-remediation.md)
  shows ARC already has signed receipts, immutable local checkpoints, local
  consistency proofs, same-size fork detection, trust-anchor-bound publication
  records, bounded anchor discovery policy/freshness projection, and
  preview-gated transparency claims

**Exact work required to make it literally true**

- anchor receipt and checkpoint verification to an external operator or trust
  chain rather than self-authenticating embedded keys
- finish replacing tool-receipt batch checkpoints with one prefix-growing
  append-only log over the full claim tree
- include child receipts and any claim-relevant derived artifacts in the log
- extend the current bounded trust-anchor or witness publication path into a
  broader independently reviewable publication network with anti-equivocation
  detection
- define key rotation, revocation, and operator-identity continuity for the
  receipt-signing authority

### 7. ARC offers strong sender-constrained identity continuity and hosted isolation

**Status:** bounded now on the recommended hosted profile; not yet literally
true across all hosted modes.

**Current evidence**

- [06-authentication-dpop-remediation.md](./06-authentication-dpop-remediation.md)
  shows ARC already has native DPoP checks and deterministic identity-federation
  support in some configurations
- [09-session-isolation-remediation.md](./09-session-isolation-remediation.md)
  shows per-session kernels and edges are real and that some cross-tenant reuse
  protections exist
- [ARC_BOUNDED_OPERATIONAL_PROFILE.md](../standards/ARC_BOUNDED_OPERATIONAL_PROFILE.md)
  already documents the stronger recommended profile

**Exact work required to make it literally true**

- make the strong sender-constrained profile the default or clearly fence weaker
  modes as compatibility-only
- compare the full authorization context on session reuse rather than a narrow
  identity tuple
- define stable caller-binding semantics across refresh, restart, and failover
- provide durable replay or freshness semantics that match the public claim
- either prove non-interference for `shared_hosted_owner` or keep it outside the
  strong hosted-security story
- ensure the kernel's caller identity is cryptographically or transport-bound,
  not merely string-matched

### 8. ARC is a comptroller-grade HA control plane

**Status:** not yet literally true.

**Current evidence**

- [07-ha-control-plane-remediation.md](./07-ha-control-plane-remediation.md)
  and [08-distributed-budget-remediation.md](./08-distributed-budget-remediation.md)
  show ARC already has leader-local control-plane writes, minority fail-closed
  behavior, remote budget-store abstraction, and clustered visibility
- the bounded operational profile already labels these surfaces as
  `leader-local` or `local-only`

**Exact work required to make it literally true**

- replace deterministic leader-local coordination with consensus or another real
  quorum-commit protocol
- add stale-leader fencing and term semantics that survive partitions and repair
- define authority-key, issuance, and receipt continuity under failover
- provide linearizable read semantics or an explicitly proved read-consistency
  model
- qualify failover behavior under real recovery scenarios rather than only local
  cluster simulation

### 9. ARC has distributed truthful spend and budget semantics

**Status:** not yet literally true.

**Current evidence**

- single-node atomic budget enforcement is real
- the kernel already pre-debits provisional spend and reconciles later
- the current cluster story documents a bounded HA overrun rather than denying
  it
- [08-distributed-budget-remediation.md](./08-distributed-budget-remediation.md)
  records the exact current boundary

**Exact work required to make it literally true**

- stop treating money as a merged mutable counter and move to immutable
  authorization events
- distinguish available budget, reserved budget, captured spend, released holds,
  and expired authorizations
- implement consensus-backed spend authorization or partitioned escrow that can
  preserve a distributed spend invariant
- make truthful exposure reporting a first-class runtime output
- require metering inputs strong enough to support billing claims rather than
  only tool self-report

### 10. ARC is a portable trust, passport, and federation network with Sybil resistance

**Status:** not yet literally true.

**Current evidence**

- [11-reputation-federation-remediation.md](./11-reputation-federation-remediation.md)
  shows local reputation scoring, bounded imported trust, conservative
  federation controls, and multi-issuer passport packaging are already real
- the current federation surface already honestly preserves visibility without
  ambient runtime trust

**Exact work required to make it literally true**

- define first-class issuer descriptors with ownership, accountability,
  trust-root lineage, and correlation boundaries
- define subject-continuity and subject-migration semantics that survive
  cross-operator rebinding
- turn portability from artifact portability into trust portability through an
  explicit clearing model
- implement network-level anti-Sybil mechanisms:
  issuance-cost model, issuer limits, corroboration rules, and cross-identity
  correlation
- define the public identity and discovery layer explicitly if the goal is a
  real network rather than bilateral evidence portability

### 11. ARC is formally verified

**Status:** partially true only for a narrower symbolic model.

**Current evidence**

- [01-formal-verification-remediation.md](./01-formal-verification-remediation.md)
  shows the repo has real Lean proofs, proof CI, and differential tests
- the current proof surface covers a narrower model than the full Rust runtime

**Exact work required to make it literally true**

- define one explicit `Verified Core` boundary
- map every public formal claim to a named theorem inside that boundary
- prove or machine-check a refinement from the production Rust decision logic to
  the Lean model
- state symbolic and computational crypto assumptions explicitly
- route the security-critical pure evaluator through the verified core
- fail CI and release qualification when theorem inventory, proof boundary, or
  public claim language drift

### 12. ARC is the comptroller of the agent economy

**Status:** not repo-provable today.

**Current evidence**

- [STRATEGIC-VISION.md](../protocols/STRATEGIC-VISION.md) already frames this as
  a strategic thesis rather than a current fact
- [comptroller-market-position qualification](../../target/release-qualification/comptroller-market-position/qualification-report.md)
  explicitly says ARC is comptroller-capable software, not a proved market
  position

**Exact work required to make it literally true**

- finish the protocol, economic, provenance, attestation, transparency, and
  federation work described above
- prove multi-operator production use beyond one bounded operator surface
- prove partner dependence and operator adoption in the real market
- show that outside parties rely on ARC's control-plane truth rather than merely
  being able to integrate with it

This final claim cannot be closed by repo work alone. Part of the gap is code
and protocol machinery. Part of the gap is external market evidence.

## Most Leveraged Sequence

If the goal is to make the full ARC thesis become literally true in the
shortest honest path, the highest-leverage sequence is:

1. provenance classes plus authenticated parent linkage
2. verified-attestation records as the only runtime-assurance admission input
3. consensus or escrow-backed control-plane and spend truth
4. transparency-log semantics with external anchoring and anti-equivocation
5. stronger hosted identity continuity and shared-owner boundary discipline
6. only then: portable trust clearing, Sybil resistance, and market-position
   proof
