# Design: capability protocol primitives (burns, quorum, proof-carrying)

- Status: DRAFT (awaiting review)
- Date: 2026-07-09
- Scope: two capability-model additions to `chio-core-types` and `chio-kernel` (use-count burns), and two new crates under `crates/security/` (`chio-quorum`, `chio-proof-carry`).
- Related normative docs: `spec/PROTOCOL.md` (capability and caveat semantics), `spec/SECURITY.md`, `docs/security/threat-coverage.md`.
- Sibling arcs: `2026-07-09-security-folder-design.md` (active defense), `2026-07-09-enterprise-hardening-design.md` (enterprise hardening).

## 1. Summary

This arc deepens the capability model itself. Where the active-defense and enterprise arcs add engines and infrastructure, these three primitives change what a capability can express and what the kernel checks before dispatch. They are the deepest moat and the slowest to ship, because each is a normative wire-level change with conformance impact.

- Use-count burns: a capability may be spendable a bounded number of times. The kernel enforces a monotonic burn counter and the capability dies when the count is exhausted. Today capabilities are time-bounded but not spend-bounded.
- `chio-quorum` (m-of-n co-signed invocation): a caveat that requires a threshold of independent signatures before a destructive-class tool call is dispatched. The two-person rule, at the invocation boundary.
- `chio-proof-carry` (proof-carrying requests): a request may carry a verifiable proof that it satisfies a policy, which the kernel checks before dispatch, so the agent proves authorization rather than the kernel re-deriving it. This is the most research-forward primitive and is scoped accordingly.

## 2. Goals and non-goals

Goals:

- Add spend-bounding to capabilities so a stolen or over-delegated token has a hard, verifiable ceiling on use.
- Require m-of-n independent authorization for destructive-class operations, so a single stolen signing key cannot invoke them.
- Provide a normative envelope for a request to carry a proof the kernel verifies before dispatch, with a reference verifier.
- Keep enforcement in the kernel (where capability constraints already live) and keep collection and proof generation outside the TCB.

Non-goals:

- No general-purpose zero-knowledge proof system in v1. `chio-proof-carry` ships a concrete, checkable proof form (a signed policy-satisfaction attestation verified against the transaction-passport evidence graph) and a trait seam for richer proof systems later. It is explicitly the least mature of the three.
- No change to the existing time-bound, scope, delegation, or attenuation semantics. Burns are additive and optional.
- No new signature algorithm. Quorum composes the existing multi-backend signing and the existing signed-envelope format.

## 3. Background: what already exists

- Capabilities: `chio-core-types` `CapabilityToken` carries id (UUIDv7), issuer, subject, scope, `issued_at`, `expires_at`, delegation chain, typed caveats, scope attenuations, and `budget_share_bps`. There is no use-count field today.
- Caveats: `CaveatKind` currently has `RestrictTool`, `BindSession`, `RestrictAudience`, `RestrictGeo`, `RestrictTimeWindow`. The active-defense arc adds `Declassify`. This arc adds `RequireQuorum`.
- Replay and freshness: a nonce and replay store exists with in-memory and SQLite backends. The burn counter reuses this monotonic-store pattern.
- Action classes: `crates/trust/chio-governance` defines action classes (observe, delegate, destructive). Quorum keys off the destructive class.
- Signed envelopes: `chio-core-types` has a signed-artifact envelope used for DSSE-style signing. Quorum collects m-of-n of these.
- Evidence graphs: `crates/platform/chio-transaction-passport` validates an evidence graph and runtime security claims; `crates/kernel/chio-runtime-proof-parity` regenerates and parity-checks proofs. `chio-proof-carry` verifies against these.

## 4. Use-count burns

Placement: the `use_limit: Option<u32>` field lands on `CapabilityToken` in `chio-core-types` (protocol-normative). Enforcement lands in `chio-kernel` at the same point that checks `expires_at`. The burn counter is a monotonic store (the nonce-store pattern), keyed by capability id, optionally anchored in the `chio-revocation-oracle` epoch for cross-instance consistency.

Core invariants:

- A capability with `use_limit = Some(n)` may be spent at most `n` times. The `(n+1)`th dispatch is denied (fail-closed).
- The counter is monotonic and never rewinds. A rewind attempt (replaying an older counter value) is denied, reusing the clock-rewound and replayed-nonce defenses already in the adversarial corpus.
- Each spend emits a `Burn` receipt recording the capability id and the remaining count, so spend is auditable.

TCB posture: enforcement is in the kernel, which is correct: a burn is a capability constraint exactly like TTL.

Threat relevance: `capability_token_theft` (a spent token is inert, so theft has a hard ceiling) and `delegation_chain_abuse` (burns bound how often a delegated child can be reused).

## 5. `chio-quorum` (m-of-n co-signed invocation)

Modules: `caveat` (the `RequireQuorum { m, n, signer_set }` semantics behind the new `CaveatKind::RequireQuorum`), `envelope` (collect m-of-n signed authorization envelopes over the canonical request, reusing the existing signed-artifact format), `verify` (check that at least `m` distinct authorized signers from the declared set signed the exact request), `gate` (the kernel hook that blocks dispatch of a destructive-class operation until the quorum is satisfied).

Core invariants:

- A destructive-class operation carrying a `RequireQuorum` caveat is dispatched only when at least `m` distinct signers from the declared set have signed the canonical request. Fewer than `m`, or a signature over a different request, is denied (fail-closed).
- Signers must be distinct and in the declared set; duplicate signatures from one signer do not count twice.
- Quorum satisfaction emits a `QuorumSatisfied` receipt listing the satisfying signers, so the authorization is attested.

Relationship to `chio-quarantine`: distinct mechanisms. Quarantine's co-sign gates *containment actions* (response). Quorum gates *tool invocations* (prevention). They share the m-of-n idea and the envelope format but sit at different boundaries.

TCB posture: the caveat check is in the kernel (TCB). Envelope collection is outside the TCB: a compromised collector cannot forge signatures, only fail to reach quorum, which fails closed.

Threat relevance: `capability_token_theft` and `kernel_impersonation` defense in depth (a single stolen key cannot authorize a destructive op alone).

## 6. `chio-proof-carry` (proof-carrying requests)

Modules: `proof` (the proof envelope attached to a request: a signed policy-satisfaction attestation plus the evidence it references), `verify` (check the proof against the `chio-transaction-passport` evidence graph and, where applicable, `chio-runtime-proof-parity`), `contract` (the normative pre-dispatch verification contract the kernel enforces).

Core invariants:

- A request that declares it carries a proof is dispatched only if the proof verifies against the evidence graph. A missing or failing proof is denied (fail-closed).
- The proof binds to the exact canonical request, so a proof cannot be lifted onto a different request.
- Verification emits a `ProofVerified` receipt, so the proof-checked path is auditable.

TCB posture: proof verification is in the kernel (TCB). Proof generation is the agent's responsibility and is untrusted; a bad proof simply fails to verify.

Scope honesty: this is the most research-forward primitive. v1 ships one concrete, checkable proof form and a trait seam, not a general proof system. It is called out as the least mature of the three so reviewers weight it accordingly.

Threat relevance: raises the bar generally by letting the kernel demand positive evidence of authorization for sensitive operations rather than inferring it.

## 7. Protocol deltas

This arc is protocol-heavy by design (its whole point is normative capability semantics). Each needs `spec/PROTOCOL.md` and `spec/SECURITY.md` edits plus conformance vectors:

- `CapabilityToken.use_limit: Option<u32>` and the burn-counter enforcement contract.
- `CaveatKind::RequireQuorum` and the quorum envelope wire format.
- The proof-carrying request envelope and its pre-dispatch verification contract.
- Three new receipt subtypes: `Burn`, `QuorumSatisfied`, `ProofVerified`.

## 8. Threat-model mapping

Mechanisms that make rows closable, not closures.

| Threat row | Current state | Mechanism this arc adds |
|------------|---------------|--------------------------|
| `capability_token_theft` | Pending | use-count burns (spent token is inert); quorum (single key insufficient) |
| `delegation_chain_abuse` | Pending | burns bound delegated-child reuse |
| `kernel_impersonation` | Pending | quorum requires m independent signers for destructive ops |

## 9. Testing and evidence

- Adversarial corpus: new classes in `chio-adversarial-suite` (`burn_replay` for a rewound burn counter, `quorum_forgery` for sub-threshold or duplicate-signer quorum, `proof_forgery` for a proof bound to a different request), wired into `chio-arena`.
- Conformance: burn exhaustion and monotonicity, quorum threshold and distinctness, proof-to-request binding.
- Release gates: `check-burn-monotonic` (counter never rewinds), `check-quorum-distinct-signers` (duplicate signers rejected), `check-proof-request-binding` (proof binds to canonical request).
- Formal: burn monotonicity and quorum threshold are small, checkable properties well suited to the existing `formal/` Kani and TLA scaffolding.

## 10. Risks and open questions

- Burn-counter consistency across kernel instances. A capability spent on two instances concurrently could exceed its limit without shared state. Mitigation: anchor the counter in the revocation-oracle epoch for deployments that need cross-instance guarantees; document single-instance semantics otherwise (no silent widening of the guarantee).
- Quorum signer-set distribution. The declared signer set must itself be trustworthy. Mitigation: source it from the `chio-keyring` transparency log so signers are pinned and auditable.
- Proof-carrying maturity. The proof form is concrete but narrow. Mitigation: ship the trait seam and label the primitive research-scoped in both the spec and the plan; do not claim general proof-carrying authorization.

## 11. Crate and type manifest summary

| Unit | Location | In TCB |
|------|----------|--------|
| use-count burns | `chio-core-types` (field) + `chio-kernel` (enforcement) | Yes (kernel constraint) |
| `chio-quorum` | `crates/security` | Caveat check in kernel; collection out of TCB |
| `chio-proof-carry` | `crates/security` | Verification in kernel; generation untrusted |
