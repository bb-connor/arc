# chio-federation architecture

## Responsibility and boundary

This crate owns federation artifact types, structural validators, pinned-peer
handshakes, treaty evaluation, bilateral receipt verification, and FROST
execution proofs. `lib.rs` exposes modules and re-exports core capability and
receipt modules plus listing and open-market contracts.

Network endpoints, operator review, capability issuance, and persistent
storage belong to embedding services. Artifact references bind identifiers
and digests; structural validation does not fetch or authenticate their targets.

## Structure

| Module | Responsibility |
| --- | --- |
| `artifacts`, `activation` | Exchange references, trust scope, delegation and import controls. |
| `quorum` | Publisher observations, anti-eclipse policy, and report-state consistency. |
| `open_admission`, `reputation` | Stake requirements and bounded clearing-input validation. |
| `qualification` | Scenario matrix shape and required requirement coverage. |
| `trust_establishment` | Signed challenges, conformance tiers, peer pins, store interface. |
| `treaty` | Governance ladders, intersections, and cross-boundary admission reports. |
| `bilateral` | Co-sign protocol seam and detached-signature compatibility receipts. |
| `bilateral_dsse` | Statement construction, canonical payloads, PAE signatures, profile checks. |
| `bilateral_verifier` | Receipt, lease, governance, revocation, and treaty-aware verification. |
| `frost` | Typed action preimages, rosters, artifact trust, epoch and slot transitions. |
| `pheromone_gossip`, `revocation_gossip` | Local queues, frame contracts, and catch-up history seams. |
| `metrics`, `error`, `input`, `validation` | Observability, errors, bounded decoding, shared checks. |
| `demo` | Test and optional demo revocation oracle. |

`bilateral_dsse` splits builder, policy, signing, types, and verification into
private files. `bilateral_verifier` separates configuration, state interfaces,
co-sign validation, treaty review, and diagnostic mapping. The `typestate`
feature exposes generated producer states alongside the ordinary APIs.

## Data and control flow

1. `local_envelope` signs a canonical handshake challenge. The receiving
   `KernelTrustExchange` checks identity, address, freshness, and trust anchors
   before storing a peer. Capability negotiation is bound to the signed body.
2. Operators construct activation exchanges, publisher quorum reports, and
   admission or reputation artifacts. Validators check their declared controls
   and internal relationships before an integration signs or imports them.
3. `compute_ladder_intersection` combines participant ladders.
   `evaluate_cross_boundary_admission` checks freshness, treaty/intersection
   bindings, allowed actions, and required evidence declarations.
4. Bilateral producers sign canonical in-toto statements using DSSE PAE.
   `verify_chio_bilateral_invocation` resolves pinned peers and local evidence
   through `VerifierConfig`, then validates operational bindings.
5. FROST verification resolves signed rosters and anchored state. Execution
   verification binds the proof to the expected action, scope, resource, epoch,
   validity window, and completed authorization slot.

## Trust and invariants

`PeerHandshakeEnvelope::verify_signature` checks the schema and signature
against the declared key. Admission additionally checks the configured anchor
or existing pin; first contact without an anchor is rejected. `resolve` denies
expired pins. The default rotation window is twelve hours and allowed skew is
five minutes. No seen-nonce set is maintained. Transport or caller replay
protection is required inside that skew window.

`FederationPeerStore` allows replacement storage; `InMemoryPeerStore` uses a
mutex-protected map. Gossip queues and the provided bilateral evidence stores
are also process-local. Revocation catch-up takes a caller-owned history.
Execution epoch and slot anchors are traits whose freshness and durable
ordering depend on their supplied implementations.

Activation validation requires attenuation and bounded hops as declared
controls. It does not traverse a capability delegation chain. Quorum validation
counts supplied freshness observations and checks declared conflict state;
it does not independently compare all observed listing digests. Admission
report evaluation consumes caller-provided `verified` evidence flags.
Integrations must authenticate those observations and evidence first.

Reputation clearing checks participating issuer IDs, per-issuer input caps,
per-input weight ceilings, independent accepted issuers, and corroborated
blocking events. These checks use declared inputs and classifications; the
validator does not query remote reputation services or compute a global score.

`verify_chio_bilateral_dsse_envelope` verifies the strict profile and both
independent signer keys. The higher-level invocation verifier adds revocation,
local receipt integrity, policy disposition, lease, and governance resolution.
The signature-slice verifier and detached `DualSignedReceipt` compatibility
APIs have distinct payload contracts.

`RevocationRootGossip::validate_envelope` is structural. Consumers must call
`SignedEpochRoot::verify` with a pinned oracle verifier before installation.
Pheromone frame checks enforce origin and transit relationships; deposit
signature verification is a separate receiver responsibility.

`ConformanceEvidence::derive_tier` derives a tier from supplied metrics, and
handshake admission checks the signed advertised tier. Neither API runs the
cross-surface campaign required by the protocol. The qualification validator
checks matrix structure and coverage rather than executing its cases.

## Dependencies

`chio-core-types` supplies canonical JSON, signatures, receipts, and capability
negotiation. `chio-listing` supplies publisher and admission vocabulary;
`chio-open-market` supplies bond classes. `chio-pheromone` and
`chio-revocation-oracle` supply deposit and signed-root types.
`frost-ed25519` verifies aggregate signatures. Base64, SHA-256, and hex support
DSSE payloads and key fingerprints; `chio-metrics-spec` names telemetry.

## Verification

From the workspace root, run `cargo test -p chio-federation` for artifact,
handshake, treaty, bilateral, gossip, and FROST tests. Run
`cargo test -p chio-federation --features typestate` for generated producer
coverage. `tests/generated_sources.rs` checks generated-source consistency.

`tests/distributed_revocation_refinement.rs` exercises loss, duplicate and
reordered delivery, forged roots, partitions, and stale views.
`tests/oracle_gossip_e2e.rs` measures an in-process oracle-to-verifier path.
`cargo bench -p chio-federation --bench bilateral_verify` measures strict DSSE
verification with a fixed receipt fixture. Its scope excludes network latency.
