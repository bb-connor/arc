# Trajectory-4 Synthesis v2 — Integrated Plan

**Status**: revised after reviewer pass. Integrates `SYNTHESIS-V1-INTERNAL-ONLY.md` (substrate-hardening floor) with `BRAINSTORM-V1-FEATURE-CATALOG.md` (9-lens feature brainstorm). Reviewer-recommended scope adopted; full ladder retained as opt-in.

**Reviewer fixes applied in this revision**:
- Threat-count language made exact: 20 threats / 8 covered / 12 pending (6 stub `unimplemented!()` + 3 missing `coveredBy` JSON link + 3 mobile-pending).
- Capability-negotiation handshake (`chio.capabilities.v1`) and `CapabilityToken` schema-tag promoted to **T1.0** ahead of macaroon caveats (the hinge ordering).
- Verdict cache key fully specified: composite of cap_hash + scope + tool + guard-set hash + policy version + tenant/agent identity + caveat state + revocation epoch + trust-root epoch. Demoted to T2 only after S-1 flame-graph profile lands. Pure-preflight-only; explicit invalidation contract required.
- Receipt-DAG formal model expanded: node IDs, parent-set hashes, acyclicity invariants, fanout limits, join semantics, replay rules. Old "sliding `recent_chain_signatures` set" loop guard replaced with formal DAG-level acyclicity.
- Anchor-batch reframed as additive: per-receipt local sign stays verifiable; batch root upgrades continuity + non-repudiation, does not replace per-receipt signing.
- `BudgetSplit::PerChildShare(f32)` replaced with **fixed-point integer units (basis points or micros)**.
- Narrow `chio explain <receipt-id>` CLI promoted from T3 into T1 (CLI only — full web explorer stays in T3).
- Cargo-vet debt added to plan with "no net-new exemptions plus top-risk burn-down" close bar.
- "Three tiers" prose corrected to **four tiers** throughout (T0/T1/T2/T3).
- Recommended scope-lock narrowed per reviewer: T0 + reordered T1 core + selected T2.1 + `chio explain` CLI + **one of {T1.5 SRE redaction/metrics, T2.3 trust-graph quorum/rotation}**, not both.

## Scope rule (unchanged from v1)

Trajectory-4 is internal-only code work. Out of scope: design partners, vendor crypto review, HITRUST audit, AWS Marketplace publication, MCP Registry publication, real partner cosign-OIDC sig (M02), 30-day pilot, TestFlight cohort, external red-team. These remain in `CLOSEOUT-BLOCKERS.md` for a later trajectory. See `REJECTED-IDEAS.md` for the full list of considered-but-cut items.

## Theme

**Multi-agent trust primitives, with substrate hardening as the floor.**

The 9-lens brainstorm produced one strong cross-cutting consensus and one subordinate one:

1. **4-way consensus**: macaroon-style capability attenuation. Capability-extension #1, AI-frontier #4, protocol-evolution #2, trust-graph #1 — four independent lenses converged on the same primitive. The substrate already has `caveats: Vec<String>` placeholders in `chio-a2a-edge`; the structure is acknowledged but unbuilt.
2. **2-way consensus**: anchor-batch Merkle trees. Perf-scale (CPU savings) and protocol-evolution (public non-repudiation) want the same primitive for different reasons. **Reframing: additive over per-receipt signing, not a replacement.**

These two combine naturally with the floor's mobile-attestation work to produce a coherent trajectory-4 narrative: **the trust boundary becomes multi-agent-aware, hardware-rooted, and publicly anchorable**.

## Tiered scope (four tiers)

The plan has **four tiers**. Scope-lock decision picks the boundary; each tier compounds on the prior.

### Tier 0 — The floor (from synthesis-v1, 8-10 weeks single-track)

Required for any trj4 close. Earns the right to add anything else.

**Phase A (W1-2): trj3 closeout finalization**
- Drive remaining trj3.2 PRs through CI cascade-merge.
- Tag `v3.18.1-trj3.1`; trigger release-binaries + slsa + reproducible-build workflows.
- Commit produced artifacts to `releases/provenance/`, `releases/reproducible-builds/`, `supply-chain/checksums/`.
- Replace TODO markers in `TRAJECTORY-FINAL.md` + `CI-DEBT.md` with real close SHA + run URLs.
- Drain remaining trj3.2 P2 backlog.

**Phase B (W2-6): substrate hardening**
- Unblock hosted nightly cargo-mutants. Drive each trust-boundary crate kill rate to >= 65%, >= 80% on `chio-attest-verify` with `# unreachable: <justification>` annotations.
- Three deferred Kani harnesses: `chio-attest-verify`, `chio-anchor`, `chio-weights`.
- TLA+ rewrites: `RevocationCutCompleteness` transitive closure, `ReceiptBeforeAllow` split into `LogReceipt` + `PublishAllow`. Bump `EpochMax` to 6. Fix `RevocationEventuallySeen` apalache temporal lane back to required.
- Hosted-vs-portable equivalence property test in CI: 10k cases per PR + 1M nightly, zero divergence.
- `trust_control_cluster_multi_region_partition_qualification` root-cause fix.
- `chio-tee-frame::validate` real signature verification. `chio-tee-frame::schema::validate_timestamp` real RFC-3339 parse.

**Phase C (W6-8): mobile attestation real verifiers**
- Apple App Attest real verifier (CBOR + cert chain + counter monotonicity + nonce binding + KeyId binding) replacing `AttestationUnavailable`.
- Play Integrity real verifier (JWS + Google JWKS rotation + audience + nonce + verdict).
- Real `ChioKernel.xcframework` binary in `Frameworks/` with reproducible-build attestation.
- Threat-coverage flip for `mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay` (the 3 mobile-pending threats from X-2). These move from "no test files" to "covered" with real conformance tests.

**Phase D (W8-10): meta-improvements + threat-coverage push**
- Threat-coverage cargo-mutants per-row gate.
- **Threat-coverage finishing push** (X-2): fill the 6 `unimplemented!()` stubs (`agent_velocity_abuse`, `behavioral_sequence_attack`, `cumulative_data_exfiltration`, `pii_phi_exposure`, `ssrf_via_http_substrate`, `wasm_guard_resource_exhaustion`); update the 3 missing-`coveredBy` JSON links (`pq_signature_downgrade`, `tee_quote_forgery`, `weights_hash_spoof`). Combined with Phase C's 3 mobile flips, this lands 12 threats and brings coverage from 8/20 to 20/20.
- Fail-closed philosophy audit doc.
- CI-DEBT.md final pass.

### Tier 1 — Multi-agent trust primitives (4-6 additional weeks)

Targeted additions; each pulls weight in multiple lenses simultaneously. **Reordering**: T1.0 (capability negotiation + token versioning) ships first or atomic with T1.1 because macaroon caveats and `attenuation_proof` alter the signed capability surface and `CapabilityToken` has no schema field today.

**T1.0 Capability negotiation + token versioning (the hinge, ~1 week)**
- `chio.capabilities.v1` capability-negotiation handshake (P-11): peer advertises feature bitset; without it every additive proposal forces flag-day rollouts.
- `CapabilityToken` schema-tag (P-1): closes the only un-schema-tagged signed artifact.
- Capability-token versioning story: explicit `chio.capability.v1` + reserved fields for `chio.capability.v2` carrying caveats. v1.x peers stay on default; v2-aware peers negotiate up.

**T1.1 Macaroon capability attenuation (~3 weeks, gated on T1.0)**
- Capability caveats with typed first-party predicates (P-2, C-3): `Vec<Caveat>` reachable from `ToolGrant` where each `Caveat` carries `{kind, predicate, sig?}`. Third-party caveats with discharge are an XL follow-on.
- `attenuation_proof: { parent_scope_hash, child_scope_hash, normalized_subset_proof }` embedded so verifiers skip scope normalization (P-8).
- `CapabilityAttenuationGuard` enforcing subset-of-parent at runtime (C-3).
- `chio-federation::delegation::issue_token` / `verify_chain` for cross-org scoped delegation (T-1).
- `SubAgentBudgetPropagation` (C-4): `BudgetSplit` carried in child receipts and verified at join. **Use fixed-point integer units (basis points or micros) for the share field.** Floats inside signed/canonical authority artifacts are a footgun.

Result: sub-agents cannot re-amplify parent privileges; multi-org delegation is short-lived/scoped/revocable; verifiers have a witness instead of having to re-derive.

**T1.2 Multi-agent receipt DAG with fork/join (~2 weeks)**
Tighten the formal model first; otherwise the DAG is just a tree with extra fields.

- **Node IDs**: `receipt_id = H(canonical(receipt_body))` (already so today; pin behavior).
- **Parent-set hash**: `parent_set_hash = H(canonical(sort(parent_receipt_ids)))` so a verifier can cheaply check parent-set integrity without walking individual edges.
- **Acyclicity invariant**: every parent_receipt_id must have an earlier `(epoch, seq)` than the child; verifier rejects any receipt whose parent_set has same-or-later seq. Combined with monotone `(epoch, seq)` per kernel, this gives DAG acyclicity by construction.
- **Fanout limit**: per-call-chain `fanout_max` advisory in policy; `AgentLoopBoundsGuard` (C-2) enforces depth + fan-out.
- **Join semantics**: `chio.receipt_lineage_statement.v2` carries `parent_receipt_ids: Vec<String>`; canonical sort + dedupe; verifier requires every parent to exist and to share a common `chain_id` ancestor.
- **Replay rules**: receipt with same `(chain_id, kernel_id, epoch, seq)` is rejected at the receipt store; if seen on the wire, fail-closed.

The original A-15 loop-detection sliding `recent_chain_signatures` set is replaced by the acyclicity invariant above (formal, DAG-level, not local sliding).

**T1.3 Anchor-batch Merkle trees with public-witness checkpoints (~2 weeks)**
- New artifact `chio.anchor_batch.v1` carrying `{tree_root, checkpoint_ids[], witness: rekor|ots|solana_memo}` (P-4).
- Coalesced batch root computation: build a Merkle tree over N receipts/checkpoints, attach inclusion proof per element (S-2).
- **Reframing**: per-receipt local sign stays. The local receipt remains independently verifiable. The batch root is *additional* — it upgrades continuity (the batch attests N receipts as a set) and non-repudiation (the witness lane gives third-party timestamping).
- Closes the `audit_only` / `transparency_preview` ceiling explicitly admitted in PROTOCOL.md:657.

**T1.4 Archaeology finish-line (~2 weeks parallelizable)**
- Threat-model coverage push lands inside T0 Phase D; this T1.4 covers the rest of the archaeology debt.
- `chio-hosted-mcp` real extraction (X-1): lift `remote_mcp/*.rs` into its own crate; both CLI and chio-hosted-mcp consume it normally. Half-day surgical fix.
- Provider-adapter-core extraction (X-4): shared SSE-gate orchestration + `LoadedWeights` impl helper + `Provider` trait. Cuts ~3 KLOC across 7 adapters; makes 8th adapter (xAI / DeepSeek / OpenRouter / Together) a 1-day job.
- **Cargo-vet debt close-bar (X-10)**: trj4 enforces "no net-new exemptions" gate in CI; ship real audits for the top 50 highest-traffic dependencies (alloy-*, aws-sdk-*, tokio-*, hyper-*, tonic-*) to burn the count down by at least that 50.

**T1.5 Foundational SRE (~3 weeks parallelizable)** — *one of T1.5 or T2.3 per reviewer scope cap*
- `chio-metrics-spec` workspace-wide const-string registry (O-1). Compile-time enforced via `describe!` macro + CI golden snapshot.
- Prometheus alert + recording rule pack in `deploy/prometheus/` (O-3). Burn-rate alerts (14.4x/1h + 6x/6h dual-window) for slo.md targets. Routes to OpsGenie/PagerDuty already wired in `chio-siem`.
- `chio-log-redact` (O-14): `tracing_subscriber::Layer` running every event through receipt's redaction tree. `redacted!()` macro rejects raw-string formatting. Eliminates an entire class of P0 (PHI in PagerDuty).

**T1.6 `chio explain <receipt-id>` CLI (~1 week, promoted from T3 per reviewer)**
CLI only — not the full web explorer (DX-3 stays in T3 buffet). The CLI walks: which policy clause matched, which guards fired, scope diff, parent receipt(s) (DAG-aware after T1.2), batch witness lane (after T1.3), repair hint if denied. Pairs with A-12 ("why was this called?" trace).

This is in T1 because it makes the new receipt-DAG, attenuation failures, and close-bar evidence legible while the team is still building them. Without it, debugging T1.1/T1.2/T1.3 is a JSON-grep exercise.

### Tier 2 — Foundational improvements (2-4 additional weeks)

**T2.1 Trust-boundary plumbing** *(in recommended scope-lock)*
- Hybrid PQ handshake by default (T-8): make `KernelTrustExchange` generic over `SigningBackend`. Plumbing only; `HybridSigningBackend` already exists. **In scope per reviewer.**
- Conformance-tier handshake gating (T-5, `Bronze/Silver/Gold`): derived from threat-coverage + mutation-kill + Kani harness completeness. Data already produced; bind into peer record. **In scope per reviewer.**

**T2.2 Mediator hot path** *(stretch per reviewer)*
- Dispatch profile baseline + flame-graph CI artifact (S-1). Solves "we claim a <50us SLO without a profile that proves where time is spent." **Profile must land before T2.2's cache work below.**
- Lock-free verdict cache on kernel hot path: bounded LRU keyed by **fully-specified composite** `(cap_hash, scope, tool, guard_set_hash, policy_version, tenant_id, agent_id, caveat_state_hash, revocation_epoch, trust_root_epoch)`. Auto-invalidated on any component change. Pure-preflight-only — never caches a decision derived from a guard whose verdict depends on session state. Targets <5us p99 on hit. **Reviewer caution**: profile (S-1) before deciding whether the cache is worth the invariant-management cost.
- Tower load-shed middleware (S-7). `tower::LoadShed` + `tower::ConcurrencyLimit`. Translates the bounded signing queue into 503 + Retry-After at the HTTP edge.

**T2.3 Trust-graph maturity** *(one of T1.5 or T2.3, per reviewer scope cap)*
- M-of-N quorum-signed receipts (T-2): generalize `DualSignedReceipt` (2-of-2) to `QuorumSignedReceipt { body, signatures, threshold }`. Bilateral becomes a degenerate case.
- Trust-anchor rotation ceremony with rotation attestation (T-3). Ledger replicated across federation peers via existing `chio-anchor` lanes.
- DID-bound agent identity in receipts (T-9). `did:chio` already exists but isn't flowed into federation surface.

### Tier 3 — Frontier features (stretch buffet)

Pick 1-2 only if the recommended scope-lock lands fast. Listed here for catalog completeness; full descriptions in `BRAINSTORM-V1-FEATURE-CATALOG.md`.

| Tier-3 item | Effort | Lens |
|---|---|---|
| T3.1 Multi-modal receipt envelopes | XL | A-5 |
| T3.2 Agentic-deception detector (plan-vs-action diff) | L | A-4 |
| T3.3 Apple Secure Enclave kernel-key backend | M | H-1 |
| T3.4 RATS RFC 9334 evidence envelope | M | H-7 |
| T3.5 W3C trace propagation across kernel/federation/anchor | L | O-2 |
| T3.6 Streaming receipts | M | P-3 |
| T3.7 Structured-PII + Code-Secrets redactor packs | L+M | C-7+C-8 |
| T3.8 TransparencyLogReceiptExporter (Rekor-style) | L | C-13 |
| T3.9 Chaos-mesh experiment pack | L | O-7 |
| T3.10 Receipt-chain web explorer (full UI for `chio explain`) | L | DX-3 |
| T3.11 ML-shim PromptInjectionGuard | L | C-1 |
| T3.12 RAG citation attestation | L | A-6 |
| T3.13 Per-receipt output watermarking | L | A-7 |

## Recommended scope-lock (revised)

Per reviewer:

> "T0 hardening, T2.1 negotiation/versioning, T1.1 attenuation, T1.2 receipt DAG, T1.3 anchor batch, T1.4 archaeology, plus `chio explain` CLI. Then choose either SRE redaction/metrics or trust-graph quorum/rotation, not both, for the first trj4 close."

Concrete:

- **Tier 0** (full floor, 8-10 wk).
- **T1.0** (capability negotiation + token versioning, ~1 wk; the hinge).
- **T1.1** (macaroon attenuation, ~3 wk).
- **T1.2** (multi-agent receipt DAG with tightened formal model, ~2 wk).
- **T1.3** (anchor-batch Merkle trees, framed as additive, ~2 wk).
- **T1.4** (archaeology finish-line + cargo-vet debt close, ~2 wk).
- **T1.6** (`chio explain` CLI, ~1 wk).
- **One of**:
  - **T1.5** (foundational SRE: metric taxonomy + alert pack + log-redact), **OR**
  - **T2.3** (trust-graph maturity: quorum-signed receipts + trust-anchor rotation + DID-in-receipts).
- **T2.1** (hybrid PQ default + conformance-tier gating; small-effort plumbing).

Total estimated calendar: **12-15 weeks with two parallel lanes** (substrate-hardening + trust-primitives), **18-20 weeks single-track**.

T2.2 (hot-path verdict cache) and the unselected pick from {T1.5, T2.3} become **explicit stretch**; they ship if the first half lands cleanly, otherwise they slip to trj5.

## Trj4 close bar (revised for recommended scope)

All must hold simultaneously, evidenced in `releases.toml` and reproducible from a cold checkout.

**From the floor (Tier 0):**
1. CI-DEBT fully reconciled.
2. Hosted nightly cargo-mutants runs to completion; kill rate >= 65% per trust-boundary crate, >= 80% on `chio-attest-verify`.
3. 6/6 trust-boundary crates have Kani harnesses passing in nightly.
4. `RevocationCutCompleteness` transitive + `ReceiptBeforeAllow` split landed; `RevocationEventuallySeen` apalache lane back to required.
5. Equivalence property test passing 1M cases nightly, zero divergence.
6. `trust_control_cluster_multi_region_partition_qualification` 100/100 runs at 20 partition/heal cycles.
7. Mobile attestation entry points return real verdicts on real fixtures; xcframework binary in tree.
8. **Threat-model coverage at 20/20**: 6 stubs filled, 3 missing-`coveredBy` JSON links updated, 3 mobile threats covered.
9. `v3.18.1-trj3.1` tag shipped with green release-binaries + slsa + reproducible-build artifacts.
10. `TRAJECTORY-FINAL.md` committed with real close SHA.

**From multi-agent primitives (T1.0 + T1.1 + T1.2 + T1.3 + T1.4 + T1.6):**
11. `chio.capabilities.v1` capability-negotiation handshake live; peers advertise feature bitsets.
12. `CapabilityToken` schema-tagged; v2 envelope reserved fields shipped.
13. Macaroon-style typed caveats land; `CapabilityAttenuationGuard` enforces subset-of-parent at runtime.
14. `SubAgentBudgetPropagation` enforced at join, using fixed-point integer share units.
15. `call_chain` extended from tree to DAG with formal model: node IDs, parent-set hash, acyclicity invariant, canonical sort, replay rules. `chio.receipt_lineage_statement.v2` deployed.
16. Anchor-batch Merkle trees published with at least one witness lane (Rekor or OTS) — additive over per-receipt signing, not replacing it.
17. `chio-hosted-mcp` no longer `#[path]`-splices CLI internals.
18. Provider-adapter-core extracted; existing 7 adapters refactored to consume it.
19. **Cargo-vet exemption count**: no net-new exemptions added during trj4; top-50 dependency burn-down completed (target: 819 -> <= 769 exemptions).
20. `chio explain <receipt-id>` CLI ships and renders DAG + attenuation chain + batch witness + repair hint.

**From foundational improvements (T2.1 + chosen T1.5/T2.3):**
21. `KernelTrustExchange` generic over `SigningBackend`; hybrid PQ default in federation handshake.
22. Conformance-tier handshake gating live; tier derived from substrate evidence.

If T1.5 was chosen (instead of T2.3):

23a. `chio-metrics-spec` workspace-wide registry live; alert pack deployed.
24a. `chio-log-redact` enforces redaction at log layer with compile-time `redacted!()` macro.

If T2.3 was chosen (instead of T1.5):

23b. `QuorumSignedReceipt` generalizes `DualSignedReceipt`; threshold-policy verifier live.
24b. Trust-anchor rotation ceremony shipped with rotation attestation.
25b. `did:chio` flows into receipts; `agent_did` resolvable to `DidDocument`.

## Calendar (revised for recommended scope)

- **Reviewer-recommended scope (T0 + T1.0/1/2/3/4/6 + T2.1 + one of T1.5/T2.3)**: 12-15 weeks with two parallel lanes; 18-20 weeks single-track.
- **+ T2.2 (verdict cache + Tower shed)**: +2-3 weeks if profile (S-1) green-lights cache work.
- **+ T3 picks**: +3-6 weeks depending on item; treat as opt-in second half.

## What this synthesis explicitly cuts from any trj4 candidate list

- Vendor-calendar items (HITRUST, NCC/ToB, AWS Marketplace, MCP Registry publication).
- Design partner / customer outreach.
- Real partner cosign-OIDC sig (M02) — needs partner.
- TestFlight / mobile alpha cohorts.
- Multi-cloud marketplace listings.
- Operator agent that watches its own metrics and remediates (autonomous fail-open risk).
- AI-assisted policy authoring.
- ZK proofs of policy compliance (research spike, not trj4).
- Differential-privacy aggregate receipts (needs governance).
- CBOR/HTTP-3 native wire (would invalidate Lean+Kani lane).
- OCSP-shape revocation (already have the right answer with epoch+sparse-Merkle+gossip).
- Custom executor / replace tokio.
- SIMD canonical JSON.
- Intel SGX backend (deprecated 2022).
- DataDog dashboard pack.
- CAPTCHA bypass.
- Real-time semantic ML prompt-injection classifier in hot path.

See `REJECTED-IDEAS.md` for full rationale on each.
