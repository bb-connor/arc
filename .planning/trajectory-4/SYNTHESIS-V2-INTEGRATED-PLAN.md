# Trajectory-4 Synthesis v2 — Integrated Plan

**Status**: working integration of `SYNTHESIS-V1-INTERNAL-ONLY.md` (substrate-hardening floor) and `BRAINSTORM-V1-FEATURE-CATALOG.md` (9-lens feature brainstorm). Pending scope-lock decision.

## Scope rule (unchanged from v1)

Trajectory-4 is internal-only code work. Out of scope: design partners, vendor crypto review, HITRUST audit, AWS Marketplace publication, MCP Registry publication, real partner cosign-OIDC sig (M02), 30-day pilot. These remain in `CLOSEOUT-BLOCKERS.md` for a later trajectory.

## Theme

**Multi-agent trust primitives, with substrate hardening as the floor.**

The 9-lens brainstorm produced one strong cross-cutting consensus and one subordinate one:

1. **4-way consensus**: macaroon-style capability attenuation. Capability-extension #1, AI-frontier #4, protocol-evolution #2, trust-graph P1 — four independent lenses converged on the same primitive. The substrate already has `caveats: Vec<String>` placeholders in `chio-a2a-edge`; the structure is acknowledged but unbuilt.
2. **2-way consensus**: anchor-batch Merkle trees. Perf-scale #2 (CPU savings) and protocol-evolution #4 (public non-repudiation) want the same primitive for different reasons.

These two combine naturally with the floor's mobile-attestation work to produce a coherent trajectory-4 narrative: **the trust boundary becomes multi-agent-aware, hardware-rooted, and publicly anchorable**.

## Tiered scope

The plan has three tiers. Scope-lock decision picks the boundary; each tier compounds on the prior.

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
- Threat-coverage flip for `mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay`.

**Phase D (W8-10): meta-improvements**
- Threat-coverage cargo-mutants per-row gate.
- Feature archeology: identify zero-pull crates / SDKs / adapters. Deprecate or document.
- Fail-closed philosophy audit doc.
- CI-DEBT.md final pass.

### Tier 1 — Multi-agent trust primitives (4-6 additional weeks; the consensus moves)

The 4-way macaroon consensus, the 2-way anchor-batch consensus, plus the highest-leverage archaeology and SRE moves. Targeted additions; each pulls weight in multiple lenses simultaneously.

**T1.1 Macaroon capability attenuation, end to end (~3 weeks)**
- `CapabilityToken` schema-tag (`chio.capability.v1`) — closes the only un-schema-tagged signed artifact (protocol-evolution #1, S effort).
- Capability caveats with typed first-party predicates (protocol-evolution #2, capability-extension #1).
- `attenuation_proof: { parent_scope_hash, child_scope_hash, normalized_subset_proof }` embedded in capability so verifiers skip scope normalization (protocol-evolution #8).
- `CapabilityAttenuationGuard` enforcing subset-of-parent at runtime (capability-extension #1).
- `chio-federation::delegation::issue_token` / `verify_chain` for cross-org scoped delegation (trust-graph P1).
- `SubAgentBudgetPropagation`: `BudgetSplit::PerChildShare(f32)` carried in child receipts; verified at join (capability-extension #4).

Result: sub-agents cannot re-amplify parent privileges; multi-org delegation is short-lived/scoped/revocable; verifiers have a witness instead of having to re-derive.

**T1.2 Multi-agent receipt DAG with fork/join (~2 weeks)**
- Extend `call_chain` from tree to DAG: `fan_out_id`, `join_receipt_id`, `siblings: Vec<ReceiptRef>` in receipt metadata (AI-frontier #1).
- Multi-parent `parent_receipt_ids: Vec<String>` in `chio.receipt_lineage_statement.v2` (protocol-evolution #5).
- Loop-detection via sliding `recent_chain_signatures` set in call-chain envelope; sub-agent request normalizing to a previously-issued signature in this DAG fails closed (AI-frontier #15).

**T1.3 Anchor-batch Merkle trees with public-witness checkpoints (~2 weeks)**
- Coalesced PQ signing: build a Merkle tree over N receipts, sign once, attach inclusion proof per receipt (perf-scale #2). Mirrors the existing `chio-anchor` checkpoint shape.
- New artifact `chio.anchor_batch.v1` carrying `{tree_root, checkpoint_ids[], witness: rekor|ots|solana_memo}` (protocol-evolution #4).
- Closes the `audit_only` / `transparency_preview` ceiling explicitly admitted in PROTOCOL.md:657.

**T1.4 Archaeology finish-line (~2 weeks parallelizable)**
- Threat-model coverage push: fill the 6 remaining `unimplemented!()` stubs (`capability_token_theft`, `audience_confusion`, `delegation_chain_abuse`, `kernel_impersonation`, `native_channel_replay`, `passkey_credential_theft`, `pq_signature_downgrade`, `resource_exhaustion_dos`, `tee_quote_forgery`, `tool_server_escape`, `weights_hash_spoof`). Codegen + gate are already built; this is the cheapest "100% threat coverage" claim available.
- `chio-hosted-mcp` real extraction: lift `remote_mcp/*.rs` into its own crate; both CLI and chio-hosted-mcp consume it normally. Half-day surgical fix to a workspace-public entrypoint that's currently a `#[path]` splice of CLI internals.
- Provider-adapter-core extraction: shared SSE-gate orchestration + `LoadedWeights` impl helper + `Provider` trait. Cuts ~3 KLOC across 7 adapters; makes the 8th adapter (xAI / DeepSeek / OpenRouter / Together) a 1-day job.

**T1.5 Foundational SRE (~3 weeks parallelizable)**
- `chio-metrics-spec` workspace-wide const-string registry. Compile-time enforced via `describe!` macro + CI golden snapshot.
- Prometheus alert + recording rule pack in `deploy/prometheus/`. Burn-rate alerts (14.4x/1h + 6x/6h dual-window per Google SRE workbook) for slo.md targets. Routes to OpsGenie/PagerDuty already wired in `chio-siem`.
- `chio-log-redact`: `tracing_subscriber::Layer` running every event through receipt's redaction tree. `redacted!()` macro rejects raw-string formatting. Eliminates an entire class of P0 (PHI in PagerDuty).

### Tier 2 — Foundational improvements (2-4 additional weeks; high-leverage low-effort wins)

**T2.1 Trust-boundary plumbing**
- Hybrid PQ handshake by default: make `KernelTrustExchange` generic over `SigningBackend`. Plumbing only; `HybridSigningBackend` already exists. Trust-graph #P8 (S effort).
- Capability-negotiation handshake `chio.capabilities.v1`: peer advertises feature bitset; without it every additive proposal forces flag-day rollouts (protocol-evolution #11, S effort).
- Conformance-tier handshake gating (`Bronze/Silver/Gold`): derived from threat-coverage + mutation-kill + Kani harness completeness. Data already produced; bind into peer record (trust-graph #P5, S effort).

**T2.2 Mediator hot path**
- Dispatch profile baseline + flame-graph CI artifact (perf-scale #1, S). Solves "we claim a <50us SLO without a profile that proves where time is spent."
- Lock-free verdict cache on kernel hot path: bounded LRU keyed by `(cap_hash, scope, tool, revocation_epoch)`; auto-invalidated on epoch change. Targets <5us p99 on hit (perf-scale #3, M).
- Tower load-shed middleware. `tower::LoadShed` + `tower::ConcurrencyLimit`. Translates the bounded signing queue into 503 + Retry-After at the HTTP edge (perf-scale #7, S).

**T2.3 Trust-graph maturity**
- M-of-N quorum-signed receipts: generalize `DualSignedReceipt` (2-of-2) to `QuorumSignedReceipt { body, signatures, threshold }`. Bilateral becomes a degenerate case (trust-graph P2, M).
- Trust-anchor rotation ceremony with rotation attestation. Ledger replicated across federation peers via existing `chio-anchor` lanes (trust-graph P3, L).
- DID-bound agent identity in receipts. `did:chio` already exists but isn't flowed into federation surface (trust-graph P9, M).

### Tier 3 — Frontier features (stretch; 6+ additional weeks)

Pick 1-2 only if Tier 0+1+2 lands in <14 weeks total.

**T3.1 Multi-modal receipt envelopes** (XL effort)
Browser/computer-use era differentiator. `ToolInvocation::arguments_blob_ref` and `tool_output_blob_ref` with content-addressed hash + per-receipt redaction at vision layer. Receipt commits to post-redaction blob hash; unredacted blob in sealed lane. Ties to AI-frontier #5.

**T3.2 Agentic-deception detector (plan-vs-action diff)** (L effort)
Typed `stated_plan` envelope (`chio.plan_statement.v1`) + guard that diffs against receipt DAG of same `chain_id`. Research-frontier (sleeper-agents, scheming evals); kernel uniquely positioned because it has both stated plan and executed graph. Ties to AI-frontier #4.

**T3.3 Apple Secure Enclave kernel-key backend** (M effort)
Desktop chio-cli users get hardware-rooted kernel signatures via SEP. `apple_root.rs` cert-pinning already there from App Attest. Mirrors the trj4 mobile floor. Ties to TEE #1.

**T3.4 RATS RFC 9334 evidence envelope** (M effort)
EAT-shaped JSON/CBOR carrier across TDX/SEV-SNP/Nitro/TPM/Azure-MAA. Verifier dispatches on `eat_profile`. Locks in stable wire shape before more backends ship. Ties to TEE #7.

**T3.5 W3C trace propagation across kernel/federation/anchor** (L effort)
`chio-trace` crate wrapping `opentelemetry::propagation::TraceContextPropagator`; embeds `traceparent` in receipt headers (signed but not authenticated like AWS X-Amzn-Trace-Id); passes through federation hops. Production at scale without distributed traces is debugging-blind.

**T3.6 Streaming receipts** (M effort)
`chio.stream_receipt.v1` — emit alongside terminal `ChioReceipt` keyed by `request_id`. Long-running tools / SSE flows have no signed mid-stream evidence today.

**T3.7 Structured-PII redactor pack (FHIR + ISO-20022 + GDPR Art. 9)** (L effort) **and Code-Secrets pack (gitleaks-equivalent)** (M effort)
Table-stakes for regulated industries. Additive `RedactClass` flags; zero protocol risk. Default redactor catches AWS/Stripe/JWT but not GitHub PATs, Slack, Azure SAS, Anthropic `sk-ant-*`, OpenAI keys.

**T3.8 TransparencyLogReceiptExporter (Rekor-style)** (L effort)
Append-only public log of redacted receipts. Foundation (sigstore client + receipt canonicalization + redaction manifest) already in tree. No competitor offers this.

**T3.9 Chaos-mesh experiment pack** (L effort)
Three failure domains: anchor partition, federation-hop latency injection, receipt-store disk-fill. Without it the fail-closed property in CLAUDE.md is theoretical.

**T3.10 `chio explain <receipt-id>` + receipt-chain web explorer** (L effort)
Receipts are Chio's identity; making them legible turns the moat into a feature integrators love. Single command replaces 80% of "why did my call fail" Slack threads.

## Recommended scope-lock

**Tier 0 + Tier 1 + Tier 2 = 14-18 weeks, single-track.** Can compress to 12-14 weeks with parallel lanes (substrate hardening + mobile attestation + macaroon + archaeology can each run with non-overlapping ownership).

This scope:
- Closes the substrate-hardening floor (engineer-rigor + security debate winners).
- Builds out the multi-agent trust primitives the 4-way brainstorm consensus identified as missing.
- Lands the 2-way anchor-batch consensus that compounds CPU savings + public non-repudiation.
- Finishes the highest-leverage archaeology bets (threat-model coverage, hosted-mcp, provider-adapter-core).
- Establishes operational floor (metric taxonomy + alert pack + compile-time log redaction).
- Plumbs hybrid PQ + capability negotiation as forward-compat infrastructure for future trajectories.

Tier 3 items pull from a buffet for the second half of the trajectory if Tier 0+1+2 lands fast. Pick 1-2 max; do not attempt all.

## Trj4 close bar (Tier 0+1+2)

All must hold simultaneously, evidenced in `releases.toml` and reproducible from a cold checkout:

**From the floor (Tier 0):**
1. CI-DEBT fully reconciled.
2. Hosted nightly cargo-mutants runs to completion; kill rate >= 65% per trust-boundary crate, >= 80% on `chio-attest-verify`.
3. 6/6 trust-boundary crates have Kani harnesses passing in nightly.
4. `RevocationCutCompleteness` transitive + `ReceiptBeforeAllow` split landed; `RevocationEventuallySeen` apalache lane back to required.
5. Equivalence property test passing 1M cases nightly, zero divergence.
6. `trust_control_cluster_multi_region_partition_qualification` 100/100 runs at 20 partition/heal cycles.
7. Mobile attestation entry points return real verdicts on real fixtures; xcframework binary in tree.
8. 3 mobile threats back to `covered` with real test backing.
9. `v3.18.1-trj3.1` tag shipped with green release-binaries + slsa + reproducible-build artifacts.
10. `TRAJECTORY-FINAL.md` committed with real close SHA.

**From multi-agent primitives (Tier 1):**
11. `CapabilityToken` schema-tagged; macaroon-style typed caveats land; `CapabilityAttenuationGuard` enforces subset-of-parent at runtime.
12. `SubAgentBudgetPropagation` enforced at join.
13. `call_chain` extended from tree to DAG; multi-parent receipt lineage land in protocol; loop-detection guard live.
14. Anchor-batch Merkle trees published with at least one witness lane (Rekor or OTS).
15. All 17 threat-model conformance tests pass (no remaining `unimplemented!()` stubs).
16. `chio-hosted-mcp` no longer `#[path]`-splices CLI internals.
17. Provider-adapter-core extracted; existing 7 adapters refactored to consume it.
18. `chio-metrics-spec` workspace-wide registry live; alert pack deployed; `chio-log-redact` enforces redaction at log layer.

**From foundational improvements (Tier 2):**
19. `KernelTrustExchange` generic over `SigningBackend`; hybrid PQ default in federation handshake.
20. `chio.capabilities.v1` capability-negotiation handshake live; peers advertise feature bitsets.
21. Conformance-tier handshake gating live; tier derived from substrate evidence.
22. Dispatch flame-graph baseline captured; top-5 frames named in `releases.toml`.
23. Verdict cache on kernel hot path live; cache-hit p99 <5us measured.
24. Tower edge load-shed live; soak test at 2x SLO load shows zero connection-pool exhaustion.
25. `QuorumSignedReceipt` generalizes bilateral; trust-anchor rotation ceremony shipped with rotation attestation.

## Calendar

- **Tier 0 only**: 8-10 weeks single-track.
- **Tier 0 + Tier 1**: 12-14 weeks with substrate-hardening and feature lanes parallelized.
- **Tier 0 + Tier 1 + Tier 2**: 14-18 weeks with three lanes parallel.
- **Tier 0 + Tier 1 + Tier 2 + 1-2 Tier 3 items**: 18-22 weeks; treat Tier 3 as opt-in second half.

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
