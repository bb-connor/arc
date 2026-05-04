# Trajectory-4 Brainstorm v1: Feature Catalog

**Companion to** `SYNTHESIS-V1-INTERNAL-ONLY.md` (the substrate-hardening floor).

**Source**: 9 parallel brainstorm agents covering DX, perf/scale, capability-extension, protocol-evolution, AI-frontier, TEE/HW, trust-graph, observability/SRE, codebase-archaeology. All read-only; each ~700-900 words; per-proposal effort and impact ratings.

## Workspace ground truth (corrections from archaeology)

| Claim in prior planning | Actual |
|---|---|
| 119 workspace members | **89 chio-* crates** + xtask + bench/* + tests/* + formal/* + editors/zed-chio + 2 integrations + 7 examples |
| cargo-vet exemptions 26 -> 179 | **819** (767 safe-to-deploy + 52 safe-to-run) |
| Threat-model 17 of 17 covered | **11 of 17 covered, 6 unimplemented stubs** (capability_token_theft, audience_confusion, delegation_chain_abuse, kernel_impersonation, native_channel_replay, passkey_credential_theft, pq_signature_downgrade, resource_exhaustion_dos, tee_quote_forgery, tool_server_escape, weights_hash_spoof) |
| `crates/chio-tee/` is TEE attestation | **`chio-tee/` is the streaming-tap crate**; TEE attestation lives in `chio-attest-verify` (TDX + SEV-SNP + Nitro already implemented) |
| `chio-core` is the core crate | `chio-core` is a 12-line `pub use` umbrella; `chio-core-types` (35 KLOC, 112 in-tree dependents) is the real substrate |

## Cross-cutting convergence (consensus across lenses)

### 4-way consensus: macaroon-style capability attenuation

| Lens | Proposal |
|---|---|
| Capability-extension | #1 CapabilityAttenuationGuard with typed caveats |
| AI-frontier | #4 Macaroon-Shape Sub-Agent Capability Attenuation |
| Protocol-evolution | #2 Macaroon-style first-party caveats on capabilities |
| Trust-graph | P1 Scoped attenuated cross-org delegation tokens |

**This is the single strongest cross-cutting recommendation.** The substrate already has `caveats: Vec<String>` in chio-a2a-edge as a placeholder; the structure is acknowledged but unbuilt. Lifting it to typed caveats with first-party predicates and an `attenuation_proof` on capability tokens is the multi-agent safety keystone, the federation delegation primitive, the protocol forward-compat lever, and the runtime guard that prevents sub-agents from re-amplifying parent privileges.

### 2-way consensus: anchor-batch Merkle trees

| Lens | Proposal |
|---|---|
| Perf-scale | #2 Coalesced PQ signing with Merkle batching at receipt boundary |
| Protocol-evolution | #4 Anchor-batch Merkle trees with public-witness checkpoints |

Different motivations (CPU savings vs public non-repudiation) but the **same primitive**: a Merkle root over N receipts/checkpoints, signed once, with inclusion proof per element. The `chio-anchor` crate already has the merkle scaffolding for checkpoints (`bundle.rs`); mirroring it at the kernel signing boundary would address both.

### Other convergence threads

- **Hybrid PQ as plumbing, not invention**: `chio-core-types::pq::HybridSigningBackend` exists; `signature.v1.json` declares the wire format (`hybrid:<classical>:<mldsa65>:<alg_set>`); but `KernelTrustExchange` is hardcoded to `Ed25519Backend`. Trust-graph #P8 (S effort).
- **Workspace-public surfaces with no dependents**: `chio-tower` (2738 LOC), `chio-envoy-ext-authz` (1434 LOC), `chio-ag-ui-proxy` (830 LOC), `chio-openapi-mcp-bridge` (815 LOC) — archaeology #3 + DX (#5 publishable extensions). Either ship example wiring or demote.
- **The threat-model coverage gate is built but coverage is a lie**: archaeology + observability. Gate exists, stubs exist, schema exists; 6 of 17 threats remain `unimplemented!()`. Highest-leverage finishing move in the codebase.

## Feature catalog (organized by lens)

### Lens 1: Developer experience

**Top 3 bets** (per DX agent):
1. `chio explain <receipt-id>` + receipt-chain web explorer (★★★★★, M+L)
2. `chio init` interactive picker + verified golden-path templates (★★★★★, M)
3. In-process kernel for SDK tests + hot-reload `chio dev` loop (★★★★, M+L)

Other proposals: VSCode + Zed extension polish to publishable quality, `chio doctor` upgrade with `--fix` for safe repairs, SDK idiomatic-pass for Python+TypeScript first, error catalog with stable CHIO-EXXXX codes + repair hints, `chio diff` for policies/manifests/trust roots, deployable healthcare demo app, `chio trace` + OTel-receipts bridge.

Rejected: AI-assisted policy authoring (correctness too load-bearing), hosted dev sandbox (violates internal-only).

### Lens 2: Performance and scale

**Top 3 bets**:
1. Dispatch profile baseline + flame-graph CI artifact (★★★★★, S) — the dhat harness measures a placeholder, not the real path
2. Coalesced PQ signing with Merkle batching (★★★★★, L) — ML-DSA-65 sign cost ~200-400us; at 5k receipts/sec = ~2 cores burned on signing
3. Lock-free verdict cache on kernel hot path (★★★★, M) — bounded LRU keyed by (cap_hash, scope, tool, revocation_epoch); auto-invalidated on epoch change

Other: anchor publication aggregator with adaptive flush, TEE shared-memory zero-copy, revocation oracle sparse-Merkle delta (rs_merkle re-layer cost is O(n log n) per epoch at >1M keys), Tower load-shed middleware, per-tenant warm-ring autoscaling, differential perf fuzzing across kernel ports, sampling-aware OTEL exporter, receipt cold-tier with bloom-filter, continuous benchmark dashboard + budget gates.

Existing bottlenecks no one is addressing: no flame graph for `dispatch_allow`, PQ-signing CPU is uncosted, anchor publication latency unmeasured, Tower edge has no shed, TEE overhead unmeasured, sustained p99 nightly hasn't hit M06's required "seven consecutive greens".

Rejected: custom executor (M06 explicitly rejected), SIMD canonical JSON (M06 rejected; CanonicalBytes was the right abstraction).

### Lens 3: Capability extension

**Top 3 bets**:
1. CapabilityAttenuationGuard with typed caveats (★★★★★, L) — keystone; see convergence
2. Structured-PII (FHIR + ISO-20022 + GDPR) + Code-Secrets (gitleaks-equiv) redactor pack (★★★★, M+L) — table-stakes for regulated industries; additive RedactClass flags = zero protocol risk
3. TransparencyLogReceiptExporter (Rekor-style) (★★★★, L) — public verifiability of agent decisions; foundation already in tree

Other: ML-shim PromptInjectionGuard (classifier-backed; existing heuristic misses paraphrased/multilingual/encoded), AgentLoopBoundsGuard (depth/fanout/wallclock — top operational risk), SubAgentBudgetPropagation, McpToolNamespacePinningGuard (server_id+tool_id+manifest_hash binding), McpToolArgSchemaGuard, JailbreakPatternScanner with hot-reload corpus, RoleAndTenantPolicyConditions (`role_in:`, `tenant_quota:`, `geo_in:`), 4 more tool adapters (xAI Grok, DeepSeek, OpenRouter, Together), Bedrock IAM-principal scoped guards.

Rejected: ZK proofs (trj5+ research), differential-privacy aggregates (governance work outside code trajectory).

### Lens 4: Protocol evolution

**Top 3 bets**:
1. Capability-negotiation handshake `chio.capabilities.v1` (★★★★, S) — without it every additive proposal forces flag-day rollouts
2. CapabilityToken schema-tag + macaroon caveats (★★★★★, S+L) — the only un-schema-tagged signed artifact; blocks forward versioning
3. Anchor-batch Merkle trees with public-witness checkpoints (★★★★★, M) — closes `audit_only` / `transparency_preview` ceiling

Other: streaming receipts `chio.stream_receipt.v1`, branched lineage (multi-parent receipts), federation handshake hybrid PQ + SAS auth, verifier capability profiles, delegation attenuation proofs, redaction-preserving signatures (Merkle field commitments), hybrid logical clocks + clock attestation, threat-model schema v2 with structured `mitigations`.

Rejected: switching wire to CBOR/HTTP-3 (would invalidate Lean+Kani formal lane for marginal payoff), OCSP-shape revocation (already have CRL+epoch+sparse-Merkle+gossip = the right answer; OCSP adds online-availability dependency that fail-closed posture rejects).

### Lens 5: AI-frontier

**Top 4 "moves Chio from policy mediator to AI-trust infrastructure"**:
1. Multi-Modal Receipt Envelopes (★★★★★, XL) — agentic-browser/computer-use era differentiator; current ToolInvocation only has `arguments: Vec<u8>` for canonical JSON
2. Multi-Agent Receipt DAG with Fork/Join (★★★★★, L) — `call_chain` is a tree today; needs `fan_out_id`, `join_receipt_id`, `siblings[]`. Whoever standardizes this owns swarm-agent audit substrate
3. Agentic-Deception Detector via Plan-vs-Action Diff (★★★★★, L) — typed `stated_plan` envelope + guard; kernel uniquely has both stated plan and executed graph
4. Macaroon-Shape Sub-Agent Capability Attenuation (★★★★★, M) — see convergence

Other: prompt-injection heuristic guard tier (the missing kernel-side defender — arena adversary exists with no symmetric guard), RAG citation attestation, output watermarking (`H(receipt_id||agent_id||timestamp)`), cross-model lineage (token_range x model_card_id x weight_attestation_id), capability-aware least-privilege agent routing, capability-checked memory access (memory_provenance is append-only chain with unrestricted access today), marketplace v2 with conformance-attested agent definitions, tool-use chain "why-was-this-called" trace, agent reputation chain, adversarial-robustness conformance class (PCI-DSS levels for `prompt_injection_resistant_v1`), loop-detection on receipt DAG.

Rejected: CAPTCHA bypass (privacy/safety landmine), real-time semantic ML-PI classifier in hot path (violates `verdict_budget_ms` contract).

### Lens 6: TEE / hardware-attestation

**Critical correction**: TDX, SEV-SNP, and Nitro are already implemented in `chio-attest-verify` with `QuoteVerifier` trait + clean `report_data = SHA256(kernel_pk_hex || receipt_root)` binding + `non_exhaustive` `TeeKind`. **The trj4 floor's "TEE work" is mostly _new backends_, not the existing ones.**

**Top 3 bets**:
1. Apple Secure Enclave kernel-key backend (★★★★★, M) — desktop chio-cli users get hardware-rooted kernel signatures; `apple_root.rs` cert-pinning already there
2. Azure MAA + GCP Confidential Space bridges combined (★★★★, S) — both reduce to "verify a JWT then call existing SevSnpVerifier/TdxVerifier"
3. RATS RFC 9334 evidence envelope (★★★★, M) — locks in stable wire shape before more backends ship

Other: TPM 2.0 quote backend (self-hosted bare metal), Nitro PCR-set policy + freshness window (currently checks PCR0 only — closes a real gap), WebAuthn hardware-token claim binding (via existing `PasskeyVerifier`), attestation freshness oracle/cache (TDX collateral fetch is hundreds of ms), TEE breakage / generation-deny list (Sigstore-signed JSON), reproducible-build to TEE-measurement binding ("the running TEE is the SLSA-attested binary"), cross-cloud attestation router, NVIDIA H100 CC mode (XL effort, AI-positioning).

Rejected: Intel SGX backend (deprecated 2022), Confidential containers wrapper (deployment recipe, not new code).

### Lens 7: Trust-graph / federation

**Top 3 bets**:
1. M-of-N quorum-signed receipts (★★★★★, M) — generalize existing 2-of-2 `DualSignedReceipt` to `QuorumSignedReceipt { body, signatures, threshold }`. Bilateral becomes degenerate case; structure is 80% there
2. Scoped attenuated cross-org delegation tokens (★★★★★, M) — see convergence
3. Trust-anchor rotation ceremony with rotation attestation (★★★★★, L) — `KernelTrustExchange::with_trusted_peer` is set-once today; without rotation every federation eventually fails closed

Other: governance attestation onto trust graph (committee decisions as signed multi-party artifacts), conformance-tier handshake gating (S, data already exists), revocation gossip epidemic + pull-catchup hybrid (bilateral push is O(N^2) at federation scale), sealed-evidence transfer, hybrid PQ handshake by default (S, plumbing only), DID-bound agent identity in receipts (`did:chio` exists but isn't flowed into federation surface), cross-org receipt-chain forks/joins, reputation/trust score from signed evidence.

Rejected: reputation scores (becomes soft non-verifiable signal weaponized; defer until quorum+delegation land), cross-cloud anchor bridging (high engineering surface for marginal trust over existing per-lane anchoring).

### Lens 8: Observability / SRE / operability

**Top 3 bets**:
1. Workspace-wide metric taxonomy (`chio-metrics-spec`) + Prometheus alert pack combined (★★★★★, ~2wk) — turn slo.md from prose into enforced budget
2. W3C trace propagation across kernel/federation/anchor (★★★★★, ~3wk) — `gen_ai.tool.call` semconv locked but `traceparent`/`tracestate` not embedded
3. Compile-time log redaction layer `chio-log-redact` (★★★★★, ~1.5wk) — eliminates entire class of P0 (PHI in PagerDuty)

Other: deep-health endpoint with kernel-integrity probe, per-tenant rate limit + noisy-neighbor cap (kernel has no per-tenant quotas today), bench-regression hard threshold gate, chaos-mesh experiment pack (without it CLAUDE.md fail-closed property is theoretical), control-plane operational kill-switches with signed admin capability, profiling/flamegraph endpoint behind admin cap, dashboards-as-code expansion + linter, per-request cost attribution + tenant chargeback, receipt-archive hot/warm/cold tier mover (healthcare 6yr retention), synthetic probe daemon, DR drill harness with RTO/RPO assertion (RTO 15min, RPO 0).

Rejected: "operator agent that watches its own metrics and remediates" (autonomous fail-open from confused agent reasoning contradicts fail-closed invariant; **run remediation as deterministic policy, not an agent**), DataDog dashboard pack (already covered by Grafana/Tempo/Loki/Jaeger).

### Lens 9: Codebase archaeology

**Workspace shape**: 89 chio-* crates plus xtask, bench/*, tests/*, formal/*, editors/zed-chio, 2 integrations, 7 examples.

**Top 5 "finish what we started"**:
1. **Threat-model coverage push** — 6 stubs left; codegen + CI gate is built. One focused week unlocks "100% threat-model coverage" claim.
2. **Provider-adapter-core extraction** — cuts ~3 KLOC of duplication across 7 adapters; makes 8th adapter a 1-day job. Pattern is implicit (5 adapters share `loaded_weights.rs` to within whitespace) but never crystallized.
3. **`chio-hosted-mcp` real extraction** — half-day surgical. Today a workspace public entrypoint (in `[workspace.metadata.chio.rust_public_entrypoints]`) is structurally a 13-line `#[path]` splice of CLI internals.
4. **`chio-tower` example/integration** — 2738 LOC of Tower middleware with zero workspace consumers.
5. **`chio-mercury-core` test backfill** — 9363 LOC src / 14 LOC tests; this is Mercury's product spine.

**Top 3 deprecation candidates**:
1. The `chio-core` umbrella — rename `chio-core-types` -> `chio-core` and dissolve the umbrella (consumers transit through `chio-core-types` already)
2. `chio-spec-validate` as workspace member — single consumer (xtask); convert to xtask sub-bin
3. `#[deprecated]` `handle_send_message` / `handle_jsonrpc` aliases on `chio-a2a-edge`

**Other findings**: 819 cargo-vet exemptions (vs claimed 179), 62 of 89 crates have no README, `// SECTION:` marker convention is referenced in conventions but appears nowhere, 8 large domain crates have token integration tests (chio-mercury-core 9363/14 worst, chio-link 3569/31, chio-autonomy 2193/26, chio-appraisal 4092/21, chio-governance 1770/18), `chio-anchor` gated behind default-on `web3` feature flag (turning off yields empty crate), `chio-cli` is 81 KLOC and growing (passport*, certify, evidence_export look like a `chio-attestation-export` crate waiting to happen), `unsafe` blocks concentrated in 4 crates and well-reasoned but many lack canonical SAFETY blocks, stale ARC residue in docs/research/ filenames, `println!`/`eprintln!` in 9 production crates (chio-guards and chio-anchor hits suggest library-side I/O leakage), `integrations/aws-bedrock/control-plane/` lives outside `crates/` despite `chio-*` naming.

**3 surprising patterns**:
1. The "core" crate is empty. Naming inverts what newcomers expect; the 25-hour trj1-3 grind clearly involved an in-progress extraction that never completed cleanup.
2. The "tools-adapter" pattern is implicit, not codified. Seven crates follow `{lib, native, transport, streaming, loaded_weights}.rs` to the file. Single biggest "we already half-built X" opportunity in the repo.
3. The threat-model codegen gate exists, the stubs exist, the schema exists, and 6 of 17 threats are still `unimplemented!()`. Highest-leverage finishing move; CI gate already enforces it.
