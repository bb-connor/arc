# Post-v3.18 Execution Tracker

> **Date**: 2026-04-18
> **Status**: Proposed active execution tracker
> **Scope**: Repo-solvable vision closure after `v3.18`
> **Execution principle**: Runtime truth first. Release-truth cleanup last.
> **Primary sources**:
> - `docs/POST_ROADMAP_ADDENDUM.md`
> - `docs/review/01-formal-verification-remediation.md`
> - `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`
> - `.planning/PROJECT.md`
> - `.planning/STATE.md`

---

## Goal

Turn the post-`v3.18` repo into the strongest working Chio system the current
codebase can support without letting README and release cleanup displace the
runtime work itself.

This tracker is execution-first:

- close authority and budget truth first
- harden hosted and transport semantics next
- wire the missing guard and policy surfaces into the real runtime
- prove portability and economic truth on top of the hardened base
- finish with verified-core and release-gate alignment

---

## Program Rules

- Run one orchestrator plus nine specialist pods.
- Cap normal concurrent writing pods at `4`.
- Burst to `6` only when write sets are disjoint and one pod is reserved for
  integration.
- Do not run overlapping tickets against
  `crates/chio-cli/src/trust_control/cluster_and_reports.rs`,
  `crates/chio-cli/src/trust_control/service_types.rs`, or
  `crates/chio-store-sqlite/src/budget_store.rs` in parallel.
- Economic completion stays downstream of authority fencing and budget truth.
- Claim-discipline and README sync stay in the final stabilization wave.
- Each wave exits only when its gate is green, not when its tickets are merely
  "mostly implemented."

---

## Subagent Pods

| Pod | Focus | Primary write set | Notes |
| --- | --- | --- | --- |
| `P1-authority` | authority custody, node identity, stale-leader fencing | `crates/chio-kernel/src/authority.rs`, `crates/chio-store-sqlite/src/authority.rs`, `crates/chio-cli/src/trust_control/{cluster_and_reports.rs,service_types.rs,http_handlers_a.rs,http_handlers_b.rs}` | Serial with `P2-budget` on shared trust-control files |
| `P2-budget` | budget truth, replay safety, HA qualification | `crates/chio-kernel/src/budget_store.rs`, `crates/chio-store-sqlite/src/budget_store.rs`, `crates/chio-cli/tests/trust_cluster.rs`, `docs/release/QUALIFICATION.md` | Starts after leader-fencing contract is stable |
| `P3-hosted` | hosted MCP lifecycle, reconnect, shared-owner, async parity | `crates/chio-hosted-mcp`, `crates/chio-mcp-edge`, `crates/chio-a2a-edge`, `crates/chio-acp-edge`, `crates/chio-cross-protocol`, transport tests | Can overlap with `P4-boundary` after request boundary freezes |
| `P4-boundary` | receipt verify-on-ingest, tenant isolation, model metadata provenance | `crates/chio-kernel`, `crates/chio-store-sqlite`, `crates/chio-http-core`, `crates/chio-cross-protocol` | Avoid parallel edits to the same receipt/query files |
| `P5-guards` | data guards, result guards, external guards, policy loader parity | `crates/chio-data-guards`, `crates/chio-external-guards`, `crates/chio-policy`, `crates/chio-kernel`, `crates/chio-wasm-guards` | Can overlap with `P6-adoption` |
| `P6-adoption` | front-door docs, quickstarts, canonical user path, package guides | `README.md`, `docs/`, example apps, package READMEs | Start only after runtime surfaces stop moving daily |
| `P7-portable` | `chio-kernel-core`, no_std blockers, wasm/browser/mobile qualification | `crates/chio-kernel-core`, `crates/chio-kernel-browser`, `crates/chio-kernel-mobile`, `crates/chio-core-types`, CI workflows | Largely disjoint from economics and guards |
| `P8-econ` | economic envelope, settlement truth, reporting truth, risk flow | `crates/chio-core-types`, `crates/chio-kernel`, `crates/chio-store-sqlite`, operator/reporting docs | Starts only after `P2-budget` is green |
| `P9-formal` | verified-core boundary, theorem inventory, claim registry, refinement hooks | `formal/lean4`, `spec/PROTOCOL.md`, `scripts/check-formal-proofs.sh`, CI workflows, proof docs | Final stabilization pod with `P6-adoption` support |

---

## Wave Map

| Wave | Goal | Active pods | Entry gate | Exit gate |
| --- | --- | --- | --- | --- |
| `W1` | authority custody and leader fencing | `P1-authority`, `P2-budget` | tracker accepted | authority seed material is off the cluster snapshot path and stale-leader writes fail closed |
| `W2` | budget truth and request-boundary hardening | `P2-budget`, `P4-boundary` | `W1` authority contract frozen | event-derived HA budget truth, verified receipt-store boundaries, and strict tenant defaults are in place |
| `W3` | hosted runtime semantics and transport parity | `P3-hosted`, `P4-boundary` | `W2` boundary semantics stable | reconnect/resume, GET/SSE, shared-owner, async parity, and model metadata provenance all qualify together |
| `W4` | guard/runtime wiring and front-door simplification | `P5-guards`, `P6-adoption` | `W2` and late `W3` surfaces stable | all shipped guard surfaces are reachable through the supported path and the top-level user path is coherent |
| `W5` | portability proof and economic truth | `P7-portable`, `P8-econ` | `W2` trust semantics green | real `wasm32` proof exists and one canonical economic flow is truthful end to end |
| `W6` | verified-core and release gates | `P9-formal`, `P6-adoption` | `W3` through `W5` largely green | verified-core boundary, claim registry, theorem inventory, and final release-truth gate all align |

---

## Ticket Board

### W1: Authority Custody And Leader Fencing

| Ticket | Title | Pod | Depends on | Primary write set | Acceptance gate | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `TC-21A1` | Evict private seed from cluster snapshots | `P1-authority` | none | `crates/chio-kernel/src/authority.rs`, `crates/chio-store-sqlite/src/authority.rs`, `crates/chio-cli/src/trust_control/{service_types.rs,cluster_and_reports.rs}` | internal snapshots and `/v1/internal/*` authority paths no longer serialize `seed_hex` on the authoritative path | `done` |
| `TC-21B1` | Harden budget mutation idempotency and lease checks | `P2-budget` | none | `crates/chio-kernel/src/budget_store.rs`, `crates/chio-store-sqlite/src/budget_store.rs` | duplicate `event_id`, divergent reuse, and stale or missing `lease_epoch` all fail closed | `done` |
| `TC-21A2` | Replace shared bearer cluster auth with node identity | `P1-authority` | `TC-21A1` | `crates/chio-cli/src/trust_control/{service_types.rs,cluster_and_reports.rs,http_handlers_b.rs,service_runtime.rs}` | internal trust-control endpoints require authenticated node identity and peer allowlisting, not one shared bearer token | `done` |
| `TC-21A3` | Fence authority mutations with persistent term or epoch | `P1-authority` | `TC-21A2` | `crates/chio-cli/src/trust_control/{http_handlers_a.rs,cluster_and_reports.rs,service_types.rs}`, `crates/chio-store-sqlite/src/authority.rs`, cluster tests | authority epoch survives restart and stale leaders fail closed on rotate or issue after supersession | `done` |

**Wave parallel batches**

| Batch | Tickets | Notes |
| --- | --- | --- |
| `W1-A` | `TC-21A1`, `TC-21B1` | Safe parallel pair: authority custody files vs budget-store files |
| `W1-B` | `TC-21A2` | Freeze node-authenticated internal API next |
| `W1-C` | `TC-21A3` | Persistent term or epoch fencing is the wave exit gate |

### W2: Budget Truth, Qualification, And Request-Boundary Hardening

| Ticket | Title | Pod | Depends on | Primary write set | Acceptance gate | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `TC-21B2` | Make HA budget truth event-derived | `P2-budget` | `TC-21A3`, `TC-21B1` | `crates/chio-cli/src/trust_control/{cluster_and_reports.rs,http_handlers_b.rs,service_runtime.rs}`, `crates/chio-store-sqlite/src/budget_store.rs`, cluster tests | authoritative cluster reconstruction is event-derived and `upsert_usage` is projection only, not money truth | `done` |
| `TC-21C1` | Add trust-control authoritative qualification gate | `P2-budget` | `TC-21A3`, `TC-21B2` | `scripts/qualify-release.sh`, new `scripts/qualify-trust-control.sh`, `docs/release/{QUALIFICATION.md,RELEASE_AUDIT.md,OPERATIONS_RUNBOOK.md}`, `crates/chio-cli/tests/` | one command emits evidence for node identity, stale-leader fencing, duplicate-event rejection, stale-lease rejection, replay, and failover preservation | `done` |
| `RTC-05` | Verify receipts before SQLite insert | `P4-boundary` | none | `crates/chio-store-sqlite/src/receipt_store/{evidence_retention.rs,support.rs,tests.rs}` | tool and child receipts are signature and hash verified before persistence | `done` |
| `RTC-06` | Verify persisted receipts before export, report, or replay use | `P4-boundary` | `RTC-05` | `crates/chio-store-sqlite/src/{evidence_export.rs,receipt_store/evidence_retention.rs,receipt_store/reports.rs,receipt_store/bootstrap.rs}`, `crates/chio-cli/src/evidence_export.rs`, export tests | corrupt persisted receipts fail with receipt and seq context before export, report, or replay | `done` |
| `RTC-07` | Turn strict tenant isolation on by default | `P4-boundary` | none | `crates/chio-store-sqlite/src/{receipt_store/bootstrap.rs,receipt_store.rs,receipt_store/evidence_retention.rs}`, `crates/chio-store-sqlite/tests/tenant_isolation.rs` | exact-tenant filtering is default and `tenant_id IS NULL` compatibility becomes explicit opt-out behavior | `done` |

**Wave parallel batches**

| Batch | Tickets | Notes |
| --- | --- | --- |
| `W2-A` | `TC-21B2`, `RTC-05`, `RTC-07` | Event-derived budget truth beside clean store write-path and tenant-default work |
| `W2-B` | `TC-21C1`, `RTC-06` | Qualification after event semantics; store read/export verification after insert verification |

### W3: Hosted Runtime Semantics And Transport Parity

| Ticket | Title | Pod | Depends on | Primary write set | Acceptance gate | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `RTC-03` | Isolate shared-owner notifications by session | `P3-hosted` | none | `crates/chio-cli/src/remote_mcp/{session_core.rs,admin.rs}`, `crates/chio-mcp-edge/src/runtime.rs`, `crates/chio-cli/tests/mcp_serve_http.rs` | shared-owner mode no longer fans upstream notifications to every subscriber | `done` |
| `RTC-01` | Make hosted ready sessions restart-resumable | `P3-hosted` | none | `crates/chio-cli/src/remote_mcp/{session_core.rs,http_service.rs,admin.rs}`, `crates/chio-cli/tests/mcp_serve_http.rs` | a `ready` session survives process restart and resumes authenticated traffic without falling back to `404 unknown MCP session` | `done` |
| `RTC-02` | Freeze GET, POST, SSE compatibility and replay contract | `P3-hosted` | `RTC-01` | `crates/chio-cli/src/remote_mcp/{http_service.rs,oauth.rs}`, `crates/chio-cli/tests/mcp_serve_http.rs`, `crates/chio-hosted-mcp/tests/error_contract.rs` | GET and POST response modes are explicit, replay is deterministic, and late notifications are delivered once | `done` |
| `RTC-04` | Lock async semantics across in-process, stdio, and HTTP | `P3-hosted` | `RTC-02` | `crates/chio-mcp-edge/src/runtime{,/protocol.rs,/runtime_tests.rs}`, `crates/chio-mcp-adapter/src/transport.rs`, hosted tests | task creation, cancellation, late completion, and notification ordering are equivalent across all transports | `done` |
| `RTC-08` | Preserve `model_metadata` provenance on the session and runtime path | `P4-boundary` | `RTC-04` | `crates/chio-core-types/src/{session.rs,receipt.rs}`, `crates/chio-mcp-edge/src/runtime{,/protocol.rs,/runtime_tests.rs}`, `crates/chio-kernel/src/request_matching.rs` | session-originated calls carry `model_metadata` end to end with a provenance class such as asserted vs verified | `done` |

**Wave parallel batches**

| Batch | Tickets | Notes |
| --- | --- | --- |
| `W3-A` | `RTC-03`, `RTC-01` | Hosted session work is serial on `session_core.rs`; treat as one lane |
| `W3-B` | `RTC-02` | Freeze replay and response-mode contract before parity work |
| `W3-C` | `RTC-04` | Gate the hosted wave on transport parity, not feature presence |
| `W3-D` | `RTC-08` | Carry model metadata end to end only after runtime semantics are stable |

### W4: Guard Wiring And Front-Door Simplification

| Ticket | Title | Pod | Depends on | Primary write set | Acceptance gate | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `GRW-01` | Add scope-aware post-invocation hook context | `P5-guards` | none | `crates/chio-kernel/src/{post_invocation.rs,kernel/responses.rs,kernel/mod.rs,lib.rs}`, `crates/chio-data-guards/src/result_guard.rs` | post-invocation hooks receive request identity plus effective scope or matched grant | `done` |
| `GRW-03` | Close HushSpec vs Chio YAML parity on the overlapping guard surface | `P5-guards` | none | `crates/chio-cli/src/policy.rs`, `crates/chio-cli/src/cli/session.rs`, parity fixtures | equivalent HushSpec and Chio YAML fixtures produce the same runtime guard list and default capability constraints | `done` |
| `GRW-06` | Compile HushSpec `threat_intel` into a real runtime guard | `P5-guards` | none | `crates/chio-policy/src/{compiler.rs,models.rs,validate.rs}`, `crates/chio-cli/src/cli/session.rs` | `pattern_db`, `similarity_threshold`, and `top_k` materialize a concrete runtime guard | `done` |
| `GRW-02` | Wire `chio-data-guards` into Chio YAML startup and runtime loading | `P5-guards` | `GRW-01` | `crates/chio-cli/Cargo.toml`, `crates/chio-control-plane/Cargo.toml`, `crates/chio-cli/src/{policy.rs,cli/session.rs}` | Chio YAML can configure SQL, vector, warehouse, and result guards through `load_policy()` and `build_kernel()` | `done` |
| `GRW-04` | Make content-safety guards reachable at runtime | `P5-guards` | `GRW-03` | `crates/chio-cli/src/{policy.rs,cli/session.rs}`, `crates/chio-kernel/src/request_matching.rs`, `crates/chio-guards/src/content_review.rs` | `ContentReviewGuard` is instantiable and `Constraint::ContentReviewTier` no longer dead-ends at request matching | `done` |
| `GRW-05` | Wire the first `chio-external-guards` slice into policy loading | `P5-guards` | `GRW-03`, `GRW-04` recommended | `crates/chio-cli/Cargo.toml`, `crates/chio-control-plane/Cargo.toml`, `crates/chio-cli/src/{policy.rs,cli/session.rs}`, `crates/chio-external-guards/src/lib.rs` | at least one cloud content-safety provider and one threat-intel provider load through `AsyncGuardAdapter` and fail closed on bad config | `done` |
| `DIST-01` | Align public distribution coordinates and install docs | `P6-adoption` | none | `README.md`, `Homebrew/arc.rb.tmpl`, `docs/install/*`, `.github/workflows/{release-binaries.yml,sidecar-image.yml}` | one canonical GitHub repo or org and one GHCR naming scheme are used everywhere | `done` |
| `CA-01` | Canonical coding-agent quickstart | `P6-adoption` | `DIST-01` | `docs/guides/MIGRATING-FROM-MCP.md`, `docs/NATIVE_ADOPTION_GUIDE.md`, `crates/chio-cli/templates/init/README.md.tmpl`, `examples/policies/canonical-hushspec.yaml` | one 5-10 minute coding-agent path shows deny, allow, and receipt inspection on the supported stack | `done` |
| `WEB-01` | Canonical web-backend path | `P6-adoption` | `DIST-01` | `docs/guides/WEB_BACKEND_QUICKSTART.md`, `examples/hello-openapi-sidecar/README.md`, `examples/hello-fastapi/README.md`, `examples/{README.md,EXAMPLE_SURFACE_MATRIX.md}` | docs clearly say sidecar first and FastAPI second, with one consistent verify flow | `done` |
| `RS-01` | Curate the public Rust entrypoint crates | `P6-adoption` | none | `Cargo.toml`, public crate `Cargo.toml` files, new crate READMEs | the workspace has a deliberate public-crate allowlist and each public crate has real crate README metadata | `done` |
| `PKG-01` | Add package-local quickstarts for primary web SDK packages | `P6-adoption` | `WEB-01`, `DIST-01` | primary Python and TypeScript SDK `README.md` files plus package metadata | every primary SDK package has install steps, a runnable quickstart, and canonical example links | `done` |
| `FD-01` | Simplify the top-level README into a real front door | `P6-adoption` | `DIST-01`, `CA-01`, `WEB-01`, `RS-01` | `README.md`, `docs/install/README.md`, `examples/README.md` | the root README promotes only the supported starts and stops behaving like a surface inventory | `done` |
| `SEM-01` | Post-freeze docs and examples pack synced to runtime semantics | `P6-adoption` | `CA-01`, `WEB-01`, `RS-01`, runtime semantics freeze | `spec/{PROTOCOL.md,WIRE_PROTOCOL.md}`, `docs/guides/*`, `examples/hello-*/README.md` | docs and examples are derived from frozen semantics rather than roadmap language | `done` |

**Wave parallel batches**

| Batch | Tickets | Notes |
| --- | --- | --- |
| `W4-A` | `GRW-01`, `GRW-03`, `GRW-06`, `DIST-01`, `RS-01` | `GRW-01` and `GRW-06` are safe together; docs and crate-surface curation can start in parallel |
| `W4-B` | `GRW-02`, `GRW-04`, `CA-01`, `WEB-01` | Guard-loader tickets are serial on `policy.rs`; adoption quickstarts can run beside them |
| `W4-C` | `GRW-05`, `PKG-01`, `FD-01` | External guards and package/front-door docs only after the supported path is clearer |
| `W4-D` | `SEM-01` | Run only after runtime semantics are treated as frozen |

### W5: Portability Proof And Economic Truth

| Ticket | Title | Pod | Depends on | Primary write set | Acceptance gate | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `PORT-WSM` | Portable core wasm proof and no_std blocker ledger | `P7-portable` | none | `crates/chio-kernel-core/src/{lib.rs,passport_verify.rs}`, `crates/chio-kernel-core/Cargo.toml`, `docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md`, new `scripts/check-portable-kernel.sh` | one scripted command proves host plus `wasm32-unknown-unknown` builds with `--no-default-features`, and stale comments about wasm blockage are removed | `done` |
| `PORT-BRW` | Browser WASM qualification and artifact budget | `P7-portable` | `PORT-WSM` | `crates/chio-kernel-browser/{tests/wasm_bindings.rs,README.md,examples/demo.html}`, new `scripts/qualify-portable-browser.sh`, `docs/release/QUALIFICATION.md` | headless browser qualification runs real wasm bindings end to end and emits latency and artifact-size outputs | `done` |
| `PORT-MOB` | Mobile qualification matrix and Android toolchain hardening | `P7-portable` | `PORT-WSM` | `crates/chio-kernel-mobile/{Cargo.toml,build.rs,tests/ffi_roundtrip.rs,bindings/README.md}`, new `scripts/qualify-mobile-kernel.sh` | iOS qualification is scripted, Android uses a real NDK path, and supported versus environment-dependent targets are stated explicitly | `done` |
| `ECO-01` | Typed economic envelope | `P8-econ` | `TC-21B1` | `crates/chio-core-types/src/{receipt.rs,lib.rs}`, `spec/PROTOCOL.md` | one versioned envelope separates `budget`, `meter`, `rail`, and `settlement` truth without widening semantics | `done` |
| `ECO-02` | Kernel truth split for economic surfaces | `P8-econ` | `ECO-01` | `crates/chio-kernel/src/{kernel/mod.rs,payment.rs,receipt_support.rs}` | kernel emits the typed envelope from one helper and no authoritative rail data remains trapped in legacy payment fields | `done` |
| `ECO-03` | Economic envelope projection report | `P8-econ` | `ECO-02` | `crates/chio-store-sqlite/src/receipt_store/{reports.rs,support.rs}`, `crates/chio-kernel/src/operator_report.rs`, `crates/chio-cli/src/trust_control/service_types.rs` | one receipt-scoped economic report joins signed envelope truth with settlement and metering reconciliation data | `done` |
| `ECO-04` | Economic completion flow | `P8-econ` | `ECO-03` | `crates/chio-kernel/src/operator_report.rs`, `crates/chio-store-sqlite/src/receipt_store/reports.rs`, `crates/chio-cli/src/trust_control/cluster_and_reports.rs`, `spec/PROTOCOL.md` | one canonical `metering -> underwriting -> credit -> settlement` report is deterministic over persisted artifacts | `done` |
| `ECO-05` | Settlement provenance binding | `P8-econ` | `ECO-04` | `crates/chio-settle/src/{lib.rs,ops.rs}`, `crates/chio-cli/src/trust_control/capital_and_liability.rs`, `spec/PROTOCOL.md` | every settlement row links back to exactly one completion-flow row and fails closed without upstream provenance | `done` |
| `ECO-06` | Signed compliance and risk surface | `P8-econ` | `ECO-03` | `crates/chio-kernel/src/compliance_score.rs`, `crates/chio-http-core/src/compliance.rs`, `crates/chio-cli/src/trust_control/{underwriting_and_support.rs,credit_and_loss.rs}` | underwriting and provider-risk outputs can reference a signed compliance score when policy requires it | `done` |

**Wave parallel batches**

| Batch | Tickets | Notes |
| --- | --- | --- |
| `W5-A` | `PORT-WSM`, `ECO-01` | Establish a truthful portability baseline beside the first economic type split |
| `W5-B` | `PORT-BRW`, `PORT-MOB`, `ECO-02` | Browser and mobile can run in parallel if workflow edits wait for `GATE-CI` |
| `W5-C` | `ECO-03` | Keep the first report projection isolated from later flow work |
| `W5-D` | `ECO-04`, `ECO-06` | Safe together after `ECO-03`, but keep one owner on report contracts |
| `W5-E` | `ECO-05` | Settlement provenance comes last |

### W6: Verified Core And Release Gates

| Ticket | Title | Pod | Depends on | Primary write set | Acceptance gate | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `FORM-BND` | Define the verified-core boundary for portable evaluation | `P9-formal` | `RTC-04`, `PORT-WSM` recommended | `spec/PROTOCOL.md`, `docs/architecture/CHIO_RUNTIME_BOUNDARIES.md`, new `formal/proof-manifest.toml`, `crates/chio-kernel-core/src/{evaluate.rs,capability_verify.rs,scope.rs}`, `crates/chio-kernel/src/{kernel/mod.rs,kernel/responses.rs}` | one checked-in manifest names the covered Rust symbols and excluded surfaces for the verified core | `done` |
| `FORM-REG` | Theorem inventory, assumption registry, and claim registry | `P9-formal` | `FORM-BND` | `formal/lean4/Pact/Arc.lean`, `formal/lean4/Pact/Pact/Core/Revocation.lean`, new `formal/theorem-inventory.json`, new `docs/CLAIM_REGISTRY.md`, `README.md`, `docs/release/RELEASE_AUDIT.md`, `scripts/check-formal-proofs.sh` | root-imported theorems and approved axioms are enumerated machine-readably and strong formal claims are mapped or downgraded | `done` |
| `FORM-REF` | Refinement hooks from Lean or executable spec to Rust pure core | `P9-formal` | `FORM-BND` | new `crates/chio-kernel-core/src/normalized.rs`, `crates/chio-kernel-core/src/{evaluate.rs,capability_verify.rs}`, `formal/diff-tests/src/{spec.rs,generators.rs}`, new diff tests | a normalized verified-core IO shape exists and Rust/spec parity hooks are explicit and testable | `done` |
| `GATE-CI` | Wire portability and formal boundary into CI and release qualification | `P9-formal` | `PORT-BRW`, `PORT-MOB`, `FORM-REG`, `FORM-REF` | `.github/workflows/{ci.yml,release-qualification.yml}`, `scripts/{ci-workspace.sh,qualify-release.sh}`, `docs/release/QUALIFICATION.md` | merges and releases fail on portable-build drift, proof-manifest drift, theorem drift, or claim-registry drift | `done` |
| `RC-01` | Release-truth and front-door sync gate | `P6-adoption`, `P9-formal` | `GATE-CI`, `SEM-01`, `ECO-05` | `README.md`, release docs, `.planning/PROJECT.md`, `.planning/STATE.md`, sync scripts | ship-facing docs, planning state, and qualification gates all say the same thing after the runtime work is already true | `done` |

**Wave parallel batches**

| Batch | Tickets | Notes |
| --- | --- | --- |
| `W6-A` | `FORM-BND` | Freeze the verified-core boundary first |
| `W6-B` | `FORM-REG`, `FORM-REF` | Safe together if manifests/docs stay separate from diff-test normalization work |
| `W6-C` | `GATE-CI` | CI and release wiring last to avoid repeated workflow collisions |
| `W6-D` | `RC-01` | Final sync gate only after substantive runtime work is stable |

---

## Default Execution Order

1. Finish `W1` completely before expanding the writing surface.
2. Run `W2` with `P2-budget` and `P4-boundary` in parallel.
3. Start `W3` only after `TC-21B2`, `RTC-05`, and `RTC-07` are merged.
4. Start `W4` once request and hosted semantics stop moving every day.
5. Start `W5` portability work as soon as capacity exists; hold economic demos
   until `TC-21C1` is green.
6. Treat `W6` as the close-out lane, not the place to hide unfinished runtime
   work.

---

## Merge-Pressure Rules

- `P1-authority` and `P2-budget` must not write the trust-control files at the
  same time.
- `P3-hosted` owns `remote_mcp` and `chio-mcp-edge` session semantics while
  active.
- `P4-boundary` owns receipt write and read verification, tenant query, and
  model metadata semantics while active.
- `P5-guards` owns policy loader and guard pipeline code while active.
- `P6-adoption` can write docs in parallel, but should avoid top-level README
  rewrites until `FD-01`.
- `P7-portable` and `P8-econ` are the cleanest parallel pair in the program.
- `P9-formal` should avoid broad README edits until `RC-01`.

---

## Codex Automation Plan

| Automation | Kind | Cadence | Purpose | Action |
| --- | --- | --- | --- | --- |
| `PR4 Review And CI Loop` | heartbeat | every 5 minutes | old PR-bound loop for merged PR #4 | `delete` |
| `Chio Daily And Weekly Review` | heartbeat | weekdays at 10:00 AM ET | review this tracker, inspect current repo progress, update ticket states when evidence changed, and report blockers plus next-ticket recommendations; on Fridays also do the deeper wave review | `create` |

**Why only one new thread automation**

- the app supports only one heartbeat per thread, so daily polling and the
  Friday wave review are intentionally combined
- weekday polling is enough to catch drift without flooding the thread
- Friday’s run can carry the deeper wave review without needing a second thread
  heartbeat

---

## Daily Review Checklist

- read this tracker first
- inspect `git status` and recent commits
- map recent work to one or more ticket IDs
- update ticket status only when there is concrete evidence
- call out blockers, write-set collisions, and missing validation
- recommend the next highest-leverage ticket that is actually unblocked

## Weekly Review Checklist

- verify the current wave exit gate
- decide whether any ticket should split or merge
- decide whether any later-wave ticket should be pulled forward
- identify pods that are blocked on the same file set
- confirm that economics remains downstream of trust truth
- confirm that release-truth work is not replacing unfinished runtime work
