# Security Roadmap Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to execute the work packets below. Preserve the existing single-agent execution instruction. Checkboxes track remaining work; retained evidence is identified separately.

**Goal:** Finish the combined security/process foundation, complete M5-M10 developer-preview acceptance and the handoff's delivery integration, then satisfy M11's separately authorized operational acceptance.

**Architecture:** Keep PR #1160 as the common foundation, preserving both security and process histories. Compose the existing kernel, durable SQLite authority, process host, keyring, broker, cage and response authority. Complete the existing acceptance contracts without introducing another runtime or admission coordinator.

**Tech Stack:** Rust 1.94.1, SQLite, Tokio, Python and JavaScript process SDKs, four-language protocol bindings, Linux x86_64 enforcement, GitHub Actions and the existing signed-evidence machinery.

**Spec:** [Accepted execution contract](../../security/launch-execution-plan.md), [integration plan](../../security/process-security-integration.md), [execution handoff](../../reviews/2026-09-15-execution-handoff.md), [continuation directive](../../reviews/2026-09-16-execution-directive.md), and the three original plans linked in the coverage table below. This document reconciles execution against those accepted designs; it does not replace their requirements.

## Global constraints

- Fail closed; reject invalid policy at load; canonical JSON for signed payloads; conventional commits; no em dashes.
- One implementation owner and one Cargo owner per checkout. No subagents. Direct review is not independent reviewer evidence.
- Use `umask 022`, `CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`, locked dependencies and no custom `RUST_MIN_STACK`. Offline execution requires an available dependency closure.
- Preserve both parent histories: security `5d1a9ec0d900bd03ce55de903919d972be852d79` and process `2e84f121273df7f205cc218739b86e93c91bdc37`.
- Unknown external effects retain their original authority, identity and captured accounting; recovery never invents permission to retry.
- Native enforcement requires Linux x86_64, kernel 6.7 or newer, and all cage prerequisites. A supported machine is not itself trusted capture authorization.
- Preserve explicit single-operator preview scope, existing unsupported-profile denials and automatic-response-disabled defaults. No requirement disappears through an unannounced deferral.
- Existing authorization covers local implementation and PR checkpoint maintenance. Protected workflow/source rotation, merge, publication, deployment and promotion retain their documented authorization boundaries. Prepare exact artifacts before requesting any missing authority.
- Preserve `output/` and historical failed runs. Do not blanket-stage that directory or publish raw host artifacts.

## Review focus

1. External Cargo target directories must use the explicit checkout authority; an unrelated working directory must not silently supply fixtures. Packet 1 owns the conformance regression and full-run configuration.
2. A validly signed receipt can still belong to another operation, nonce, runtime or log. Packet 2 owns cross-run substitutions, missing proof and checkpoint tampering.
3. A broker crash between registration, capture and upstream send must not refund an uncertain effect or enable direct-provider fallback. Packet 5 owns process cutpoints and credential-leak observations.
4. Slow fsync, checkpoint creation and retention can interact differently from fast local storage. Packet 7 owns deterministic slow-storage reproduction and populated-store recovery.
5. Workspace path patches and cached tools can make an install pass while an external consumer gets different source. Packet 8 owns package-source identity and clean installation.

## 1. Reconciled starting point, September 22

Research refreshed Git refs, GitHub PR/check/review/ruleset APIs, the current implementation and retained artifacts. It did not rerun the workspace or native campaigns. Fresh checks passed for locked cargo-vet, the structural security CI contract and all 225 formal-source mirror entries.

| Identity | Verified value |
| --- | --- |
| Checkout / branch | `/tmp/arc-security-launch`, `integration/process-security-m4` |
| Local source | `84c0ca4e89b89fd104ca5f2b36b8b501c759fd99` |
| Published #1160 head | `bf8b666274095acb1d103e428f21eaaa7bfdeb54` |
| Current main | `f5566d9a765c21cb36652a99c79de64968a656bf` |
| Topology | Main is an ancestor; local candidate is 405 commits ahead of main and six ahead of the published branch; both required parents are ancestors |
| Published PR | Open, draft, mergeable, blocked; 3,441 changed files, 882,306 additions, 43,335 deletions |
| Published checks | 106 success, 12 failure, 16 skipped, one cancelled; MSRV has now passed |
| Review | #1160 has no review submissions or review threads; its parent #1117 still has 12 unresolved threads |
| Local disposition ledger | 109 unique records: 81 reproduced-and-repaired, 20 fixed-with-evidence, eight technically-inapplicable-with-reason |
| Lock SHA-256 | `8e7154ee265ed4521d92130aeb145070c8da1026d02b2939761af758f447ade1` |

The six unpublished commits contain the musl ioctl fix, AWS-LC DES validation repair and audit records, image-lock ratchet, two process-test synchronizations and Python-interpreter resolution. Preserve them. The September 22 `cargo vet check --locked` success reported 585 fully audited, seven partially audited and 731 exempted packages under the then-existing policy. Review later found that the path-patched `aws-lc-rs` fork was treated as first-party. The corrected policy fails on 1.18.1 until its source audit is completed; the earlier green result did not cover this fork.

### Retained evidence newer than the status prose

All paths in this table are relative to `output/process-security-20260915/resume-20260921/`. These are retained run results inspected during research, not newly executed campaigns.

| Gate at `84c0ca4e89` | Result and evidence boundary |
| --- | --- |
| Workspace build | Exit 0, `exact-head-84c0ca4e89/workspace-build.*` |
| Full workspace tests | Initial exit 101 on conformance fixture discovery; root-bound exact regression passed; broader retry exited 143. No completed full-workspace pass |
| Flow security | Exit 0, `exact-head-84c0ca4e89/flow-security.*` |
| Process worker/mailbox, host, response, lineage and native restart | All five terminal exits 0, `oci-remote/process-exact-84c0ca4e89-final/` |
| All fuzz binaries | 30 targets, ASan, pinned nightly, x86_64 build exit 0; `oci-remote/oci-fuzz-build-84c0ca4e89-retry1/qualification.json`. Compilation is not a fuzz campaign |
| Native cage | 69 tests, 26 real probes, ten mutants; exit 0 and log hash matched. `oci-remote/oci-x86-cage-release-84c0ca4e89-retry3/`. Retained runner adapts the production helper to the release build; trusted workflow still needs qualification |
| M5 scenario matrix | All seven scenarios verified, all 15 mutations rejected; `oci-remote/oci-matrix-84c0ca4e89-retry3/`. Bundle hash matches separately retained pins |
| Independent M5 observer | Both `verify` and `test-evidence` exit 0; `m5-independent-84c0ca4e89/`. Different verifier binary hash; same explicit four unchecked claims |
| Execution image | Exact source built and validated, exit 0; local image ID `sha256:0cebffabd9bf06f7eb059c9994680877856d03b054592eeb845c0e1a4987ed4f`; `oci-remote/oci-image-validation-84c0ca4e89-retry3/`. This is not a published registry digest or authorization |
| Cheap source gates | Formatting, hygiene, dependencies, structural CI and formal-source anchors have retained passing exits under `exact-head-84c0ca4e89/` |

M5 still explicitly reports `m5_acceptance_complete=false`: execution nonces, receipt-log inclusion, complete foundation qualification and designated-runner authorization are unchecked. Re-running the unchanged seven-scenario demo does not close those claims.

The three classifier comments from #1117 are also newer in source than the original launch queue: nullable regex construction and JSON Pointer syntax were repaired in `db451c6500`; the complexity allegation has a reasoned bounded-engine disposition at `63239c56c9`. Preserve those tests and assess composed resource behavior in M7. Do not reimplement the old suggestions blindly or remove valid empty-key pointer segments.

### Current hosted failures grouped by cause

| Failure | Diagnosis / next action |
| --- | --- |
| Build, lint, test | Published head fails formal mirror drift. Local manifest has the reviewed refresh; require hosted confirmation on the next candidate |
| Sidecar amd64 and arm64 | Published nono fails musl ioctl integer range compilation; `c4beda6ea0` repairs the bit-preserving conversion |
| Three cargo-vet-dependent jobs, including PostgreSQL | Shared dependency-policy failure. PostgreSQL job reached cargo-vet after its behavioral checks; do not treat its title as a new database defect |
| Kani public lane | Release download returned HTTP 504. Preserve pinned version and require a terminal solver run; tool installation failure is not a counterexample |
| Enterprise merge binding | Trusted reusable workflow lacks `GH_TOKEN`; current source contains wiring but the immutable caller still uses the old definition |
| Enterprise capture | Controller log pins source `f5566d9a` and definition `eba8cdf3`; candidate is `bf8b6662`. It fails before capture; the precise shell assertion is not printed |
| Formal/Security aggregates | Failed upstream gates; inspect new attempts after the owning failures close |
| Process recovery | Cancelled, so require a terminal result on the published candidate |

Owning hosted evidence: [main CI](https://github.com/bb-connor/arc/actions/runs/35609558875), [PostgreSQL qualification](https://github.com/bb-connor/arc/actions/runs/35609558501), [sidecar](https://github.com/bb-connor/arc/actions/runs/35609558376), [capture controller](https://github.com/bb-connor/arc/actions/runs/35609558364). Downloaded diagnosis logs are in `/tmp/arc-security-roadmap-research-20260922/` and are temporary research evidence.

## 2. Delivery strategy and critical path

Recommended: finish the existing foundation and M5 closeout on #1160, get that boundary qualified and integrated, then advance M6-M10 on the same delivery line with bounded milestone changes. Preserve the full original scope through the coverage table. Do not keep the foundation hostage to M11's calendar window.

Two alternatives cost more: reconstructing all 405 commits as a new stack repeats reconciliation and qualification; adding every remaining product and milestone to #1160 before any integration keeps invalidating its evidence. Neither is needed to finish the roadmap.

Execution order:

```text
1 foundation closeout --> 2 M5 evidence joins -----------+
       |                                                |
       +--> 3 trusted authority preparation ------------+--> 4 M5/foundation integration
                                                              |
                                                              v
5 M6 topology --> 6 M7 active defense --> 7 M8 recovery --> 8 M9 packaging
                                                              |
9 handoff consumers/repository delivery -----------------------+--> 10 M10 release
                                                                        |
                                                                        v
                                                              11 M11 observed pilot
```

Packet 3 preparation and package-closure inspection can progress while frozen tests run. This permits read-only preparation, not competing source mutations or timing-sensitive Cargo campaigns. An external authority wait does not block otherwise authorized M6/M7 implementation once their foundation inputs are stable.

### Packet 1: Finish the current foundation without replaying completed campaigns

**Owners:** `crates/tooling/chio-conformance/src/{runner.rs,peers.rs}`, `crates/tooling/chio-conformance/tests/native_suite.rs`, the qualification launcher, `formal/proof-manifest.toml`, `docs/security/process-security-qualification.md`.

**Consumes:** Current six-commit continuation and retained exact-source evidence. **Produces:** A complete local foundation record, with all retained failures and source boundaries.

- [ ] Use the existing validated `CHIO_CHECKOUT_ROOT` contract for external target directories. The recorded failure is `read internet draft: No such file or directory`, not a missing tracked standard. The same exact test passes with the explicit root. Fix the launcher configuration first; change resolver code only if a further defect reproduces.
- [ ] Run the complete owning conformance target under the configured environment, then finish the full workspace run. Preserve the existing rejection tests for invalid roots and external-target discovery.

```bash
umask 022
export CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1
export CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch
export CARGO_TARGET_DIR=/home/connor/chio-security-workspace-target-6cb-final
cargo test --locked -p chio-conformance --test native_suite
cargo test --locked --workspace --no-fail-fast
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo vet check --locked
cargo deny check
cargo xtask check formal-mirrors
cargo xtask gen proof-coverage --check
git diff --check
```

- [ ] Record terminal results and classify every ignore. Do not change security deadlines, stack limits or fixture assertions to obtain a pass.
- [ ] Retain the successful exact-head process, flow, cage and fuzz-build records above. Run their full owning gates again when changed input bytes or final release rules require it. The earlier aarch64 fuzz linker failure is superseded for required x86_64 compilation by the retained 30-target pass.
- [ ] Verify remaining consumer/codegen/formal campaign obligations against the current integration plan, then checkpoint only the intended fix and evidence index with a conventional commit.

**Exit:** The full workspace and strict lint have terminal passes on identified inputs; no interrupted run is presented as complete. No new code is required merely to re-achieve an already evidenced unchanged property.

### Packet 2: Complete M5's nonce and receipt-log joins

**Owners:** `crates/products/chio-cli/src/cli/process_host/run_evidence.rs`, `run_evidence/{export.rs,verify.rs,verify_calls.rs}`, `call_evidence/{outcomes.rs,outcomes_export.rs}`, `crates/products/chio-cli/tests/{process_run_evidence.rs,process_call_evidence.rs}`, `examples/reference-swarm/{process_matrix_evidence.py,qualify-process-matrix.py,PROCESS.md}`. Use the existing kernel nonce and receipt-checkpoint APIs; preserve the original run and call identities.

**Consumes:** Original worker responses, committed authority state and signed checkpoints. **Produces:** A versioned complete artifact whose verifier establishes nonce and log membership in addition to existing task, policy, accounting and confinement joins.

- [ ] Add failing artifact regressions for a valid nonce copied from another request, altered attempt identity, missing required nonce, duplicated nonce, missing receipt inclusion, wrong checkpoint root, altered leaf/index and a proof from another runtime.
- [ ] Export original nonce evidence and receipt-log proof material from the owning durable authorities. The worker already transports `execution_nonce_json`; carrying bytes alone is not verification. Do not mint replacement nonces during export.
- [ ] Extend the existing artifact version and Rust verification paths to authenticate those joins, then extend the Python matrix verifier and its intrinsic-signature/substitution tests. Legacy artifacts remain readable only with their explicit incomplete claims.
- [ ] Add a positive completed case and a captured-unknown case. Historical verification must not turn a nonce into renewed execution permission or fabricate a terminal receipt for an interrupted operation.

```bash
cargo test --locked -p chio-cli --test process_run_evidence
cargo test --locked -p chio-cli --test process_call_evidence
cargo test --locked -p chio-cli --test process_response_verify
cargo clippy --locked -p chio-cli --all-targets -- -D warnings
```

- [ ] Commit this behavior as `feat(security): bind swarm evidence to nonce custody and receipt checkpoints` after the positive and mutation cases pass. Keep foundation and trusted-runner claims independently checked; never close M5 by changing a literal boolean.

**Exit:** Independent verification detects each nonce/log substitution and authenticates the original complete run. Full M5 acceptance awaits Packet 4.

### Packet 3: Prepare and complete the trusted capture authority transition

**Owners:** `.github/workflows/{ci.yml,enterprise-hardening.yml,enterprise-evidence-controller.yml,enterprise-linux-capture.yml,enterprise-evidence-finalizer.yml,security-contract-revocation.yml}` (including the finalizer's publisher jobs), `deploy/docker/Dockerfile.security-evidence-runner`, `scripts/{check-security-ci-contract.py,check-committed-linux-evidence.py}`, and their existing mutation tests.

**Consumes:** Reviewed source, exact image inputs and the current repository rules. **Produces:** A concrete source/definition/image/verifier/publisher transition and accepted committed Linux evidence.

- [ ] Preserve and hash the exact-head image validation record. If Packet 2 changes its input closure, rebuild and validate the resulting candidate before publication. Publish the reviewed image only under applicable authorization, then verify its registry manifest digest. A local Docker image ID cannot be substituted for that digest.
- [ ] Diff the complete controller/capture/finalizer/publisher/revoker/reusable set against the authorized baseline. Include token wiring, nonce/FIPS aggregation, source and merge binding, toolchain installation and locked execution, not only the failing `GH_TOKEN` line.
- [ ] Prepare the exact old/new definition SHA, reusable pin, authorized source SHA, image digest, verifier digest, evidence-only descendant, runner identity and policy tuple. Validate it with the existing contract/mutation and committed-evidence tests.

```bash
python3 scripts/check-security-ci-contract.py
python3 scripts/tests/check-security-ci-contract.test.py
python3 scripts/tests/check-committed-linux-evidence.test.py
```

- [ ] Resolve the bootstrap ordering explicitly: reviewed complete workflow definitions land on main as `B`; the reusable caller and authorized definition identify the same immutable `B`; source `S` is separately authorized; capture produces the permitted three-file evidence descendant `E`. Prepare a narrowly scoped definition change if needed. Do not make the introducing PR self-authorize or return success when evidence is absent.
- [ ] Present only the finished protected operation for any missing authorization. The exact rule is [committed-linux-evidence.md](../../security/committed-linux-evidence.md): "The introducing pull request cannot establish these default-branch and environment trust roots by itself."
- [ ] Reconcile the live ruleset with the required dedicated App publisher and merge-check mirrors. Live main currently requires four ordinary checks; it does not yet demonstrate the documented App-bound five-context authority contract. Do not disable existing protection to install the new one.
- [ ] After authorized transition, execute trusted capture and verify signed evidence and all exact source/merge/run-attempt bindings. A failed tuple's tombstone requires the documented fresh tuple procedure, not cosmetic reruns.

**Exit:** Trusted Linux acceptance succeeds under independently configured authority. Image publication, repository settings and runner provisioning have separate recorded outcomes.

### Packet 4: Close M5 and integrate the foundation

**Owners:** `examples/reference-swarm/`, `docs/security/process-security-{qualification,review-dispositions}.md`, the JSON disposition ledger and PR #1160.

**Consumes:** Packets 1-3 and existing seven-scenario program. **Produces:** Qualified M5 artifact, review-complete foundation and verified protected integration.

- [ ] Freeze runtime, helper/tool, worker-image and verifier inputs. Run `qualify-process-matrix.py run` with its required `--chio`, `--cage-init`, `--probe`, `--reader`, `--output`, `--receipt-rollback-anchor-root`, `--worker-image` and `--runtime-source` arguments on the supported runner.
- [ ] Require success, authority/scope and replay denials, revocation, forbidden file access, forbidden network, host crash/restart and shared-budget contention. Map cross-agent leakage and worker death requirements to exact existing cases; add a missing case if that mapping lacks a behavioral oracle.
- [ ] Run `verify` and `test-evidence` on a separately built observer with independently retained pins. Attach Packet 1's foundation and Packet 3's trusted acceptance through the existing evidence contract.
- [ ] Push the locally qualified continuation under existing PR-maintenance authorization. Refresh the stale PR body around the final implementation and current evidence. Obtain the required review; current #1160 has no reviewer approval.
- [ ] Reconcile required checks and original findings on the final head, including both sidecar architectures, process job, Kani and nonce/FIPS/enterprise aggregates. Close failures by cause, preserving attempts.
- [ ] Prepare the protected merge only after local/remote/PR identities agree and every required gate is terminal. After any required merge authorization, verify main's integrated source and CI. Preserve immutable source/evidence refs even if the merge strategy rewrites commits.

**Exit:** The foundation and full M5 are accepted. Thread dispositions cite actual current evidence; zero threads on #1160 is not independent review, and parent-thread resolution is not a substitute for review.

### Packet 5: M6, one real keyring/broker/cage invocation

**Owners:** `crates/security/chio-keyring/`, `crates/security/chio-secret-broker/src/{authority_ipc.rs,daemon.rs,service.rs}`, `crates/kernel/chio-kernel/src/supplemental_quota.rs`, `crates/platform/chio-control-plane/src/security/`, existing CLI broker/reference provisioning and `examples/reference-swarm/`.

**Interfaces:** Reuse `BrokerAdmissionAuthority::prepare_execution` / `control`, the trusted `SupplementalQuotaVerifier`, `AdmissionCaptureAuthority` and the existing durable operation lifecycle. Do not use broker-local counters as the kernel's composite authority.

- [ ] Extend the existing provisioned brokered-native scenario into a real provider-backed invocation using the production authority adapter and original composite parent/aggregate/broker hold.
- [ ] Add process-level red regressions at intent registration, hold capture, upstream send and report loss. Independently observe provider effects and quota; duplicate delivery cannot cause a second effect or refund.
- [ ] Exercise witnessed rotation, contiguous key-log sync, stale signer fencing and trusted artifact time in this topology. Corrupt/missing key or broker evidence must deny before effect.
- [ ] Check agent/tool environments, manifests, IPC output, logs and receipts for a seeded test credential. Broker failure must refuse a direct-provider retry. Include destination/header/body/options substitutions and proof replay.
- [ ] Extend original receipt/artifact verification for the brokered invocation and run the owning gates.

```bash
bash scripts/check-keyring-transparency.sh
bash scripts/check-secret-broker-boundary.sh
bash scripts/check-cage-enforcement.sh --release
```

**Exit:** One independently verified production-equivalent invocation joins key authority, encrypted custody, single composite capture, real confinement and durable receipts. Existing provisioning/peer checks alone do not meet this exit.

### Packet 6: M7, composed active defense and reversible response

**Owners:** `crates/security/{chio-flow,chio-decoy,chio-quarantine,chio-active-response-authority}/` (including `chio-quarantine/src/correlation.rs`), `crates/platform/chio-control-plane/src/security/{event_consumer.rs,correlation.rs,active_response.rs,active_response_authority.rs,scheduler_worker.rs}`, and `crates/guards/chio-data-guards/src/structured_classification.rs`.

**Consumes:** Complete M4 consumers and qualified durable topology. **Produces:** Signed dry-run plans plus actual reversible response/rollback evidence in a controlled deployment, with production automatic effects still disabled.

- [ ] Run existing classifier repair cases and compose classification errors with native flow. Test unknown-as-Top, complete-source taint and before-dispatch/before-delivery hook order. Measure bounded adversarial classifier inputs if they threaten the declared operational budget; do not infer a regex-engine defect from nested quantifiers alone.
- [ ] Exercise canary/watermark detection before effect or release, event-store failure and secret/marker redaction.
- [ ] Qualify authenticated event provenance, deterministic event-time correlation, bounded lateness and eviction health. Advisory events cannot grant executable authority.
- [ ] Exercise every accepted response action through the shared threshold approval-only operation and dedicated durable authority. Cover exact affected-set fencing, overlapping restrictions, worker death, orphan fences, TTL reordering, partial apply/remove and rollback conflict.
- [ ] Run calibrated mutations and the owning gates; every threat closure needs executed evidence.

```bash
bash scripts/check-flow-security.sh
bash scripts/check-deception-security.sh
bash scripts/check-temporal-security.sh
bash scripts/check-response-recovery.sh
bash scripts/check-security-adversarial-evidence.sh
```

**Exit:** All original active-defense behavioral contracts pass in composition; temporary restrictions use reversible overlays and permanent revocation remains manual.

### Packet 7: M8, retention, million-entry recovery and operations

**Owners:** `crates/platform/chio-store-sqlite/src/receipt_store.rs`, `receipt_store/tests/{retention.rs,scale_proof.rs,scale_recovery.rs}`, associated writer/checkpoint tests, `scripts/check-receipt-{append-scale,history-recovery-scale}.sh` and their inventory fixtures.

**Consumes:** Final lifecycle/evidence semantics from M2-M7. **Produces:** Liveness repair evidence, restored CI coverage, measured scale and populated-store recovery.

- [ ] Reproduce [#1045](https://github.com/bb-connor/arc/issues/1045) under slow fsync with background signing and archival/appends. Capture blocking stacks or an instrumented ordering trace. The retained fast macOS run is not a slow-runner liveness fix.
- [ ] Add a deterministic regression for the reproduced handshake failure, fix the owner and execute the original property. Remove quarantine only when its original CI failure condition is covered.
- [ ] Run the real append and history-recovery campaigns with their unchanged million-entry inventories. The handoff records an append pass; recover its exact artifact before reuse. Research did not establish a terminal million-entry recovery result.

```bash
cargo test --locked -p chio-store-sqlite --lib \
  receipt_store::tests::retention::state_machine::prop_retention_preserves_append_invariant \
  -- --exact --ignored --nocapture
bash scripts/check-receipt-append-scale.sh
bash scripts/check-receipt-history-recovery-scale.sh
```

- [ ] Once the ignore is removed, invoke that property without `--ignored` and require the exact listed test to execute. Test populated backup/restore, retention proof preservation, migrations, serving-owner replacement, writer failure, readiness exhaustion and shutdown ordering.
- [ ] Record wall time, peak memory, storage, query and restart measurements with baseline comparisons. Do not introduce unrelated optimization work.

**Exit:** Real required inventories complete, no liveness quarantine substitutes for acceptance, and recovery preserves original custody and evidence.

### Packet 8: M9, publishable package closure and clean consumer

**Owners:** `Cargo.toml`, `Cargo.lock`, selected crate manifests, `third_party/*/CHIO-PATCH.md`, `scripts/qualify-process-packages.py`, release package/binary workflows and external-consumer fixtures.

**Consumes:** Stable M4-M8 API and exact audited dependencies. **Produces:** A fully identified package closure and reproducible external installation.

- [ ] Compute the chosen feature/platform dependency closure and make an explicit publication decision for each member. Current locked metadata's resolved normal/build graph reaches three local packages from kernel-core, three from swarm-authority and 39 from kernel; all those local packages are publication-disabled. These are resolved-graph counts, not a promised minimal release set.
- [ ] Resolve the patched AWS-LC source in the kernel closure. Other runtime-selected local patches also need durable external distribution. Workspace `[patch]` selection does not ensure an external consumer receives the repaired source. Use reviewed publishable revisions or appropriately versioned forks; preserve provenance, audits and exact bytes.
- [ ] Package only the actual supported closure in dependency order. Do not flip `publish` across the whole workspace. Validate licensing, included files, compatibility, error types, features, MSRV and shutdown behavior.
- [ ] Build a consumer outside this checkout using staged registry/package artifacts without workspace path patches. It must execute one allowed call, one denied call, receipt verification and restart recovery.
- [ ] Package runtime supervisor, required daemons, manifests and provisioning/readiness tools; run clean install/start/restart on the supported profile. Repeat affected SDK/FFI/C++ gates and schema negotiation.

**Exit:** A recipient can install and run the supported profile without repository-local paths or substitution of unpatched dependencies. Package preparation is separate from registry publication.

### Packet 9: Finish the handoff's consumers and repository delivery

**Owners:** Existing #1156 delivery/acceptance records, `docs/strategy/chio-direction/19-priority-agent-integrations.md`, selected public Chio product, Chio World installer #148 and the PR disposition ledger.

**Consumes:** Stable foundation and packaged compatibility contract. **Produces:** One coherent supported product and native-host delivery path; all historical requirements retain a disposition.

- [ ] Reconcile #1156 semantically with the foundation, preserving the six mandatory host profiles and I01-I08 obligations. Refresh its current acceptance record and the Cursor restriction issue before implementation; companion merged PRs are evidence inputs, not proof of complete installation.
- [ ] Use public Chio #5 as the initial bounded application candidate unless its integration evidence favors another accepted path. It remains open/draft at `1346840e` with 89 success, 11 skipped and one failure. Preserve Workbench/Megastart work and choose one common runtime path without building both as separate runtimes.
- [ ] Repair installer #148 against its current base; live refresh reports it open and conflicting at `bb846d4c`. Verify staged execution/version/identity and compatible upgrades with the actual packaged CLI/SDKs.
- [ ] Prepare an ancestry-preserving public-repository integration candidate and compare public-only changes. ARC remains intact. Release-routing changes occur only after that candidate and installation contract qualify.
- [ ] Reconcile each superseded PR to a containing integrated commit or documented patch equivalence, review disposition and current tests. #1117/#1155 are retained parents; #1029 needs requirement-level equivalence rather than an omnibus merge.
- [ ] Retain #1159 correctness fixes when required. Keep #1161 funded work, #1162 outcome/A2A, #1163 benchmark and #1164 Workbench checkpoints explicitly dispositioned; their inclusion in the handoff does not silently turn unrelated expansion into a security-preview prerequisite.

**Exit:** Required consumer and installer claims use one tested compatibility matrix. Historical PRs are closed only from integrated evidence and applicable authorization.

### Packet 10: M10, final candidate review and developer-preview release

**Owners:** Existing release-qualification workflow and scripts, all original final-verification inventories, release claims and package manifests.

- [ ] Freeze the complete release input closure and run the final workspace, schema/codegen, four-language, adapter/concurrency, Kani/Lean/TLA/Apalache, fuzz campaign, dependency, provenance, retention/scale, native-enforcement and external-consumer gates. A compilation pass or formal-source hash match never replaces a behavioral/proof campaign.
- [ ] Obtain broad final review using the original requirement map and all 109 dispositions. Reconcile latest review commit, unresolved findings, literal approval/reaction state, exact remote/PR/source SHA and final workflow attempts.
- [ ] Verify the complete trusted nonce/FIPS and enterprise evidence aggregation, publisher identity and enforced ruleset. Named green jobs alone do not satisfy the contract.
- [ ] Prepare the next unused `0.2.0-alpha.N`, signed provenance and exact publish inputs. Refresh registry state at publication time. Request only any missing release authorization for this concrete candidate.
- [ ] Publish through the existing mechanism when authorized; verify installed published artifacts and hashes with fresh allow/deny/recovery smoke tests before announcing availability.

**Exit:** The developer preview is review-complete, packaged, qualified and verified as published when authorized. Claims name the supported operator/platform boundary.

### Packet 11: M11, observed pilot and controlled promotion

**Owner:** [active-defense-rollout.md](../../security/active-defense-rollout.md) and its signed cohort evidence.

- [ ] Prepare cohort, observation collection and rollback procedure during M10; activate only under operator authority.
- [ ] Observe at least 14 consecutive days and 100,000 mediated invocations, or 30 consecutive days for a low-volume cohort. Authority reset restarts the window.
- [ ] Require at least 99 percent reviewed precision across at least 1,000 reviewed findings and every zero-tolerance/unknown-label/recall requirement. Synthetic injections remain separate from observed findings.
- [ ] Execute signed cohort stages and the required rollback drill. Verify zero active/partial overlays and exact restoration before unregistering adapters; retain signed history. Insufficient findings leave automatic response dry-run.

**Exit:** The accepted operational evidence and promotion are complete. This calendar-bound milestone cannot be accelerated by more commits or declared complete with preview publication.

## 3. Original requirement coverage

The original task bodies remain normative implementation instructions. A local historical pass survives as source-bounded evidence, while changed inputs and final-release obligations receive fresh qualification.

| Original requirement family | Owning completion packets |
| --- | --- |
| [Protocol primitives](2026-07-09-protocol-primitives.md), Tasks 1-3: baseline, family root and negotiation | 1, 4, 10 preserve M0-M4 behavior |
| Protocol Tasks 4-6: atomic quotas, fenced saga, broker capture, ordinary/nested/caller recovery | 1, 2, 4, 5, 7 |
| Protocol Tasks 7-10: threshold proposal, signer set, replay and shared federation algorithms | 1, 5, 6, 10 |
| Protocol Tasks 11-13: runtime evidence, schemas, all adapters | 2, 4, 8, 10 |
| Protocol Tasks 14-16: conformance, concurrency/formal and release | 1, 7, 8, 10 |
| [Active defense](2026-07-09-security-active-defense.md), Phases 0-5: provenance, lattice, wire, stores, classification and installation | 1, 5, 6, 10 |
| Active-defense Phases 6-9: deception, correlation, affected scope, approvals, execution, TTL/posture | 6 |
| Active-defense Phases 10-11: receipts, adversarial coverage, CI and staged rollout | 2, 3, 6, 10, 11 |
| [Enterprise hardening](2026-07-09-enterprise-hardening.md), Phases 0-3: source review, Merkle consistency, key replay and witnessed rotation | 1, 3, 5, 10 |
| Enterprise Phases 4-5: broker protocol, encrypted custody, replay, composite authority and no-secret boundaries | 5 |
| Enterprise Phases 6-8: signed manifests, deny-all compilation, real cage-init/enforcement | 3, 4, 5, 10 |
| Enterprise Phases 9-10: runtime composition, receipts, adversarial gates and migration | 3, 5, 6, 10, 11 |
| Handoff: retention/scale, packaging, native hosts, product, installer and public repository | 7, 8, 9, 10 |
| Handoff: evidence-backed PR retirement | 4, 9, 10 |

## 4. Execution cadence and completion record

The immediate batch is Packet 1 plus implementation of Packet 2, with Packet 3's exact authority proposal prepared while frozen qualification owns Cargo. Do not restart the old 26-audit campaign, the repaired classifier findings or the unchanged M5 demo.

Record each packet's source/tree/lock identity, platform/compiler, command, binary/package hashes, exact test inventory, terminal result and artifact location. Preserve implemented, locally verified, trusted-hosted-qualified, reviewed, merged, packaged, published and operationally accepted as separate states.

Use `docs/security/process-security-qualification.md` as the short current ledger. Retain detailed history and logs elsewhere. A blocker entry must name its owner, the exact missing condition and the next executable action. After two checkpoints without advancing an acceptance criterion, reassess the blocker instead of adding more peripheral work.

No credible all-roadmap completion date follows from the current evidence: M6 composition and retention liveness remain engineering uncertainties, and M11 has a fixed observation window. The fastest defensible route is to finish and integrate the foundation now, complete each remaining acceptance boundary once, and start the authorized observation window as soon as the qualified preview permits it.
