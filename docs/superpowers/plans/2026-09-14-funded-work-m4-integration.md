# Funded Work and M4 Integration Plan

> **For agentic workers:** Execute inline with `superpowers:executing-plans`. Preserve both input worktrees. This plan authorizes only the isolated local candidate; no upstream merge, release or live funding.

**Goal:** Combine the paper's checked-output and unknown-payment successor behavior with M4's authenticated caller/native custody, then qualify the combined source before native funded admission.

**Inputs:** Security `5d1a9ec0d900bd03ce55de903919d972be852d79` (clean, committed M4 local acceptance) and research `926e1aa8411e3b516fe737988dd1a0989c447d08` (clean). Local/remote/PR security heads matched when selected on 2026-09-14. Hosted serial/MSRV and release qualification are separate and remain incomplete.

**Architecture:** Use security as the first parent of a separate integration candidate. Resolve overlaps by preserving both security and research invariants, not by choosing a whole branch. Keep security's canonical admission SQL and historical catalog builders unchanged, add the unknown-payment release table as a separately named SQL extension in admission version 35, and permit only exact predecessor migration. The anchored global commit catalog gains the payment-resolution projection without rewriting original records. Adapt consumers to verified manifest construction.

**Spec:** [Integration gate](../../market/open-agent-work/execution/06-native-integration.md), [source reconciliation](../../market/open-agent-work/09-security-roadmap-sync-review.md), Task 3 of [vertical-slice plan](2026-09-14-funded-work-claim-escrow.md).

## Tasks

### 1. Freeze and baseline the candidate

- [x] Verify committed M4 local acceptance, clean source and current PR/local identity. Retain the hosted/release limitations.
- [x] Create `/home/connor/backbay/arc-funded-integration`, branch `integration/funded-work-m4`, at the M4 checkpoint. Preserve research and security worktrees.
- [x] Recompute merge-tree from the exact committed inputs: nine code conflicts and one generated coverage conflict; shared ancestor `f5566d9a765c21cb36652a99c79de64968a656bf`.
- [x] Run a fresh native-store provisioning baseline before modifying Rust source. Use a dedicated target on `/home` with three jobs, incremental disabled and debug info disabled for these selected checks; record that profile.

### 2. Compose native custody and financial successors

- [x] Merge the research checkpoint without committing, and retain exact conflict resolutions for review. Keep new test modules from both inputs; preserve security's moved helper implementations.
- [x] Preserve authenticated return-context validation, retain returned work before output evaluation, and preserve caller release/declassification checks. Run the paper's actual checked-output denial/zero-charge tests and security delivery tests.
- [x] Keep the version-34 admission SQL as the historical source; move research unknown-payment DDL into `admission_operation_unknown_release.sql`. Set version 35 and add the extension during provisioning/migration and to the version-35 expected catalog only.
- [x] Reject legacy research version 10 and unsupported catalogs before mutation. Verify exact security-v34 predecessor, including populated immutable operation/commit records; preserve original bytes and anchored history. Add failing regression tests for these requirements before the migration implementation.
- [x] Compose unknown-payment global coverage and reference validation with security's current global-chain modules. Recognize the exact prior security catalog and reject unsupported future records. Keep canonical row/digest chains unchanged.
- [x] Run targeted migration, schema, unknown-payment, checked-output, runtime and A2A checks. Fix actual compatibility failures while preserving the stated boundaries.

### 3. Adapt the selected provider and qualify the candidate

- [x] Replace unsigned manifest construction in the federated provider with the selected signed manifest/registry policy. Preserve local publisher pins, profile negotiation and custody semantics; no compatibility bypass.
- [x] Refresh the standalone lockfile for the combined dependency source and run its Rust/Python/process regressions explicitly. Artifact-only profile hashes remain tied to unchanged checker bytes.
- [x] Run affected caller/native/consumer/flow inventories and required formatting/build/Clippy/generated checks, retaining exact commands and their profile. Regenerate coverage after semantic changes.
- [x] Commit a reviewable combined candidate and evidence only after the selected checks pass. Mark incomplete broader qualification explicitly; do not start native funding Task 4 until Task 3's required qualification is complete.

## Boundaries

No native operator database is opened or migrated. Migration fixtures are disposable copies or generated test databases. Do not import the optional process stack or legacy PR #1029. Private-chain observations remain separate from existing settlement finality proofs. No task here asserts independent operators, public activation, all-PR success or release readiness.

## Selected verification progress

The [integration report](../../market/open-agent-work/execution/14-native-integration-results.md)
records the reviewed resolutions, compatibility fixes and limits. The selected
profile is three Rust build jobs, no incremental compilation or debug symbols,
and serial test execution. Historical evidence files retain their original bytes.

| Surface | Observed result |
| --- | --- |
| Untouched security baseline | One provisioning test passed before native edits |
| Schema and global predecessors | Red regressions reproduced; 105 selected checks passed after implementation |
| Kernel | 1,440 library and 18 SQLite integration tests passed initially; all 1,445 library tests passed after the final caller-custody guard |
| Admission store | 506 selected tests passed |
| Authenticated caller gate | 34 caller, nine executor and 19 native custody cases passed |
| Restart gate | 47 process and five ownership cases passed |
| Runtime | 88 admission, ten predicate, 12 context-scanner and 37 binding cases passed |
| Protocol and federation | 102 A2A, two A2A interop, seven verifier-conformance and 190 iroh tests passed |
| Standalone provider | 11 Rust, 30 Python unit and 65 process scenarios passed; strict Clippy passed |
| Comparison examples | Nine composed tests plus executable smoke, and nine outcome experiments passed |
| Recovered Git-hook repair | Seven regressions failed first; adapter-base passed 205, Hermes 196 with four existing skips |
| Consumer SDKs | Python, TypeScript and Go gate passed |
| Compilation | Full workspace check and strict Clippy passed for all targets; all 29 fuzz binaries compile |
| Generated and formal | Four protocol lanes in sync; 225 reviewed source anchors match; full Lean and assumption-audit gate passed |
| Hygiene | Final workspace formatting and Rust file-size checks passed |
| Rust consumer | Full script passed, including 38 exact inventories, peer negotiation, mediation and HTTP egress |
| Flow security | All 69 exact inventories, WASM checks and Apalache calibration passed before the final custody repair; the changed 35-case inventory passed again afterward |
| Caller-custody follow-up | Red reproduced; five controls, 35 frozen-context, 34 caller, nine executor, 19 native and one physical DPoP cases passed; final workspace and generated checks passed |

Task 3 closes with the completed selected gates, retained evidence review and
this local commit. Native funded admission has not started. A source snapshot
check confirms the original checkout's head, status and 3,688 recorded file
hashes/modes are preserved. Private process fixtures remain outside the repository.
