# Relying-Party Wedge M1 Item 5 Implementation Plan: Revocation Target Kinds

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land M1 item 5 of the relying-party wedge: the existing SQLite revocation store holds closed-kind revocation entries (`capability_id`, `root_policy_rule`, `anchor_subject`, `tenant_tag`, `replay_key`); every entry is linearized with budget admission, capture and mint through the serving writer; a denied or refused call names its entry; item 6 can export each entry with the capability ids it covers; the provider revokes through `/admin/revocations` and `chio mcp revoke`.

**Architecture:** One new table, `revocation_entries`, records each target once under a deterministic id. A target entry is materialized into the existing `revoked_capabilities` projection for every live anchored root it matches, in the same IMMEDIATE transaction that writes the entry. The root exchange checks the entries in the same transaction that inserts an anchored root. Every existing in-transaction revocation reader (budget authorize-hold, composite capture, native dispatch capture) keeps reading `revoked_capabilities` by capability id over the leaf and its delegation chain, so none of them changes and the existing cascade covers descendants. Export coverage is computed from the `anchored_roots` target columns, not from `revoked_capabilities`, so it does not depend on which entry reached a root first. Entries join the global authority commit chain so a restored backup that loses an entry is detected.

**Tech Stack:** Rust workspace (every cargo command through `cs`, defined under Global Constraints), SQLite through `rusqlite` (bundled), JSON Schema draft 2020-12, `cargo xtask codegen`.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`, sections 2.2 (D3, D4, D5, D17), 2.3 ("Revocation freshness"), 2.5 (G12, G17, G18), 7.11, 7.12 (tags, plaintext rule), 8.2 (revocation rule), 8.3 (startup refusals), 10.7, 11.1 ("Revocation"), 11.3 (`revocation_local`), 12 M1 ("The provider can revoke a capability, a principal, a policy rule or a tenant"), 13.2 item 5 (M, 4-6), 13.3 step 5. Staged scenarios: `docs/superpowers/specs/relying-party-wedge/verdict-matrix/revocation_local/` (14 files, with 010a to 010c in place of 010) and its `README.md`. Item 6 plan: `docs/superpowers/plans/2026-10-20-m1-item6-verifier-export.md` (`revocations_covering`, Decision 4).

**Reviews applied:** Root-2 `ws2:~/lanes/claude-pr1160-evidence/root2/review-1721-root2.md` (Q2 ACK with conditions, Q3 request changes, Q1 wording) and arc-5b `ws2:~/lanes/claude-pr1160-evidence/lead2/review-1721-arc5b.md` (B1 export coverage and `reason`, B2 capture wording and attribution, index-key fingerprint, nits, size).

**Census base:** facts below were read at `origin/main` `a93a2f69a3`, `feat/coop2c-federated-revocation` `180f014ea0` (#1607), `fix/root2-trace-publication` `734c7e2cb9` (#1708) and `feat/root-exchange-id-jag` (#1709). Task 1 re-reads every cited site at the integrated base.

## Facts this plan builds on

| # | Fact | Source |
|---|---|---|
| R1 | `revoked_capabilities(capability_id PK, revoked_at, revocation_index UNIQUE, admission_authority_commit_index UNIQUE)`, `revocation_delta_log`, `revocation_delta_meta`, `revocation_stream_meta`, and in joint mode `admission_authority_meta`, `admission_authority_commits(kind IN ('genesis','revocation'), capability_id FK)`. Schema version 1, key `revocation`. | `crates/platform/chio-store-sqlite/src/revocation_store.rs:719-800` |
| R2 | A joint (serving-owner) revocation opens on the serving owner's shared `Arc<StoreConnection>`; `begin_write` is `TransactionBehavior::Immediate`, verifies the fence and authority anchor and observes authority time; `record_revocation` appends the delta row, the admission commit and a global commit (`projection_kind = 'revocation'`) in that transaction; `revoke` commits and then syncs the authority anchor. `is_revoked` (`:630`) is its own deferred read transaction. | `revocation_store.rs:187-275,630-658`; `serving_owner.rs:906` |
| R3 | The global commit chain's `projection_kind` is a closed CHECK list and each kind has a reference digest and an exact-coverage clause. | `serving_owner/global_commit_chain.rs:47,990-1045,1095-1120,1740-1750` |
| R4 | In-transaction revocation readers, all by capability id: budget authorize-hold over `admission.revocation_set` (leaf plus every `delegation_chain` id, serving owner only, folds into `allowed`); composite capture, which returns `BudgetStoreError::Invariant("composite invocation capture includes a revoked authority member")`; native dispatch capture, which returns `invalid("native capture capability or ancestor is revoked")`. Both capture refusals occur after the upstream effect has run. | `budget_store/composite.rs:296-305`; `budget_store/composite/transitions/capture.rs:282-296` (error at 289-292); `admission_operation_store/security_participant_state/dispatch_ledger/capture.rs:64-78` (error at 76) |
| R5 | Every serve-http call with durable admission takes a budget hold through `durable_budget_binding` and `claim_and_authorize_budget_and_commit_admission`; that IMMEDIATE transaction is the admission commit. | `chio-kernel/src/kernel/validation.rs:1152-1215`; `admission_coordinator.rs:1381-1500` |
| R6 | Out-of-transaction reads: `check_tool_call_revocation_admission` (pre-dispatch, early deny) and the allowed-receipt recheck. At #1708 `734c7e2cb9`, `record_chio_receipt_with_federation` takes the local publication guard, calls `check_revocation` (`receipt_persistence.rs:251-253`, a completed read transaction per id), then `record_chio_receipt_during_trace_transition`, whose append runs separately (`:442-456`). A revoked hold from R4 reaches the kernel as `BudgetAuthorizeHoldDecision::Denied`, with no revocation attribution. | `validation/revocation_trace.rs:30-70`; `validation.rs:614-625`; #1708 `responses/receipt_persistence.rs:245-260,436-460`; `chio-kernel/src/budget_store.rs:596` |
| R7 | serve-http builds one `ChioKernel` per session (and per approval bind). #1708 replaces the kernel trace mutex with a per-kernel `PublicationSync`; `revoke_capability` takes `fence(true)`, the admission revocation check takes `fence(false)`. Lock domains are per kernel. | `session_core/factory.rs:131,164,401,608`; #1708 `kernel/publication_sync.rs` |
| R8 | `/admin/revocations` POST writes `store.revoke` directly (no kernel, no fence); it uses the durable runtime's local serving-owner store, falls back to a path-opened store from `revocation_db_path`, and forwards to trust-control when `control_url` is set. Body `{capabilityId}`; response `{capabilityId, revoked, newlyRevoked}`. | `remote_mcp/admin.rs:452-555,819-845`; `session_forms.rs:47` |
| R9 | A path open of a provisioned (serving-owner) database refuses: "provisioned sqlite authority store requires joint serving owner at epoch N". | `revocation_store.rs:117-123` |
| R10 | #1607 adds no table to `chio-store-sqlite`. It pages leaves of `chio-revocation-oracle`'s own SQLite tree (`chio_revocation_oracle_leaves`, passport `RevocationKey`) and adds control-plane passport feed, mirror and door checks. | `git diff --stat origin/main...feat/coop2c-federated-revocation` |
| R11 | #1709 computes `ReplayKey::digest()` = `SHA-256("chio.root-exchange.replay-key.v1\0" || namespace || 0 || issuer || 0 || id)` and records `replay_key_digest` and `root_policy_rule_id` in the delegation context. It binds the replay key before the root is signed; no `anchored_roots` table exists yet. | #1709 `root_exchange/replay.rs`, `exchange.rs:395-470` |
| R12 | `GuardEvidence { guard_name: String, verdict: bool, details: Option<String> }`; `guard_name` is a free string in the receipt schema. | `chio-core-types/src/receipt/metadata.rs:193`; `spec/schemas/chio-wire/v1/receipt/record.schema.json:408-430` |
| R13 | `KernelError::RevocationStore` reports the non-URN code `CHIO-KERNEL-REVOCATION-STORE`; G12 converts it in item 5. | `kernel/error.rs:796` |
| R14 | `RevocationStore` has 8 implementors: `InMemoryRevocationStore`, `SqliteRevocationStore`, CP `RemoteRevocationStore`, conformance `BlindRevocationStore` and four test doubles. | `chio-kernel/src/revocation_runtime.rs:16`; grep `impl RevocationStore for` |
| R15 | Item 6 consumes coverage through the plain store method `SqliteRevocationStore::revocations_covering(&self, roots: &[RevocationCoverageRoot]) -> Result<Vec<RevocationCoverage>, RevocationStoreError>` (Task 5; item 6 plan as amended by #1771); each exported entry carries the item 5 entry plus an unsigned `covered_capability_ids` list; a covering entry counts only when its `revoked_at` is at or before the receipt timestamp. | item 6 plan lines 486, 491 (Task 8 store methods and mapping) and 600 (Decision 4) |
| R16 | Subject and tenant tags are `HMAC-SHA256(index_key, ...)` over issuer and value; `index_key` is a 32-byte file loaded at startup. The subject is the provider record's principal claim (`subject_mapping.principal_source`, for example `oid` for Entra). | spec 7.12, G17 |

## Store reconciliation with #1607 (D17, spec 7.11 last paragraph)

#1607 and item 5 change disjoint stores. #1607 writes the passport sparse-Merkle oracle in `chio-revocation-oracle` (credential keys, signed epoch roots under `chio.trust.passport-revocation-root.v1`); item 5 writes `chio-store-sqlite`'s capability revocation store inside the serve-http state directory. No table, column, file or wire type is shared, and neither PR edits the other's files. The one store shape for capability revocation is the one in this plan. #1607 does not need to land before item 5; it lands before item 1 for the `passport-revocation-root` wrapper id, which is unrelated to this item. The lead records this on `sync.md` as the D17 reconciliation result (Task 1 Step 3).

## Signing form and item 1 sequencing

- #1607's epoch root signs under `chio.trust.passport-revocation-root.v1`, and the vectors under `spec/vectors/passport-revocation/v1/` change bytes in M1 item 1 (the signing wrapper). Item 5 neither reads, signs, verifies nor regenerates them, and depends on no passport-revocation artifact.
- Item 5 adds no signed artifact, no signed fixture and no signing vector. `chio.revocation-entry.v1` and `chio.revocation-admin-request.v1` are unsigned. Item 6 exports entries under the kernel-signed export manifest; that signature is item 6's and uses the post-wrapper form.
- The hashes item 5 adds are hash domains, not signature domains: `chio.revocation-entry-id.v1` (entry id) and `chio.sqlite-authority-revocation-entry-reference.v1` (chain reference digest); the subject and tenant tags are keyed values under the tenant index key set (item 2 Task 5, `subject-tag` and `tenant-tag` purposes), which adds no domain here. G5 leaves hash domains unchanged, so the wrapper does not alter them, and `scripts/check-signing-exemptions.py` (item 1) has nothing to list for item 5.
- The only signed bytes item 5 changes are deny receipts that gain the `chio.revocation` guard evidence (PR 2). Those receipts are signed by the existing producers in the post-wrapper, committed form. PR 2 tests assert decoded receipt members (`guard_evidence`, reason code) and verify signatures through the item 1 helper (`verify_wrapped` with the receipt schema id against the pinned kernel key); no test compares receipt bytes, signatures or a checked-in signed fixture, so no fixture joins item 1's `cargo xtask gen signed-fixtures` set.
- Sequencing (lead decision 2026-10-20): PR 0 and PR 1 sign nothing and may land before item 1. PR 2, PR 3 and PR 4 merge after item 1. PR 2 also waits for item 2, which follows item 1 (13.3). PR 3 waits for item 4's anchored-root store, which follows item 3, which follows item 1. PR 4 adds `spec/schemas/registry.json` rows and regenerated code, which item 1 rewrites, so it rebases on item 1's merged registry.
- arc-5b ACKs this plan on `sync.md` before any item 5 code starts (Task 1 Step 3).

## Global Constraints

- Merge order (precondition): #1708 (trace-lock publication fence) merges before PR 2, because both edit `kernel/validation/revocation_trace.rs` and the kernel revocation tests. M1 item 4's anchored-root store PR (the `anchored_roots` table, the tenant index with per-row `tag_key_id`, and the mint transaction) merges before PR 3. M1 item 2 (committed receipts, guard-evidence allowlist) merges before PR 2, so the revocation guard evidence is declared safe once. #1706 merges before PR 1 (module location `root_authority`).
- Every format is v1. `revocation_entries` lands in revocation store schema version 1 in place; fresh-only v1 catalog rules apply: no migration, no adoption of an older catalog, no second schema version, no `Legacy*` double, no default trait method that keeps `is_revoked` alive beside its replacement.
- Fail-closed: a store error on any revocation read denies (admission, capture), refuses (mint) or answers 503 (admin). An unknown target member, kind or shape rejects with no state change. A commit whose anchor sync fails reports outcome unknown and never reports success. The existing capture-time and pre-receipt rechecks stay as they are; item 5 neither removes nor weakens them.
- Privacy (spec 7.11, 7.12, 8.4): plaintext subjects and tenant values exist only in the admin request and in process memory while the tag is computed. They are never stored, logged, traced, echoed in a response, put in an error string or exported. `reason` is a closed enum, so no free text reaches the store or a caller bundle. The CLI reads plaintext from stdin only.
- Root-held edits are limited to: `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs` in PR 1 (Q2 ACK and its conditions, Task 3), and in PR 2 the narrow typed-refusal edits ACKed under Q11 (kernel `budget_store`, store `budget_store/composite.rs` and `composite/transitions/capture.rs`, the native dispatch ledger `dispatch_ledger/capture.rs`, and the `AdmissionOperationStoreError` and `AdmissionCaptureError` variants with their mapping closure, Task 4). No other Root-held file is edited: `tool_outcome`, store `security_state`, `serving_owner.rs`, http-core `receipt.rs`, CP `evidence_export/verification.rs`, and every part of the Q11 files outside the typed refusal.
- Clock reads only through the store clock (`self.clock`, `observe_authority_time`). Fixtures use fixed timestamps (`1792234800`). Run `python3 scripts/check-security-clocks.py` on every PR.
- Clippy denies `unwrap_used` and `expect_used` outside tests. Format with `cs cargo fmt --all`.
- No em dashes (U+2014). No narrative or meta comments; comments state invariants and contracts.
- Public-path rule: files under `spec/`, `docs/adr/`, `tests/`, `scripts/`, `crates/`, `sdks/` never mention milestones, the wedge, pilots or `docs/superpowers`.
- Build slots: on ws2, `cs` means `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/var/tmp/claude-targets/m1i5 ~/lanes/cslot.sh`; on x86 and host 3, `CARGO_INCREMENTAL=0 ~/cslot.sh` with that host's lane target dir. Every cargo command and every script that reaches cargo runs under `cs`.
- Work happens on ws2 in one worktree per PR off fresh `origin/main` fetched over https (`~/lanes/m1i5-pr<N>`). Coder checks under `cs`; heavy suites (chio-kernel, chio-store-sqlite, chio-control-plane, chio-cli, chio-conformance) on `integ-x86` and `integ-h3`. Never `git stash`. Inspect `git diff --cached --stat -M` before every commit. Push explicit SHAs over https.
- Shared surfaces: before requesting merge of a PR touching chio-kernel, chio-store-sqlite, chio-control-plane, chio-core-types or `spec/`, post `<UTC> <lane>: REVIEW? #<N> <scope>` to `ws2:~/lanes/claude-pr1160-evidence/lead2/sync.md`; at merge, `MERGING #<N>`, the full 10-minute window and the OBJECT check. PR 1 also needs Root-2's source review of the `global_commit_chain.rs` change.
- Commits follow conventional commits and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. PR bodies are written to lane-private `pr-<N>-<slug>-body.md` files and end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## Review Focus

1. **A target revocation that misses a live root.** Expected: entry insert, fan-out into `revoked_capabilities` and the mint-side entry check all run in IMMEDIATE transactions on the serving owner's one connection, so for every pair (revocation W, mint M) either M commits first and W's fan-out marks M's root, or W commits first and M refuses. Pinned in PR 3 by the barrier schedules S5 and S6 (Linearization) and by `revocation_and_mint_interleavings_never_leave_a_live_matching_root` (500 iterations against real SQLite).
2. **An in-transaction reader that stops seeing revocations.** Expected: no change to the R4 readers; every target revocation becomes `revoked_capabilities` rows that those readers already read. Pinned by schedules S1 to S3.
3. **An overclaim about publication.** Expected: the plan, PROTOCOL and spec 7.11 state the guarantee G-A/G-C/G-M (Linearization) and the disclosed receipt gap; no text says an acknowledgement prevents every later allowed receipt or guarantees that an admitted call completes. Pinned by schedules S4 and S9, which assert the gap as current behavior, including a check whose per-id reads straddle the revocation.
4. **Plaintext reaching disk, logs or exports.** Expected: only `subject_tag` and `tenant_tag` (64 lowercase hex) are stored; `reason` is a closed enum. Pinned in PR 3 by `subject_and_tenant_revocations_store_only_tags` (scans the database file, WAL and SHM bytes for the fixture marker) and in PR 4 by a log-capture test on the admin route.
5. **An entry lost on backup restore, or orphaned by a key change.** Expected: every entry advances the global commit chain, including an entry that matches no root; startup refuses when a tenant index key generation that a stored entry references is not loaded, and an entry tag with an unknown `key_id` refuses. Pinned in PR 1 by `restored_snapshot_missing_an_entry_refuses_open` and in PR 3 by `startup_refuses_when_only_a_revocation_entry_references_a_generation` and `revoke_under_n_then_admit_under_n_plus_1_denies`.
6. **A mis-attributed deny.** Expected: a deny names an entry only from evidence recorded by the read that refused, in the transaction that refused; no later read relabels an error. Pinned in PR 2 by `hold_denied_by_revocation_names_the_entry`, `capture_refused_by_revocation_names_the_entry`, `capture_failure_then_revoke_keeps_the_original_error` and `budget_denied_then_revoke_keeps_the_budget_denial`.
7. **Export coverage that depends on fan-out order.** Expected: `revocations_covering` derives coverage from `anchored_roots` columns, so a root first revoked by entry E1 is still covered by a later rule entry E2. Pinned in PR 3 by `later_rule_entry_covers_a_root_revoked_earlier`.

---

## File Structure

| Path | PR | Responsibility |
|---|---|---|
| `crates/core/chio-core-types/src/root_authority/revocation_entry.rs` (new) | 1 | `RevocationTarget`, `RevocationTargetKind`, `RevocationReason`, `RevocationEntryId`, `RevocationEntry`, id derivation, strict serde |
| `crates/platform/chio-store-sqlite/src/revocation_store.rs` | 1, 3 | `revocation_entries` DDL, entry column on `revoked_capabilities`, entry write, fan-out, mint check, reads, `revocations_covering` |
| `crates/platform/chio-store-sqlite/src/revocation_store/entry_tests.rs` (new), `target_tests.rs` (new) | 1, 3 | store tests |
| `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs` (Root-held, Q2 ACK) | 1 | `revocation_entry` projection kind, reference digest, coverage, absence and extra-row validation |
| `crates/kernel/chio-kernel/src/revocation_runtime.rs`, `src/revocation_store.rs` | 2 | trait `revocation_entry` replaces `is_revoked`; `TargetRevoked` error |
| `crates/kernel/chio-kernel/src/kernel/validation.rs`, `validation/revocation_trace.rs`, `evaluation/async_evaluation_core.rs`, `evaluation/nested_flow_evaluation.rs`, `responses/deny_responses.rs`, `kernel/error.rs`, `kernel/admission_coordinator.rs` (capture error mapping only) | 2 | attribution at hold and capture, guard evidence, URN |
| 8 `RevocationStore` implementors (R14) and every trait `is_revoked` caller | 2 | trait change |
| `crates/kernel/chio-kernel/src/budget_store.rs` (`DeniedBudgetHold.revoked_member`, `BudgetStoreError::Revoked`), `crates/platform/chio-store-sqlite/src/budget_store/composite.rs`, `composite/transitions/capture.rs`, `admission_operation_store/security_participant_state/dispatch_ledger/capture.rs` (Root-held, Q11 ACK) | 2 | typed revocation evidence recorded in the refusing transaction |
| `crates/kernel/chio-kernel/tests/durable_admission_sqlite/revocation_targets.rs` (new), `revocation_schedules.rs` (new) | 2, 3 | real-SQLite attribution tests and the deterministic two-kernel schedules |
| item 4's anchored-root store module in `chio-store-sqlite` and its mint call site in `chio-mcp-remote` | 3 | entry check inside the mint transaction; per-generation `revocation_entry_tags` rows and the referenced-generation startup check |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/error.rs` | 3 | `RootExchangeError::Revoked { entry_id }` |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs`, `admin/revocation_targets.rs` (new), `session_forms.rs`, `admin/revocation_batch.rs` | 4 | admin POST and GET, fail-closed rules, fallback deletion |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/tests/revocation_admin.rs` (new) | 4 | HTTP tests |
| `crates/platform/chio-control-plane/src/trust_control/service_types/structured_budget.rs` and its client conversion | 2 | revoked member on the remote authorize-hold response |
| `crates/platform/chio-control-plane/src/trust_control/{config_and_public,authority_handlers}.rs`, `service_runtime/{client,remote_stores}.rs` | 4 | forwarded capability revocation and listing on the entry wire |
| `crates/platform/chio-control-plane/src/trust_control/service_types/cluster_budget.rs`, `cluster/snapshots.rs` | 1 | replicated entry reason |
| `crates/products/chio-cli/src/cli/types/runtime.rs`, `src/cli/dispatch/mcp_revoke.rs` (new), `tests/mcp_revoke.rs` (new) | 4 | `chio mcp revoke` and `chio mcp revocations` |
| `spec/schemas/chio-wire/v1/root_authority/revocation-entry.schema.json`, `revocation-admin-request.schema.json` (new), examples, `spec/schemas/registry.json`, `MANIFEST.sha256`, `spec/wire-schemas.lock`, generated code | 4 | wire shapes |
| `spec/PROTOCOL.md` (`/admin/revocations` section near line 2946), `spec/errors/registry.yaml` | 2, 3, 4 | contract text and URNs |
| `scripts/check-domain-separation.py` inventory | 1, 3 | entry-id domain |
| `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md` 7.11, 8.3, 11.3 | 0 | revocation boundaries, index-key refusal, scenario count |
| staged `revocation_local` scenarios 010a, 010b, 010c | staged on `main` | replace 010; PR 2 names their tests |

## PR Grouping

| PR | Tasks | Branch | Title | Depends on | Root-held |
|---|---|---|---|---|---|
| 0 | 2 | `docs/m1i5-revocation-spec` | `docs(superpowers): state the revocation check and commit boundaries` | none | no |
| 1 | 3 | `feat/m1i5-revocation-entries` | `feat(store): record capability revocations as chained revocation entries` | #1706 | yes: `global_commit_chain.rs` (Q2 ACK) |
| 2 | 4 | `feat/m1i5-revocation-attribution` | `feat(kernel): name the revocation entry in hold and capture denials` | PR 1, #1708, item 1, item 2 | no (Root-active files, after #1708) |
| 3 | 5 | `feat/m1i5-revocation-targets` | `feat(store): revoke by root policy rule, subject, tenant and replay key` | PR 2, item 1, item 4 anchored-root store PR | no |
| 4 | 6, 7 | `feat/m1i5-revocation-admin` | `feat(mcp-remote): revocation target kinds on the admin route and chio mcp revoke` | PR 3, item 1 (registry) | no |

PRs 0 and 1 may land before item 1; PRs 2 to 4 merge after item 1. PRs 1 and 2 do not need item 4.

---

### Task 1: Base, census and coordination

**Files:** none changed. Output: `ws2:~/lanes/claude-pr1160-evidence/m1i5/census-<base>.md`.

- [ ] **Step 1: Preconditions per PR** (Global Constraints merge order). `gh pr view <N> --repo bb-connor/arc --json state` for #1706, #1708, item 1, the item 2 PR and the item 4 anchored-root store PR, as each PR needs them. A missing predecessor holds that PR; it does not reorder.
- [ ] **Step 2: Census at the integrated base.**
```bash
git grep -n "revoked_capabilities" -- crates ':!**/tests/**'
git grep -n -E "impl (chio_kernel::)?RevocationStore for"
git grep -n -E "\.is_revoked\(" -- crates ':!crates/trust/**' ':!**/revocation_view.rs'
git grep -n -E "CapabilityRevoked|DelegationChainRevoked" -- crates/kernel
git grep -n -E "revoked authority member|capability or ancestor is revoked" -- crates
git grep -n -E "AdmissionOperationStoreError::Invariant|AdmissionCaptureError::Invariant|BudgetStoreError::Invariant" -- crates/kernel crates/platform/chio-control-plane/src crates/platform/chio-store-sqlite/src
git grep -n -E "revocation_db_path|ADMIN_REVOCATIONS_PATH|AdminRevokeCapabilityRequest"
```
  Expected at `a93a2f69a3`: the R4 readers (3 non-test sites) plus the store's own; 8 implementors; about 69 `is_revoked` call lines of which about 20 go through the trait; the two capture refusal strings once each; `revocation_db_path` in factory, admin and config. Re-read R6 at the merged #1708 SHA and record the check and append line numbers.
- [ ] **Step 3: D17, arc-5b and Root-2.** Wait for arc-5b's plan ACK on `sync.md`. Post `<UTC> <lane>: D17 m1i5 store reconciliation: #1607 and item 5 share no store, table or wire type (oracle vs chio-store-sqlite); item 5 adds revocation_entries + revocation_entry chain kind (global_commit_chain.rs, Root-2 Q2 ACK) and states the G-A/G-C/G-M guarantee with the disclosed receipt gap (Root-2 Q3)` to `sync.md`, and wait for the lead's ACK and Root-2's re-review of the Linearization section.

---

### Task 2: Spec wording (PR 0)

**Files:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md` (7.11 "Linearization" paragraph, 8.3 startup refusals, 11.3 `revocation_local` count).

- [ ] **Step 1 (7.11):** Replace the paragraph from "Linearization:" to "'Next call' in this spec means exactly this." with:

  "Linearization: a revocation is one serving-writer transaction on the state-directory database, acknowledged after it commits and the authority anchor syncs. Let T be that commit. (1) Every budget authorize-hold transaction, which is where an admission commits, that begins after T denies, and the call does not dispatch. (2) Every root-exchange mint transaction that begins after T and matches the entry refuses. (3) A call admitted before T may dispatch. Its budget capture and its native dispatch capture re-check revocation inside the capture transaction, and a capture that begins after T refuses. By then the upstream effect has run and streamed chunks may already have reached the caller; the remaining output is withheld and the call ends with a revocation denial. (4) A call that captured before T reaches the allowed-receipt check, which is one read per id in the call's chain (the leaf, then each ancestor), each separate from the others and from the receipt append. If the read of the id the revocation marked begins after T the allowed receipt is refused; if it began before T the allowed receipt is appended, even when later reads or the append land after T. An acknowledgement therefore guarantees (1) to (3) and does not guarantee that no allowed receipt is appended after it, nor that a call admitted before it completes. 'Next call' in this spec means a call whose budget authorize-hold begins after the acknowledgement."
- [ ] **Step 2 (8.3):** No 8.3 text: spec 7.12 (#1732) states the rotating key set, the referenced-generation startup refusal and the unknown `key_id` refusal.
- [ ] **Step 3 (11.3):** `revocation_local` M1 count 12 becomes 14 (scenario 010 splits into 010a, 010b, 010c). The split, the README mutations and counts, and the matching protocol 5.6 fragment text are staged with the PR 0 wording; PR 2 names the tests.
- [ ] **Step 4:** `grep -rn $'\xe2\x80\x94' <changed files>; test $? -eq 1`.

---

### Task 3: Revocation entries, capability entries and the chain kind (PR 1)

**Files:**
- Create: `crates/core/chio-core-types/src/root_authority/revocation_entry.rs`; export from `root_authority/mod.rs`
- Modify: `crates/platform/chio-store-sqlite/src/revocation_store.rs`
- Create: `crates/platform/chio-store-sqlite/src/revocation_store/entry_tests.rs`
- Modify (Root-held, Q2 ACK): `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs`
- Modify: `scripts/check-domain-separation.py` (one inventory row)
- Modify (replicated reason): `crates/kernel/chio-kernel/src/revocation_store.rs` (`RevocationRecord`), CP `trust_control/service_types/cluster_budget.rs` (`RevocationDeltaResponse`), `trust_control/cluster/snapshots.rs` (`RevocationSnapshotExport`)

**Types (core-types):**

```rust
pub const REVOCATION_ENTRY_ID_DOMAIN: &[u8] = b"chio.revocation-entry-id.v1\0";

/// Closed set; unknown kinds reject at decode. `as_str` returns the serde name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTargetKind { CapabilityId, RootPolicyRule, AnchorSubject, TenantTag, ReplayKey }

/// Closed set (Q12). Exported as is; never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    OperatorRequest, CredentialCompromise, PrincipalOffboarded,
    TenantOffboarded, PolicyWithdrawn, IncidentResponse,
}

/// Stored form. `value` is the capability id, the rule id, or 64 lowercase hex
/// (subject tag, tenant tag, replay key digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationTarget { kind: RevocationTargetKind, value: String }
impl RevocationTarget {
    pub fn capability(id: &str) -> Result<Self>;          // 1..=512 bytes, no NUL
    pub fn root_policy_rule(rule_id: &str) -> Result<Self>;
    pub fn subject_tag(tag: Sha256Digest) -> Self;
    pub fn tenant_tag(tag: Sha256Digest) -> Self;
    pub fn replay_key(digest: Sha256Digest) -> Self;
    /// "rev_" + lowercase hex of
    /// SHA-256(REVOCATION_ENTRY_ID_DOMAIN || ascii(kind.as_str()) || 0x00 || utf8(value)).
    /// Kind names and values are NUL-free, so the preimage is injective. `reason`
    /// is not part of the id: the id names the target.
    pub fn id(&self) -> RevocationEntryId;
}

/// `chio.revocation-entry.v1`, unsigned. Exported by item 6 with role `revocation_entry`.
/// Fields are private; a value exists only through `RevocationEntry::new` or a
/// validated decode, so every held entry satisfies the invariants below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RevocationEntryWire", into = "RevocationEntryWire")]
pub struct RevocationEntry {
    entry_id: RevocationEntryId,
    target: RevocationTarget,
    revoked_at: u64,
    reason: RevocationReason,
}

/// Wire form. `deny_unknown_fields`; `schema` is a string only here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationEntryWire {
    schema: String,
    entry_id: String,
    target_kind: RevocationTargetKind,
    target_value: String,
    revoked_at: u64,
    reason: RevocationReason,
}

/// `TryFrom<RevocationEntryWire>` refuses, with `invalid revocation entry: <rule>`:
/// a `schema` other than "chio.revocation-entry.v1"; an `entry_id` that is not
/// "rev_" plus 64 lowercase hex; a `target_value` that does not satisfy its kind
/// (`RevocationTarget::capability` and `root_policy_rule` limits, or exactly 64
/// lowercase hex for the three digest kinds); `revoked_at = 0`; and an `entry_id`
/// not equal to `RevocationTarget { kind, value }.id()` (G18).
```

A repeated revocation of one target is idempotent: the first write's `revoked_at` and `reason` stand, on every path, replication included (below). Every decode of an entry (admin response, export bundle, replication, store read) goes through the validated form; the store also re-derives the id on read and refuses a row whose `entry_id` does not match its target. The id is equal across stores for `capability_id`, `root_policy_rule` and `replay_key` targets; tag targets are equal only under the same index key.

**Schema delta (in place, schema version 1):**

```sql
CREATE TABLE IF NOT EXISTS revocation_entries (
    entry_seq INTEGER PRIMARY KEY CHECK (entry_seq > 0),
    entry_id TEXT NOT NULL UNIQUE CHECK (
        length(entry_id) = 68 AND substr(entry_id, 1, 4) = 'rev_'
        AND substr(entry_id, 5) NOT GLOB '*[^0-9a-f]*'
    ),
    target_kind TEXT NOT NULL CHECK (target_kind IN (
        'capability_id', 'root_policy_rule', 'anchor_subject', 'tenant_tag', 'replay_key'
    )),
    target_value TEXT NOT NULL CHECK (
        length(target_value) BETWEEN 1 AND 512 AND instr(target_value, char(0)) = 0
    ),
    revoked_at INTEGER NOT NULL CHECK (revoked_at > 0),
    reason TEXT NOT NULL CHECK (reason IN (
        'operator_request', 'credential_compromise', 'principal_offboarded',
        'tenant_offboarded', 'policy_withdrawn', 'incident_response'
    )),
    UNIQUE (target_kind, target_value),
    CHECK (
        target_kind IN ('capability_id', 'root_policy_rule')
        OR (length(target_value) = 64 AND target_value NOT GLOB '*[^0-9a-f]*')
    )
) STRICT;

-- One row per tenant index key generation loaded when a tag entry is written
-- (Task 5). No rows for capability_id, root_policy_rule or replay_key entries.
CREATE TABLE IF NOT EXISTS revocation_entry_tags (
    entry_id TEXT NOT NULL REFERENCES revocation_entries(entry_id),
    tag_key_id TEXT NOT NULL CHECK (length(tag_key_id) = 64 AND tag_key_id NOT GLOB '*[^0-9a-f]*'),
    tag TEXT NOT NULL CHECK (length(tag) = 64 AND tag NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (entry_id, tag_key_id)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_revocation_entry_tags_match ON revocation_entry_tags(tag_key_id, tag);

-- revoked_capabilities gains, in its CREATE TABLE:
    revocation_entry_id TEXT NOT NULL REFERENCES revocation_entries(entry_id),
CREATE INDEX IF NOT EXISTS idx_revoked_capabilities_entry ON revoked_capabilities(revocation_entry_id);
```

`revoked_capabilities.revocation_entry_id` names the first entry that reached the capability; it is the deny attribution, not the export coverage (Task 5). `revocation_delta_meta`, `revocation_stream_meta`, `admission_authority_meta` and `admission_authority_commits` are unchanged. Replication carries the source entry: `RevocationRecord` (`chio-kernel/src/revocation_store.rs:27`, today `{capability_id, revoked_at}`) gains `reason: RevocationReason`, `revocation_delta_log` gains a `reason` column under the same closed CHECK, and the trust-control delta and snapshot records (`RevocationDeltaResponse`, `RevocationSnapshotExport`) carry it. Conflict rule: an entry is written once per store and never rewritten. A follower applying `upsert_revocation_if_newer` for a capability with no local entry writes the `capability_id` entry and the projection row with the source's `revoked_at` and `reason`, so the peer shows the source's entry. When the follower already holds an entry for that capability (its own local revoke, or divergent state after a leader change), the call commits nothing and returns `false`: the local entry and its `revoked_capabilities.revoked_at` stay as they are, so the projection always equals the entry, and export cut-offs on that store use the time that store began refusing the capability. The projection's newer-timestamp overwrite is removed for capabilities that have an entry, which after PR 1 is every revoked capability. Peers still receive capability rows only; target entries are local to the state directory (Q4).

**Global commit chain (Root-held, Q2 ACK conditions):**
- `'revocation_entry'` joins the closed `projection_kind` CHECK list. Mutation kind `revocation_entry_record`.
- Reference digest, domain-separated: `chio.sqlite-authority-revocation-entry-reference.v1` over `{entry_seq, entry_id, target_kind, target_value, revoked_at, reason, tags}`, where `tags` is the entry's `revocation_entry_tags` rows as `(tag_key_id, tag)` pairs sorted by `tag_key_id` (empty for every entry PR 1 writes). A tag row added, removed or altered after the commit fails the digest.
- Validation: every `revocation_entries` row has exactly one `authority_global_commits` row with `projection_kind = 'revocation_entry'`, `projection_key = entry_id`, `projection_sequence = entry_seq` (coverage); every such commit row has its entry (absence); no second commit row per entry (extra rows); each reference digest recomputes.
- An entry that matches no root still gets its commit (zero-match coverage). A restored database missing an entry refuses open (restore-loss refusal).
- The entry, its fan-out rows and every chain commit are written in one transaction; the serving-owner fence check, anchor verification and the existing anchor-sync failure semantics (`OutcomeUnknown`) apply unchanged.
- Fresh-only v1 catalog: a database whose catalog lacks the new table or CHECK value is refused, not adopted.

**Behavior:**
- `revoke(capability_id)` (trait) and `upsert_revocation_if_newer` write the `capability_id` entry (insert or keep) and the `revoked_capabilities` row with `revocation_entry_id` in one transaction; in joint mode the entry's global commit precedes the row's.
- `pub fn revocation_entry(&self, capability_id: &str) -> Result<Option<RevocationEntryId>>`: one indexed read.
- `pub fn list_revocation_entries_after(&self, after_seq: u64, kind: Option<RevocationTargetKind>, limit: usize) -> Result<RevocationEntryPage>`: one read snapshot, `entry_seq > after_seq` in ascending order, at most `limit` rows. `limit` must be 1 to 500; 0 or more than 500 refuses with `RevocationStoreError::InvalidPageLimit`, so an empty page always means the end of the stream. `RevocationEntryPage { entries: Vec<SequencedRevocationEntry { entry_seq: u64, entry: RevocationEntry }>, next_after: u64, head: u64 }`: `next_after` is the `entry_seq` of the last returned row, or `after_seq` when the page is empty; `head` is the highest `entry_seq` in the store. A caller pages by passing `next_after` back until a page is empty; `head` is informational and is never a cursor.
- Open refuses a `revoked_capabilities` row whose entry is absent (the FK check already runs at open, `verify_revocation_foreign_keys`).

- [ ] **Step 1: Failing tests** in `entry_tests.rs` (RED: none of the names exist):
```rust
#[test]
fn entry_ids_are_pinned_for_every_kind() {
    // one fixed value per kind; the five 68-char ids are computed once from the formula and pinned
    assert_eq!(RevocationTarget::capability("cap-fixture-1").unwrap().id().as_str(), "rev_<pinned>");
    // root_policy_rule "rule-fixture-1"; subject_tag, tenant_tag, replay_key over [0x11; 32], [0x22; 32], [0x33; 32]
}
#[test]
fn kind_is_part_of_the_id() // same value under two kinds yields two ids
#[test]
fn capability_revocation_records_and_names_one_entry() -> TestResult {
    let store = SqliteRevocationStore::open(&fixture_path("entry-1"))?;
    assert!(store.revoke("cap-fixture-1")?);
    assert!(!store.revoke("cap-fixture-1")?);
    assert_eq!(store.revocation_entry("cap-fixture-1")?, Some(RevocationTarget::capability("cap-fixture-1")?.id()));
    let page = store.list_revocation_entries_after(0, None, 10)?;
    assert_eq!((page.entries.len(), page.next_after, page.head), (1, 1, 1));
    Ok(())
}
#[test]
fn listing_pages_by_next_after_without_gaps_or_repeats() // 5 entries, limit 2: pages 2, 2, 1, then empty; every entry_seq once
#[test]
fn decoding_refuses_an_entry_that_breaks_an_invariant()  // wrong schema, non-hex tag value, entry_id not derived from its target: each "invalid revocation entry: ..."
#[test]
fn replicated_capability_entry_keeps_the_source_reason()   // source revokes with credential_compromise; follower with no entry stores the source entry
#[test]
fn replicated_entry_conflict_keeps_the_local_entry_and_projection() // follower already revoked with another reason and revoked_at: upsert returns false, entry and projection revoked_at unchanged and equal
#[test]
fn revoked_row_without_entry_refuses_open() -> TestResult {
    // insert a revoked_capabilities row with foreign_keys off, reopen
    assert_eq!(error.to_string(), "revocation store synchronization error: sqlite foreign key violation in `revoked_capabilities` row 1");
}
#[test]
fn table_refuses_non_hex_tag_values_and_unknown_reasons() // "CHECK constraint failed" for each
```
  Joint-mode tests (serving-owner fixture from `serving_owner/tests/authority_fixture.rs`, read-only use):
```rust
#[test] fn every_entry_advances_the_global_commit_chain()     // zero-match entry still adds one 'revocation_entry' commit
#[test] fn restored_snapshot_missing_an_entry_refuses_open()   // the existing authority-anchor rollback error, quoted exactly
#[test] fn deleting_an_entry_commit_fails_coverage()           // exact text from the coverage function
#[test] fn an_extra_entry_commit_fails_validation()
#[test] fn an_entry_commit_without_its_entry_fails_validation()
#[test] fn an_altered_entry_reason_fails_its_reference_digest()
#[test] fn anchor_sync_failure_after_entry_commit_reports_outcome_unknown()
```
- [ ] **Step 2:** Implement types, DDL, writes, reads, chain kind. Register the hash domain in `scripts/check-domain-separation.py`.
- [ ] **Step 3: Verify** (PR 1 block under Verification).

---

### Task 4: Attribution at hold and capture, guard evidence, URN, scenario 010 split (PR 2)

**Files:** `chio-kernel/src/revocation_runtime.rs`, `src/revocation_store.rs`, `src/kernel/validation.rs`, `src/kernel/validation/revocation_trace.rs`, `src/kernel/evaluation/{async_evaluation_core,nested_flow_evaluation}.rs`, `src/kernel/responses/deny_responses.rs`, `src/kernel/error.rs`, `src/kernel/admission_coordinator.rs` (capture error mapping), the 8 implementors (R14), every trait `is_revoked` caller, `spec/errors/registry.yaml`, `crates/core/chio-errors/src/_generated/error_codes.rs` (regenerated), `tests/durable_admission_sqlite/revocation_targets.rs` (new), the budget mutation event DDL and `budget_store/composite/model.rs` (persisted revoked member), CP `service_types/structured_budget.rs` and its client conversion (remote hold denial), `chio-kernel/src/budget_store/model.rs` (`BudgetMutationRecord`), CP `service_types/cluster_budget.rs` (`BudgetMutationEventView`) and `cluster/deltas.rs`, store `budget_store/store.rs` (`import_mutation_record`).

**Interface:**

```rust
pub trait RevocationStore: Send + Sync {
    /// The entry that revokes `capability_id`, if any. Entries are never removed,
    /// so a `Some` stays true for the life of the store.
    fn revocation_entry(&self, capability_id: &str) -> Result<Option<RevocationEntryId>, RevocationStoreError>;
    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError>;
    fn observe_revocation(&self, capability_id: &str) -> Result<RevocationObservation, RevocationStoreError>; // unchanged
    fn is_ephemeral(&self) -> bool; // unchanged
}
```

`is_revoked` is deleted from the trait and every caller uses `revocation_entry(..)?.is_some()`. `InMemoryRevocationStore` stores the entry id of `RevocationTarget::capability(id)`. CP `RemoteRevocationStore` (`service_runtime/remote_stores.rs:67-81`) keeps its trust-control read: `revoked: true` returns `Some(RevocationTarget::capability(id).id())`, which is valid because `capability_id` entry ids are equal across stores; `revoked: false` returns `None`; an omitted status stays an error, never `None`. From PR 4 the per-capability check also returns `entry_id`, and the client refuses a `revoked: true` answer whose `entry_id` is absent or differs from the derived id. Its `revoke` sends reason `operator_request` on the PR 4 wire, because the trait's `revoke` carries no reason.

**Behavior:**
- `check_revocation` returns `Err(KernelError::CapabilityRevoked(id))` / `DelegationChainRevoked(id)` as today (no variant change, so the recovery and active-response match sites are untouched). The entry id it records is the one returned by the same `revocation_entry` read that produced the deny.
- The pre-dispatch deny and the receipt-persistence deny attach `GuardEvidence { guard_name: "chio.revocation", verdict: false, details: Some(<entry id>) }`. Item 2's evidence allowlist declares `chio.revocation` `details` safe under committed disclosure.
- Attribution is causal: only typed evidence written by the refusing transaction names an entry. No read after the refusal attributes anything, so an unrelated error or budget denial followed by a revocation keeps its original error.
- Hold: the authorize-hold transaction's revocation loop (`composite.rs:296-305`) selects `revocation_entry_id` from `revoked_capabilities` for each member in order, and the first revoked member is recorded on the denial: `DeniedBudgetHold { .., revoked_member: Option<RevokedMember> }` with `RevokedMember { capability_id, entry_id }`. The kernel converts a denial with `revoked_member` into `CapabilityRevoked` (leaf) or `DelegationChainRevoked` (chain member) with the guard evidence. A denial without it is a budget denial, unchanged, even when a member is revoked later.
- Hold replay: the denial's member is persisted with the denied hold event in the refusing transaction. The budget mutation event row gains `revoked_member_capability_id` and `revoked_member_entry_id` (both NULL or both set, CHECK; the entry id under the `revocation_entries` id CHECK). `authorization_decision_from_event` (`composite.rs:952`) and `decision_from_persisted_event` (`composite/model.rs:1593`) rebuild `revoked_member` from those columns, so a retried request whose first response was lost gets the same attributed denial. A replay never reads `revoked_capabilities`; an event whose two columns are both NULL replays as a budget denial. The member also replicates: `BudgetMutationRecord` (`chio-kernel/src/budget_store/model.rs:354`) and the cluster `BudgetMutationEventView` (`service_types/cluster_budget.rs:264`) gain `revoked_member: Option<RevokedMember>` (wire `RevokedMemberWire`, present only on a denied authorization event), the delta and snapshot builders (`cluster/deltas.rs:1603-1700`) copy it, and `import_mutation_record` (`budget_store/store.rs:713-726`) writes both columns, so a retry served by a new leader after failover replays the same attributed denial.
- Capture: composite capture (`capture.rs:282-296`) returns `BudgetStoreError::Revoked { capability_id, entry_id }` in place of the revoked-member `Invariant`, and native dispatch capture (`dispatch_ledger/capture.rs:64-78`) returns its typed revoked refusal with the same two fields in place of `invalid("native capture capability or ancestor is revoked")`, each read in the capture transaction. The kernel attributes only those typed refusals. Every other capture error keeps its original error and path. The existing post-effect handling (output withholding, unknown-outcome custody, settlement idempotency) is unchanged for both.
- Typed refusal definition and mapping closure (Q11 ACK). One shared value `RevokedMember { capability_id: String, entry_id: RevocationEntryId }` in `chio-kernel` (`budget_store.rs`), carried by:
  - store-side errors: `BudgetStoreError::Revoked(RevokedMember)` (kernel `budget_store.rs`), returned by composite capture; `AdmissionOperationStoreError::Revoked(RevokedMember)` (kernel `admission_operation/store.rs`), returned by native dispatch capture at `dispatch_ledger/capture.rs:76` in place of `invalid(..)`; `AdmissionCaptureError::Revoked(RevokedMember)` (kernel `admission_operation`), produced by the existing `BudgetStoreError` to `AdmissionCaptureError` conversion. Every other `invalid(..)` and `Invariant` use is unchanged.
  - remote authority (trust-control joint admission RPC): `AdmissionAuthorityErrorCode::Revoked` and `AdmissionAuthorityWireError.revoked_member: Option<RevokedMemberWire>` (`service_types/admission_authority.rs`), present exactly when the code is `revoked`; a wire error with one and not the other fails decoding. The server mappings `operation_store_error`, `admission_capture_error` and the budget error mapping (`service_runtime/admission_authority.rs:852-881`) emit it; the client mappings `operation_error` (`remote_admission.rs:1091-1108`) and `into_budget_store_error` (`service_runtime/errors.rs:11`) restore the typed variant. A `revoked` code without a valid member maps to `Invariant` and is not attributed. A revoked authorize-hold is not an error on this wire: the server returns it as a successful `StructuredBudgetAuthorizeResponse` built by `from_core` (`service_runtime/admission_authority.rs:766-823`). `StructuredBudgetAuthorizeResponse` (`service_types/structured_budget.rs:894-906`) therefore gains `revoked_member: Option<RevokedMemberWire>`, `from_core` copies it from `DeniedBudgetHold`, and the client conversion back to `BudgetAuthorizeHoldDecision` restores it. A member with a `decision` other than `denied` fails decoding.
  - kernel: `durable_store_error` keeps wrapping store errors; the deny mapping converts a `Revoked(member)` from hold, composite capture or native capture into `CapabilityRevoked` (member is the leaf) or `DelegationChainRevoked` (member is a chain id), only when `member.capability_id` is in the hold's `revocation_set`; otherwise the error stays as returned.
  - custody: a `Revoked` refusal is a definite refusal of a rolled-back transaction and takes exactly the path the revoked-member `Invariant` takes today (output withholding, custody retention, settlement idempotency); `OutcomeUnknown`, `Unavailable`, `Fenced` and every unrelated `Invariant` keep their paths. Task 1's census lists every match on these error enums in post-effect, custody and recovery code, and each gains `Revoked` on the arm that handled the revoked-member `Invariant`.
- `KernelError::RevocationStore` reports `urn:chio:error:kernel:revocation-store` (G12); the code is registered in `spec/errors/registry.yaml`.
- Scenarios 010a to 010c are already staged in place of 010 (`revocation-local-010a-revocation-before-capture-denies`, deny, `urn:chio:error:capability:revoked`; `010b-revocation-after-capture-before-receipt-check-denies`, deny, same code; `010c-revocation-after-receipt-check-appends-allowed`, allow, `urn:chio:error:none`, the disclosed gap), with README mutations `revoke_before_capture`, `revoke_after_capture_before_receipt_check` and `revoke_after_receipt_check_before_append` and the category count at 14. PR 2 names the test that asserts each one's `expected` block.

- [ ] **Step 1: Failing tests.** Kernel lib tests (in-memory stores):
```rust
#[test] fn revocation_deny_receipt_names_the_entry()        // guard_evidence == [GuardEvidence{"chio.revocation", false, Some(entry)}]
#[test] fn chain_revocation_deny_names_the_ancestor_entry()
#[test] fn revocation_store_error_reports_the_urn()          // report code "urn:chio:error:kernel:revocation-store"
```
  Real-SQLite tests in `tests/durable_admission_sqlite/revocation_targets.rs`:
```rust
#[test] fn hold_denied_by_revocation_names_the_entry()
#[test] fn capture_refused_by_revocation_names_the_entry()          // composite capture
#[test] fn native_capture_refused_by_revocation_names_the_entry()
#[test] fn budget_exhaustion_is_not_attributed_to_revocation()
#[test] fn non_revocation_capture_error_is_not_attributed()         // capture invariant with no entry keeps its error
#[test] fn capture_failure_then_revoke_keeps_the_original_error()   // barrier: capture fails on an unrelated invariant; W commits a matching entry; the kernel's error is the original one, no guard evidence
#[test] fn budget_denied_then_revoke_keeps_the_budget_denial()      // barrier: hold denied for budget; W commits a matching entry; the denial stays a budget denial
#[test] fn revoked_refusal_round_trips_the_remote_authority()       // store -> wire `revoked` + member -> client -> kernel: same RevokedMember
#[test] fn revoked_wire_code_without_member_is_not_attributed()     // and member without code fails decoding
#[test] fn revoked_capture_refusal_takes_the_invariant_custody_path() // output withheld, custody and settlement state equal to the pre-change revoked-member Invariant run
#[test] fn unrelated_native_invalid_keeps_its_error_and_custody()
#[test] fn revoked_hold_denial_round_trips_the_remote_success_wire() // control_url: authorize-hold Denied with revoked_member -> StructuredBudgetAuthorizeResponse -> client: same RevokedMember, CapabilityRevoked with guard evidence
#[test] fn replayed_revoked_hold_names_the_same_entry()             // first response dropped; retry of the same request replays the persisted event with the same RevokedMember
#[test] fn replayed_revoked_hold_after_failover_names_the_same_entry() // denied event replicated to a follower; leader change; retry on the new leader: same RevokedMember
```
- [ ] **Step 2:** Implement; regenerate error codes (`cs cargo xtask codegen`); name the tests for staged 010a to 010c.
- [ ] **Step 3: Verify** (PR 2 block). The full chio-kernel suite and native-cage chio-cli and chio-conformance run on the integrators.

---

### Task 5: Target kinds, fan-out, mint check, coverage and index-key generations (PR 3)

**Files:** `chio-store-sqlite/src/revocation_store.rs`, `src/revocation_store/target_tests.rs` (new), item 4's anchored-root store module (the insert function), `chio-mcp-remote/src/remote_mcp/root_exchange/error.rs`, the mint call site item 4 owns, `tests/durable_admission_sqlite/revocation_schedules.rs` (new), `spec/errors/registry.yaml`, `scripts/check-domain-separation.py`.

**Contract required from item 4** (item 4 owns these; PR 3 fails review if any is missing):
- `anchored_roots`: `capability_id TEXT PRIMARY KEY`, `root_policy_rule_id TEXT NOT NULL`, `tag_key_id TEXT NOT NULL` (the generation that computed both tags), `subject_tag TEXT NOT NULL` (64 hex, HMAC of the provider record's principal claim, R16), `tenant_tag TEXT` (64 hex or NULL when the rule has no tenant), `replay_key_digest TEXT NOT NULL` (64 hex, R11), `expires_at INTEGER NOT NULL`, with item 4's indexes `root_policy_rule_id`, `replay_key_digest`, `(tag_key_id, subject_tag)` and `(tag_key_id, tenant_tag)`, which the fan-out and coverage joins use.
- Every insert goes through the serving owner's connection in an IMMEDIATE transaction; the root is returned to the client only after that transaction commits.
- Rows are retained as long as any receipt under the root is retained, so export coverage stays computable (R15).
- Index-key generations: the tenant index key set rotates (item 2 Task 5, all-generation match mode). Each `anchor_subject` and `tenant_tag` entry's `target_value` is the tag under the active generation, and the entry id derives from it. In the same transaction the entry writes one `revocation_entry_tags` row per loaded generation (`key_ids()` with `derive_in` over the admin plaintext), so the entry carries its tag under every generation that can have tagged a live or retained root. Every match is on `(tag_key_id, tag)` against those rows: the fan-out joins `anchored_roots (tag_key_id, subject_tag | tenant_tag)` to them, coverage does the same (below), and the mint check derives the request's tag under every loaded generation and looks each pair up, so a generation added after the revocation still refuses the target. Open validates every entry's tag rows: an `anchor_subject` or `tenant_tag` entry has at least one row and exactly one row whose `tag` equals its `target_value`, and every other kind has none; a violation refuses open with `revocation entry <entry id> has inconsistent tag rows`. Because a tag entry writes a row under every generation loaded at write time, every such generation stays pinned for the life of the store (entries are never removed); operators retire a generation only from the active role, never unload it. Startup refuses when a generation that any `revocation_entry_tags` row references is not loaded (`tenant index key generation <key_id> referenced by a revocation entry is not loaded`), and an entry or request naming an unknown `key_id` refuses. Tests: `startup_refuses_when_only_a_revocation_entry_references_a_generation`, `revoke_under_n_then_admit_under_n_plus_1_denies`, `revocation_entry_with_unknown_key_id_refuses`, `rotation_to_a_new_active_generation_starts_and_keeps_old_entries_matching`, `entry_written_under_b_covers_a_root_tagged_under_a`.

**Store API:**

```rust
impl SqliteRevocationStore {
    /// Records the entry and marks every matching anchored root revoked, in one
    /// IMMEDIATE transaction. Returns the stored entry, whether it is new, how many
    /// anchored roots match the target, and how many of them this call marked.
    pub fn revoke_target(&self, target: &RevocationTarget, reason: RevocationReason)
        -> Result<TargetRevocation, RevocationStoreError>;
}
/// `roots_matched` counts every `anchored_roots` row matching the target, already
/// revoked or not; `roots_revoked` counts the rows this call inserted.
pub struct TargetRevocation { pub entry: RevocationEntry, pub newly_revoked: bool, pub roots_matched: u64, pub roots_revoked: u64 }

/// Called inside item 4's anchored-root insert transaction, before the insert.
pub(crate) fn refuse_revoked_root(tx: &Transaction<'_>, root: &AnchoredRootTargets<'_>)
    -> Result<(), RevocationStoreError>;   // RevocationStoreError::TargetRevoked { entry_id }

pub struct AnchoredRootTargets<'a> {
    pub root_policy_rule_id: &'a str,
    /// The request's subject tag under every loaded generation.
    pub subject_tags: &'a [KeyedIndexValue],
    /// The request's tenant tag under every loaded generation; empty when the rule has no tenant.
    pub tenant_tags: &'a [KeyedIndexValue],
    pub replay_key_digest: &'a Sha256Digest,
}

impl SqliteRevocationStore {
    /// Export coverage for item 6 (R15), read through `ExportStores::revocations`.
    /// A plain inherent method: chio-control-plane depends on chio-store-sqlite,
    /// so no store trait sits between them.
    pub fn revocations_covering(&self, roots: &[RevocationCoverageRoot])
        -> Result<Vec<RevocationCoverage>, RevocationStoreError>;
}

// chio-core-types `root_authority::revocation_entry`, beside `RevocationEntry`.
pub struct RevocationCoverageRoot { pub root_capability_id: String, pub capability_ids: Vec<String> }
pub struct RevocationCoverage { pub entry: RevocationEntry, pub covered_capability_ids: Vec<String> }
// RevocationStoreError::AnchoredRootMissing { capability_id }
```

Item 6 reads it through `ExportStores { exchange, receipts, revocations }` (item 6 plan, `evidence_export/stores.rs`), whose `revocations` member is a borrowed `&SqliteRevocationStore`; there is no store trait. The item 6 mapping builds `RevocationCoverageRoot` from each presentation, wraps each `RevocationCoverage` as an `ExportedRevocationEntry`, fails the export with `urn:chio:error:attest:export-evidence-incomplete` on `RevocationStoreError::AnchoredRootMissing`, and fails it with the internal export failure on every other `RevocationStoreError`; no store error becomes an empty list. On a store opened without a joint serving owner (no `anchored_roots`), the method refuses with `RevocationStoreError::CoverageRequiresServingOwner`, displayed `revocation coverage requires the serving-owner state directory`. PR 3 merges before item 6c and depends on no item 6 type; item 6c's Task 8 consumes these names as written here.

- Fan-out: `INSERT` into `revoked_capabilities` for every `anchored_roots` row that matches the entry (target column equal to the entry value for `root_policy_rule` and `replay_key`; `(tag_key_id, tag)` in the entry's `revocation_entry_tags` rows for `anchor_subject` and `tenant_tag`) and is not already revoked, expired roots included; each through `record_revocation` (delta row, admission commit, global commit) with `revocation_entry_id`. Expiry is not a filter: composite capture rechecks revocation and supplemental expiry but not capability expiry (`composite/transitions/capture.rs:279-335`), so a call admitted before its root expired can still capture after it, and only a `revoked_capabilities` row refuses that capture (G-C). The fan-out therefore reads no clock and compares no `expires_at`. Rows for expired roots are bounded by the item 4 retention rule. `capability_id` targets keep the PR 1 path.
- Retry with a different reason: the stored entry is returned unchanged with `newly_revoked = false`; the admin response sets `reason_conflict = true`.
- Mint error path: item 4's `SqliteRootExchangeStore::mint_anchored_root(MintRequest, &dyn MintRevocationCheck)` returns `RootExchangeStoreError`. PR 3 provides the one production `MintRevocationCheck`, which calls `refuse_revoked_root` on the mint's open IMMEDIATE transaction (item 4 step 2). `mint_anchored_root` maps `RevocationStoreError::TargetRevoked { entry_id }` to `RootExchangeStoreError::Revoked { entry_id }`, and every other `RevocationStoreError` to `RootExchangeStoreError::RevocationCheckUnavailable`, which the token endpoint and bearer intake answer 503 `temporarily_unavailable` with no description. No root is inserted or returned on either path.
- Mint check: one indexed lookup of `(target_kind, target_value)` for the rule and replay-key pairs, plus one indexed lookup of `revocation_entry_tags (tag_key_id, tag)` joined to the entry's kind for the request's subject and tenant tags under every loaded generation; `LIMIT 1` each. `AnchoredRootTargets` carries those per-generation tags as item 2's `KeyedIndexValue { key_id, value }` (the same candidate form as item 4's `candidate_tags`). When more than one entry matches, the lookup returns the lowest `entry_seq`, so the refusal names one entry deterministically. A match raises `TargetRevoked { entry_id }`, displayed `anchored root matches revocation entry <entry id>`; the exchange maps `RootExchangeStoreError::Revoked { entry_id }` to `RootExchangeError::Revoked { entry_id }`, OAuth `invalid_grant`, URN `urn:chio:error:transport:exchange-revoked` (registered here).
- Bearer intake that maps a token digest to an existing root (`bearer_token_roots`) needs no check: the root is already in `revoked_capabilities`.
- Coverage: for each `RevocationCoverageRoot` (root capability id plus the capability ids under it that the bundle carries), an entry covers the root when the root's `anchored_roots` row matches it by the fan-out rule above (column equality for `root_policy_rule` and `replay_key`; the root's `(tag_key_id, subject_tag)` or `(tag_key_id, tenant_tag)` in the entry's `revocation_entry_tags` rows for `anchor_subject` and `tenant_tag`, so an entry written under generation B covers a root tagged under A), and covers an id when the entry is a `capability_id` entry for that id. The result lists each covering entry once with `covered_capability_ids` sorted and deduplicated. Coverage reads `anchored_roots`, `revocation_entries` and `revocation_entry_tags` only, in one read snapshot, never `revoked_capabilities`, and includes expired roots. Item 6 applies the `revoked_at` cut-off and the chain cascade (R15). A ref whose root capability id has no `anchored_roots` row (retention bug, restore, pruned row) fails the whole call with `RevocationStoreError::AnchoredRootMissing { capability_id }`, displayed `anchored root row missing for <capability id>`, and the export fails; coverage is never computed from a partial set. The mint path inserts the row and never reads an existing one, and admission, capture and receipt checks read `revoked_capabilities`, not `anchored_roots`, so no other path needs this refusal; the fan-out reads `anchored_roots`, and a live root without its row cannot exist under the item 4 contract (the root is released only after its row commits; restore loss is caught by the chain).

- [ ] **Step 1: Failing tests** (`target_tests.rs`, joint serving-owner fixture with item 4's table):
```rust
#[test] fn root_policy_rule_revocation_marks_every_live_root_under_the_rule_only()
#[test] fn anchor_subject_revocation_marks_every_live_root_with_the_tag_only()
#[test] fn tenant_revocation_marks_every_live_root_in_the_tenant_only()
#[test] fn replay_key_revocation_marks_the_one_root()
#[test] fn fan_out_marks_expired_matching_roots()                 // a call admitted before its root expired: capture after W refuses
#[test] fn repeated_target_revocation_is_idempotent()           // same entry, newly == false, no extra delta rows
#[test] fn retry_with_a_different_reason_keeps_the_first()
#[test] fn zero_match_revocation_reports_zero_roots()           // roots_matched == 0 and roots_revoked == 0
#[test] fn already_revoked_roots_count_as_matched_not_revoked()  // second entry over the same roots: roots_matched == n, roots_revoked == 0
#[test] fn mint_matching_an_entry_is_refused_with_the_entry()   // "anchored root matches revocation entry rev_..."
#[test] fn revocation_and_mint_interleavings_never_leave_a_live_matching_root() // 500 iterations, barrier
#[test] fn later_rule_entry_covers_a_root_revoked_earlier()      // capability entry first, rule entry second: both cover
#[test] fn coverage_includes_expired_roots_and_ignores_unrelated_entries()
#[test] fn coverage_refuses_when_anchored_root_row_missing()      // RevocationStoreError::AnchoredRootMissing { capability_id }, exact display; no partial result
#[test] fn coverage_on_a_non_joint_store_refuses()               // RevocationStoreError::CoverageRequiresServingOwner, exact display
#[test] fn tag_entry_without_tag_rows_refuses_open()              // delete an entry's revocation_entry_tags rows with the chain digest recomputed by hand: open refuses
#[test] fn subject_and_tenant_revocations_store_only_tags()      // marker absent from db, -wal, -shm bytes
#[test] fn fan_out_failure_rolls_back_the_entry()                // trigger RAISE(ABORT) on revoked_capabilities insert: no entry, no rows
```
- [ ] **Step 2:** Implement; wire `refuse_revoked_root` into item 4's insert; implement `revocations_covering`.
- [ ] **Step 3:** The two-kernel schedules S1 to S9 (Linearization) in `revocation_schedules.rs`.
- [ ] **Step 4: Verify** (PR 3 block).

---

### Task 6: Admin route (PR 4)

**Files:** `remote_mcp/admin.rs`, `admin/revocation_targets.rs` (new), `session_forms.rs`, `admin/revocation_batch.rs`, `remote_mcp/tests/revocation_admin.rs` (new), schemas under `spec/schemas/chio-wire/v1/root_authority/`, `spec/PROTOCOL.md`; for the forwarded path, CP `trust_control/config_and_public.rs` (`RevokeCapabilityRequest`, `RevokeCapabilityResponse`), `trust_control/authority_handlers.rs` (revoke and list handlers), `service_runtime/client.rs` and `service_runtime/remote_stores.rs`.

**`POST /admin/revocations`** body (`revocation-admin-request.schema.json`, strict at every level, tagged union through `lossless_serde!`):

```json
{"target": {"kind": "capability_id", "capability_id": "cap_..."}, "reason": "principal_offboarded"}
{"target": {"kind": "root_policy_rule", "rule_id": "okta-agents"}, "reason": "policy_withdrawn"}
{"target": {"kind": "anchor_subject", "issuer": "https://acme.okta.com", "subject": "00u..."}, "reason": "principal_offboarded"}
{"target": {"kind": "tenant_tag", "issuer": "https://acme.okta.com", "tenant": "acme-eu"}, "reason": "tenant_offboarded"}
{"target": {"kind": "replay_key", "anchor_kind": "oauth_id_jag", "issuer": "https://acme.okta.com", "assertion_id": "jti-..."}, "reason": "credential_compromise"}
```

`reason` is required and closed. For `anchor_subject`, `subject` is the value of the provider record's principal claim (`subject_mapping.principal_source`, for example the Entra `oid`), the value item 4 tags; the issuer is the record's issuer.

Response 200: `{"entry": <chio.revocation-entry.v1>, "newly_revoked": bool, "roots_matched": <u64>, "roots_revoked": <u64>, "reason_conflict": bool}`, sent only after the commit and the authority-anchor sync. `roots_matched` and `roots_revoked` are the `TargetRevocation` counts (Task 5) and are 0 for a `capability_id` target.

**`GET /admin/revocations`**: `?after=<seq>&limit=<n>&kind=<kind>` returns `{"entries": [{"entry_seq": <seq>, "entry": <chio.revocation-entry.v1>}, ...], "next_after": <seq>, "head": <seq>}` from one `list_revocation_entries_after` snapshot; the caller passes `next_after` as the next `after` until `entries` is empty; `limit` outside 1 to 500 answers 400 `invalid revocation request`; `?capability_id=<id>` returns `{"capability_id", "revoked", "entry_id"}`. No GET takes a plaintext subject or tenant.

**Fail-closed rules (status, exact body):**

| Condition | Status | Body |
|---|---|---|
| admin token not configured | 403 | `remote admin API is disabled` (existing) |
| missing or wrong bearer | 401 | `missing or invalid admin bearer token` (existing) |
| unknown member, unknown kind, unknown reason, missing reason, oversized body, empty or NUL value | 400 | `invalid revocation request` |
| `rule_id` not in the loaded root policy | 422 | `revocation target names no rule in the loaded root policy` |
| `issuer` not the issuer of any provider record or non-provider anchor kind | 422 | `revocation target names an unknown issuer` |
| `replay_key` with an `anchor_kind` that has no assertion id (`operator_static_bearer`, `chio_local_as`, `chio_operator_key`, `oauth_introspection`), or `entra_agent_id` before M2 | 422 | `revocation target kind has no assertion id for this anchor kind` |
| `control_url` (remote durable admission) and kind other than `capability_id` | 409 | `revocation target kind requires the local admission store` |
| no local serving-owner store | 409 | `remote trust admin requires durable revocation state` (existing text; the path-open fallback is deleted) |
| store error before commit, writer busy past `busy_timeout`, or tenant index unavailable | 503 | `revocation store unavailable` |
| commit outcome unknown (anchor sync failed), or any later request on the poisoned serving owner | 503 | `revocation outcome unknown; restart the provider, then retry the same request` |

- Retry of the same request under the same active generation returns the same entry with `newly_revoked = false`. A tag-kind retry after the active generation rotates records a second entry and reports `newly_revoked` again (item 4 Decision 10, "Item 5 amendment"); both entries deny, and attribution names the lowest `entry_seq`. A retry with a different reason after rotation records that second entry with the new reason and `reason_conflict = false`, because no stored entry was hit; the first entry keeps its own reason.
- Outcome unknown is not retryable in the same process. `outcome_unknown` poisons the serving owner (`serving_owner.rs:181-199`), and every later read and write on it, revocation, admission and mint alike, returns `OutcomeUnknown` until the process exits (`require_unpoisoned`, `:234-240`). Recovery is a provider restart: the reopen runs `reconcile_startup` (`serving_owner/rollback_anchor.rs:117`), which accepts a database one commit ahead of its anchor and re-anchors it, or refuses open. After the restart, a retry of the same request returns the committed entry with `newly_revoked = false`, or writes it fresh if the commit did not land.
- With `control_url`, a `capability_id` revocation forwards to trust-control `POST /v1/revocations` over an upgraded wire: `RevokeCapabilityRequest` (`trust_control/config_and_public.rs:25`) becomes `{capabilityId, reason}` and `RevokeCapabilityResponse` (`:31`) becomes `{entry, newlyRevoked}`, written by trust-control's own `SqliteRevocationStore` through the PR 1 entry path. serve-http returns the same 200 body as the local path (`roots_matched = roots_revoked = 0`, `reason_conflict` against the returned entry). `GET` forwards to trust-control's list handler, which gains the same `after`, `kind` and `limit` page form and the per-capability check. `RemoteRevocationStore` (`service_runtime/remote_stores.rs:87`) reads `newlyRevoked` from the new response. The old `{capabilityId, revoked, newlyRevoked}` body is removed in the same PR.
- Tags are computed with item 4's tenant index (`subject_tag(issuer, subject)`, `tenant_tag(issuer, tenant)`); the plaintext is dropped before the store call. The request body is not logged; tracing records the entry id, kind and reason only.
- `revocation_batch.rs` (session trust revoke) writes `capability_id` entries with reason `operator_request` through the same store path.
- The path-opened `SqliteRevocationStore::open(revocation_db_path)` fallback in `open_revocation_store` is deleted (it is a second writer outside the serving owner). If item 4 has already deleted `revocation_db_path`, this is a no-op.
- The admin route takes no kernel fence. It does wait on the shared writer: the serving owner's connection lock and the SQLite writer lock, including any in-flight transaction and its fsync. No progress or fairness bound is claimed.

- [ ] **Step 1: Failing tests** in `revocation_admin.rs`, one per table row with the exact status and body, plus `each_target_kind_round_trips_and_denies_the_next_call` (in-process serve-http harness), `plaintext_subject_never_appears_in_logs_or_responses` (tracing capture), `outcome_unknown_poisons_until_restart_then_retry_returns_the_same_entry` (fault-injected anchor sync: the retry before restart gets the outcome-unknown 503; after restart, with no rotation in between, it gets the same entry with `newly_revoked = false`), `tag_retry_after_rotation_records_a_second_entry_and_both_deny`, `retry_with_another_reason_reports_conflict`, `listing_pages_through_next_after`, and with a trust-control fixture `control_url_capability_revocation_returns_the_entry_and_reason` and `control_url_listing_pages_through_next_after`.
- [ ] **Step 2:** Implement; register `chio.revocation-entry.v1` and `chio.revocation-admin-request.v1` with positive and negative examples (padding, unknown kind, unknown reason, non-hex tag); `cs cargo xtask codegen`; PROTOCOL `/admin/revocations` subsection with the target table, the guarantee G-A/G-C/G-M with the disclosed receipt gap, and the status table.

---

### Task 7: `chio mcp revoke` (PR 4)

**Files:** `chio-cli/src/cli/types/runtime.rs` (under `McpCommands`), `src/cli/dispatch/mcp_revoke.rs` (new), `tests/mcp_revoke.rs` (new).

```text
chio mcp revoke capability --url <serve-http base> --capability-id <id> --reason <reason> [--json]
chio mcp revoke rule       --url <base> --rule-id <id> --reason <reason> [--json]
chio mcp revoke subject    --url <base> --issuer <uri> --reason <reason> [--json]   # principal claim value from stdin
chio mcp revoke tenant     --url <base> --issuer <uri> --reason <reason> [--json]   # tenant value from stdin
chio mcp revoke replay-key --url <base> --anchor-kind <kind> --issuer <uri> --assertion-id <jti|uti> --reason <reason> [--json]
chio mcp revocations list  --url <base> [--kind <kind>] [--after <seq>] [--limit <n>] [--json]
chio mcp revocations check --url <base> --capability-id <id> [--json]
```

- `--reason` takes the closed enum values (clap `ValueEnum`).
- The admin token comes only from `CHIO_ADMIN_TOKEN`; there is no argv form. Missing token exits non-zero with `CHIO_ADMIN_TOKEN is required` before any request.
- Plaintext subject and tenant come only from stdin (one line, trailing newline stripped, empty refused, 4096-byte cap).
- For a non-`capability_id` kind with `roots_matched = 0`, stderr prints `warning: no anchored root matched; the entry refuses future mints only`. `roots_matched > 0` with `roots_revoked = 0` (an idempotent retry, or roots already revoked by another entry) prints no warning. `reason_conflict = true` prints `warning: target already revoked with reason <stored>; the stored reason is kept`. Both are also in `--json` output.
- The HTTP client uses the CLI's existing blocking client with a bounded response read and is added to the egress contract inventory; `scripts/check-http-egress-contract.sh` passes.
- Any non-200 prints the server body and exits 2; outcome unknown exits 3, and a script retries after the provider restarts.
- `chio trust revoke` (trust-control and local revocation databases, capability only) is unchanged. Pointed at a serve-http state database it refuses through R9; `trust_revoke_refuses_a_serving_owner_database` pins that.

- [ ] **Step 1: Failing tests** in `tests/mcp_revoke.rs` against a spawned `serve-http` (native-cage run on the integrator): each subcommand, token-missing refusal, stdin-only plaintext, both warnings, exit codes 2 and 3.
- [ ] **Step 2:** Implement.

---

## Linearization

**Transactions.** A revocation is one IMMEDIATE transaction `W` on the serving owner's `Arc<StoreConnection>` (R2): entry insert, chain commit, fan-out rows (delta, admission commit, chain commit each), commit, then authority-anchor sync. The admin route acknowledges only after both. An admission commits in its budget authorize-hold transaction `A` (`claim_and_authorize_budget_and_commit_admission`, IMMEDIATE, same connection, R5), which reads `revoked_capabilities` for every id in `admission.revocation_set` (R4). A capture is one transaction `C` (composite capture or native dispatch capture) that reads the same set (R4). A mint is one IMMEDIATE transaction `M` that runs `refuse_revoked_root` and inserts the anchored root. The allowed-receipt check `R` is a sequence of reads, `R_1` to `R_k`, each its own deferred read transaction: the leaf, then each `delegation_chain` id in order (`check_revocation`, `kernel/validation.rs:614-625`; R2 `is_revoked`, R6). `R` refuses at the first `R_i` that sees a revoked id. The receipt append `P` is a separate operation (R6).

**Guarantee.** `W`, `A`, `C` and `M` serialize on one writer, so with T the commit of `W`:

- **G-A:** every `A` that begins after T denies (fan-out rows for the root or an ancestor), and the kernel attributes the deny to the entry (Task 4).
- **G-C:** every `C` that begins after T refuses; the effect has already run; the kernel attributes the refusal (Task 4) and the existing post-effect handling applies.
- **G-M:** every `M` that begins after T and matches the entry refuses; every `M` that committed before T has its root marked by `W`'s fan-out.

**Disclosed gap.** `R` is not one snapshot, `R` and `P` are not one transaction, and `W` is not excluded between any of them. With T inside or after `R`, the outcome depends on which `R_i` reads the id `W` marked (the named capability for a `capability_id` entry, the anchored root for the other kinds): if that `R_i` begins after T, `R` refuses; if it began before T, `R` passes even when a later `R_j` begins after T, and `P` appends an allowed receipt after the acknowledgement. Only a call whose `A` and `C` committed before T reaches this point. Item 5 does not close the gap: closing it needs a store-side revocation check coupled to the receipt append in one transaction, or a serialization spanning every writer path and the whole check-to-append boundary (Q10). The existing rechecks stay as they are. This guarantee is not equivalent to #1708's local fence guarantee and is not described as such.

**Read path in kernel admission.**
1. `check_tool_call_revocation_admission` (pre-dispatch): `revocation_entry` per id, early deny with entry evidence. Not a linearization point.
2. `durable_budget_binding` builds `revocation_set` (leaf plus `delegation_chain`) and `authorize_durable_budget_hold` runs `A` (G-A).
3. Capture `C` (`capture.rs`, `dispatch_ledger/capture.rs`) (G-C).
4. `record_chio_receipt_with_federation` runs `R`, then `P` (the disclosed gap).

The hold and capture transactions record typed revocation evidence from their own reads (Task 4); no check is added or removed.

**#1708.** `PublicationSync` is per kernel (R7) and serve-http runs one kernel per session, so the exclusive fence orders a kernel's own `revoke_capability` against that kernel's publications and checks only; it cannot order a revocation against another session's kernel or a direct store call. The admin route takes no kernel fence, so it never waits on one; it does wait on the shared writer (Task 6). `ChioKernel::revoke_capability` keeps #1708's exclusive fence for in-process callers (conformance native suite, CLI tests) and writes a `capability_id` entry through the same store method. Item 5 adds no kernel-level revocation method for the other kinds.

**Model scope.** The #1708 Loom harnesses and the `revocation_propagation` trace model cover kernel API events within one kernel. They are not claimed to cover store-level revocations, cross-kernel order or the admin route. G-A, G-C, G-M and the gap are evidenced by the deterministic real-store schedules below; no formal model is claimed for them in M1.

**Deterministic schedules** (`tests/durable_admission_sqlite/revocation_schedules.rs`, PR 3; the capability-kind subset S1 to S4, S7 in PR 2; S9 in PR 3). Two `ChioKernel`s share one real serving owner, as two serve-http sessions; revocation is the store-level admin path. Barriers come from delegating wrappers around the real stores (revocation store, budget store calls, receipt store append), never from sleeps:

| # | Schedule | Asserts |
|---|---|---|
| S1 | kernel 1 passes pre-dispatch check; barrier; `W` commits and acknowledges; kernel 1 runs `A` | hold denied, `CapabilityRevoked` with entry; no dispatch; effect counter 0 |
| S2 | kernel 1 `A` commits; barrier; `W`; kernel 1 dispatches and runs `C` | capture refused and attributed; effect counter 1; output withheld; receipt classification recorded |
| S3 | kernel 1 `C` commits; barrier before `R`; `W`; `R` | allowed receipt refused; effect counter 1; output withheld; receipt classification recorded |
| S4 | kernel 1 `R` returns not revoked; barrier before `P` (delayed receipt writer); `W` commits and acknowledges; `P` | allowed receipt appended after the acknowledgement (the disclosed gap); kernel 2's next `A` denies |
| S5 | `W` commits; then kernel 2's exchange runs `M` for a matching root | mint refused with the entry |
| S6 | `M` commits; then `W` | the new root is in `revoked_capabilities`; kernel 2's next `A` under it denies |
| S7 | `W` commits; anchor sync fault-injected; admin returns 503 outcome unknown | a retry and kernel 2's next `A` in the same process both get `OutcomeUnknown` (poisoned owner, no dispatch); after reopening the state directory, kernel 2's next `A` denies and the retry returns the same entry with `newly_revoked = false` |
| S8 | delayed receipt writer holds kernel 1's `P`; `W` from the admin path | `W` does not wait on any kernel fence; the test asserts completion order only, no latency bound |
| S9 | delegated leaf under a root, after `C`; barrier between `R_1` (leaf) and `R_2` (root); `W` for the root's rule; then `R_2` | allowed receipt refused (`R_2` began after T); the variant with a depth-2 leaf, the barrier after `R_2` (root) and `W` before `R_3` appends the allowed receipt (the disclosed gap with a mixed read) |

## Verification

Run at each PR head after the final rebase; every cargo command under `cs`. Logs go to `ws2:~/lanes/claude-pr1160-evidence/m1i5/` with sha256 in the PR body.

**PR 1**
```bash
cs cargo test -p chio-core-types --no-fail-fast && cs cargo clippy -p chio-core-types --all-targets -- -D warnings
cs cargo test -p chio-store-sqlite --no-fail-fast && cs cargo clippy -p chio-store-sqlite --all-targets -- -D warnings   # integrator
cs cargo test -p chio-control-plane --no-fail-fast                                                                        # integrator, trust-control replication
cs cargo check --locked --workspace --all-targets && cs cargo fmt --all --check
python3 scripts/check-security-clocks.py && python3 scripts/check-escape-hatches.py && python3 scripts/check-negative-assertions.py \
 && python3 scripts/check-trust-boundaries.py && python3 scripts/check-rust-file-hygiene.py && python3 scripts/check-domain-separation.py \
 && bash scripts/tests/check-domain-separation.test.sh
# /usr/bin/sqlite3 on the crate DDL: EXPLAIN QUERY PLAN of the entry lookup shows SEARCH using an index, never SCAN
cs cargo xtask gen proof-coverage --check   # last commit after the final rebase
```

**PR 2**
```bash
for c in chio-kernel chio-store-sqlite chio-control-plane chio-mcp-remote chio-conformance chio-errors; do cs cargo test -p $c --no-fail-fast; cs cargo clippy -p $c --all-targets -- -D warnings; done   # integrators
cs cargo test -p chio-kernel --test durable_admission_sqlite --no-fail-fast
python3 scripts/check-error-urn-registry.py && cs bash scripts/check-adapter-no-bypass.sh && python3 scripts/check-negative-assertions.py
cs make codegen-check
# native-cage chio-cli and chio-conformance full suites on host 3 or x86 (lane-common setup), rc=0 required
cs cargo xtask check formal-mirrors && cs cargo xtask gen proof-coverage --check
```

**PR 3**
```bash
cs cargo test -p chio-store-sqlite --no-fail-fast && cs cargo test -p chio-kernel --test durable_admission_sqlite --no-fail-fast
cs cargo test -p chio-mcp-remote --no-fail-fast && cs cargo clippy -p chio-mcp-remote --all-targets -- -D warnings
python3 scripts/check-error-urn-registry.py && python3 scripts/check-trust-boundaries.py && python3 scripts/check-security-clocks.py && python3 scripts/check-domain-separation.py
# /usr/bin/sqlite3 on the crate DDL: EXPLAIN QUERY PLAN of the four fan-out selects, the mint lookup and the coverage selects shows SEARCH using an index
# schedules S1 to S9 run 50 times each on the integrator; every run must pass
```

**PR 4**
```bash
cs cargo test -p chio-mcp-remote --no-fail-fast && cs cargo clippy -p chio-mcp-remote --all-targets -- -D warnings
bash scripts/check-chio-schema-registry.sh && bash scripts/tests/check-chio-schema-registry.test.sh && bash scripts/check-chio-owned-v1-only.sh
python3 scripts/check-wire-schemas.py && uv run --with jsonschema==4.26.0 --with referencing==0.37.0 python3 -I scripts/check-root-authority-schema-examples.py
cs make codegen-check && bash scripts/check-http-egress-contract.sh && python3 scripts/check-trust-boundaries.py
cs cargo test -p chio-core-types --test claim_registry_integrity --no-fail-fast
# native-cage chio-cli full suite (tests/mcp_revoke.rs, tests/mcp_serve_http.rs) rc=0
```

The CLAUDE.md one-liner runs once at the PR 4 tip on the integrator, each step under `cs`. Pre-existing reds on `main` are reported with `main`'s result at the same base.

The 14 staged `revocation_local` scenarios move into the live corpus when the `rust-mcp-serve-http` driver exists (item 7). Until then each scenario id has one named test in PR 2, PR 3 or PR 4 that asserts its `expected` block, listed in the PR 4 body; 010a to 010c map to S2 to S4.

## Open Questions

| # | For | Question | Status or recommendation |
|---|---|---|---|
| Q1 | owner | Spec 7.11 says calls admitted before the acknowledgement "run to completion". | Resolved by Root-2 and arc-5b review: keep both rechecks; PR 0 replaces the text with the exact boundaries (Task 2); PR 2 adds capture attribution; scenario 010 is staged as 010a to 010c with the PR 0 wording. |
| Q2 | Root-2 | `revocation_entry` chain kind in `global_commit_chain.rs`. | ACK (review 1721) with conditions, all in Task 3. Source review and the normal merge window still apply. |
| Q3 | Root-2 | Cross-kernel order without a kernel fence. | Revised per review 1721: the plan claims G-A, G-C and G-M only, discloses the receipt check-to-append gap, removes the claim that the admin route never blocks, adds schedules S1 to S9 and scopes the existing models to kernel API events. Re-review requested. |
| Q4 | owner | With remote durable admission (`control_url`), target kinds other than `capability_id` cannot be linearized, because anchored roots live in the local state directory. | Refuse them with 409 in M1. If item 4 forbids remote durable admission under a root policy, the 409 path is deleted with it. |
| Q5 | owner | A revocation that names a rule id or issuer the provider does not know: refuse, or accept as a pre-revocation? | Refuse with 422. `capability_id` keeps today's accept-any-id behavior because a child id may never have been seen. |
| Q6 | owner | Revocations are monotone: no un-revoke in M1. A wrong `tenant_tag` revocation blocks that tenant on this state directory permanently. | Keep monotone in M1 (it keeps the linearization and export coverage sound). A lift operation is an M2 candidate. |
| Q7 | lead | `RevocationStore::is_revoked` is replaced by `revocation_entry` (about 20 trait call sites, 8 implementors). | Replace. Two methods answering one question is a dual API under the house rule. |
| Q8 | lead | Entry ids are deterministic. | Deterministic: idempotent retries; equal ids across stores for `capability_id`, `root_policy_rule` and `replay_key`; tag kinds are equal only under one index key; no plaintext in any id. |
| Q9 | lead | CLI shape `chio mcp revoke` / `chio mcp revocations`, token from env, plaintext from stdin. | Accept. `chio trust revoke` stays for trust-control and refuses serve-http state databases (R9). |
| Q10 | owner | Close the allowed-receipt check-to-append gap in M1? It needs a store-side revocation check atomic with the receipt append (the receipt append and the revocation projection would share one transaction), or a serialization over every writer path and the whole check-to-append boundary, while keeping late-acknowledgement handling, output withholding and settlement idempotency. | Defer to M2 and disclose it in M1. It affects only calls whose admission and capture committed before the revocation, the effect has already run for them, and the M1 "May say" line ("Every call admitted after the revocation is recorded denies") stays true. Closing it touches the receipt store and #1708's publication path, Root-2's area. |
| Q11 | Root-2 | Typed revocation evidence for hold denials and capture refusals (kernel `budget_store`, store composite and capture, native dispatch ledger). | ACK (r2) for the narrow typed-refusal edits. After-the-fact attribution reads are removed (r2 repair); Task 4 attributes only from transaction-bound evidence. |
| Q12 | owner | The closed `reason` set: `operator_request`, `credential_compromise`, `principal_offboarded`, `tenant_offboarded`, `policy_withdrawn`, `incident_response`. | Accept. A closed set keeps plaintext out of the store and caller bundles (spec 7.12) and is exportable as is. |

## Size

Spec 13.2 sizes item 5 at M, 4-6 engineer-days.

| Part | Days |
|---|---|
| PR 0 spec text for 7.11, 8.3, 11.3 | 0.25 |
| PR 1 entry types, closed reason, DDL, capability entries, reads, chain kind with full validation, tests | 1.5-2 |
| PR 2 trait replacement over 8 implementors, hold and capture attribution, guard evidence, URN, scenario split, real-SQLite tests | 1.5-2 |
| PR 3 fan-out for four kinds, mint check in item 4's insert, exchange error, `revocations_covering`, per-generation tag matching, tests | 1.5-2 |
| Schedules S1 to S9 with barrier wrappers over real stores | 1-1.5 |
| PR 4 admin route and status table, schemas, PROTOCOL, CLI with warnings, egress inventory, tests | 1-1.5 |
| Integration, native-cage runs, review rounds | 0.5-1 |
| Total | 7.25-10.25 |

Planning figure 8. The range agrees with arc-5b's 7-9 estimate at its low end and sits 3.25 to 4.25 days above 13.2. The additions over 13.2 are the chain kind (Q2), the trait replacement (Q7), capture attribution, export coverage, the per-generation tag matching and the deterministic schedules. Waiting time on #1708, item 1, item 2 and item 4 is not counted.

## Spec coverage

| Spec requirement | Task |
|---|---|
| 7.11 closed target kinds, indexed equality at exchange and admission | 3, 5 |
| 7.11 subject and tenant stored as tags only | 5, 6 |
| 7.11 linearization through the serving writer (as revised by PR 0) | 2, 5, Linearization |
| 7.11 deny names the entry in guard evidence | 4 |
| 7.11 entries exported with tags only; coverage for item 6 | 3, 5 (`revocations_covering`, `chio.revocation-entry.v1`, closed `reason`) |
| 7.11 D17 reconciliation with coop2c | Store reconciliation, Task 1 |
| 7.12 tags under the rotating tenant index key set; referenced-generation startup refusal | 5 (index-key generations) |
| 8.2 any token in the chain matched by an entry denies; store error denies | 4, 5 |
| 10.7 existing revocation tables gain the target kinds, writes through the serving writer | 3, 5 |
| 11.1 revocation unit tests (each kind, cascade, store error, tags only, acknowledged-before-pending) | 3, 4, 5, 6, Linearization schedules |
| 11.3 `revocation_local` scenarios (14 after the split) | named tests in PRs 2 to 4; move-in with item 7 |
| G12 `urn:chio:error:kernel:revocation-store` | 4 |
| G17 subject is the provider record's principal claim | 5, 6 |
| G18 strict decoding of the admin request and entry | 3, 6 |
| 12 M1 "The provider can revoke a capability, a principal, a policy rule or a tenant" | 3 to 7 |
| 13.3 step 5 after the coop2c reconciliation | Task 1 |
