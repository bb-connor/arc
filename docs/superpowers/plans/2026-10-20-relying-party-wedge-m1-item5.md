# Relying-Party Wedge M1 Item 5 Implementation Plan: Revocation Target Kinds

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land M1 item 5 of the relying-party wedge: the existing SQLite revocation store holds closed-kind revocation entries (`capability_id`, `root_policy_rule`, `anchor_subject`, `tenant_tag`, `replay_key`); every entry is linearized with admission through the serving writer; a denied call names its entry; the provider revokes through `/admin/revocations` and `chio mcp revoke`.

**Architecture:** One new table, `revocation_entries`, records each target once under a deterministic id. A target entry is materialized into the existing `revoked_capabilities` projection for every anchored root it matches, in the same IMMEDIATE transaction that writes the entry. The root exchange checks the entries in the same transaction that inserts an anchored root. Every existing in-transaction revocation reader (budget authorize-hold, composite capture, native dispatch capture) keeps reading `revoked_capabilities` by capability id over the leaf and its delegation chain, so none of them changes and the existing cascade covers descendants. Entries join the global authority commit chain so a restored backup that loses an entry is detected.

**Tech Stack:** Rust workspace (every cargo command through `cs`, defined under Global Constraints), SQLite through `rusqlite` (bundled), JSON Schema draft 2020-12, `cargo xtask codegen`.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`, sections 2.2 (D3, D4, D5, D17), 2.3 ("Revocation freshness"), 2.5 (G12, G17, G18), 7.11, 7.12 (tags), 8.2 (revocation rule), 10.7, 11.1 ("Revocation"), 11.3 (`revocation_local`), 12 M1 ("The provider can revoke a capability, a principal, a policy rule or a tenant"), 13.2 item 5 (M, 4-6), 13.3 step 5. Staged scenarios: `docs/superpowers/specs/relying-party-wedge/verdict-matrix/revocation_local/` (12 files) and its `README.md`.

**Census base:** facts below were read at `origin/main` `a93a2f69a3`, `feat/coop2c-federated-revocation` `180f014ea0` (#1607), `fix/root2-trace-publication` (#1708) and `feat/root-exchange-id-jag` (#1709). Task 1 re-reads every cited site at the integrated base.

## Facts this plan builds on

| # | Fact | Source |
|---|---|---|
| R1 | `revoked_capabilities(capability_id PK, revoked_at, revocation_index UNIQUE, admission_authority_commit_index UNIQUE)`, `revocation_delta_log`, `revocation_delta_meta`, `revocation_stream_meta`, and in joint mode `admission_authority_meta`, `admission_authority_commits(kind IN ('genesis','revocation'), capability_id FK)`. Schema version 1, key `revocation`. | `crates/platform/chio-store-sqlite/src/revocation_store.rs:719-800` |
| R2 | A joint (serving-owner) revocation opens on the serving owner's shared `Arc<StoreConnection>`; `begin_write` is `TransactionBehavior::Immediate`, verifies the fence and authority anchor and observes authority time; `record_revocation` appends the delta row, the admission commit and a global commit (`projection_kind = 'revocation'`) in that transaction; `revoke` commits and then syncs the authority anchor. | `revocation_store.rs:166-275,643-658`; `serving_owner.rs:906` |
| R3 | The global commit chain's `projection_kind` is a closed CHECK list and each kind has a reference digest and an exact-coverage clause. | `serving_owner/global_commit_chain.rs:47,990-1045,1095-1120,1740-1750` |
| R4 | In-transaction revocation readers, all by capability id: budget authorize-hold over `admission.revocation_set` (leaf plus every `delegation_chain` id, serving owner only, folds into `allowed`); composite capture; native dispatch capture. | `budget_store/composite.rs:296-305`; `budget_store/composite/transitions/capture.rs:282-296`; `admission_operation_store/security_participant_state/dispatch_ledger/capture.rs:64-78` |
| R5 | Every serve-http call with durable admission takes a budget hold through `durable_budget_binding` and `claim_and_authorize_budget_and_commit_admission`; that IMMEDIATE transaction is the admission commit. | `chio-kernel/src/kernel/validation.rs:1152-1215`; `admission_coordinator.rs:1381-1500` |
| R6 | Out-of-transaction reads: `check_tool_call_revocation_admission` (pre-dispatch, early deny) and the allowed-receipt recheck `check_revocation` before append. Both read `RevocationStore::is_revoked` per id. A revoked hold from R4 reaches the kernel as `BudgetAuthorizeHoldDecision::Denied`, with no revocation attribution. | `validation/revocation_trace.rs:30-70`; `validation.rs:614-625`; `responses/receipt_persistence.rs:253`; `chio-kernel/src/budget_store.rs:596` |
| R7 | serve-http builds one `ChioKernel` per session (and per approval bind). #1708 replaces the kernel trace mutex with a per-kernel `PublicationSync`; `revoke_capability` takes `fence(true)`, the admission revocation check takes `fence(false)`. Lock domains are per kernel. | `session_core/factory.rs:131,164,401,608`; #1708 `kernel/publication_sync.rs` |
| R8 | `/admin/revocations` POST writes `store.revoke` directly (no kernel, no fence); it uses the durable runtime's local serving-owner store, falls back to a path-opened store from `revocation_db_path`, and forwards to trust-control when `control_url` is set. Body `{capabilityId}`; response `{capabilityId, revoked, newlyRevoked}`. | `remote_mcp/admin.rs:452-555,819-845`; `session_forms.rs:47` |
| R9 | A path open of a provisioned (serving-owner) database refuses: "provisioned sqlite authority store requires joint serving owner at epoch N". | `revocation_store.rs:117-123` |
| R10 | #1607 adds no table to `chio-store-sqlite`. It pages leaves of `chio-revocation-oracle`'s own SQLite tree (`chio_revocation_oracle_leaves`, passport `RevocationKey`) and adds control-plane passport feed, mirror and door checks. | `git diff --stat origin/main...feat/coop2c-federated-revocation` |
| R11 | #1709 computes `ReplayKey::digest()` = `SHA-256("chio.root-exchange.replay-key.v1\0" || namespace || 0 || issuer || 0 || id)` and records `replay_key_digest` and `root_policy_rule_id` in the delegation context. It binds the replay key before the root is signed; no `anchored_roots` table exists yet. | #1709 `root_exchange/replay.rs`, `exchange.rs:395-470` |
| R12 | `GuardEvidence { guard_name: String, verdict: bool, details: Option<String> }`; `guard_name` is a free string in the receipt schema. | `chio-core-types/src/receipt/metadata.rs:193`; `spec/schemas/chio-wire/v1/receipt/record.schema.json:408-430` |
| R13 | `KernelError::RevocationStore` reports the non-URN code `CHIO-KERNEL-REVOCATION-STORE`; G12 converts it in item 5. | `kernel/error.rs:796` |
| R14 | `RevocationStore` has 8 implementors: `InMemoryRevocationStore`, `SqliteRevocationStore`, CP `RemoteRevocationStore`, conformance `BlindRevocationStore` and four test doubles. | `chio-kernel/src/revocation_runtime.rs:16`; grep `impl RevocationStore for` |

## Store reconciliation with #1607 (D17, spec 7.11 last paragraph)

#1607 and item 5 change disjoint stores. #1607 writes the passport sparse-Merkle oracle in `chio-revocation-oracle` (credential keys, signed epoch roots under `chio.trust.passport-revocation-root.v1`); item 5 writes `chio-store-sqlite`'s capability revocation store inside the serve-http state directory. No table, column, file or wire type is shared, and neither PR edits the other's files. The one store shape for capability revocation is the one in this plan. #1607 does not need to land before item 5; it lands before item 1 for the `passport-revocation-root` wrapper id, which is unrelated to this item. The lead records this on `sync.md` as the D17 reconciliation result (Task 1 Step 3).

## Signing form and item 1 sequencing

- #1607's epoch root signs under `chio.trust.passport-revocation-root.v1`, and the vectors under `spec/vectors/passport-revocation/v1/` change bytes in M1 item 1 (the signing wrapper). Item 5 neither reads, signs, verifies nor regenerates them, and depends on no passport-revocation artifact.
- Item 5 adds no signed artifact, no signed fixture and no signing vector. `chio.revocation-entry.v1` and `chio.revocation-admin-request.v1` are unsigned. Item 6 exports entries under the kernel-signed export manifest; that signature is item 6's and uses the post-wrapper form.
- The hashes item 5 adds are hash domains, not signature domains: `chio.revocation-entry-id.v1` (entry id) and `chio.sqlite-authority-revocation-entry-reference.v1` (chain reference digest). G5 leaves hash domains unchanged, so the wrapper does not alter them, and `scripts/check-signing-exemptions.py` (item 1) has nothing to list for item 5.
- The only signed bytes item 5 changes are deny receipts that gain the `chio.revocation` guard evidence (PR 2). Those receipts are signed by the existing producers in the post-wrapper, committed form. PR 2 tests assert decoded receipt members (`guard_evidence`, reason code) and verify signatures through the item 1 helper (`verify_wrapped` with the receipt schema id against the pinned kernel key); no test compares receipt bytes, signatures or a checked-in signed fixture, so no fixture joins item 1's `cargo xtask gen signed-fixtures` set.
- Sequencing after item 1: PR 2, PR 3 and PR 4 merge after item 1. PR 2 also waits for item 2, which follows item 1 (13.3). PR 3 waits for item 4's anchored-root store, which follows item 3, which follows item 1. PR 4 adds `spec/schemas/registry.json` rows and regenerated code, which item 1 rewrites, so it rebases on item 1's merged registry. PR 0 (docs only) and PR 1 (unsigned core-types type, store DDL, chain kind) sign nothing and may land before item 1; PR 1 adds one new file under `root_authority/` and edits no file item 1 edits. If the lead prefers one rule, PR 1 also waits for item 1, at no cost to the critical path because PR 2 waits for item 1 anyway.
- arc-5b ACKs this plan on `sync.md` before any item 5 code starts (Task 1 Step 3).

## Global Constraints

- Merge order (precondition): #1708 (trace-lock publication fence) merges before PR 2, because both edit `kernel/validation/revocation_trace.rs` and the kernel revocation tests. M1 item 4's anchored-root store PR (the `anchored_roots` table, the tenant index and the mint transaction) merges before PR 3. M1 item 2 (committed receipts, guard-evidence allowlist) merges before PR 2, so the revocation guard evidence is declared safe once. #1706 merges before PR 1 (module location `root_authority`).
- Every format is v1. `revocation_entries` lands in revocation store schema version 1 in place; no migration, no second schema version, no `Legacy*` double, no default trait method that keeps `is_revoked` alive beside its replacement.
- Fail-closed: a store error on any revocation read denies (admission), refuses (mint) or answers 503 (admin). An unknown target member, kind or shape rejects with no state change. A commit whose anchor sync fails reports outcome unknown and never reports success.
- Privacy (spec 7.11, 7.12, 8.4): plaintext subjects and tenant values exist only in the admin request and in process memory while the tag is computed. They are never stored, logged, traced, echoed in a response or put in an error string. The CLI reads them from stdin only.
- No Root-held file is edited except `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs` in PR 1, which waits for Root-2's `REVIEW #<N> OK` (Open Question Q2). Untouched Root-held files: kernel `budget_store`, `tool_outcome`, `admission_operation_store` (including the native dispatch ledger capture read), store `security_state`, `serving_owner.rs`, http-core `receipt.rs`, CP `evidence_export/verification.rs`.
- Clock reads only through the store clock (`self.clock`, `observe_authority_time`). Fixtures use fixed timestamps (`1792234800`). Run `python3 scripts/check-security-clocks.py` on every PR.
- Clippy denies `unwrap_used` and `expect_used` outside tests. Format with `cs cargo fmt --all`.
- No em dashes (U+2014). No narrative or meta comments; comments state invariants and contracts.
- Public-path rule: files under `spec/`, `docs/adr/`, `tests/`, `scripts/`, `crates/`, `sdks/` never mention milestones, the wedge, pilots or `docs/superpowers`.
- Build slots: on ws2, `cs` means `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/var/tmp/claude-targets/m1i5 ~/lanes/cslot.sh`; on x86 and host 3, `CARGO_INCREMENTAL=0 ~/cslot.sh` with that host's lane target dir. Every cargo command and every script that reaches cargo runs under `cs`.
- Work happens on ws2 in one worktree per PR off fresh `origin/main` fetched over https (`~/lanes/m1i5-pr<N>`). Coder checks under `cs`; heavy suites (chio-kernel, chio-store-sqlite, chio-control-plane, chio-cli, chio-conformance) on `integ-x86` and `integ-h3`. Never `git stash`. Inspect `git diff --cached --stat -M` before every commit. Push explicit SHAs over https.
- Shared surfaces: before requesting merge of a PR touching chio-kernel, chio-store-sqlite, chio-control-plane, chio-core-types or `spec/`, post `<UTC> <lane>: REVIEW? #<N> <scope>` to `ws2:~/lanes/claude-pr1160-evidence/lead2/sync.md`; at merge, `MERGING #<N>`, the full 10-minute window and the OBJECT check.
- Commits follow conventional commits and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. PR bodies are written to lane-private `pr-<N>-<slug>-body.md` files and end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## Review Focus

1. **A target revocation that misses a live root.** Expected: entry insert, fan-out into `revoked_capabilities` and the mint-side entry check all run in IMMEDIATE transactions on the serving owner's one connection, so for every pair (revocation W, mint M) either M commits first and W's fan-out marks M's root, or W commits first and M refuses. Pinned in PR 3 by `revocation_and_mint_interleavings_never_leave_a_live_matching_root` (two threads, barrier, 500 iterations against real SQLite).
2. **An in-transaction reader that stops seeing revocations.** Expected: no change to the R4 readers; every target revocation becomes `revoked_capabilities` rows that those readers already read. Pinned in PR 3 by the per-kind kernel tests in `tests/durable_admission_sqlite/revocation_targets.rs`, which commit the revocation between the pre-dispatch check and the hold and assert the hold denies.
3. **Plaintext reaching disk or logs.** Expected: only `subject_tag` and `tenant_tag` (64 lowercase hex) are stored. Pinned in PR 3 by `subject_and_tenant_revocations_store_only_tags` (scans the database file, WAL and SHM bytes for the fixture marker) and in PR 4 by a log-capture test on the admin route.
4. **An entry lost on backup restore without detection.** Expected: every entry advances the global commit chain, including an entry that matches no root. Pinned in PR 1 by `restored_snapshot_missing_an_entry_refuses_open`.
5. **A mis-attributed deny.** Expected: a deny names an entry id only when `revocation_entry` returns one for an id in the leaf-plus-chain set; otherwise the original reason stands. Pinned in PR 2 by `hold_denied_by_revocation_names_the_entry` and `budget_exhaustion_is_not_attributed_to_revocation`.

---

## File Structure

| Path | PR | Responsibility |
|---|---|---|
| `crates/core/chio-core-types/src/root_authority/revocation_entry.rs` (new) | 1 | `RevocationTarget`, `RevocationTargetKind`, `RevocationEntryId`, `RevocationEntry`, id derivation, strict serde |
| `crates/platform/chio-store-sqlite/src/revocation_store.rs` | 1, 3 | `revocation_entries` DDL, entry column on `revoked_capabilities`, entry write, fan-out, mint check, reads |
| `crates/platform/chio-store-sqlite/src/revocation_store/entry_tests.rs` (new), `target_tests.rs` (new) | 1, 3 | store tests |
| `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs` (Root-held, Q2) | 1 | `revocation_entry` projection kind, reference digest, coverage clause |
| `crates/kernel/chio-kernel/src/revocation_runtime.rs`, `src/revocation_store.rs` | 2 | trait `revocation_entry` replaces `is_revoked`; `TargetRevoked` error |
| `crates/kernel/chio-kernel/src/kernel/validation.rs`, `validation/revocation_trace.rs`, `evaluation/async_evaluation_core.rs`, `evaluation/nested_flow_evaluation.rs`, `responses/deny_responses.rs`, `kernel/error.rs` | 2 | attribution, guard evidence, URN |
| 8 `RevocationStore` implementors (R14) and every trait `is_revoked` caller | 2 | trait change |
| `crates/kernel/chio-kernel/tests/durable_admission_sqlite/revocation_targets.rs` (new) | 2, 3 | real-SQLite admission linearization tests |
| item 4's anchored-root store module in `chio-store-sqlite` and its mint call site in `chio-mcp-remote` | 3 | entry check inside the mint transaction |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/error.rs` | 3 | `RootExchangeError::Revoked { entry_id }` |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs`, `admin/revocation_targets.rs` (new), `session_forms.rs`, `admin/revocation_batch.rs` | 4 | admin POST and GET, fail-closed rules, fallback deletion |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/tests/revocation_admin.rs` (new) | 4 | HTTP tests |
| `crates/products/chio-cli/src/cli/types/runtime.rs`, `src/cli/dispatch/mcp_revoke.rs` (new), `tests/mcp_revoke.rs` (new) | 4 | `chio mcp revoke` and `chio mcp revocations` |
| `spec/schemas/chio-wire/v1/root_authority/revocation-entry.schema.json`, `revocation-admin-request.schema.json` (new), examples, `spec/schemas/registry.json`, `MANIFEST.sha256`, `spec/wire-schemas.lock`, generated code | 4 | wire shapes |
| `spec/PROTOCOL.md` (`/admin/revocations` section near line 2946), `spec/errors/registry.yaml` | 2, 3, 4 | contract text and URNs |
| `scripts/check-domain-separation.py` inventory | 1 | `chio.revocation-entry-id.v1` domain |
| `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md` 7.11, staged `revocation-local-010` | 0 | Q1 wording, if approved |

## PR Grouping

| PR | Tasks | Branch | Title | Depends on | Root-held |
|---|---|---|---|---|---|
| 0 | 2 | `docs/m1i5-revocation-spec` | `docs(superpowers): state when a revocation stops an admitted call` | Q1 answer | no |
| 1 | 3 | `feat/m1i5-revocation-entries` | `feat(store): record capability revocations as chained revocation entries` | #1706 | yes: `global_commit_chain.rs` (Q2) |
| 2 | 4 | `feat/m1i5-revocation-attribution` | `feat(kernel): name the revocation entry in revocation denials` | PR 1, #1708, item 1, item 2 | no (Root-active files, after #1708) |
| 3 | 5 | `feat/m1i5-revocation-targets` | `feat(store): revoke by root policy rule, subject, tenant and replay key` | PR 2, item 1, item 4 anchored-root store PR | no |
| 4 | 6, 7 | `feat/m1i5-revocation-admin` | `feat(mcp-remote): revocation target kinds on the admin route and chio mcp revoke` | PR 3, item 1 (registry) | no |

PRs 0 and 1 sign nothing and may land before item 1; PRs 2 to 4 merge after item 1 (see Signing form and item 1 sequencing). PRs 1 and 2 do not need item 4. PR 0 is docs-only and independent.

---

### Task 1: Base, census and coordination

**Files:** none changed. Output: `ws2:~/lanes/claude-pr1160-evidence/m1i5/census-<base>.md`.

- [ ] **Step 1: Preconditions per PR** (Global Constraints merge order). `gh pr view <N> --repo bb-connor/arc --json state` for #1706, #1708, the item 2 PR and the item 4 anchored-root store PR, as each PR needs them. A missing predecessor holds that PR; it does not reorder.
- [ ] **Step 2: Census at the integrated base.**
```bash
git grep -n "revoked_capabilities" -- crates ':!**/tests/**'
git grep -n -E "impl (chio_kernel::)?RevocationStore for"
git grep -n -E "\.is_revoked\(" -- crates ':!crates/trust/**' ':!**/revocation_view.rs'
git grep -n -E "CapabilityRevoked|DelegationChainRevoked" -- crates/kernel
git grep -n -E "revocation_db_path|ADMIN_REVOCATIONS_PATH|AdminRevokeCapabilityRequest"
```
  Expected at `a93a2f69a3`: the R4 readers (3 non-test sites) plus the store's own; 8 implementors; about 69 `is_revoked` call lines of which about 20 go through the trait; `revocation_db_path` in factory, admin and config.
- [ ] **Step 3: D17, arc-5b and Root-2.** Wait for arc-5b's plan ACK on `sync.md`. Post `<UTC> <lane>: D17 m1i5 store reconciliation: #1607 and item 5 share no store, table or wire type (oracle vs chio-store-sqlite); item 5 adds revocation_entries + revocation_entry chain kind (global_commit_chain.rs, Root-held) - REVIEW? requested before PR 1 opens` to `sync.md`, and wait for the lead's ACK and Root-2's answer to Q2 and Q3.

---

### Task 2: Spec wording for admitted calls (PR 0, only if Q1 is answered "keep the code")

**Files:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md` (7.11 "Linearization" paragraph), `docs/superpowers/specs/relying-party-wedge/verdict-matrix/revocation_local/revocation-local-010-admission-committed-before-revocation-completes.json`, its README row.

- [ ] **Step 1:** Replace the two sentences "Calls whose admission committed before it run to completion; in-flight streaming results are not cut off." with: "A call whose admission committed before the acknowledgement may dispatch. Its budget capture and its allowed receipt re-check revocation in their own transactions, so a call that has not captured when the revocation commits ends with a revocation denial and its output is withheld."
- [ ] **Step 2:** Rewrite scenario 010 to `expected.verdict = "deny"`, `reason_code = "urn:chio:error:capability:revoked"`, title "Revocation before capture denies an admitted call", and add scenario text that a call which captured before the acknowledgement completes (`revocation-local-010` keeps its id and count).
- [ ] **Step 3:** `grep -rn $'\xe2\x80\x94' <changed files>; test $? -eq 1`; JSON parse check from the M0 plan's PR 2 verify block.

---

### Task 3: Revocation entries, capability entries and the chain kind (PR 1)

**Files:**
- Create: `crates/core/chio-core-types/src/root_authority/revocation_entry.rs`; export from `root_authority/mod.rs`
- Modify: `crates/platform/chio-store-sqlite/src/revocation_store.rs`
- Create: `crates/platform/chio-store-sqlite/src/revocation_store/entry_tests.rs`
- Modify (Root-held, Q2): `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs`
- Modify: `scripts/check-domain-separation.py` (one inventory row)

**Types (core-types):**

```rust
pub const REVOCATION_ENTRY_ID_DOMAIN: &[u8] = b"chio.revocation-entry-id.v1\0";

/// Closed set; unknown kinds reject at decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTargetKind { CapabilityId, RootPolicyRule, AnchorSubject, TenantTag, ReplayKey }

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
    pub fn id(&self) -> RevocationEntryId;               // "rev_" + hex(SHA-256(DOMAIN || kind || 0x00 || value))
}

/// `chio.revocation-entry.v1`, unsigned. Exported by item 6 with role `revocation_entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    pub schema: String,                 // "chio.revocation-entry.v1"
    pub entry_id: RevocationEntryId,
    pub target_kind: RevocationTargetKind,
    pub target_value: String,
    pub revoked_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,         // 1..=256 bytes, no NUL, no control characters
}
```

The id is deterministic so that a repeated revocation of one target is idempotent and a capability entry is the same id on every store that records it.

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
    reason TEXT CHECK (reason IS NULL OR (length(reason) BETWEEN 1 AND 256 AND instr(reason, char(0)) = 0)),
    UNIQUE (target_kind, target_value),
    CHECK (
        target_kind IN ('capability_id', 'root_policy_rule')
        OR (length(target_value) = 64 AND target_value NOT GLOB '*[^0-9a-f]*')
    )
) STRICT;

-- revoked_capabilities gains, in its CREATE TABLE:
    revocation_entry_id TEXT NOT NULL REFERENCES revocation_entries(entry_id),
CREATE INDEX IF NOT EXISTS idx_revoked_capabilities_entry ON revoked_capabilities(revocation_entry_id);
```

`revocation_delta_log`, `revocation_delta_meta`, `revocation_stream_meta`, `admission_authority_meta` and `admission_authority_commits` are unchanged. Replication peers keep receiving capability rows only.

**Global commit chain (Root-held):** add `'revocation_entry'` to the `projection_kind` CHECK list; reference digest `chio.sqlite-authority-revocation-entry-reference.v1` over `{entry_seq, entry_id, target_kind, target_value, revoked_at}`; an exact-coverage clause "every `revocation_entries` row has exactly one `authority_global_commits` row with `projection_kind = 'revocation_entry'`, `projection_key = entry_id`, `projection_sequence = entry_seq`". Mutation kind `revocation_entry_record`.

**Behavior:**
- `revoke(capability_id)` (trait) and `upsert_revocation_if_newer` write the `capability_id` entry (insert or keep) and the `revoked_capabilities` row with `revocation_entry_id` in one transaction; in joint mode the entry's global commit precedes the row's.
- `pub fn revocation_entry(&self, capability_id: &str) -> Result<Option<RevocationEntryId>>`: one indexed read.
- `pub fn list_revocation_entries_after(&self, after_seq: u64, limit: usize) -> Result<(Vec<RevocationEntry>, u64)>`: one read snapshot, page plus head (consumed by PR 4 and item 6).
- Open refuses a `revoked_capabilities` row whose entry is absent (FK check already runs at open, R1 `verify_revocation_foreign_keys`).

- [ ] **Step 1: Failing tests** in `entry_tests.rs` (RED: none of the names exist):
```rust
#[test]
fn capability_entry_id_is_pinned() {
    let id = RevocationTarget::capability("cap-fixture-1").unwrap().id();
    assert_eq!(id.as_str(), "rev_<64 hex computed once by the coder from the formula and pinned>");
}
#[test]
fn capability_revocation_records_and_names_one_entry() -> TestResult {
    let store = SqliteRevocationStore::open(&fixture_path("entry-1"))?;
    assert!(store.revoke("cap-fixture-1")?);
    assert!(!store.revoke("cap-fixture-1")?);
    assert_eq!(store.revocation_entry("cap-fixture-1")?, Some(RevocationTarget::capability("cap-fixture-1")?.id()));
    let (page, head) = store.list_revocation_entries_after(0, 10)?;
    assert_eq!((page.len(), head), (1, 1));
    Ok(())
}
#[test]
fn revoked_row_without_entry_refuses_open() -> TestResult {
    // insert a revoked_capabilities row with foreign_keys off, reopen
    assert_eq!(error.to_string(), "revocation store synchronization error: sqlite foreign key violation in `revoked_capabilities` row 1");
}
#[test]
fn subject_entry_with_non_hex_value_is_refused_by_the_table() {
    // direct INSERT of ('anchor_subject', 'alice@example.com') fails with "CHECK constraint failed"
}
```
  Joint-mode tests (serving-owner fixture from `serving_owner/tests/authority_fixture.rs`, read-only use):
```rust
#[test]
fn every_entry_advances_the_global_commit_chain() // entry with zero matching roots still adds one 'revocation_entry' commit
#[test]
fn restored_snapshot_missing_an_entry_refuses_open() // copy db, revoke, restore copy, reopen: the existing authority-anchor rollback error, quoted exactly from serving_owner
#[test]
fn deleting_an_entry_commit_fails_coverage() // delete its authority_global_commits row: "global authority commit coverage is not exact" (exact text from the coverage function)
```
- [ ] **Step 2:** Implement types, DDL, writes, reads, chain kind. Register the hash domain in `scripts/check-domain-separation.py`.
- [ ] **Step 3: Verify** (PR 1 block under Verification).

---

### Task 4: Attribution, guard evidence and the URN (PR 2)

**Files:** `chio-kernel/src/revocation_runtime.rs`, `src/revocation_store.rs`, `src/kernel/validation.rs`, `src/kernel/validation/revocation_trace.rs`, `src/kernel/evaluation/{async_evaluation_core,nested_flow_evaluation}.rs`, `src/kernel/responses/deny_responses.rs`, `src/kernel/error.rs`, the 8 implementors (R14), every trait `is_revoked` caller, `spec/errors/registry.yaml`, `crates/core/chio-errors/src/_generated/error_codes.rs` (regenerated), `tests/durable_admission_sqlite/revocation_targets.rs` (new).

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

`is_revoked` is deleted from the trait and every caller uses `revocation_entry(..)?.is_some()`. `InMemoryRevocationStore` stores the entry id of `RevocationTarget::capability(id)`.

**Behavior:**
- `check_revocation` returns `Err(KernelError::CapabilityRevoked(id))` / `DelegationChainRevoked(id)` as today (no variant change, so the recovery and active-response match sites are untouched) and records the entry id on the deny path.
- The pre-dispatch deny and the receipt-persistence deny attach `GuardEvidence { guard_name: "chio.revocation", verdict: false, details: Some(<entry id>) }`. Item 2's evidence allowlist declares `chio.revocation` `details` safe under committed disclosure.
- After `BudgetAuthorizeHoldDecision::Denied`, the kernel reads `revocation_entry` for the leaf and each chain id in order. The first match converts the deny into `CapabilityRevoked` or `DelegationChainRevoked` with the guard evidence; no match leaves the budget denial unchanged. This read is sound after the fact because entries are append-only.
- `KernelError::RevocationStore` reports `urn:chio:error:kernel:revocation-store` (G12); the code is registered in `spec/errors/registry.yaml`.

- [ ] **Step 1: Failing tests.** Kernel lib tests (in-memory stores):
```rust
#[test] fn revocation_deny_receipt_names_the_entry()        // guard_evidence == [GuardEvidence{"chio.revocation", false, Some(entry)}]
#[test] fn chain_revocation_deny_names_the_ancestor_entry()
#[test] fn revocation_store_error_reports_the_urn()          // report code "urn:chio:error:kernel:revocation-store"
```
  Real-SQLite tests in `tests/durable_admission_sqlite/revocation_targets.rs` (lib tests cannot use chio-store-sqlite stores):
```rust
#[test] fn hold_denied_by_revocation_names_the_entry()       // revoke between pre-dispatch check and hold via a pausing store wrapper
#[test] fn budget_exhaustion_is_not_attributed_to_revocation()
#[test] fn revocation_acknowledged_before_hold_denies_every_later_admission() // 3 kernels on one serving owner, as serve-http sessions
```
- [ ] **Step 2:** Implement; regenerate error codes (`cs cargo xtask codegen`).
- [ ] **Step 3: Verify** (PR 2 block). The full chio-kernel suite and native-cage chio-cli and chio-conformance run on the integrators.

---

### Task 5: Target kinds, fan-out and the mint check (PR 3)

**Files:** `chio-store-sqlite/src/revocation_store.rs`, `src/revocation_store/target_tests.rs` (new), item 4's anchored-root store module (the insert function), `chio-mcp-remote/src/remote_mcp/root_exchange/error.rs`, the mint call site item 4 owns, `tests/durable_admission_sqlite/revocation_targets.rs`, `spec/errors/registry.yaml`.

**Contract required from item 4's `anchored_roots`** (item 4 owns the table; PR 3 fails review if any column or index is missing): `capability_id TEXT PRIMARY KEY`, `root_policy_rule_id TEXT NOT NULL`, `subject_tag TEXT NOT NULL` (64 hex), `tenant_tag TEXT` (64 hex or NULL when the rule has no tenant), `replay_key_digest TEXT NOT NULL` (64 hex, R11), `expires_at INTEGER NOT NULL`, one index on each of the four target columns; every insert goes through the serving owner's connection in an IMMEDIATE transaction; the root is returned to the client only after that transaction commits; rows are kept at least until `expires_at + max_clock_skew_secs`.

**Store API:**

```rust
impl SqliteRevocationStore {
    /// Records the entry and marks every matching anchored root revoked, in one
    /// IMMEDIATE transaction. Returns the entry and whether it is new.
    pub fn revoke_target(&self, target: &RevocationTarget, reason: Option<&str>)
        -> Result<(RevocationEntry, bool), RevocationStoreError>;
}

/// Called inside item 4's anchored-root insert transaction, before the insert.
pub(crate) fn refuse_revoked_root(tx: &Transaction<'_>, root: &AnchoredRootTargets<'_>)
    -> Result<(), RevocationStoreError>;   // RevocationStoreError::TargetRevoked { entry_id }

pub struct AnchoredRootTargets<'a> {
    pub root_policy_rule_id: &'a str,
    pub subject_tag: &'a Sha256Digest,
    pub tenant_tag: Option<&'a Sha256Digest>,
    pub replay_key_digest: &'a Sha256Digest,
}
```

- Fan-out: `INSERT` into `revoked_capabilities` for every `anchored_roots` row whose target column equals the entry value and that is not already revoked, each through `record_revocation` (delta row, admission commit, global commit) with `revocation_entry_id`. `capability_id` targets keep the PR 1 path.
- Mint check: one indexed lookup `(target_kind, target_value) IN` the four pairs, `LIMIT 1`. A match raises `TargetRevoked { entry_id }`, displayed `anchored root matches revocation entry <entry id>`; the exchange maps it to `RootExchangeError::Revoked { entry_id }`, OAuth `invalid_grant`, URN `urn:chio:error:transport:exchange-revoked` (registered here).
- Bearer intake that maps a token digest to an existing root (`bearer_token_roots`) needs no check: the root is already in `revoked_capabilities`.

- [ ] **Step 1: Failing tests** (`target_tests.rs`, joint serving-owner fixture with item 4's table):
```rust
#[test] fn root_policy_rule_revocation_marks_every_root_under_the_rule_only()
#[test] fn anchor_subject_revocation_marks_every_root_with_the_tag_only()
#[test] fn tenant_revocation_marks_every_root_in_the_tenant_only()
#[test] fn replay_key_revocation_marks_the_one_root()
#[test] fn repeated_target_revocation_is_idempotent()          // same entry, newly == false, no extra delta rows
#[test] fn mint_matching_an_entry_is_refused_with_the_entry()  // "anchored root matches revocation entry rev_..."
#[test] fn revocation_and_mint_interleavings_never_leave_a_live_matching_root() // 500 iterations, barrier
#[test] fn subject_and_tenant_revocations_store_only_tags()     // marker absent from db, -wal, -shm bytes
#[test] fn fan_out_failure_rolls_back_the_entry()               // trigger RAISE(ABORT) on revoked_capabilities insert: no entry, no rows
```
  Kernel real-SQLite (`revocation_targets.rs`): one test per kind that commits the target revocation, then runs an admission under a root (and under a depth-1 child for the rule kind) and asserts `CapabilityRevoked` or `DelegationChainRevoked` with the entry in guard evidence.
- [ ] **Step 2:** Implement; wire `refuse_revoked_root` into item 4's insert.
- [ ] **Step 3: Verify** (PR 3 block).

---

### Task 6: Admin route (PR 4)

**Files:** `remote_mcp/admin.rs`, `admin/revocation_targets.rs` (new), `session_forms.rs`, `admin/revocation_batch.rs`, `remote_mcp/tests/revocation_admin.rs` (new), schemas under `spec/schemas/chio-wire/v1/root_authority/`, `spec/PROTOCOL.md`.

**`POST /admin/revocations`** body (`revocation-admin-request.schema.json`, strict at every level, tagged union through `lossless_serde!`):

```json
{"target": {"kind": "capability_id", "capability_id": "cap_..."}, "reason": "offboarded"}
{"target": {"kind": "root_policy_rule", "rule_id": "okta-agents"}}
{"target": {"kind": "anchor_subject", "issuer": "https://acme.okta.com", "subject": "00u..."}}
{"target": {"kind": "tenant_tag", "issuer": "https://acme.okta.com", "tenant": "acme-eu"}}
{"target": {"kind": "replay_key", "anchor_kind": "oauth_id_jag", "issuer": "https://acme.okta.com", "assertion_id": "jti-..."}}
```

Response 200: `{"entry": <chio.revocation-entry.v1>, "newly_revoked": bool, "roots_revoked": <u64>}`, sent only after the commit and the authority-anchor sync.

**`GET /admin/revocations`**: `?after=<seq>&limit=<n>&kind=<kind>` returns `{"entries": [...], "head": <seq>}`; `?capability_id=<id>` returns `{"capability_id", "revoked", "entry_id"}`. No GET takes a plaintext subject or tenant.

**Fail-closed rules (status, exact body):**

| Condition | Status | Body |
|---|---|---|
| admin token not configured | 403 | `remote admin API is disabled` (existing) |
| missing or wrong bearer | 401 | `missing or invalid admin bearer token` (existing) |
| unknown member, unknown kind, oversized body, empty or NUL value | 400 | `invalid revocation request` |
| `rule_id` not in the loaded root policy | 422 | `revocation target names no rule in the loaded root policy` |
| `issuer` not the issuer of any provider record or non-provider anchor kind | 422 | `revocation target names an unknown issuer` |
| `replay_key` with an `anchor_kind` that has no assertion id (`operator_static_bearer`, `chio_local_as`, `chio_operator_key`, `oauth_introspection`), or `entra_agent_id` before M2 | 422 | `revocation target kind has no assertion id for this anchor kind` |
| `control_url` (remote durable admission) and kind other than `capability_id` | 409 | `revocation target kind requires the local admission store` |
| no local serving-owner store | 409 | `remote trust admin requires durable revocation state` (existing text; the path-open fallback is deleted) |
| store error before commit, or tenant index key unavailable | 503 | `revocation store unavailable` |
| commit outcome unknown (anchor sync failed) | 503 | `revocation outcome unknown; retry the same request` |

- Retry of the same request returns the same entry with `newly_revoked = false`.
- Tags are computed with item 4's tenant index (`subject_tag(issuer, subject)`, `tenant_tag(issuer, tenant)`); the plaintext is dropped before the store call. The request body is not logged; tracing records the entry id and kind only.
- `revocation_batch.rs` (session trust revoke) writes `capability_id` entries through the same store path.
- The path-opened `SqliteRevocationStore::open(revocation_db_path)` fallback in `open_revocation_store` is deleted (it is a second writer outside the serving owner). If item 4 has already deleted `revocation_db_path`, this is a no-op.

- [ ] **Step 1: Failing tests** in `revocation_admin.rs`, one per table row with the exact status and body, plus `each_target_kind_round_trips_and_denies_the_next_call` (in-process serve-http harness), `plaintext_subject_never_appears_in_logs_or_responses` (tracing capture), `retry_after_outcome_unknown_returns_the_same_entry`.
- [ ] **Step 2:** Implement; register `chio.revocation-entry.v1` and `chio.revocation-admin-request.v1` with positive and negative examples (padding, unknown kind, non-hex tag); `cs cargo xtask codegen`; PROTOCOL `/admin/revocations` subsection with the target table, the linearization statement and the status table.

---

### Task 7: `chio mcp revoke` (PR 4)

**Files:** `chio-cli/src/cli/types/runtime.rs` (under `McpCommands`), `src/cli/dispatch/mcp_revoke.rs` (new), `tests/mcp_revoke.rs` (new).

```text
chio mcp revoke capability --url <serve-http base> --capability-id <id> [--reason <r>] [--json]
chio mcp revoke rule       --url <base> --rule-id <id> [--reason <r>] [--json]
chio mcp revoke subject    --url <base> --issuer <uri> [--reason <r>] [--json]   # subject read from stdin
chio mcp revoke tenant     --url <base> --issuer <uri> [--reason <r>] [--json]   # tenant value read from stdin
chio mcp revoke replay-key --url <base> --anchor-kind <kind> --issuer <uri> --assertion-id <jti|uti> [--json]
chio mcp revocations list  --url <base> [--kind <kind>] [--after <seq>] [--limit <n>] [--json]
chio mcp revocations check --url <base> --capability-id <id> [--json]
```

- The admin token comes only from `CHIO_ADMIN_TOKEN`; there is no argv form. Missing token exits non-zero with `CHIO_ADMIN_TOKEN is required` before any request.
- Plaintext subject and tenant come only from stdin (one line, trailing newline stripped, empty refused, 4096-byte cap).
- The HTTP client uses the CLI's existing blocking client with a bounded response read and is added to the egress contract inventory; `scripts/check-http-egress-contract.sh` passes.
- Any non-200 prints the server body and exits 2; outcome unknown exits 3 so scripts can retry.
- `chio trust revoke` (trust-control and local revocation databases, capability only) is unchanged. Pointed at a serve-http state database it refuses through R9; `trust_revoke_refuses_a_serving_owner_database` pins that.

- [ ] **Step 1: Failing tests** in `tests/mcp_revoke.rs` against a spawned `serve-http` (native-cage run on the integrator): each subcommand, token-missing refusal, stdin-only plaintext, exit codes 2 and 3.
- [ ] **Step 2:** Implement.

---

## Linearization

**Transaction boundary.** A revocation is one IMMEDIATE transaction `W` on the serving owner's `Arc<StoreConnection>` (R2): entry insert, global commit, fan-out rows (delta, admission commit, global commit each), commit, then authority-anchor sync. The admin route acknowledges only after both. An admission is linearized at its budget authorize-hold transaction `A` (`claim_and_authorize_budget_and_commit_admission`, IMMEDIATE, same connection, R5), which reads `revoked_capabilities` for every id in `admission.revocation_set` (R4). A mint is one IMMEDIATE transaction `M` that runs `refuse_revoked_root` and inserts the anchored root.

**Claim.** SQLite admits one writer at a time on the database and the in-process `StoreConnection` lock serializes the process's transactions, so `W`, `A` and `M` are totally ordered. If `W` commits before `A` begins, `A` reads the fan-out rows for the root or an ancestor and the hold denies; the kernel attributes the deny to the entry (Task 4). If `W` commits before `M` begins, `M` refuses. If `M` commits before `W`, `W`'s fan-out reads `M`'s row and marks it. If `A` commits before `W`, the call was admitted; it then meets the in-transaction capture recheck (R4) and the allowed-receipt recheck (R6), which deny once `W` has committed (Q1).

**Read path in kernel admission.**
1. `check_tool_call_revocation_admission` (pre-dispatch): `revocation_entry` per id, early deny with entry evidence. Not the linearization point.
2. `durable_budget_binding` builds `revocation_set` (leaf plus `delegation_chain`) and `authorize_durable_budget_hold` runs `A`. This is the linearization point.
3. Capture (`capture.rs`, `dispatch_ledger/capture.rs`) rechecks in its own transaction.
4. `record_chio_receipt_with_federation` rechecks before appending an allowed receipt.

No step changes except the attribution read after a denied hold.

**Interaction with #1708.** `PublicationSync` is per kernel (R7) and serve-http runs one kernel per session, so the exclusive fence orders a kernel's own `revoke_capability` against that kernel's receipt publications and trace events only. It cannot order a revocation against other sessions' kernels. The admin route therefore does not take any kernel fence: cross-session order comes from the serving writer alone, and the admin route never blocks behind in-flight receipt appends (the #1708 "queued revoke can block admission threads" caveat does not apply to it). `ChioKernel::revoke_capability` keeps #1708's exclusive fence for in-process callers (conformance native suite, CLI tests) and writes a `capability_id` entry through the same store method. Item 5 adds no kernel-level revocation method for the other kinds. serve-http installs no runtime trace observer, so no trace model consumes admin-route revocations (Q3 asks Root-2 to confirm).

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
python3 scripts/check-error-urn-registry.py && python3 scripts/check-trust-boundaries.py && python3 scripts/check-security-clocks.py
# /usr/bin/sqlite3 on the crate DDL: EXPLAIN QUERY PLAN of the four fan-out selects and the mint lookup shows SEARCH using an index
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

The 12 staged `revocation_local` scenarios move into the live corpus when the `rust-mcp-serve-http` driver exists (item 7). Until then each scenario id has one named test in PR 3 or PR 4 that asserts its `expected` block, listed in the PR 4 body.

## Open Questions

| # | For | Question | Recommendation |
|---|---|---|---|
| Q1 | owner | Spec 7.11 says calls admitted before the acknowledgement "run to completion; in-flight streaming results are not cut off". Code on `main` rechecks revocation at capture and before an allowed receipt (R4, R6), so an admitted call that has not captured when the revocation commits ends denied with its output withheld. Staged scenario 010 expects allow. | Keep the code. The capture recheck is the fail-closed guard for effects (KERN-2 line) and the M1 "May say" line stays true. Land PR 0 to change 7.11 and scenario 010. |
| Q2 | Root-2 | PR 1 edits `serving_owner/global_commit_chain.rs` (Root-held) to add the `revocation_entry` projection kind, its reference digest and coverage clause. | Approve. Without it an entry that matches no root does not advance the chain, and a restored backup can drop it undetected, so later mints under the revoked target succeed. |
| Q3 | Root-2 | The admin route revokes at the store and takes no #1708 fence. Confirm that no trace model or Loom harness needs a `RevocationCommitted` event for store-level revocations, and that #1708's per-kernel fence is not meant to order other kernels. | Confirm as written. The serving writer is the cross-session order; adding a process-wide fence would serialize every session's receipt publication behind admin writes. |
| Q4 | owner | With remote durable admission (`control_url`), target kinds other than `capability_id` cannot be linearized, because anchored roots live in the local state directory. | Refuse them with 409 in M1. If item 4 forbids remote durable admission under a root policy, the 409 path is deleted with it. |
| Q5 | owner | A revocation that names a rule id or issuer the provider does not know: refuse, or accept as a pre-revocation? | Refuse with 422. A typo that revokes nothing is an operator error that must be loud; `capability_id` keeps today's accept-any-id behavior because a child id may never have been seen. |
| Q6 | owner | Revocations are monotone: no un-revoke in M1. A wrong `tenant_tag` revocation blocks that tenant on this state directory permanently. | Keep monotone in M1 (it makes the linearization and the after-the-fact attribution sound). A lift operation, with its own linearization rules, is an M2 candidate. |
| Q7 | lead | `RevocationStore::is_revoked` is replaced by `revocation_entry` (about 20 trait call sites, 8 implementors) instead of adding a second method. | Replace. Two methods answering one question is a dual API under the house rule. |
| Q8 | lead | Entry ids are deterministic (`rev_` + domain-separated SHA-256 of kind and value) rather than random. | Deterministic: idempotent retries, the same capability entry id on leader and replication followers, and no plaintext in the id because subject and tenant values are already tags. |
| Q9 | lead | The CLI is `chio mcp revoke` / `chio mcp revocations` (client of `/admin/revocations`), token from `CHIO_ADMIN_TOKEN` only, plaintext from stdin only. | Accept. `chio trust revoke` stays for trust-control and refuses serve-http state databases (R9). |

## Size

Spec 13.2 sizes item 5 at M, 4-6 engineer-days.

| Part | Days |
|---|---|
| PR 0 spec wording and scenario 010 (if Q1 is "keep the code") | 0.25 |
| PR 1 entry types, DDL, capability entries, reads, chain kind, tests | 1-1.5 |
| PR 2 trait replacement over 8 implementors, attribution, guard evidence, URN, real-SQLite tests | 1-1.5 |
| PR 3 fan-out for four kinds, mint check in item 4's insert, exchange error, interleaving tests | 1-1.5 |
| PR 4 admin route and status table, schemas, PROTOCOL, CLI, egress inventory, tests | 1-1.5 |
| Integration, native-cage runs, review rounds | 0.5-1 |
| Total | 4.75-7.25 |

Planning figure 5.5. The range sits up to 1.25 days above 13.2 because the chain projection kind (Q2) and the trait replacement (Q7) were not in the 13.2 estimate. Waiting time on #1708, item 2 and item 4 is not counted.

## Spec coverage

| Spec requirement | Task |
|---|---|
| 7.11 closed target kinds, indexed equality at exchange and admission | 3, 5 |
| 7.11 subject and tenant stored as tags only | 5, 6 |
| 7.11 linearization through the serving writer | 5, Linearization |
| 7.11 deny names the entry in guard evidence | 4 |
| 7.11 entries exportable with tags only (export itself is item 6) | 3 (`list_revocation_entries_after`, `chio.revocation-entry.v1`) |
| 7.11 D17 reconciliation with coop2c | Store reconciliation, Task 1 |
| 8.2 any token in the chain matched by an entry denies; store error denies | 4, 5 |
| 10.7 existing revocation tables gain the target kinds, writes through the serving writer | 3, 5 |
| 11.1 revocation unit tests (each kind, cascade, store error, tags only, acknowledged-before-pending) | 3, 4, 5, 6 |
| 11.3 `revocation_local` scenarios | named tests in PRs 3 and 4; move-in with item 7 |
| G12 `urn:chio:error:kernel:revocation-store` | 4 |
| G18 strict decoding of the admin request and entry | 3, 6 |
| 12 M1 "The provider can revoke a capability, a principal, a policy rule or a tenant" | 3 to 7 |
| 13.3 step 5 after the coop2c reconciliation | Task 1 |
