---
phase: 09-compliance-and-dpop
verified: 2026-03-22T00:00:00Z
status: passed
score: 13/13 must-haves verified
re_verification: false
---

# Phase 09: Compliance and DPoP Verification Report

**Phase Goal:** Colorado and EU AI Act compliance documents are filed against tested and shipped code, receipt retention is configurable, and DPoP proof-of-possession closes the stolen-token replay story.
**Verified:** 2026-03-22
**Status:** passed
**Re-verification:** No -- initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Receipts older than retention_days are archived to a separate read-only SQLite file | VERIFIED | `archive_receipts_before` in receipt_store.rs (line 478) uses ATTACH DATABASE; `retention_rotates_at_time_boundary` test passes |
| 2 | Receipts are archived when DB size exceeds max_size_bytes | VERIFIED | `rotate_if_needed` (line 569) checks `db_size_bytes()` against threshold; `retention_rotates_at_size_boundary` test passes |
| 3 | Archived receipts remain verifiable against stored Merkle checkpoint roots | VERIFIED | `archived_receipt_verifies_against_checkpoint` test passes; archive DB receives checkpoint rows via `INSERT OR IGNORE INTO archive.kernel_checkpoints` |
| 4 | Checkpoint rows are preserved in the archive alongside receipt rows | VERIFIED | `archive_preserves_checkpoint_rows` test passes; partial-batch exclusion uses `batch_end_seq <= max_archived_seq` guard |
| 5 | Retention is configurable via KernelConfig struct fields (retention_days, max_size_bytes, archive_path) | VERIFIED | `pub retention_config: Option<crate::receipt_store::RetentionConfig>` at lib.rs:707; `RetentionConfig` struct at receipt_store.rs:19 with all three fields |
| 6 | A DPoP proof with correct binding fields is accepted | VERIFIED | `dpop_valid_proof_accepted` test passes (7/7 dpop tests pass) |
| 7 | A DPoP proof with wrong action_hash is rejected | VERIFIED | `dpop_wrong_action_hash_rejected` test passes |
| 8 | A DPoP proof signed by a key other than capability.subject is rejected | VERIFIED | `dpop_wrong_agent_key_rejected` test passes; verify_dpop_proof checks `proof.body.agent_key != capability.subject` at dpop.rs:216 |
| 9 | A DPoP proof with expired issued_at is rejected | VERIFIED | `dpop_expired_proof_rejected` test passes |
| 10 | A reused DPoP nonce within TTL window is rejected | VERIFIED | `dpop_nonce_replay_within_ttl_rejected` test passes; `nonce_store.check_and_insert` at dpop.rs:266 |
| 11 | A reused DPoP nonce after TTL window has expired is accepted | VERIFIED | `dpop_nonce_replay_after_ttl_accepted` test passes |
| 12 | Colorado SB 24-205 compliance document exists with tested clause-to-test mappings | VERIFIED | `docs/compliance/colorado-sb-24-205.md` exists; 16 clause rows with test file + test function columns; all referenced tests pass |
| 13 | EU AI Act Article 19 compliance document exists with tested clause-to-test mappings | VERIFIED | `docs/compliance/eu-ai-act-article-19.md` exists; 19 clause rows with test file + test function columns; all referenced tests pass |

**Score:** 13/13 truths verified

---

## Required Artifacts

### Plan 09-01 Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/pact-kernel/src/receipt_store.rs` | RetentionConfig, db_size_bytes, archive_receipts_before, rotate_if_needed | VERIFIED | All 4 symbols present at lines 19, 449, 478, 569 |
| `crates/pact-kernel/src/lib.rs` | retention_config field on KernelConfig | VERIFIED | `pub retention_config: Option<crate::receipt_store::RetentionConfig>` at line 707 |
| `crates/pact-kernel/tests/retention.rs` | 4 retention tests | VERIFIED | All 4 test functions present at lines 57, 103, 146, 217 |

### Plan 09-02 Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/pact-kernel/src/dpop.rs` | DpopProofBody, DpopProof, DpopConfig, DpopNonceStore, verify_dpop_proof | VERIFIED | All 5 symbols present; DPOP_SCHEMA = "pact.dpop_proof.v1" at line 39 |
| `crates/pact-core/src/capability.rs` | dpop_required field on ToolGrant | VERIFIED | `pub dpop_required: Option<bool>` at line 193 with serde(default, skip_serializing_if) |
| `crates/pact-kernel/tests/dpop.rs` | 7 DPoP tests | VERIFIED | All 7 test functions present at lines 71, 98, 132, 181, 224, 300, 369 |
| `crates/pact-kernel/Cargo.toml` | lru dependency | VERIFIED | `lru = "0.16.3"` at line 12 |

### Plan 09-03 Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `docs/compliance/colorado-sb-24-205.md` | Colorado SB 24-205 compliance mapping with Clause Mapping table | VERIFIED | File exists; 16-row clause-to-test table; Verification section present |
| `docs/compliance/eu-ai-act-article-19.md` | EU AI Act Article 19 compliance mapping with Clause Mapping table | VERIFIED | File exists; 19-row clause-to-test table; Verification section present |

---

## Key Link Verification

### Plan 09-01 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `receipt_store.rs` | `kernel_checkpoints` table in archive | `ATTACH DATABASE + INSERT INTO archive.kernel_checkpoints` | VERIFIED | Pattern `archive\.kernel_checkpoints` found at lines 506 and 542 |
| `lib.rs` | `receipt_store.rs` | `RetentionConfig in KernelConfig` | VERIFIED | `retention_config` field references `crate::receipt_store::RetentionConfig` at lib.rs:707 |

### Plan 09-02 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `dpop.rs` | `pact_core::canonical` | `canonical_json_bytes for proof body signing` | VERIFIED | `use pact_core::canonical::canonical_json_bytes` at line 31; used at lines 90, 256 |
| `dpop.rs` | `pact_core::capability::CapabilityToken` | `proof.body.agent_key == capability.subject` | VERIFIED | Sender constraint check at line 216 |
| `dpop.rs` | `DpopNonceStore` | `check_and_insert in verify_dpop_proof` | VERIFIED | `nonce_store.check_and_insert` at line 266 |

### Plan 09-03 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `colorado-sb-24-205.md` | `crates/pact-kernel/tests/retention.rs` | clause-to-test table entries | VERIFIED | `retention_rotates_at_time_boundary` and `archived_receipt_verifies_against_checkpoint` referenced in table |
| `eu-ai-act-article-19.md` | `crates/pact-kernel/src/checkpoint.rs` | clause-to-test table entries | VERIFIED | `build_checkpoint_signature_verifies` and `inclusion_proof_verifies_for_leaf_n` referenced in table |

---

## Requirements Coverage

Phase 09 plans claim requirements: COMP-01, COMP-02, COMP-03, COMP-04, SEC-03, SEC-04

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| COMP-01 | 09-03 | Published document maps PACT receipts to Colorado SB 24-205 requirements | SATISFIED | `docs/compliance/colorado-sb-24-205.md` exists; 16 clause mappings; Clause Mapping table; Verification section; all referenced tests pass under `cargo test --workspace` |
| COMP-02 | 09-03 | Published document maps PACT to EU AI Act Article 19 traceability requirements | SATISFIED | `docs/compliance/eu-ai-act-article-19.md` exists; 19 clause mappings; Clause Mapping table; Verification section; all referenced tests pass |
| COMP-03 | 09-01 | Receipt retention policies are configurable (time-based and size-based rotation) | SATISFIED | `RetentionConfig` struct with `retention_days` and `max_size_bytes`; `rotate_if_needed` archives receipts exceeding either threshold; 4 retention tests pass |
| COMP-04 | 09-01 | Archived receipts remain verifiable via stored Merkle checkpoint roots | SATISFIED | `archive_receipts_before` copies checkpoint rows into archive DB; `archived_receipt_verifies_against_checkpoint` test confirms cryptographic verifiability after archival |
| SEC-03 | 09-02 | DPoP per-invocation proofs bind to capability_id + tool_server + tool_name + action_hash + nonce | SATISFIED | `verify_dpop_proof` in dpop.rs validates all 5 binding fields; `dpop_valid_proof_accepted` and `dpop_wrong_action_hash_rejected` tests pass |
| SEC-04 | 09-02 | DPoP nonce replay store rejects reused nonces within configurable TTL window | SATISFIED | `DpopNonceStore` with LRU-backed nonce tracking; `dpop_nonce_replay_within_ttl_rejected` test passes; `dpop_nonce_replay_after_ttl_accepted` confirms TTL expiry allows re-use |

**Orphaned requirements check:** REQUIREMENTS.md maps COMP-01, COMP-02, COMP-03, COMP-04, SEC-03, SEC-04 to Phase 9. All six appear in plan frontmatter. No orphaned requirements.

---

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/pact-kernel/src/receipt_store.rs` | 722, 749, 770, 777-785 | `expect` / `unwrap` calls | Info | All instances are inside `#[cfg(test)]` module (module boundary at line 703); production code is clean; clippy passes with -D warnings |

No blockers or warnings found. The `expect`/`unwrap` instances in receipt_store.rs are entirely within the test module and are exempt by convention (CLAUDE.md: "Test code is exempt").

---

## Test Results

| Test Suite | Command | Result |
|------------|---------|--------|
| Retention tests | `cargo test -p pact-kernel -- retention` | 4 passed, 0 failed |
| DPoP tests | `cargo test -p pact-kernel -- dpop` | 7 passed, 0 failed |
| Full workspace | `cargo test --workspace` | All suites ok, 0 failures (30 test result lines, all "ok") |
| Clippy | `cargo clippy --workspace -- -D warnings` | Clean (no errors) |

---

## Human Verification Required

The compliance documents are Markdown files containing clause-to-test mappings. Two items benefit from human review:

### 1. Legal Accuracy of Clause Interpretations

**Test:** Review the "Requirement Summary" column in each compliance document against the actual enrolled bill text (Colorado SB 24-205) and the EU AI Act Official Journal text (Regulation 2024/1689).
**Expected:** The clause summaries should accurately paraphrase the regulatory obligations; PACT mechanisms should genuinely satisfy those obligations.
**Why human:** Automated verification confirms that referenced test functions exist and pass, but cannot assess whether the clause-to-mechanism mapping is legally sufficient.

### 2. Compliance Document Filing Readiness

**Test:** Review both documents for completeness and PR-readiness as regulatory filings.
**Expected:** Documents should be suitable for submission to legal counsel and external reviewers before the June 30, 2026 (Colorado) and August 2, 2026 (EU) deadlines.
**Why human:** Deadline compliance and regulatory interpretation require human judgment.

---

## Gaps Summary

No gaps found. All 13 observable truths verified, all 9 artifacts exist and are substantive, all 7 key links are wired, all 6 requirement IDs are satisfied, and no blocker anti-patterns were identified.

---

_Verified: 2026-03-22_
_Verifier: Claude (gsd-verifier)_
