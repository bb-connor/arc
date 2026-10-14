# EU AI Act Article 19 Compliance Mapping

## Metadata

| Field | Value |
|-------|-------|
| Regulation | EU AI Act, Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744 |
| Scope | Article 19: Automatically generated logs; Annex IV: Technical documentation; Annex VIII: EU database registration |
| Chio Profile | Current v1-only pre-release profile |
| Document Date | 2026-03-22 |
| Application Date | Chapter III, Sections 1 to 3 (including Articles 12, 19 and 26): 2 December 2027 for Annex III high-risk systems; 2 August 2028 for Annex I (Article 6(1)) high-risk systems |
| Maintained by | Chio Protocol Team |

---

## Executive Summary

The EU AI Act (Regulation 2024/1689) imposes logging, traceability, and technical documentation requirements on providers and deployers of high-risk AI systems. Article 12 requires high-risk AI systems to technically allow the automatic recording of events (logs) over their lifetime, with logging capabilities that enable traceability appropriate to the intended purpose. Article 19(1) requires providers, and Article 26(6) deployers, to keep those logs for at least six months. Annex IV extends this to require technical documentation that describes the system's design, capabilities, and monitoring procedures. Chio satisfies these requirements through its cryptographically-signed receipt log, Merkle-committed checkpoint infrastructure, and configurable retention policy.

Every tool invocation processed by the Chio kernel produces a signed `ChioReceipt` -- a tamper-evident log entry containing the capability identifier, tool server, tool name, invocation parameters and their SHA-256 hash, decision (allow or deny), policy hash, and a kernel key reference. Receipts are appended to an SQLite log in sequence order and are periodically committed into Merkle checkpoint batches, each signed by the kernel's Ed25519 keypair. This provides a tamper-evident, automatically-generated operation log that satisfies Article 12(2)'s traceability requirement without requiring any manual recording by operators or users.

Articles 19(1) and 26(6) require logs to be kept for a period appropriate to the intended purpose, of at least six months, unless other Union or national law provides otherwise. Chio's `RetentionConfig` on `KernelConfig` provides configurable `retention_days` (default 90 days) and `max_size_bytes` (default 10 GB) for time-based and size-based rotation. Archived receipts are moved to a separate SQLite file and continue to verify against stored Merkle checkpoint roots in the archive database -- satisfying the requirement that records remain verifiable after archival. The DPoP (Demonstration of Proof-of-Possession) module adds per-invocation cryptographic binding between the invoking agent's keypair and each specific tool call, providing Article 14-compatible human oversight anchors and ensuring that agent actions are attributable to the registered entity that holds the capability token.

---

## Clause Mapping

| Article/Annex | Requirement Summary | Chio Mechanism | Test File | Test Function |
|---------------|---------------------|----------------|-----------|---------------|
| Article 12(1) -- Automatic logging | High-risk AI systems must technically allow for the automatic recording of events (logs) over the lifetime of the system | Signed `ChioReceipt` appended automatically for every tool invocation (allow or deny); no manual recording required | `crates/kernel/chio-kernel/src/lib.rs` | `all_calls_produce_verified_receipts` |
| Article 12(2) -- Traceability of AI system actions | Logging capabilities must enable a level of traceability of the functioning of the system appropriate to its intended purpose | Receipt log links `capability_id`, `tool_server`, `tool_name`, `decision`, `policy_hash`, and `parameter_hash` in every record; `kernel_persists_tool_receipts_to_sqlite_store` confirms durable persistence | `crates/kernel/chio-kernel/src/lib.rs` | `kernel_persists_tool_receipts_to_sqlite_store` |
| Article 19(1) -- Denial traceability | Logs must record denied operations with sufficient detail for audit | Deny `ChioReceipt` is signed and persisted with the same fields as allow; monetary denials carry `FinancialReceiptMetadata.attempted_cost` | `crates/kernel/chio-kernel/src/lib.rs` | `monetary_denial_receipt_contains_financial_metadata` |
| Article 19(2) -- Logging capability description | Technical documentation must describe the logging capabilities of the system | `ToolManifest` with signed `ToolDefinition` per tool including human-readable description and parameter schema; manifest verification via Ed25519 signature | `crates/platform/chio-manifest/src/lib.rs` | `sign_and_verify_manifest` |
| Articles 19(1) and 26(6) -- Log retention | Providers and deployers must keep automatically generated logs for a period appropriate to the intended purpose, of at least six months, unless other Union or national law provides otherwise | `RetentionConfig.retention_days` (default 90, configurable) controls time-based rotation; operators set the retention period to match their regulatory obligation | `crates/kernel/chio-kernel/tests/retention.rs` | `retention_rotates_at_time_boundary` |
| Annex IV Section 2(g) -- Size-based rotation | Storage management must not lose records; size-based triggers must archive, not delete | `RetentionConfig.max_size_bytes` (default 10 GB) triggers archival (not deletion) of older receipts when the live DB exceeds the threshold | `crates/kernel/chio-kernel/tests/retention.rs` | `retention_rotates_at_size_boundary` |
| Annex IV Section 2(g) -- Records verifiable after archival | Archived records must remain verifiable and accessible for review | Archived receipts verify against Merkle checkpoint roots stored in the archive DB; `verify_checkpoint_signature` confirms the checkpoint signature is authentic in the archive | `crates/kernel/chio-kernel/tests/retention.rs` | `archived_receipt_verifies_against_checkpoint` |
| Annex IV Section 2(g) -- Checkpoint integrity in archive | Checkpoints must accompany their receipt batches in the archive | Archival logic copies checkpoint rows whose `batch_end_seq` is fully covered by archived receipts (partial-batch exclusion); batch 2 checkpoint remains in live DB when only batch 1 is archived | `crates/kernel/chio-kernel/tests/retention.rs` | `archive_preserves_checkpoint_rows` |
| Annex IV Section 7 -- Monitoring: tamper-evident audit | Technical documentation must describe measures ensuring log integrity; tamper-evident storage is required | Merkle-committed receipt batches: each batch of receipts produces a signed `KernelCheckpoint` with a Merkle root; checkpoint signature is verified via Ed25519 over canonical JSON | `crates/kernel/chio-kernel/src/checkpoint.rs` | `build_checkpoint_signature_verifies` |
| Annex IV Section 7 -- Individual receipt inclusion proof | Any individual log entry must be provably included in the audit record | Merkle inclusion proofs via `build_inclusion_proof` allow verifying any single receipt against the stored checkpoint root without re-reading the full batch | `crates/kernel/chio-kernel/src/checkpoint.rs` | `inclusion_proof_verifies_for_leaf_n` |
| Annex IV Section 7 -- Checkpoint trigger cadence | Logs must be committed at sufficient frequency for meaningful oversight | `checkpoint_batch_size` (default 100) controls how frequently Merkle checkpoints are triggered; `checkpoint_triggers_at_100_receipts` confirms the trigger fires at the configured batch size | `crates/kernel/chio-kernel/src/lib.rs` | `checkpoint_triggers_at_100_receipts` |
| Annex IV Section 7 -- End-to-end inclusion proof via receipt store | Inclusion proofs must be reproducible from persisted receipt data | `inclusion_proof_verifies_against_stored_checkpoint` confirms that receipts loaded from the SQLite store produce valid inclusion proofs against the stored checkpoint root | `crates/kernel/chio-kernel/src/lib.rs` | `inclusion_proof_verifies_against_stored_checkpoint` |
| Article 14 -- Human oversight: attributable decisions | Systems must enable human oversight; every decision must be attributable to the acting entity and to the policy applied | `ChioReceipt.decision` (Allow/Deny) combined with `policy_hash` and `capability_id` provides a signed, attributable audit record for every decision; receipt is signed by kernel keypair | `crates/kernel/chio-kernel/src/lib.rs` | `all_calls_produce_verified_receipts` |
| Article 14 -- Human oversight: proof of possession | Oversight requires that agent actions are bound to the registered entity | DPoP Ed25519 proof binds `capability_id + tool_server + tool_name + action_hash + nonce` to the agent's registered keypair; `proof.body.agent_key` must equal `capability.subject` | `crates/kernel/chio-kernel/tests/dpop.rs` | `dpop_valid_proof_accepted` |
| Article 14 -- Human oversight: replay prevention | Actions must not be replayed; each logged action must be unique | DPoP `action_hash` (SHA-256 of canonical invocation arguments) prevents cross-invocation replay; nonce store prevents same-invocation replay within TTL window | `crates/kernel/chio-kernel/tests/dpop.rs` | `dpop_nonce_replay_within_ttl_rejected` |
| Article 14 -- Agent identity binding | Oversight measures must verify that the recorded agent identity is authentic | `dpop_wrong_agent_key_rejected` confirms that a proof signed by a different keypair than `capability.subject` is rejected before any action is taken | `crates/kernel/chio-kernel/tests/dpop.rs` | `dpop_wrong_agent_key_rejected` |
| Article 14 -- Freshness of oversight evidence | Stale or replayed oversight evidence must be rejected | DPoP proof `issued_at` is checked against kernel clock; proofs older than `proof_ttl_secs` (default 5 min) are rejected | `crates/kernel/chio-kernel/tests/dpop.rs` | `dpop_expired_proof_rejected` |
| Article 9 -- Risk management: budget accountability | Risk management systems must include controls on monetary resource consumption by AI systems | `FinancialReceiptMetadata` (`cost_charged`, `attempted_cost`, `settlement_status`) is attached to every receipt involving a monetary `ToolGrant`; `max_total_cost` and `max_cost_per_invocation` are enforced atomically | `crates/kernel/chio-kernel/src/lib.rs` | `monetary_full_pipeline_three_invocations_third_denied` |
| Article 9 -- Risk management: monetary allow evidence | Receipts for allowed monetary actions must record actual cost | Allow receipts carry `FinancialReceiptMetadata.cost_charged` reflecting the actual cost reported by the tool server | `crates/kernel/chio-kernel/src/lib.rs` | `monetary_allow_receipt_contains_financial_metadata` |

---

## Architecture Overview

```
Agent  -->  Chio Kernel (TCB)  -->  Tool Server
              |
              +-- Validates CapabilityToken (issuer, expiry, scope, revocation)
              |     Satisfies: Article 19(1) traceability (capability_id in receipt)
              |
              +-- Checks DPoP proof (if dpop_required on ToolGrant)
              |     Satisfies: Article 14 human oversight (agent identity binding)
              |
              +-- Runs guard pipeline (velocity, policy, budget)
              |     Satisfies: Article 9 risk management
              |
              +-- Dispatches tool call (or produces deny receipt)
              |
              +-- Signs ChioReceipt (allow or deny)
              |     Satisfies: Article 19(1) automatic logging
              |
              +-- Appends to SqliteReceiptStore (durable, sequential)
              |     Satisfies: Annex IV Section 2(g) record retention
              |
              +-- Triggers Merkle checkpoint (every checkpoint_batch_size receipts)
              |     Satisfies: Annex IV Section 7 tamper-evident monitoring
              |
              +-- rotate_if_needed() archives per RetentionConfig
                    Satisfies: Annex IV Section 2(g) verifiable archival
```

The kernel fails closed: any error during evaluation produces a signed deny receipt. Log entries are never omitted on error paths.

---

## Verification

To confirm that all claims in this document are backed by passing test artifacts, run:

```bash
cargo test --workspace
```

All tests in the workspace must pass. Key tests referenced in this document:

```bash
# Retention and archival tests (Annex IV Section 2(g))
cargo test -p chio-kernel -- retention

# DPoP proof-of-possession tests (Article 14)
cargo test -p chio-kernel -- dpop

# Checkpoint tamper-evidence tests (Annex IV Section 7)
cargo test -p chio-kernel -- checkpoint

# Automatic logging and traceability tests (Article 12(1) and 12(2))
cargo test -p chio-kernel -- all_calls_produce_verified_receipts kernel_persists_tool_receipts

# Monetary budget tests (Article 9)
cargo test -p chio-kernel -- monetary

# Manifest description tests (Article 19(2))
cargo test -p chio-manifest -- sign_and_verify_manifest
```

Expected output: all referenced test functions exist and report `ok`.

---

## Regulatory Notes

The Article and Annex references above reflect the EU AI Act as published in the Official Journal of the European Union (OJ L 2024/1689, 12 July 2024) and as amended by Regulation (EU) 2026/1744 (OJ L 2026/1744, 24 July 2026), which entered into force on 27 July 2026. Under Article 113, as amended, Chapter III, Sections 1 to 3 (which contain Articles 12, 19 and 26) apply from 2 December 2027 to high-risk AI systems classified under Article 6(2) and Annex III, and from 2 August 2028 to those classified under Article 6(1) and Annex I. Article 19 applies to providers of high-risk AI systems; Article 26(6) places the corresponding log-keeping obligation on deployers. Annex IV specifies technical documentation content requirements. Annex VIII specifies EU database registration obligations.

Chio operates as infrastructure for the Runtime Kernel layer of an AI agent system. It provides the automatic logging (Article 19), technical documentation anchors (Annex IV), and human oversight support (Article 14) described above.

Legal review of this mapping against the final Official Journal text is recommended before filing. Technical claims in the "Clause Mapping" table are verifiable by running `cargo test --workspace`.
