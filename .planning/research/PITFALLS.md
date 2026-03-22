# Pitfalls Research

**Domain:** Agent economy infrastructure -- economic primitives on a capability-based security protocol
**Researched:** 2026-03-21
**Confidence:** HIGH (all pitfalls derived from actual codebase, known risk register in CLAWDSTRIKE_INTEGRATION.md, and structural analysis of the v2.0 scope)

---

## Critical Pitfalls

### Pitfall 1: deny_unknown_fields Removal Not Sequenced Before New Fields Ship

**What goes wrong:**
`CapabilityToken`, `CapabilityTokenBody`, `PactScope`, `ToolGrant`, `ResourceGrant`, `PromptGrant`, `DelegationLink`, `DelegationLinkBody`, `ToolCallAction`, `GuardEvidence`, `PactReceipt`, `PactReceiptBody`, `ChildRequestReceipt`, `ChildRequestReceiptBody`, and additional types all carry `#[serde(deny_unknown_fields)]`. When `MonetaryAmount`, `max_cost_per_invocation`, `max_total_cost`, or any other new field is added to a type that still has `deny_unknown_fields`, any old kernel that receives a token or receipt containing the new field will panic with a deserialization error rather than ignoring it. This is a silent wire-level compatibility break: the new kernel issues tokens that the old kernel rejects, but the old kernel produces no useful diagnostic about why.

**Why it happens:**
Developers add the new fields behind `#[serde(default, skip_serializing_if = "Option::is_none")]`, which makes them optional for serialization, but forget that `deny_unknown_fields` applies during deserialization. The `default` attribute only helps when the field is absent from the JSON; it has no effect when the field is present but unknown to an older deserializer. Because both old and new kernels compile and pass their own tests independently, the breakage only appears during cross-version token exchange.

**How to avoid:**
Remove `deny_unknown_fields` from all 18 affected types in a dedicated release before any new fields are added to wire-serialized structs. This removal must ship and be deployed before the monetary budget fields appear in any token or receipt payload. The removal itself is non-breaking: it only widens what existing deployments will accept. Use a migration test that round-trips a token built with new optional fields through the old deserialization path to confirm tolerance.

**Warning signs:**
- A plan phase proposes adding `MonetaryAmount` or any new field to `ToolGrant` or `PactReceipt` without a preceding phase that removes `deny_unknown_fields`.
- Test coverage for deserialization of tokens with unknown fields does not exist.
- The migration sequence in planning does not call out schema-tolerance as a prerequisite gate.

**Phase to address:**
Schema compatibility phase -- must be the first substantive v2.0 phase, before any economic-primitive work begins. Gate: old kernel can deserialize token produced by new kernel without error.

---

### Pitfall 2: DPoP Proof Binding Copied From HTTP Shape Rather Than PACT Invocation Shape

**What goes wrong:**
ClawdStrike's DPoP implementation binds proofs to HTTP requests using fields `method`, `url`, and `body_sha256`. If the PACT port replicates this shape, proofs become meaningless at the PACT layer: a proof bound to an HTTP POST to `/invoke` is not bound to which capability, which tool, or which argument content was authorized. An attacker who can observe the transport layer can replay the same HTTP request (same method + url + body) against a different capability context. The proof-of-possession property -- that the agent holding the keypair authorized this specific invocation -- is not provided.

**Why it happens:**
The ClawdStrike source is a working, tested implementation. Porting developers default to copying it. HTTP-specific fields look generic enough that they appear to provide meaningful binding. The type shapes are similar; the semantic gap is invisible until threat-modeled.

**How to avoid:**
The PACT DPoP proof message must bind to `capability_id`, `tool_server`, `tool_name`, canonical hash of the invocation arguments, and `issued_at` + nonce. This is documented explicitly in `CLAWDSTRIKE_INTEGRATION.md` section 3.1. The port must also add replay protection via a nonce store (ClawdStrike's source does not have one). Treat the ClawdStrike code as a reference for the signature verification flow only, not as the proof message schema.

**Warning signs:**
- The PACT DPoP proof message struct contains `method` or `url` fields.
- No nonce replay store is present in the implementation.
- DPoP tests only cover freshness/signature checks, not argument-content binding.
- The DPoP PR description says "port from ClawdStrike" without calling out the proof message rewrite.

**Phase to address:**
DPoP implementation phase. Verification gate: a proof generated for invocation A of tool T cannot be replayed against invocation B of tool T, even when issued_at and nonce are identical.

---

### Pitfall 3: Velocity Guard Implemented With async/await

**What goes wrong:**
ClawdStrike's `TokenBucket` uses `tokio::Mutex` and `async` acquire semantics. `pact_kernel::Guard::evaluate()` is a synchronous trait method. If the velocity guard wraps the async bucket without wrapping it in `std::sync::Mutex` and a synchronous try-acquire, the compiler will refuse to compile. A developer who works around this by making the guard async-first, or by calling `block_on()` inside `evaluate()`, introduces executor-within-executor panics in async runtime contexts and violates the kernel's guard contract.

**Why it happens:**
The source is async. The target is sync. The mechanical impedance mismatch is obvious in the type system but not obvious in intent. Developers unfamiliar with the kernel internals may assume guards can be async.

**How to avoid:**
Use `std::sync::Mutex` (not `tokio::Mutex`) for the velocity window state. Implement `try_acquire()` that returns `Verdict::Deny` immediately when the bucket is empty rather than waiting. This is documented explicitly in `CLAWDSTRIKE_INTEGRATION.md` section 3.3. Do not call `tokio::runtime::Handle::current().block_on()` inside a guard.

**Warning signs:**
- `tokio::Mutex` appears in the velocity guard source.
- Guard `evaluate()` is `async fn`.
- The guard compiles only when called from an async context.
- `block_on` appears inside the guard module.

**Phase to address:**
Velocity guard implementation phase. Verification gate: the guard evaluates correctly from a non-async test harness using `#[test]` (not `#[tokio::test]`).

---

### Pitfall 4: Monetary Budget Enforcement Using Last-Writer-Wins Replication Allows Double-Spend

**What goes wrong:**
The existing `SqliteBudgetStore` replication conflict resolution for `invocation_count` uses `MAX(local.invocation_count, remote.invocation_count)` as a fallback when sequence numbers are equal. For invocation counts this is safe: it is slightly conservative (may over-count) but never under-counts. For monetary `cost_units_charged`, the same MAX strategy is safe as a fallback. However, if two HA nodes each accept a charge concurrently (same seq, concurrent writes) and both use `try_charge_cost` with a total budget of 10000 units, each could approve up to 10000 units of spend before replication reconciles. The `MAX` conflict resolution then picks the higher cumulative charge -- but the time window during which both nodes approved independently created an exposure window proportional to the replication lag.

**Why it happens:**
Invocation-count budgets with eventual consistency are a known acceptable design (documented in `AGENT_ECONOMY.md`). Developers assume monetary budgets follow the same pattern because the code structure is identical. The difference is that invocation counts have no direct financial consequence; monetary charges do. The HA design optimizes for availability over consistency, which is correct for counts but warrants explicit discussion for money.

**How to avoid:**
Explicitly document the consistency model for monetary budgets in the design: best-effort enforcement under split-brain with bounded overrun equal to `max_cost_per_invocation` times the number of HA nodes. This is not necessarily wrong, but it must be a deliberate design decision documented in the capability spec. Do not silently inherit the invocation-count replication semantics for monetary fields. Consider adding a per-grant maximum-overrun bound as a configuration parameter.

**Warning signs:**
- The budget store replication design doc does not mention monetary charge consistency.
- Monetary budget tests run against single-node SQLite only.
- No test exercises concurrent charge approval under simulated HA split.

**Phase to address:**
Monetary budget phase. Verification gate: HA budget replication test with concurrent charge attempts documents the overrun bound explicitly.

---

### Pitfall 5: Merkle Checkpoint Computed Per-Receipt Rather Than Batched

**What goes wrong:**
If the checkpoint is signed on every receipt append, the kernel's hot path incurs SHA-256 over all accumulated receipt leaf hashes on every invocation. At 1,000 receipts, each checkpoint recomputes a 1,000-leaf Merkle tree. At 100,000 receipts the cost becomes measurable. More importantly, `MerkleTree::from_leaves` requires materializing all leaf hashes at once, meaning the SQLite checkpoint step reads all receipt rows in each batch.

**Why it happens:**
The natural implementation wires the checkpoint into `append_pact_receipt` as the simplest integration. The test suite runs with small receipt counts where per-receipt checkpoints are imperceptible.

**How to avoid:**
Checkpoint every N receipts (configurable, default suggested in `CLAWDSTRIKE_INTEGRATION.md` as the design intent). Store the batch leaf hashes in a staging buffer, not by re-reading historical rows. The checkpoint references `prev_checkpoint_hash` for chain continuity. This is how Certificate Transparency logs work: they batch entries, not one-per-entry.

**Warning signs:**
- `append_pact_receipt` calls a Merkle build function on every call.
- No `batch_size` or `checkpoint_interval` config parameter exists.
- The checkpoint implementation reads all receipts from the database to build the tree.
- Performance benchmarks are not part of the checkpoint acceptance criteria.

**Phase to address:**
Merkle checkpoint wiring phase. Verification gate: receipt append latency does not regress beyond 2x baseline when checkpoint interval is 100; checkpoint can be verified from a cold read without scanning all historical receipts.

---

### Pitfall 6: Receipt Query API Inherits ClawdStrike's Tenant/Policy Chain Model

**What goes wrong:**
ClawdStrike's receipt query API is indexed by `(tenant_id, policy_name)` chain keys. PACT's receipt model does not have tenants or policy names as first-class identifiers. If the PACT receipt query layer is built with these as primary index keys, queries for "all receipts for agent X" require a workaround join, and the receipt dashboard cannot answer agent-centric questions. This also creates a false dependency: PACT queries start requiring tenant context that is not part of the PACT protocol.

**Why it happens:**
The ClawdStrike query API is production-tested and the path of least resistance. The structural mismatch between ClawdStrike's multi-tenant broker model and PACT's capability-centric model is easy to miss when porting at the module level.

**How to avoid:**
PACT receipt queries must be keyed by `capability_id`, `tool_server`, `tool_name`, `decision`, and timestamp. Child-request queries are keyed by `session_id` and `parent_request_id`. Capability lineage joins (agent-centric queries) require the capability lineage index built in a later phase -- do not attempt to synthesize them from the receipt table alone before the index exists. This is documented explicitly in `CLAWDSTRIKE_INTEGRATION.md` section 3.2.

**Warning signs:**
- The `ReceiptQueryStore` trait has `tenant_id` or `policy_name` parameters.
- The receipt store schema adds a `tenant_id` column.
- Query tests are written against ClawdStrike fixture data that includes tenant context.

**Phase to address:**
Receipt query API phase. Verification gate: `receipt list --capability-id X` and `receipt list --tool-server Y --decision deny` work without any tenant parameter.

---

### Pitfall 7: Schema Evolution Without a Migration Test for Old Receipts

**What goes wrong:**
When new columns are added to `capability_grant_budgets` or `pact_tool_receipts` via `ALTER TABLE ... ADD COLUMN ... DEFAULT`, existing rows get `NULL` (or the specified default) for the new column. If the application code assumes the new column is always non-null (for example, treating `cost_units_charged = NULL` as zero), aggregate queries like `SUM(cost_units_charged)` silently return `NULL` in SQLite rather than the sum. This produces a nil budget-remaining value, which depending on error handling could either block all invocations (fail-closed: safe) or bypass budget enforcement (fail-open: dangerous).

**Why it happens:**
SQLite `ALTER TABLE ADD COLUMN` is convenient but produces a mixed-schema database. Developers test with freshly created databases where all rows have the new column from the start. The migration path for existing databases with historical rows is not tested.

**How to avoid:**
Always include a migration test that: (1) creates a database using the old schema, (2) populates it with test rows, (3) applies the migration, (4) runs queries against the migrated database, and (5) asserts that budget enforcement behaves correctly for rows created before the migration. For `cost_units_charged`, set `DEFAULT 0` explicitly and use `COALESCE(cost_units_charged, 0)` in any aggregate query as a belt-and-suspenders measure.

**Warning signs:**
- Migration tests only run against databases created after the migration.
- `ALTER TABLE` adds columns without `DEFAULT 0` for numeric accumulator fields.
- Aggregate queries over `cost_units_charged` do not use `COALESCE`.

**Phase to address:**
Monetary budget phase, alongside the `BudgetStore` schema migration work. Verification gate: migration test passes against a database pre-populated with historical invocation-count-only rows.

---

### Pitfall 8: SIEM Exporter DLQ Grows Without Bound

**What goes wrong:**
The SIEM exporter dead letter queue is designed as a filesystem-backed overflow for batches that fail all retries. If the SIEM endpoint is unavailable for an extended period (hours or days), the DLQ accumulates unboundedly. On a long-running kernel node, this can exhaust disk space. Worse, if the DLQ itself is not flushed correctly on reconnect, the backlog may replay in the wrong order relative to new events, producing misleading SIEM timelines.

**Why it happens:**
DLQ implementations are typically tested with small, bounded failure windows. Long-term endpoint unavailability is not exercised. The DLQ size cap and expiry policy are easy to omit from the initial port because they are an operational concern, not a protocol concern.

**How to avoid:**
The DLQ must have a configurable `max_entries` and `max_age_secs`. When `max_entries` is reached, new entries should displace the oldest (ring buffer) or be dropped with a metric increment, not silently accumulate. On reconnect, DLQ replay should interleave with live events in timestamp order, not flush the entire backlog before resuming live. Add a health endpoint that reports DLQ depth.

**Warning signs:**
- `DeadLetterQueue` has no `max_size` parameter.
- Tests do not exercise DLQ behavior under sustained endpoint failure.
- The exporter manager does not expose DLQ depth in its health struct.

**Phase to address:**
SIEM exporter phase. Verification gate: DLQ rejects new entries after `max_entries` is reached and the test confirms depth does not grow beyond the cap.

---

### Pitfall 9: Compliance Mapping Documents That Lag Behind Code

**What goes wrong:**
The Colorado AI Act (June 30, 2026) and EU AI Act (August 2, 2026) compliance documents are written once and then not updated as the economic primitives ship. When a regulator audits the system after June 2026, the compliance document may describe planned features (e.g., "Merkle-committed receipts provide tamper-evident audit trails") that were not yet wired in at the time the document was filed. This is the exact failure mode that Perspective A in STRATEGIC_ROADMAP.md warned about: compliance documents must describe shipping code, not roadmap intentions.

**Why it happens:**
Compliance documents are written by the team with the most context at the start of the compliance phase. As implementation details change, the documents drift. Nobody owns the cross-check between document claims and code behavior.

**How to avoid:**
Every claim in the compliance document that references a technical mechanism must include a reference to the test or verification artifact that confirms the mechanism is active. The compliance phase plan should explicitly list each claim and the corresponding evidence artifact. Before filing, run the qualification matrix to confirm each evidence artifact is green.

**Warning signs:**
- Compliance documents describe Merkle commitment, DPoP, or monetary budgets before those features have passed acceptance tests.
- No traceability matrix links document claims to test artifacts.
- The compliance document review is not gated on the feature completion dates.

**Phase to address:**
Compliance documentation phase (must follow Merkle wiring and monetary budget phases). Verification gate: each claim in both compliance documents has a passing test artifact cited inline.

---

### Pitfall 10: Capability Lineage Index Assumed to Exist Before It Is Built

**What goes wrong:**
The receipt dashboard, agent-centric billing queries, and SIEM exporter event enrichment all want to join `receipt.capability_id` to the issuing agent's identity, delegation depth, and grant metadata. This join is not possible from the receipt table alone -- receipts store `capability_id` but not `subject` or `grant_index`. If the dashboard or billing query layer is built before the capability lineage index exists, developers will add ad-hoc joins against the `capability_grant_budgets` table, hard-code issuer-key lookups, or simply omit the agent-identity dimension from queries. These workarounds become load-bearing code that the lineage index must not break when it ships later.

**Why it happens:**
The receipt dashboard needs to show something. The simplest join available is against whatever tables exist. The lineage index is Q3 work; the dashboard is Q2 work. Without explicit sequencing discipline, the dashboard ends up with a data model that fights the later index.

**How to avoid:**
Define the capability lineage index schema and query API (even as a stub returning empty results) before building any query layer that needs agent-centric joins. Build the dashboard against the stub API so it degrades gracefully when the index is empty. When the real index ships, the dashboard's join path already works.

**Warning signs:**
- The dashboard queries `capability_grant_budgets` directly using `capability_id` as a substitute for the lineage join.
- Agent-centric queries hard-code an assumption that `capability_id` encodes the agent identity.
- The dashboard data model has no column or placeholder for `subject_key`.

**Phase to address:**
Receipt query API phase (define stub) and capability lineage index phase (implement). Verification gate: dashboard renders correctly with an empty lineage index and correctly with a populated one.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Copy DPoP verifier without rewriting proof message schema | Faster port, working tests | Proof binding is HTTP-shaped, not invocation-shaped -- replay protection is incomplete | Never |
| Leave `deny_unknown_fields` removal for "later cleanup" | Saves one PR | Any new field ships as a wire-breaking change until removal lands | Never |
| Per-receipt Merkle checkpoint with no batching | Simpler initial implementation | Quadratic read cost at receipt volume; checkpoint becomes a bottleneck | Only if a `batch_size` config knob gates the behavior for quick iteration, with a TODO tracking the fix |
| Use ClawdStrike's `(tenant_id, policy_name)` index in PACT receipt API | Faster port, reuse query logic | Agent-centric queries require structural workarounds; lineage index design is constrained | Never |
| Monetary budget enforcement without HA overrun documentation | Simpler mental model | Auditors and security reviewers will find the gap; surprise overrun window in production | Never -- document the model explicitly |
| SIEM DLQ without size cap | One fewer config knob | Unbounded disk growth under sustained SIEM unavailability | Only in a feature-flagged dev build, never in a production release |
| Compliance documents drafted before features ship | Meet deadlines on paper | Regulatory risk if the document describes non-shipping code at audit time | Never for regulatory filings |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| ClawdStrike DPoP port | Copy `validate_dpop_binding()` including HTTP proof message fields | Rewrite proof message to bind `capability_id + tool_server + tool_name + arg_hash + issued_at + nonce`; add nonce replay store |
| ClawdStrike velocity guard port | Use `tokio::Mutex` and `async acquire()` from the source | Use `std::sync::Mutex` with synchronous `try_acquire()` returning `Verdict::Deny` immediately |
| ClawdStrike checkpoint pattern | Copy domain-separation tag `"AegisNetCheckpointHashV1"` | Replace with `"PactCheckpointHashV1"` and schema ID `"pact.checkpoint_statement.v1"` |
| ClawdStrike SIEM `SecurityEvent` | Use the ClawdStrike event type directly | Define a PACT-native `ReceiptEvent` wrapping `PactReceipt`; map schema formats (ECS, CEF, OCSF, Native) at export time |
| SQLite budget schema migration | Run `ALTER TABLE ADD COLUMN` and test only on fresh databases | Include a migration test that populates a pre-migration database and verifies correct behavior after migration |
| Receipt query API from ClawdStrike | Carry over `tenant_id` and `policy_name` index keys | Rekey on `capability_id`, `tool_server`, `tool_name`, `decision`, and timestamp |
| HA budget replication for monetary charges | Assume invocation-count consistency model applies to money | Explicitly document the overrun window; add HA concurrent-charge test |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Per-receipt Merkle checkpoint | Receipt append latency climbs linearly with receipt count; checkpoint step reads all historical rows | Batch every N receipts (configurable); stage leaf hashes in memory | At ~10,000 receipts the per-receipt read cost becomes measurable; at 100,000 it is a bottleneck |
| SIEM exporter blocking the receipt append path | Receipt signing latency spikes when SIEM endpoint is slow | Run SIEM export in a background channel with a fixed-depth queue; never block `append_pact_receipt` on export | First SIEM endpoint with >100ms latency; any transient network hiccup |
| Velocity guard with in-memory window state and unbounded key space | Memory grows linearly with unique `(capability_id, grant_index)` pairs | Cap the window map size; evict expired windows on access | At high grant-cardinality deployments (thousands of active capabilities) |
| SQLite WAL checkpoint accumulation under high receipt volume | Write latency spikes during automatic checkpoints | Tune `wal_autocheckpoint` pragma; use explicit checkpoint calls at known-quiet moments | Above ~10,000 receipts/minute on a typical laptop-grade disk |
| Full-JSON scan for cost queries before indexed columns exist | Billing aggregate queries scan every receipt row | Add `cost_charged` and `cost_currency` columns at receipt insert time, not as a later migration | At ~100,000 receipts, a full-scan aggregate query takes seconds |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| DPoP nonce replay protection omitted | An attacker who captures a proof can replay it within the TTL window against a different session context | Add a nonce store keyed by `(key_thumbprint, nonce)` with TTL expiry; reject duplicate nonces regardless of timestamp freshness |
| Monetary budget enforcement on only the issuing kernel, not the receiving kernel | An agent with two kernels in play can exceed the budget by issuing to the second kernel after the first exhausted | Budget state must be replicated across all HA nodes before any charge is approved; document the overrun window explicitly |
| Receipt dashboard served without kernel-key verification | Dashboard displays unsigned or tamper-modified receipt data | The dashboard must verify each receipt's Ed25519 signature against the embedded `kernel_key` before displaying it |
| Compliance document claims tamper-evident receipts before Merkle wiring ships | If the log is audited before Merkle is wired, individual receipts can be silently omitted | Gate compliance documents on Merkle wiring acceptance test |
| ClawdStrike checkpoint domain tag carried over | Checkpoints from PACT and ClawdStrike produce identical-looking proofs, enabling cross-system confusion | Replace domain tag with `"PactCheckpointHashV1"` in all checkpoint hash inputs |

---

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Receipt dashboard shows `capability_id` (UUID) with no agent-identity join | Compliance officers cannot identify which agent produced a receipt without a separate lookup | Show `subject_key` (truncated) and delegation depth alongside `capability_id`; use the lineage index stub from day one |
| Budget exhaustion error message lacks remaining budget and grant context | Agent developer cannot tell how much budget was used or which grant was exhausted | Include `grant_index`, `cost_units_charged`, and `budget_total` in the deny reason; populate `FinancialReceiptMetadata` even on deny |
| SIEM exporter config errors surface only at startup | Misconfigured SIEM endpoint silently drops events after startup succeeds | Validate exporter config at startup and emit a structured error on first export failure; expose exporter health in the CLI |
| Velocity guard denial has no `wait_estimate_ms` | Rate-limited agents cannot back off intelligently | Include `tokens_remaining`, `rate_per_sec`, and `wait_estimate_ms` in `GuardEvidence.details` |

---

## "Looks Done But Isn't" Checklist

- [ ] **deny_unknown_fields removal:** Verify that the removal PR covers all 18 affected types. Check `capability.rs`, `receipt.rs`, and `manifest.rs` individually with `grep deny_unknown_fields`. Count must be zero before any new fields ship.
- [ ] **DPoP proof binding:** Verify the proof message schema contains `capability_id`, `tool_server`, `tool_name`, and argument hash -- not `method` or `url`. Check with a test that generates a proof for tool invocation A and attempts to use it for tool invocation B.
- [ ] **Velocity guard sync boundary:** Verify `Guard::evaluate()` in `velocity.rs` has no `async` keyword and no `tokio` imports. Run the guard from a `#[test]` (not `#[tokio::test]`) harness.
- [ ] **Merkle checkpoint batching:** Verify `append_pact_receipt` does not call `MerkleTree::from_leaves` on every call. Look for a `checkpoint_interval` or `batch_size` config. Confirm the checkpoint test appends 1,000 receipts and measures latency.
- [ ] **Budget migration test:** Verify a test creates a pre-migration database, inserts invocation-count rows, runs the migration, then exercises `try_charge_cost`. This test must exist before merging the monetary budget phase.
- [ ] **SIEM DLQ size cap:** Verify `DeadLetterQueue` has a `max_entries` field and a test that confirms the depth cap is enforced.
- [ ] **Compliance document claims:** Verify each document claim has a passing test or verification artifact cited. Check the traceability matrix before filing.
- [ ] **Receipt dashboard signature verification:** Verify the dashboard or query layer calls `receipt.verify_signature()` before displaying receipt content.

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| deny_unknown_fields shipped with new fields (wire break in production) | HIGH | Roll back new-field-bearing kernel; issue emergency patch removing deny_unknown_fields from affected types; redeploy; re-issue capability tokens |
| DPoP HTTP-shaped proof in production | HIGH | Rotate all active capability tokens; patch DPoP module with correct proof binding; require clients to regenerate proofs |
| Velocity guard async deadlock in production | MEDIUM | Disable velocity guard via config flag; patch with sync implementation; re-enable |
| Monetary budget overrun under HA split | MEDIUM | Audit receipts for over-budget charges; document incident; patch budget store with overrun documentation; compensate externally |
| Merkle checkpoint performance regression | MEDIUM | Increase checkpoint interval via config; add batching in follow-up PR; no data loss |
| DLQ disk exhaustion | MEDIUM | Rotate DLQ file; add size cap in follow-up PR; confirm no event duplication on restart |
| Compliance document filed with non-shipping feature claims | HIGH | Issue correction to regulator; accelerate feature shipping; do not let more than one sprint pass between document filing and feature GA |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| deny_unknown_fields removal not sequenced first | Schema compatibility phase (Phase 1 of v2) | `grep -r deny_unknown_fields crates/pact-core/src/capability.rs crates/pact-core/src/receipt.rs` returns no results before monetary field PRs open |
| DPoP proof binding HTTP-shaped | DPoP implementation phase | Cross-invocation proof replay test: proof from invocation A is rejected for invocation B |
| Velocity guard uses async | Velocity guard implementation phase | Guard passes `#[test]` (non-async) harness without `block_on` |
| Monetary budget HA overrun undocumented | Monetary budget phase | HA concurrent-charge test documents overrun bound in test name and assertion message |
| Merkle checkpoint per-receipt | Merkle wiring phase | Benchmark test: 1,000-receipt append does not regress append latency beyond 2x baseline |
| Receipt query inherits tenant model | Receipt query API phase | `ReceiptQueryStore` trait has no `tenant_id` parameter; query tests use PACT-native keys |
| SQLite migration missing pre-migration test | Monetary budget phase | Migration test exists and runs against pre-populated database |
| SIEM DLQ unbounded | SIEM exporter phase | DLQ depth cap test passes; `ExporterHealth` reports `dlq_depth` |
| Compliance claims lead code | Compliance documentation phase | Traceability matrix links each claim to a passing test artifact |
| Lineage index assumed before built | Receipt query API phase (stub) | Dashboard renders with empty lineage index without errors or workaround joins |

---

## Sources

- `crates/pact-core/src/capability.rs` -- 18 `deny_unknown_fields` annotations confirmed by direct code inspection
- `crates/pact-core/src/receipt.rs` -- `deny_unknown_fields` on `PactReceipt`, `PactReceiptBody`, `ChildRequestReceipt`, `ChildRequestReceiptBody`, `ToolCallAction`, `GuardEvidence`
- `docs/CLAWDSTRIKE_INTEGRATION.md` -- Section 3.1 (DPoP proof message rewrite), Section 3.3 (sync guard requirement), Section 3.2 (receipt query key model), Section 8 (risk register)
- `docs/AGENT_ECONOMY.md` -- Section 3.1.1 (deny_unknown_fields migration requirement explicitly called out), Section 2.3 (HA replication conflict resolution for monetary charges)
- `docs/STRATEGIC_ROADMAP.md` -- Perspective A (Merkle commitment must back compliance claims), debate resolution sequencing
- `crates/pact-kernel/src/lib.rs` -- `Guard::evaluate()` synchronous trait confirmation
- `crates/pact-core/src/merkle.rs` -- `MerkleTree::from_leaves` build semantics (full batch required)
- `.planning/PROJECT.md` -- v2.0 feature list, regulatory deadlines, known risks

---
*Pitfalls research for: agent economy infrastructure on a capability-based security protocol*
*Researched: 2026-03-21*
