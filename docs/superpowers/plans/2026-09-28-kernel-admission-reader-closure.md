# Kernel and SQLite correctness closure

> **For agentic workers:** Use superpowers:executing-plans inline. Preserve the
> user's single-agent, implementation-first directive. Batch owner changes before
> focused verification; keep one Cargo owner per checkout.

**Goal:** Close kernel and SQLite decoder classifications, finish their pending
arithmetic/clock dispositions and required repairs, remove obsolete retained-
request formats, and exercise the last uncovered SQLite terminal authorization-
consumption contract.

**Architecture:** Apply the existing constrained JSON readers at original-byte
entry points, preserving the owning signature, canonicalization and authority
checks. Keep verification results sealed. Exercise signed terminal projections
through production verification, atomic SQLite commit and durable readback.

**Tech Stack:** Rust, serde, `chio-core::canonical::UntrustedJsonText`,
`chio-kernel`, `chio-store-sqlite`, rusqlite and the existing Python source gates.

**Spec:** [Unrepresentable defects](../specs/2026-09-26-unrepresentable-defects-design.md),
[admission operations](../specs/2026-07-12-admission-operation-design.md),
[engineering standard](../../security/engineering-standard.md), and corrections
1D/1F plus packets 10.2/10.3 of the
[engineering plan](2026-09-26-security-engineering-excellence.md).

Status: implemented and locally verified after `f16d4e781c` on
`packet/3-retention-accounting`, checkout `/tmp/arc-security-launch`.
The preceding [execution record](../../reviews/2026-09-28-signed-reader-tenant-execution.md)
is the evidence baseline. The [batch execution record](../../reviews/2026-09-28-kernel-admission-reader-execution.md)
records implementation, repaired failures, passing targeted reruns and actual
runtime bypass calibration. All seven scoped tasks below are complete; broader
roadmap acceptance remains open.
The [remaining-work reconciliation](../../reviews/2026-09-28-remaining-security-work.md)
places this batch within the broader review/spec backlog.

## Global constraints

- Fail closed; parsing does not establish signer trust or execution authority.
- Preserve strict external I-JSON, native full-width integers and exact canonical
  storage as distinct contracts. Retain original bytes until their contract runs.
- No legacy compatibility path for unshipped formats. Update writers, readers,
  fixtures and current documentation together.
- Do not add public fields, `Deserialize` or an assertion-based constructor to a
  sealed proof just to construct a test fixture.
- Preserve exact operation, request, tenant, capability, lease, fence, outcome and
  receipt bindings. Rejection must leave durable state unchanged.
- Keep diagnostic output redacted and error causes inspectable where the owning
  API permits them. Use precise negative assertions.
- No broad workspace, million-entry or hosted campaign during implementation.
  Those remain acceptance gates for a frozen candidate. Do not touch `output/`.
- No em dashes in code, comments or documentation.

## Verified starting point

- The inventory has 447 `raw-input-baseline` files, including **36 in
  `chio-kernel` and 37 in `chio-store-sqlite`**. These are unclassified decoder-
  bearing files, not 73 proven vulnerabilities. Some are custom deserializers
  or already-canonical readers.
- The historical arithmetic inventory has 264 pending entries in these crates
  (78 kernel, 186 SQLite). The clock inventory has 112 occurrences (31 kernel,
  81 SQLite). Both include fixtures; dispositions must follow current code.
- `RetainedToolAdmissionRequestV1::from_canonical_bytes` accepts schemas v1-v4.
  The production coordinator retains requests only with an explicit authority
  profile, which selects v4. The old decoding branches remain removable debt.
- The SQLite runtime matrix covers 84 of 85 tables through shared fixtures.
  `admission_operation_authorization_consumptions` remains the explicit gap.
- `VerifiedAuthorizationReceiptConsumption::from_source_verified` is test-only.
  Ordinary kernel completion supplies `authorization: None`. The signed remote
  verifier and SQLite insertion/readback paths exist, but their presence does
  not establish end-to-end support for every participant combination.

## Review focus

1. Nested duplicate fields or numeric aliases must not change a signed or hashed
   interpretation. Tasks 1-3 own original-byte rejection tests.
2. Well-formed retained data must not supply fresh authority, resurrect one-shot
   credentials, or obtain a missing historical authority selection. Task 1 owns
   current-schema and recovery-binding cases.
3. A valid signature over a foreign tenant, request, outcome or claimant must
   reject before durable consumption. Task 5 owns these substitutions.
4. Exact replay must be idempotent; altered replay, double consumption and
   tampered sidecar readback must fail without a partial terminal commit. Task 5
   owns transaction and reopen evidence.
5. Malformed-input denials must retain a specific reason without disclosing
   retained capability/request content. Task 6 owns error and evidence checks.
6. Arithmetic refusal or a clock fault after acquiring a write transaction must
   leave all participants unchanged. Task 4 owns the numeric and clock cutpoints.

## Task 1: Harden retained admission and recovery inputs

Owners under `crates/kernel/chio-kernel/src/`:
`admission_operation/{retained_request,runtime_replay,native_caller_custody,
caller_dispatch_context,execution_nonce,governed_approval_replay}.rs`,
`capability_lineage.rs`, `dpop/replay_source/snapshot.rs`, and
`kernel/active_response_committed_recovery.rs`.
Tests: existing admission-operation tests, durable-admission authority-profile
tests, threshold-issuance retained-request tests and caller-custody tests.

Interfaces: preserve the public `from_canonical_bytes` result types and existing
authority-verification entry points. Consume `UntrustedJsonText::from_wire` plus
`decode_canonical` for exact typed canonical records; use `decode_signed` only
where the established contract permits noncanonical signed text.

- [x] Classify each owner by actual input provenance, numeric domain, bound and
  validation sequence. Keep explicit dispositions for safe typed conversions.
- [x] Migrate original-byte readers and remove equivalent duplicate canonical
  work. Preserve source seals, lineage signatures and recovery custody checks.
- [x] Make retained-request persistence require the current v4 profile. Remove
  v1-v3 acceptance and obsolete constructors; retain supported native and
  non-native profile semantics. Update the producer and fixture construction in
  the same change. Do not delete current cryptographic binding layers merely
  because their domain string has an earlier version number.
- [x] Add current-profile roundtrip/recovery controls, rejection of older schemas
  and missing profiles, duplicate/alias rejection, and changed request/profile/
  custody negatives through production readers. Confirm transient credentials
  remain excluded and fresh authority validation remains mandatory.

## Task 2: Harden terminal, output and caller-delivery readers

Owners under `crates/kernel/chio-kernel/src/`:
`admission_operation/projection.rs`,
`admission_operation/projection/{channel_terminal,economic_cancellation}.rs`,
`admission_operation/remote_projection.rs`, `caller_delivery.rs`,
`caller_delivery/retained.rs`, `tool_outcome.rs`,
`tool_outcome/{release,security_release}.rs`,
`tool_outcome/release/persistence.rs`, `kernel/admission_terminal_receipt.rs`,
`kernel/admission_coordinator/{federation_context,native_output}.rs`,
`kernel/admission_coordinator/native_egress/{ledger,lifecycle}.rs`,
`kernel/admission_coordinator/return_context/caller.rs`, and
`kernel/active_response_coordinator/execution_validation.inc`.

Interfaces: retain `SignedAdmissionTerminalProjectionV1::verify` returning the
sealed `VerifiedAdmissionTerminalProjectionV1`; keep release proof verification
separate from persisted evidence decoding.

- [x] Migrate bounded original-byte decoding before `Value` conversion. Audit
  nested base64 records, manifests and artifacts under their own size bounds.
- [x] Retain signatures, expected signer/claimant, manifest membership, exact
  record digests, source/terminal successor and outcome-version checks. Do not
  replace these with successful parsing or a valid envelope signature alone.
- [x] Exercise nested duplicate keys, exact canonical mismatch, numeric limits,
  record/digest substitution, wrong outcome/version and signed wrong-principal
  inputs. Pair each negative with a valid fixture reaching the same boundary.
- [x] Classify the remaining kernel census owners in the same batch:
  `admission_operation.rs`, `admission_operation.part2.inc`,
  `admission_operation/{identity,
  native_security_binding}.rs`, `kernel/{admission_cleanup,delivery_contract,
  mod}.rs`, `payment.rs`, `provider_verdict.rs`, and `transport.rs`.
  Modify only readers whose actual contract requires it. All 36 baseline files
  must finish with reviewed semantic dispositions.

## Task 3: Complete the remaining SQLite reader owners

Scope is all 37 SQLite `raw-input-baseline` entries in
`docs/security/trust-boundary-inventory.json` at the recorded base. Their owners
under `crates/platform/chio-store-sqlite/src/` include approval/threshold readers,
capability lineage, channel lifecycle/release, economic state cache, Finding
market/pool/operator evidence, fiscal storage, receipt claim-log and checkpoint
support, security-state participant sources, and serving-owner anchors.

Interfaces: keep the existing store ports, principal contexts and typed errors.
Use the same constrained original-byte reader contract as tasks 1 and 2.

- [x] Disposition every baseline entry against its current producer and consumer.
  Distinguish signed/digested artifacts, unsigned configuration, custom typed
  deserialization and test-only fragments. Register safe conversions explicitly.
- [x] Migrate the actual wire/database/file inputs that require it and retain
  identity, signer, canonical, digest and mirrored-column checks. Remove obsolete
  fallback/default behavior in the touched production contracts and update writers.
- [x] Exercise changed store families through their public production readers,
  with valid controls, malformed bytes, validly signed wrong-binding inputs and
  reopen where the data is durable. Preserve existing tenant-family evidence.

## Task 4: Finish kernel/SQLite arithmetic and clock correctness

Sources: the 264 pending entries for these crates in
`docs/reviews/2026-09-27-arithmetic-inventory.tsv`, and their 112 clock occurrences
in `scripts/security-clock-inventory.json`. Kernel production owners include
checkpoint/reporting, receipt analytics and surviving counters/deadlines. SQLite
owners include receipt/retention, participant journals and durable state; the
inventories also include many test fixtures. Historical line numbers must be
resolved to the current implementation before changing code.

Interfaces: reuse the shared fallible `Clock`, distinct epoch/monotonic values,
`ExposureUnits` and `InvocationCount`. Keep database integer bounds explicit and
preserve SQL refusal predicates. Do not introduce another clock trait.

- [x] Give all 264 entries an evidenced disposition: checked repair, intentional
  bounded behavior, removed/moved implementation or fixture. Never rewrite a
  saturation simply to make the inventory smaller. Unbounded accounting clamps
  and wrapping authority counters require checked refusal at their owner.
- [x] Complete the production clock migrations in this scope and record each
  deadline's epoch/monotonic contract. Classify fixture and external clock
  adapters explicitly; keep unclassified production occurrences open until
  migrated or justified by the shared clock's boundary contract.
- [x] Preserve atomicity on numeric/clock failure, including after transaction
  acquisition or sequence allocation. Checked retries must retain their original
  authority window; historical readback must not become fresh authority.
- [x] Add focused overflow/underflow, clock outage/regression, exact replay and
  rollback tests for changed behavior, asserting the specific rule and unchanged
  state. Keep safe fixture arithmetic with its documented bound.

## Task 5: Close durable authorization-consumption coverage

Owners: kernel `admission_operation/{projection,remote_projection}.rs`,
`kernel/admission_coordinator/terminal.rs`, and SQLite
`crates/platform/chio-store-sqlite/src/admission_operation_store/projection.rs`.
Create `crates/platform/chio-store-sqlite/src/admission_operation_store_tests/authorization_consumption.rs`
and register it in `admission_operation_store_tests.rs`.

Interfaces: production signed-envelope `verify`, store
`commit_signed_terminal_projection`, and `load_terminal_replay`. Extend source
verification only where the fixture exposes missing production composition;
never turn the existing test-only proof factory into an unchecked public API.

- [x] Construct a protocol-valid signed terminal projection from source receipts,
  the durable operation, its claimant and required participant evidence. Drive
  production verification and commit; no direct SQL insert as the positive path.
- [x] Prove successful consumption, exact replay, reopen and retained readback.
  Require one terminal/consumption result and exact original signed evidence.
- [x] Reject validly signed substitutions of tenant, request, source/consumer
  receipt, parameter hash, outcome/version and claimant. Check unchanged state
  after rejection. Exercise double consumption and altered replay explicitly.
- [x] Tamper persisted sidecar projections in a negative fixture and require
  readback failure. Repair missing validation at its production owner, retaining
  transaction atomicity and source verification.
- [x] Map the table to the actual exercised principal/test family only after
  terminal runtime evidence exists. Do not claim ordinary local completion can
  produce this participant unless its source-verification path is implemented
  and exercised too.

## Task 6: Preserve precise rejection provenance and ratchet the gate

Files: touched kernel error owners, `scripts/check-trust-boundaries.py`,
`scripts/tests/check-trust-boundaries.test.py`,
`docs/security/trust-boundary-inventory.json`,
`docs/security/{signed-json-boundaries,tenant-read-contracts}.md`.

- [x] Preserve structured parser causes across touched local error boundaries;
  retain registered redacted rules at signed-receipt/log projections. Replace
  weak negative assertions in the changed cases with expected variants/codes.
- [x] Register the classified kernel and SQLite owners and justify each retained raw
  conversion. Distinguish unsigned input from already-verified typed conversion.
- [x] Demonstrate that a real parser bypass and a real terminal principal/binding
  bypass make their respective regression fail. Restore source after each
  focused mutation; source-regex calibration alone is insufficient.

## Task 7: Verify and record the bounded result

- [x] Build changed kernel and SQLite test targets together after implementation.
  Run affected admission, projection, retained-request, release, delivery and
  store cases. Compile direct consumers if public types changed. Avoid unrelated
  scale, crash-selector and full-workspace runs.
- [x] Run changed-owner strict Clippy and formatting, then
  `python3 scripts/check-trust-boundaries.py` and
  `python3 scripts/tests/check-trust-boundaries.test.py`. Run the existing source
  arithmetic, clock and negative-assertion gates for their changed inventories,
  and the hygiene gate if file structure changes. Preserve failed/interrupted logs.
- [x] Write `docs/reviews/2026-09-28-kernel-admission-reader-execution.md` with
  source identity, commands, terminal evidence, discovered defects and residual
  scope. Update parent plan checkboxes only to the extent proved.

Exit: all 73 kernel/SQLite baseline files have semantic dispositions and required
reader changes; the 264 historical arithmetic entries have evidenced dispositions
and required repairs; production clock occurrences in the named scope have their
shared-clock contracts enforced, with fixture/adapter dispositions explicit;
current retained-request producers/readers agree without old
format acceptance; authorization-consumption has genuine production SQLite
runtime evidence; focused regressions and calibrated bypass checks pass.

This does not close the other 374 current baseline files, remaining arithmetic
and ambient-clock inventories, broader error/mutation cleanup, retention issue
#1045, large temporal-model timeout, module/performance work, native/scale/hosted
qualification, supply-chain/trusted-delivery gates or operational acceptance.
