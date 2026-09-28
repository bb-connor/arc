# Signed-reader and tenant-isolation closure

Status: named reader migrations and SQLite matrix expansion implemented from
`0460314617` on `packet/3-retention-accounting` in `/tmp/arc-security-launch`.
Full packets 10.2/10.3 remain open for the explicit gaps below.

For execution: use the executing-plans workflow inline. Follow the user's
implementation-first, single-agent directive. Batch related changes, then run
focused owner checks. Do not begin with a full workspace build or test campaign.

## Goal and scope

Finish correction 1F and packets 10.2/10.3 of the
[engineering plan](2026-09-26-security-engineering-excellence.md): classify the
remaining signed-data entry points, enforce their original-byte parsing
contracts, and give all 85 inventoried SQLite tenant tables traceable runtime
evidence for their enforcing principal. Repair discovered defects in this batch.

The preceding replay-clock and financial-receipt batch is committed. Its scope
and local evidence remain in the
[execution record](../../reviews/2026-09-28-replay-clock-completion.md).

## Baseline evidence at `0460314617`

- The source gate tracks 44 constrained-reader constructors and 41 signed-input
  files. `scan` only looks for raw serde decoders inside registered files. A new
  reader in an unregistered file is outside that check.
- `chio-credentials/src/financial.rs` decodes financial credentials and versioned
  passports through `serde_json::Value` before typed validation. Bundled financial
  source validation also contains independent JSON readers.
- `chio-control-plane/src/passport_verifier.rs` loads verifier-policy, lifecycle
  and issuance-offer registries through raw serde before verifying their records.
  `reputation.rs` also chooses signed versus plain policy interpretation using
  parse success. These paths need explicit input and authentication contracts.
- `chio-federation/src/bilateral_dsse/{types,verify}.rs` and `frost/slot.rs` have
  separate statement, embedded-receipt and completed-authorization readers.
  Some already compare canonical bytes; raw serde alone is not evidence that
  signature verification or canonical enforcement is absent.
- The tenant inventory classifies 85 tables and 170 SQL statements. Existing
  receipt and model/SQLite security-state tests cover several families, but the
  per-table/principal runtime matrix is explicitly incomplete.

## Task 1: Close the reader inventory and gate scope

Files: `scripts/check-trust-boundaries.py`,
`scripts/tests/check-trust-boundaries.test.py`,
`docs/security/trust-boundary-inventory.json`,
`docs/security/signed-json-boundaries.md`.

- Enumerate production wire, file and database decoders. Record signed or hashed
  entry points, already-validated typed conversions, and genuinely unsigned
  inputs with their owning contract. Include imported decoder spellings and
  custom decoding entry points when classifying the sources.
- Make new decoder-bearing production files require classification. Do not solve
  the current blind spot by adding only the files touched in this batch.
- Preserve the three existing contracts: strict external I-JSON, native signed
  JSON with full-width integers, and exact canonical bytes. Decoding does not
  establish signer trust or authorization.
- Calibrate detection with a new unregistered reader file, a decoder bypass in a
  registered owner, and permitted conversion of an already-validated value.

## Task 2: Migrate credentials, passport registries and Finding readers

Primary owners: `crates/trust/chio-credentials/src/financial.rs`,
`financial/validation.rs`; `crates/platform/chio-control-plane/src/passport_verifier.rs`,
`reputation.rs`, `certify/helpers.rs`, `certify/registry.rs`;
`crates/economy/chio-finding/src/{purchase_context,recovery_context,status,validate}.rs`.

- Use bounded `UntrustedJsonText` at original-byte entry points before any lossy
  `Value` conversion. Retain schema, signature, signer-role, key/record identity
  and validity checks after parsing.
- Consolidate equivalent hand-written canonical parsers without weakening their
  typed round-trip or schema restrictions. Keep Finding's explicit I-JSON bounds.
- Make policy input modes explicit. Malformed signed input must not silently
  fall through to another interpretation; retain intentionally supported local
  configuration formats under their actual operator contract.
- Remove obsolete readback defaults or compatibility paths encountered in these
  owners, updating writers and callers together. No transitional fallback.
- Exercise duplicate keys at nested levels, numeric aliases, full-width integers
  where permitted, wrong signer/role, invalid signatures and mismatched registry
  keys. Pair rejections with valid fixtures that reach the intended check.

## Task 3: Migrate federation and durable evidence readers

Primary owners: `crates/trust/chio-federation/src/bilateral_dsse/{types,verify}.rs`,
`frost/slot.rs`; signed transport readers in
`crates/trust/chio-federation-transport-iroh/src/`;
`crates/platform/chio-store-sqlite/src/tool_outcome_store.rs` and
`admission_operation_store/` persistence decoders identified by task 1.

- Preserve the actual DSSE signed preimage and embedded-receipt contract. Require
  exact canonical input only where the format promises it; preserve existing
  signature, roster, epoch-anchor and digest bindings.
- Route persisted authenticated evidence through the shared decoder contract,
  then enforce projection and operation identity. Classify unsigned store
  projections explicitly rather than describing them as signed artifacts.
- Remove duplicate parsing paths where the constrained reader already provides
  the same guarantees. Keep secret-bearing zeroizing decoders under their
  existing dedicated ownership contract.
- Add focused malformed-input and valid-signature/wrong-binding cases through
  production readers, including persisted readback after reopen.

## Task 4: Complete the tenant runtime matrix and repair boundary defects

Files: `docs/security/trust-boundary-inventory.json`,
`docs/security/tenant-read-contracts.md`, owning SQLite test modules and the
authenticated adapters that select their read contexts.

Map every table to enforcing principal, production entry point and runtime test.
Reuse existing passing tests where they already establish the exact contract;
share family fixtures instead of writing 85 copies of one test.

Prioritize the families not covered by the recent matrix extension:

- Encrypted blobs and reference-mutation replay (3 tables), Finding payloads
  (1), sealed decoy/watermark registry (5), and IOU settlement (1).
- Kernel admission and participant projections (20), including declassification
  identity, receipt outbox, tombstone and nonce/output/egress event bindings.
- The remaining security-runtime families within its 54 tables: declassification,
  dispatch/recovery, attested-Finding batches/outbox, and typed suspension,
  throttling, issuance-freeze and egress-restriction effects.
- Retain the receipt table and existing flow, correlation, plan/effect, overlay,
  lineage and scheduler exact-identifier tests as mapped evidence.

For tenant entry points, first prove A can read its record, then present A's exact
unchanged identifiers using B's authenticated scope. Repeat durable reads after
reopen. Cover relevant list/range reads, mutation replay and forged tenant
projections with precise refusal or empty-result assertions.

For privileged-only tables, test the composition boundary that admits the named
principal and rejects tenant callers. An internal global scan does not become a
tenant endpoint merely because its rows contain `tenant_id`. IDs never grant
authority. Fix any exposed bypass with constrained context types and binding
checks, without retaining legacy fallback behavior.

## Task 5: Focused evidence and completion

- Build changed owner test targets together after implementation. Run reader and
  tenant tests for the changed families, then focused consumer compilation where
  public interfaces changed. Run formatting and strict Clippy for changed owners.
- Run `python3 scripts/check-trust-boundaries.py` and
  `python3 scripts/tests/check-trust-boundaries.test.py`. Use a small set of direct
  production-source mutations to demonstrate the new parser and tenant-binding
  regressions detect a bypass. Do not run an unrelated broad mutation campaign.
- Update the main plan and write an execution record with exact commands, terminal
  results and any unresolved scope. Keep rejection provenance typed and specific.
- Complete 10.2 only when the decoder census has no unclassified production
  entry points in its stated workspace scope. Complete 10.3's runtime item only
  when all 85 tables map to exercised principal contracts. A lexical inventory or
  test name alone is insufficient evidence.

Separate follow-on work: remaining clock/arithmetic census, broader weak-negative
cleanup, module/pool changes, native/scale/hosted qualification and operational
acceptance. Those gates do not close as a side effect of this batch. PostgreSQL
tenant surfaces are outside the existing SQLite inventory and require their own
explicit scope and evidence.


## Execution checkpoint

See the [execution record](../../reviews/2026-09-28-signed-reader-tenant-execution.md)
for changed owners, commands, runtime results and calibration limits.

- [x] Broaden the source gate to newly added decoder files, imported spellings and
  custom decoding; register the complete lexical census with explicit dispositions.
- [x] Migrate the named credential/registry/Finding and federation/persisted-evidence
  readers; repair IOU signature/row binding, registry identity and SD-JWT header gaps.
- [x] Map every SQLite tenant table to a principal runtime family or an explicit gap;
  add exact identifier, replay, restart and native-principal tests for the named families.
- [x] Complete focused runtime checks, strict Clippy for changed owners, source
  and hygiene gates, and parser/SQL mutation calibration. Repair the independent
  model's transition replay scoping; all 38 referenced tenant-family tests have
  terminal passing local evidence. Preserve failed/interrupted logs separately.
- [ ] Semantically classify and migrate the 447 raw-input-baseline files. This is
  required before claiming broad signed-reader census closure.
- [ ] Exercise `admission_operation_authorization_consumptions` through a genuine
  production signed-terminal projection fixture, with durable readback and foreign
  principal/projection rejection. Kernel-only sealed-type tests are insufficient.

The scope proved by this batch is the implemented named-reader migration and
expanded local tenant/principal evidence, not full correction 1F or 10.2/10.3 closure.
