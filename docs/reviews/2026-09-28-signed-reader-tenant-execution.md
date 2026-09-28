# Signed-reader and tenant execution

Plan: [signed-reader and tenant-isolation batch](../superpowers/plans/2026-09-28-signed-reader-tenant-closure.md).
Base: `0460314617`, branch `packet/3-retention-accounting`, existing isolated
checkout `/tmp/arc-security-launch`. Preexisting `output/` is untouched.

The named reader migrations and tenant-matrix expansion are implemented. Full
packets 10.2/10.3 remain open: 447 decoder-bearing files have only a lexical
baseline disposition, and one durable authorization-consumption table lacks an
exercised production SQLite fixture. No hosted, merge or release qualification
is claimed.

## Implementation

- [x] Expand the decoder gate beyond registered files. Pin direct/imported serde
  readers, `Deserializer`, custom `Deserialize` implementations and occurrence
  counts. New files and new reader spellings require review. The inventory has
  114 constrained constructor occurrences, 88 registered reader files, 556
  decoder-bearing files and 1,881 raw decoder spellings.
- [x] Migrate financial credentials/passports, JWT and SD-JWT, passport/issuance/
  certification registries, explicit reputation policy inputs, and Finding
  purchase/recovery/status/artifact readers. Original-byte checks precede lossy
  value conversion; native full-width integers and strict external I-JSON keep
  their separate contracts.
- [x] Migrate DSSE statements and embedded receipts, completed FROST authorization,
  federation transport, SQLite tool outcomes and durable admission/participant
  evidence. Preserve the signed preimage, signer/role, roster/epoch, canonical,
  digest and operation/row checks. Remove redundant canonical serialization where
  the shared typed reader already proves the same equality.
- [x] Map every one of the 85 SQLite tenant tables to a principal runtime family
  or an explicit runtime gap. Preserve all 170 reviewed SQL principal contracts.
  The source gate checks mapping and test references, not runtime semantics.
- [x] Extend exact-ID, replay, restart and native-principal negatives across blobs,
  Finding payloads/pool debits, receipts, decoys/watermark sequences, typed effects,
  flow/fences, correlation/advisories, response dispatch/cursors, scheduler retry,
  signed ingress and attested Finding batch/outbox readback.

Defects repaired during implementation:

1. IOU storage previously decoded without verifying the envelope signature on
   readback or matching all mirrored columns. Insert/read now verify the
   signature; reads additionally require canonical bytes and exact receipt ID,
   tenant, IOU ID, amount, currency, timestamp and issuer binding. Integrity
   failures have a typed store error. Embedded issuer integrity does not grant
   independent trust in that issuer.
2. Passport, offer and certification registry keys could disagree with the
   contained record. Readers now require exact identity. Missing/zero lifecycle
   timestamps reject instead of receiving synthesized readback defaults.
3. Stored challenge and OID4VP request JSON now binds its identity and expiry
   projections; transaction snapshots also bind issuance time. A valid challenge
   substituted under another stored identifier rejects after reopen.
4. Reputation JSON no longer falls through from a malformed signed document to
   another policy interpretation. YAML requires its explicit operator file mode.
5. SD-JWT used a separate decoder and did not check its signed header. It now
   shares the bounded compact JWT reader, checks EdDSA and the supported type,
   rejects duplicate header fields, and bounds segment/disclosure/JWK decoding
   before base64 allocation. Valid issuer signatures cannot bypass these checks.
6. DSSE bounds apply before base64 allocation and PAE construction, with the
   established noncanonical-statement diagnostic preserved.
7. The independent flow test model cached transitions globally by ID, unlike
   SQLite's tenant-scoped transition ledger. The new exact-ID collision case
   exposed this mismatch. The model now binds tenant, transition kind and exact
   original request, rejects changed replays, and loads the current snapshot on
   valid replay. Its implementation moved into an ordinary test module.

Fanout/revocation tests, credential tests/helpers and the flow model now use
ordinary modules.
Two obsolete source-size exceptions were removed; no cap was increased. Strict
Clippy also exposed small existing test-only borrow/clock/unwrap issues, which
were corrected without lint suppressions.

## Runtime evidence scope

The 85 table mappings comprise 63 exact-tenant/reopen cases, 17 native-authority
cases, one privileged-integrity case, one tenant-replay/reopen case, one
authenticated-ingress/reopen case, one exact-tenant/replay case and one explicit
runtime gap. These are per-table mappings to shared family fixtures, not 85
independent tests or a claim that every query was mutated.

Native declassification's exact tenant SQL runs in a rolled-back fixture;
qualified-store tests separately enforce signed source and authority binding.
IOU reads belong to an internal composition dependency, not a tenant API. Global
pending-ingress scans belong to the installed recovery coordinator; the new
negative exercises signed ingress and acknowledgement binding.

The remaining table is `admission_operation_authorization_consumptions`. The
sealed local proof factory is test-only in `chio-kernel`, and those kernel type
tests do not exercise SQLite. A genuine signed-terminal projection fixture must
exercise positive durable readback and foreign principal/projection rejection.
No public or deserializable proof constructor was added merely to make that
coverage count green.

The lexical reader inventory records 447 `raw-input-baseline`, 86
`typed-value-conversion`, 14 `example-or-fuzz`, and nine
`reviewed-signed-owner` files. Baseline entries are not semantic signed/unsigned
classifications. The source filter is lexical and can include unconventional test
fragments; it does not implement Rust name resolution.

## Local verification

Evidence directory: `/tmp/chio-reader-tenant-20260928`. Each log below retains its
terminal result; JSON result files retain the exact binary paths and filters.

The combined owner build command was:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch \
  cargo test --locked \
  -p chio-credentials -p chio-finding -p chio-federation \
  -p chio-federation-transport-iroh -p chio-store-sqlite -p chio-control-plane \
  --lib --test security_state --test security_state_contract \
  --test response_dispatch --test finding_pool_ledger --test tenant_isolation \
  --no-run
```

`build-module-cleanup-2.log`: passed in 2m39s. Focused binaries use two test
threads and `CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`. Latest results:

| Target | Result | Evidence |
| --- | --- | --- |
| Credentials | 58 passed | `chio_credentials-tests-final.log` |
| Federation | 106 passed | `chio_federation-tests-final.log` |
| Iroh catchup, fanout, revocation and bilateral lanes | 94 passed | `chio_federation_transport_iroh-tests-final.log` |
| Finding unit | 9 passed | `chio_finding-tests-final.log` |
| Finding artifacts, purchases, recovery, status | 80 passed, 1 existing ignored | `reader-results-3.json` |
| Federation FROST authorization and rotation | 6 passed | `reader-results-3.json` |
| Control-plane reader/registry/event/native-output selection | 69 passed, 1 existing ignored | `chio_control_plane-tests-final.log` |
| SQLite blob/payload/IOU/tool-outcome/declassification/native selection | 76 passed | `sqlite-focused-3.log` |
| Latest SQLite IOU/reopen, receipt consumption, native nonce and factor readback | 13 passed | `chio_store_sqlite-tests-final.log` |
| Capability sets, egress restrictions, issuance freezes, decoys, throttles | 46 passed | corresponding `*-tests-2.log` files |
| Dispatch and recovery/cursor cases | 5 passed | `response_dispatch-tests-final.log` |
| Authenticated Finding-pool cases | 3 passed | `finding_pool_ledger-tests-final.log` |
| Receipt tenant isolation | 5 passed | `tenant_isolation-tests-final.log` |
| Scheduler retry after reopen | 1 passed | `security_state-tests-final.log` |

Overlapping runs are not summed into a total. After the last cleanup,
`build-last.log` rebuilt the six libraries plus the response-dispatch and shared
contract integration targets in 2m23s. `terminal-focused-results.json` records
58 credential tests, 70 selected control-plane tests (one existing ignored), all
31 response-dispatch tests, and 10 targeted SQLite credit/runtime/threshold,
native egress/nonce, and clock-helper cases passing. Its flow-contract failure
was the model defect described above; the corrected final result is recorded
separately below.

Strict Clippy passed (`clippy-5.log`, terminal exit 0) with:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch \
  cargo clippy --locked \
  -p chio-credit -p chio-credentials -p chio-finding -p chio-federation \
  -p chio-federation-transport-iroh -p chio-store-sqlite -p chio-control-plane \
  --lib --tests -- -D warnings
```

The subsequent flow-model correction passed all 14 shared model/SQLite contract
cases (`flow-contract-terminal.log`) and strict Clippy for that integration
target (`clippy-flow-terminal.log`). These reruns use the same six package
selectors as the build command, with only `--test security_state_contract`;
test execution uses `-- --test-threads=2`, and Clippy uses `-- -D warnings`.
The source-size/text gate passed again after that module extraction
(`hygiene-flow-terminal.log`).

`matrix-runtime-evidence.json` matches all 38 named matrix test references to
terminal passing local test logs. The 84 mapped tables share those fixtures.
The explicit runtime-gap table has no test reference and is not counted as
exercised. Earlier failed/partial logs remain unchanged.

Gate evidence:

- `trust-gate-terminal.log`: passed, 114 constructors, 85 tables, 170 SQL
  contracts. Command: `python3 scripts/check-trust-boundaries.py`.
- `trust-calibration-module-cleanup.log`: all 13 calibration tests passed.
  Command: `python3 scripts/tests/check-trust-boundaries.test.py`.
- `hygiene-terminal.log`: source-size/text gate passed after the module
  splits. Command: `python3 scripts/check-rust-file-hygiene.py`.
- Changed `.rs` files were formatted directly, including files normally hidden
  behind `include!`; `git diff --check` and the staged diff check passed.

Production-source calibration (`source-calibration-results.json`): the actual
`signed_input.rs` and its unchanged test pass in an isolated Rust harness. A
mutant replacing its strict decoder with raw serde fails that test (exit 101).
The actual standalone/native declassification `LOAD_USE` SQL literals accept A
and hide A's exact ID from B; removing either tenant predicate breaks the
isolation assertion. The SQL calibration evaluates those real query literals,
not a complete Rust facade or broad mutation campaign.

## Failed and interrupted evidence

- Initial builds exposed facade imports, exhaustive error matching and fixture
  conversion issues; their logs remain. The module cleanup also caught a test
  assertion treating signature verification's boolean as a result; corrected.
- The first dispatch fixture exceeded its signed plan TTL. Its lease was fixed,
  and the terminal dispatch reruns passed.
- A DSSE regression caught loss of the established canonical-statement error;
  that diagnostic was restored before the passing federation run.
- Two new flow fixtures initially expected a session-only label. Both model and
  SQLite correctly join principal and lineage restrictions into that label.
  The expectation was corrected while retaining the foreign tenant's empty-label
  and egress-fence refusal assertions. The subsequent model-only failure exposed
  its global transition cache; the production SQLite case already passed. After
  fixing the model, all 14 shared contracts pass.
- An overly broad SQLite selector entered the existing process-crash campaigns.
  That process was stopped; `chio_store_sqlite-tests-2.log` has no terminal pass
  and is not counted. The bounded 76-case replacement completed successfully.
- Initial hygiene and Clippy failures remain in their original logs. No result
  is described as passing merely because a later command started.

No full workspace test/lint run, PostgreSQL tenant audit, scale campaign, hosted
CI qualification, merge, publication or operational activation was performed.
