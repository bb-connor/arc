# Signed readback execution checkpoint

This batch follows the user's direction to prioritize substantial implementation
with focused verification. The previous broad sweep was deliberately interrupted;
its partial results remain in the [response/keyring checkpoint](2026-09-26-execution-boundaries.md).
No new full-workspace run is required for this checkpoint.

Source checkpoints are `18be6b39be` (signed readback) and `d29c3d8188`
(conformance preflight cleanup). All 20 changed source paths match the hashes
recorded in `signed-readback-candidate.json`.

## Changes

Forty economy export readers now validate original JSON tokens and verify the
persisted signature before using the record. They cover underwriting decisions,
credit facilities/bonds/loss events, provider lookup and supersession, quote and
placement workflows, and the liability claim/payout/settlement chain. Previously,
these readers used ordinary typed deserialization after insertion-time signature
checks. An altered stored body or damaged predecessor signature could therefore
flow into a report or a later workflow comparison.

The shared reader uses the existing compatibility parser. It preserves full-width
unsigned amounts and ordinary, pretty and canonical writer encodings. Duplicate
keys and over-precise numeric aliases fail before typed decoding. Verification
checks integrity against the embedded signer; it does not establish an external
trust root or independently authenticate mutable lifecycle columns.

Signed lineage readback uses one shared path for ordinary and retained lookups.
It verifies the signature and binds `child_receipt_id` to the requested row key.
A valid statement for a different child can no longer be returned as that
child's signed lineage. Unsigned backfill metadata remains a separate existing
contract; no writer format or archive schema was changed.

Source review of checkpoint statements found a closed directly decoded body,
with integer and string/hash/key fields and no arbitrary JSON or floats. Its
duplicate-field rejection, mirrored-column checks and authenticated head/chain
checks remain intact. Broker execute/prepared paths already enforce canonical
bytes before authority checks, with whole-frame binding for prepared execution.
The [boundary inventory](../security/signed-json-boundaries.md) records these
dispositions without inventing unnecessary parser changes.

Eleven duplicated conformance preflight helpers were removed. They only checked
`repo_root/target/debug/chio`, causing unnecessary nested CLI builds when
`CARGO_TARGET_DIR` pointed elsewhere. The existing harness owns executable
discovery and fallback building, including the external target directory. All
scenario assertions and peer-availability conditions are retained.

## Verification

All 23 focused tests passed: seven new signed-readback regressions and 16
existing underwriting, liability, lineage and canonical-reader tests. The latter
include the real claim chain through its payout receipt. They ran on the same
production source; the only intervening source change supplied a required
session anchor in the new lineage fixture. The first new-test run's foreign-key
failure is retained in `signed-readback-focused.log`; no database validation was
relaxed. `signed-readback-final.log` and `signed-readback-existing.log` contain the
terminal passing results.

The first focused build took 2m 41s and the fixture rerun took 1m 23s; test
execution took 0.54s and 1.09s respectively. Formatting for the two touched crates,
`git diff --check`, Rust file hygiene and the negative-assertion gate passed.
The conformance cleanup was checked by source review and formatting; live peer
campaigns were not rerun for deletion of redundant preflight code. No broad
workspace or hosted qualification is claimed.

The new SQLite regressions check signature corruption, rejected successor
writes, valid-statement substitution, precision aliases and full-width amount
compatibility. The precision and duplicate-key cases explicitly demonstrate that
the old ordinary reader erased the ambiguity while retaining a valid signature.
Lineage tests cover ordinary lookup and retained lookup's live-store fallback;
the archive branch uses the same reader but was not a new archival campaign.

Evidence is retained under `/tmp/chio-execution-batch-20260926/`. The earlier
response/keyring checkpoint's 312 passing focused tests and workspace build
remain separate evidence for those earlier source commits.

## Remaining acceptance work

Cross-store legacy obligation discovery/retirement and production dry-run/report
composition remain open. This batch does not establish all-workspace signed JSON
coverage, native-runner or hosted acceptance, release publication, or operator
authorization. See the [remaining queue](2026-09-26-resumed-execution.md#remaining-acceptance-work).
