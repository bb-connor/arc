# chio-replay-corpus architecture

## Responsibility and boundary

The public surface normalizes existing capture frames for replay tooling.
`invocation_hash`, `dedupe_last_wins`, and `reredact_default` operate in memory.
`write_fixture` owns destination shape validation and writes one fixture set.
`write_tee_bless_audit_entry` appends a signed operator audit entry.

Capture ingestion, operator capability authorization, TEE attestation, and
execution of replay scenarios belong to callers. `TEE_BLESS_CAPABILITY` records
the capability name in the audit body; its presence does not enforce a grant.
The fixture root commits replay bytes and is unrelated to kernel checkpoint
membership verification.

## Structure

| Module | Responsibility |
|--------|----------------|
| `dedupe` | RFC 8785 invocation hash and last-occurrence ordering |
| `reredact` | Default redactor invocation and stable result projection |
| `fixture_writer` | Scenario paths, replay records, staging, root bytes |
| `audit` | Blessing identity/counts, canonical signatures, append writer |
| `lib` | Exports, default pass id, normalization error conversion |

## Data and control flow

1. Derive each frame's dedupe key from the canonical invocation object.
2. Replace prior frames with the same key, then order survivors by final
   occurrence in the original stream.
3. Serialize each retained invocation canonically and re-redact it using the
   current default full redaction class.
4. Strictly decode the redacted invocation and create a stripped replay record
   containing invocation, verdict, denial reason, and would-have-blocked flag.
5. Build `receipts.ndjson` and a replay checkpoint describing the scenario and
   default redaction pass. Compute `root.hex` from receipt bytes without the
   final LF followed by checkpoint bytes.
6. Stage each file with `sync_all`, rename the files, and return byte sizes and
   frame counts. The separate audit writer records the operator's blessing.

The destination must end in a valid family/name suffix. Existing destinations
may be empty or contain only fixture filenames; validation of a completed set
requires the exact three regular files.

## Trust and invariants

Invocation object key order does not change the dedupe hash. The complete frame
is retained from the last occurrence; dedupe does not merge provenance or choose
an earlier signature. Re-redaction excludes elapsed timing from its stable
projection so repeated normalization can compare bytes and matches.

The fixture writer does not authenticate frames. Its stripped records discard
capture provenance and signature fields. A deterministic root detects byte
changes only when a trusted reference root is retained by the consumer.
Each staging rename replaces one file; a failure between renames can leave a
mixed set, and the caller must handle the reported error and revalidate it.

Audit signing validates nonempty fields, count ordering, event/capability
constants, and a lowercase SHA-256 root. The timestamp is a required string;
this layer does not establish trusted wall-clock time or operator authorization.
The append writer has filesystem side effects and remains separate from fixture
writing, so callers coordinate their persistence policy.

## Dependencies

`chio-core-types`, imported as `chio-core`, provides canonical JSON and signing.
`chio-tee` provides raw buffers and default fail-closed redactors.
`chio-tee-frame` provides capture fields and verdicts. `serde_json`, `sha2`, and
`hex` encode stripped records and deterministic replay roots.

## Verification

Run `cargo test -p chio-replay-corpus` from the workspace root.
`dedupe_lastwins.rs` tests final-occurrence ordering across key order changes.
`reredact_stable.rs` tests stable bearer, email, and SSN redaction.
`audit_log_entry.rs` tests signed audit serialization and append behavior.
`e2e_bless_to_replay_gate.rs` tests written fixture shape and replay-root bytes.
The README runs in-memory hashing and email redaction without writing files.
