# Architecture

## Responsibility and boundary

`ShadowRunner` implements `TrafficTap` and captures a request/receipt pair
at the host kernel boundary. It owns redaction, encrypted spool access,
mode state, tenant signing key, and a capture writer. `Observation` is also
available as an NDJSON ingest format for the `chio-tee run` binary.

The runner reads the observed receipt decision. It performs no independent
policy evaluation, quote verification, or receipt-signature validation.
The host must authenticate the observation source and control tenant keys.

## Structure

| Module | Responsibility |
| --- | --- |
| `runner`, `tap` | Observation orchestration and kernel hook interface |
| `buffer`, `redact` | Zeroizing raw buffer and mandatory native redaction |
| `persist`, `spool` | Tenant-key encrypted SQLite blob adapter and pairs |
| `capture`, `frame` | Event/time generation, signing, append, wire re-exports |
| `mode`, `config` | Mode precedence, state transitions, environment/TOML input |
| `observation_input` | Bounded original NDJSON line parsing |
| `main` | CLI key/store/config loading and Unix signal handling |

## Data and control flow

The before hook checks request canonicalizability. The after hook canonicalizes
receipt parameters, request envelope, and full signed receipt separately.
It runs each through native redaction; failure aborts before any blob write.
The inline invocation is decoded again after redaction and must remain JSON.

The spool writes redacted request then response blobs using the tenant key.
The runner hashes those redacted bytes, derives the verdict from the receipt,
and builds a frame with a generated event id and receipt-derived timestamp.
Current provenance uses zero trace/span identifiers; upstream is normalized
to MCP with an unknown API version. The tenant signs canonical frame fields,
then the writer appends and flushes one NDJSON line.

Mode resolution is environment, TOML, tenant manifest, then `verdict-only`.
Shadow/enforce set `would_have_blocked` for deny/rewrite decisions.
Enforce returns `EnforceBlocked` after recording such a frame; the host must
propagate that error at its intended enforcement point.

## Trust and invariants

Raw redaction buffers zeroize on drop. The default redactor recognizes its
configured classes; its output is not a guarantee that all sensitive data
was identified. Paranoid mode refuses a zero-match payload over 256 bytes.
Redaction errors surface as `tee.redact_failed` errors; receipt-log emission
is the host's responsibility.

The persistence facade accepts arbitrary byte slices, so redaction ordering
is enforced by the runner. Request blob, response blob, and frame append
are separate writes. A later error can leave earlier blobs persisted.
Appends are mutex-serialized and flushed, with no transactional crash guarantee
across those writes. Capture frames contain hashes, without persisted handles.

`MoteState::transition` permits downgrades and requires nonempty token text
for upgrades. It does not authenticate signature, scope, audience, or expiry.
The signal path reads the local mode-request file and uses that same check.
Operators must protect this input and authenticate upgrade authority.

The binary requires a signing key. It permits an ephemeral generated key
for local use and a zero at-rest key only for an in-memory blob store.
Persistent stores require an explicit at-rest key. Observations are bounded
while reading to 16 MiB per line, including their terminator.

## Dependencies

`chio-tee-frame` owns schema validation and signature preimages. The native
redactor supplies match/output data. `chio-store-sqlite` encrypts blobs.
Core types supply observations, canonical bytes, keys, and hashes;
`arc-swap` holds mode state and `signal-hook` handles Unix toggles.

## Verification

Run `cargo test -p chio-tee` and `cargo test -p chio-tee --doc`.
Tests exercise CLI configuration, mode precedence, redaction determinism,
fail-closed/paranoid behavior, encrypted persistence, and spool failures.
Runner unit tests exercise observed verdicts, signed frames, bounded ingest,
and enforce errors. FIPS smoke builds use `--features fips`; enabling that
feature alone does not certify a deployed sidecar or hardware boundary.

[README](README.md) | [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
