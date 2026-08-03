# chio-adversarial-suite architecture

## Overview

`chio-adversarial-suite` is a pure data and validation crate: no I/O on its
default path, no async runtime, `#![forbid(unsafe_code)]`, and no dependency
on any other `chio-*` crate. It exists so trust-boundary tests across the
workspace share one corpus of malicious-but-well-formed inputs instead of each
maintaining private fixtures. `chio-kernel-core`, `chio-attest-verify`, and
`chio-conformance` dev-depend on it to validate their relevant corpus subsets,
answer-key metadata, and threat-coverage projections.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs`, `src/lib.part1.inc` | Public module shell plus the case envelope (`AdversarialCase`), embedded schema and corpus, semantic validation, `AttackClass`, `ExpectedVerdict`, `CaseError`, coverage gate (`CoverageCase`), and bundled-corpus loader functions. |
| `src/manifest.rs` | `Manifest` / `ManifestEntry`: projects non-pending bundled cases into the cross-SDK manifest and renders it as canonical JSON. |
| `schema/case.schema.json` | JSON Schema contract for on-disk case files; embedded verbatim as `CASE_SCHEMA_JSON`. |
| `cases/<class>/*.json` | 68 current vectors grouped by attack class and embedded at compile time into `BUNDLED_CASES`. |
| `manifest.json` | Checked-in canonical manifest; `tests/manifest_emit.rs` fails if it drifts from `Manifest::from_bundled()`. |
| `tests/manifest_emit.rs` | Drift detection, per-class coverage checks, and an `#[ignore]`d regenerator. |

## Security and evidence constraints

- Every bundled case is deny-asserted. A malformed case must fail before it can count as threat coverage.
- `expected_reason` is a machine-consumed verdict key for harnesses and cross-SDK comparisons, not free-form prose.
- Pending cases may be loaded for triage but must not enter coverage or manifest outputs.
- The manifest must stay deterministic and pinned to bundled case content hashes.
- Promoted mutation outcomes bind both the exact cargo-mutants JSON and an
  input digest over the mutation contract, behavioral-control contract,
  mutation source, control source, and both package manifests. Source, test,
  selector, target, feature, or manifest drift invalidates the stored evidence.
- Release verification executes every distinct promoted behavioral control on
  the current tree and executes full caught-only campaigns for any pending
  selection. A fully promoted suite is therefore an active control run, not a
  zero-work success.
- `scripts/check-security-adversarial-evidence.sh --refresh-outcome <id>` is the
  only supported overwrite path for promoted mutation evidence. It reruns the
  checked-in semantic selection and exact behavioral control, rejects every
  result other than caught-only, verifies that source and control inputs stayed
  fixed during the run, stages the outcome, case, and manifest bindings, and
  commits all three with rollback protection. A candidate file supplied by a
  caller cannot refresh existing evidence.
- Public loader names and case wire fields must stay source and JSON compatible.
- `expected_reason` and threat IDs are strict lowercase tokens
  (`^[a-z][a-z0-9_]*$`), while case IDs use
  `^[a-z0-9][a-z0-9._-]*$`, in both the Rust loader and the case schema. A
  padded or control-bearing verdict key therefore fails validation rather than
  matching a harness reason key by accident.

## Case lifecycle

1. A case is authored as JSON under `cases/<class>/` and must satisfy
   `schema/case.schema.json` (required fields, `additionalProperties: false`,
   id/reason/threat-id patterns, `expected_verdict` fixed to `"DENY"`).
2. `include_str!` embeds the file into `BUNDLED_CASES`; its class must already
   be a variant of `AttackClass`.
3. `AdversarialCase::from_slice` (or `from_path`, which reads the file from
   disk) parses with `serde_json` under `deny_unknown_fields`, then `validate`
   re-checks schema version, id/reason/threat-id character classes, non-empty
   notes, and a non-empty object `artifact` in Rust, so a malformed case is
   rejected the same way regardless of which layer sees it first.
4. `into_coverage_case` rejects `pending: true`, yielding a `CoverageCase`
   that callers may treat as real threat coverage.
5. `manifest::Manifest::from_bundled` re-derives the corpus, drops pending
   cases, checks each case id against its bundled path
   (`CaseError::ManifestDrift` on mismatch), sorts by id, and hashes each
   file's bytes into `content_sha256`; `tests/manifest_emit.rs` pins the
   result against `manifest.json`.

## Invariants and failure modes

- Every bundled, non-pending case has `expected_verdict: DENY`; `ExpectedVerdict`
  has no `Allow` variant, so any other value fails to parse.
- `id` allows `^[a-z0-9][a-z0-9._-]*$`; `expected_reason` and `threat_id` both
  require `^[a-z][a-z0-9_]*$`, enforced identically by the JSON Schema and the
  Rust validators, so a padded, uppercase, or control-character reason string
  fails closed in either layer.
- `artifact` must be a non-empty JSON object; empty objects and non-object
  values are rejected.
- `pending: true` cases load for triage but are excluded from both
  `into_coverage_case` and `Manifest::from_bundled`, so an untriaged
  libFuzzer-promoted case cannot silently count as coverage.
- A unit test (`every_non_pending_case_cites_a_known_threat_id` in
  `src/lib.rs`) cross-checks every non-pending case's `threat_id` against
  `spec/security/chio-threat-model.v1.json`, so a case cannot cite a threat
  that does not exist in the workspace threat model.
- `#[serde(deny_unknown_fields)]` on `AdversarialCase` and the manifest types
  rejects unrecognized top-level fields.

## Dependencies

External only: `serde` and `serde_json` for the case and manifest schema,
`sha2` and `hex` for manifest content hashing, `thiserror` for `CaseError`. No
internal `chio-*` dependency. `chio-kernel-core`, `chio-attest-verify`, and
`chio-conformance` each pull this crate in under `[dev-dependencies]`.
