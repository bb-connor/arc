# Funded-native integration into current security enforcement

The semantic merge is committed at `71e5cbc3bf7b08f477ed0e0361f2cca0c36eaea3`
on `paper/funded-security-20261002`, with tree
`07165a27b9e0f6e07feaf2f56266f4d59862c075`. The parents are security checkpoint
`491f585e9013dcb6335589c82d00ac219efbf0a6` and funded-native checkpoint
`7755d3762baa5e0fda0d171835a9000c26de9033`. The isolated worktree is
`/tmp/chio-paper-security-integration`; its tracked and untracked status is clean.
The main checkout, dirty security-launch worktree and paper worktree were not
edited by this integration worker.

This qualifies a focused local native example and its selected process paths.
It does not qualify the complete workspace, formal correspondence, independently
administered observers, public-chain finality, hostile-host isolation, release,
deployment or real funds. The inherited generated evidence and previous execution
reports remain historical.

## Semantic decisions

- Preserve checked authority clocks, fallible clock propagation, mandatory caller
  approval authority and the current raw-first signed JSON ingress. Adapt funded
  code to these APIs rather than restoring older wall-clock or parsed-value paths.
- Keep the funded extracted pre-dispatch compensation and recovery logic, including
  observed but unacknowledged authorization and retained settling releases. Keep
  the current checked-time refresh at these effect boundaries.
- Preserve current terminal financial replay verification, including exact grant
  budget ceiling and optional-value presence, while retaining funded capture-waiver
  resolution and checked-output denial. Remove superseded duplicate modules.
- Add execution evidence to the current SQLite participant/projection structure.
  Evidence writes recheck the serving owner's fenced clock after writer-lock
  acquisition and before committing; the older direct SystemTime read is removed.
- Adapt A2A v1 to checked task deadlines, bounded task counters and the current
  response wrapper, preserving both namespace task identities and local
  notification error state. The example forwards original JSON bytes to the edge.
- Union funded/source-inventory additions without replacing current security IDs;
  regenerate the schema-file manifest from the merged registry. Formal mapping
  metadata is not blessed or claimed to match the changed implementation.
- Refresh the standalone lockfile offline to the current security dependencies;
  every reported final Rust build/test uses `--locked --offline`.

## Behavior regression found and fixed

The initial isolated refund process failed when the governance draft and status
attestation crossed a second boundary. Enrollment had validated the later signed
standing at the earlier profile issue time. Historical custody now validates at
the signed observation time; fresh enrollment still validates against current
time before creating any native authority. A deterministic signed regression
failed before the fix and passes afterward, also rejecting future standing before
any enrollment marker and preserving the exact original authority on retry.

The initial peer process correctly rejected a trusted certificate for the wrong
hostname, but its diagnostic changed in the newer rustls dependency. The harness
accepts either of the two known hostname-error strings; the required nonzero exit
and absent output are unchanged. TLS checks were not relaxed.

Strict Clippy found one redundant explicit dereference in `peer_https.rs`. Removing
that dereference is the only source change after the v2 process qualification.
`v2-to-final.patch` and `v2-to-final-source-changes.json` retain the complete delta.

## Passing checks and exact scope

Each named check has a `.json` command/environment/exit receipt and a complete
`.log` in this directory. All listed exit codes are zero.

| Check receipt | Scope | Result |
| --- | --- | --- |
| `standalone-all-final` | v2 source; locked offline standalone test suite with `--include-ignored --test-threads=4` | 95 passed, 0 failed, 0 ignored |
| `peer-process-final` | Immutable v2 executable; authenticated peer pay/reject | 2 scenarios |
| `isolated-process-final` | Immutable v2 executable; isolated bilateral pay/reject | 2 scenarios |
| `earned-child-process-final` | Immutable v2 executable; earned child after parent refund, including pay recovery | 4 scenarios |
| `refund-resolution-final` | Immutable v2 executable; capture-waiver refund and recovery | 7 scenarios |
| `execution-custody-final` | Immutable v2 executable; SIGKILL around execution evidence and custody | 5 scenarios |
| `standalone-clippy-retry` | Final source; all standalone targets with `-D warnings` | Passed |
| `peer-unit-final` | Final source; peer verifier unit subset | 4 passed, 91 filtered |
| `standalone-build-v3` | Final source; locked offline binary build | Passed |
| `peer-process-v3` | Immutable final executable; authenticated peer pay/reject | 2 scenarios |
| `standalone-format-v3` | Final standalone source | Passed |
| `workspace-format` | Integrated workspace; before the one-character Clippy fix in the excluded standalone example | Passed |
| `final-schema-registry` | Merged registry and generated schema manifest | Passed |

The v2 process total is 20 selected scenarios. Final peer qualification is a rerun
of two of those scenarios against v3, not two additional behaviors. Parent-worktree
Python/model/bytecode checks are separate evidence; they are not counted here.

## Source and binary provenance

| Snapshot | Executable SHA-256 | Source manifest SHA-256 |
| --- | --- | --- |
| v1 | `58635df3aabb84a0a3a55fd6b0f84aff12df3fd5f0b3090a89b08d8ccb14e2aa` | `630618345d64fa8f9f4e0c9cf943811ef4387ac4951d4eac14e5a250f03880c8` |
| v2 | `71d3d0c43134ceea39660c48ec1e8a6d90aa7b49e38ed3f11c3d96e69efde1d5` | `0c318a449ef0c5c67fadcb421af4a680716ee6ae30cf32905fa7651348c1ce53` |
| v3 | `919d5f4bad46f318f4e505e0377ee94f751a35a218c4713c1af58b06a1cdcfdf` | `c69a4db94361b2e4719ecac0d43af1d8088357903895d73637951f9a905710b4` |

The v1 executable was overwritten by the later build; its source manifest is
preserved because the parent worker already qualified Python checks against its
recorded hash. Immutable v2 and v3 executables remain under `bin/`. Each source
manifest retains 21,093 hashes. `integration-commit.json` confirms every v3 source
hash against the clean committed worktree. `environment.json` and
`python-installed-distributions.json` retain tool/dependency information; `pip
freeze` was unavailable in the pip-free locked environment, so distribution
metadata was read directly without changing it.

Public v2 artifacts are in `public/`; final peer artifacts are separately retained
in `public-v3-peer/`. The index hashes all 115 public files. Binding summaries
recompute the signed agreement body digest and check agreement/allocation/native
identity correspondence, original-identity replay, money/event outcomes, and the
earned child's continued payout while the parent's unknown execution remains
unknown. They do not replace signature or chain verification in the actual tests.
No role seeds, private requests, journals or TLS private keys are in those public
directories.

## Failed or unqualified gates retained honestly

- Initial compile attempts 1-6 failed on stale lock/API boundaries. Their logs and
  `initial-check-status.json` are retained; later terminal builds supersede them.
- `delayed-attestation-red-exact` records the real regression failure. The earlier
  short-name `--exact` attempt selected zero tests and is not positive evidence.
- Initial peer and isolated-process failures and the first strict Clippy failure
  remain in their original logs, separate from successful retries.
- Formal mirror checking remains open: the security parent already refers to the
  deleted `credential_reservation/legacy_nonce.rs`; a diagnostic attempt also found
  a moved `append_chio_receipt_tx` anchor. A temporary metadata-only diagnostic
  change was reverted. No regenerated formal correspondence is claimed.
- Proof coverage generation fails because the response-state Kani harness maps to
  an absent `chio_security_types::response_state::is_legal_response_transition`
  surface. The generated coverage page is not newly qualified.
- Rust file hygiene reports five failures: projection.rs 2023/2014 lines;
  runtime_admission.rs 3716/3673 assembled lines; global_commit_chain.rs 2658/2554;
  A2A edge 6321/5818 assembled lines and 13/11 include fragments. No cap was raised.
- Full merge whitespace checking reports historical logs/patches, CSV CRLF and
  old review-document EOF blanks in 36 files. Every flagged file is byte-identical
  to the funded parent. Evidence bytes were preserved. Implementation-path staged
  diff checking passes.
- Full workspace tests, workspace Clippy, fuzzing, hosted checks and release gates
  were not run. Local Ganache is an owned mock chain on one trusted host. The peer
  HTTPS topology and five-domain namespace topology are separately exercised;
  composition and independent administration remain unqualified.
