# Native multi-route evidence

The records below describe the preceding partial qualification. The
[September 30 continuation](continuation-20260930/README.md) carries the consumer
migration, later native acceptance, final source/binary identities and current
worker lifecycle. Historical failures below remain evidence of those attempts.

See the [execution record](../../2026-09-29-native-multiroute-consumers-execution.md)
for task states and acceptance limits. Local and native logs are separate gzip
streams; `gzip -dc PATH` reads them. Earlier failures, interrupted disk-full
checks, empty selectors and diagnostic runs remain present. Their presence does
not make them passing evidence.

## Source and runtime identities

- `local-source-manifest.json` records changed and added source/config over the
  shared `cacaf69fc9d4b709ebe30fd9c549fc0eeffc12f9` base. Local HEAD before this
  batch is `95f04d5d74`; the worktree was dirty during qualification.
- `source-manifest-profile-5.json` records those paths on the x86_64 worker while
  the final production CLI was built. Local test/fixture updates and formatting
  differ. `source-differences.json` names every difference. This is not an
  exact-final-commit binary qualification.
- `binary-manifest.json` identifies separate CLI builds, the Docker adapter,
  static broker MCP target and native probe. Earlier campaigns used the earlier
  binaries stated in their scripts/logs, not the final CLI by implication.
- `worker.json` records OCI lifecycle state. Boot/anchor volumes, build caches,
  failed campaign state and private authority material stay on the retained VM.
  Private keys and authority databases are not copied into this artifact set.

## Evidence interpretation

`verification-index.json` identifies terminal checks and open campaigns.
The fresh signed budget receipt and its public verification pins live in
`crates/products/chio-cli/tests/fixtures/process-worker-outcomes/`, with their
own provenance. Native campaign logs establish the separately observed effect
count; a receipt verifier alone cannot establish physical effects.

Native mini-SWE runs 1 through 12 failed. The optimized history repair completes
four calls, but the fifth lifecycle handoff still fails. Original uncertain
operations are retained, not resubmitted. There is no accepted mini-SWE baseline,
session/public-repository matrix, full packaged-consumer matrix, hosted run or
M5 claim in this directory.

`review.md` records the independent review and repairs. Source and artifact hashes
are listed in `SHA256SUMS`; the manifest excludes itself.
