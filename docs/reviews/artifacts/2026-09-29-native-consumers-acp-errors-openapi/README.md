# Native consumer and protocol evidence

See the [execution record](../../2026-09-29-native-consumers-acp-errors-openapi-execution.md)
for the implemented scope and the incomplete mini-SWE integration.

- `local/` contains development and terminal local checks. Cargo JSON streams
  are retained as deterministic gzip files; readable `.log` projections include
  compiler diagnostics, test output and Cargo stderr. Text logs normalize
  trailing whitespace; any affected original stream also has a `.raw.gz` copy.
- `native/` contains the OCI x86_64 logs, source identities and tested binary
  hashes. Private fixture authority directories, credentials, binaries and raw
  perf recordings are excluded. The text perf report is retained.
- `source-manifest.json` pins final local modified/new source and configuration
  against the base commit and lists its differences from the native snapshot.
- `verification-index.json` identifies the terminal accepted checks. Other
  logs remain superseded/intermediate evidence and must not be counted as
  passing acceptance checks.
- `review.md` records the independent review findings and their repairs.
- `worker.json` identifies only this restored worker and its retained volumes.
- `SHA256SUMS` covers every other file in this artifact directory.

This is local/native development qualification. No remote CI, merge,
publication, M5 acceptance or complete mini-SWE qualification is asserted.
