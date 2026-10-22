# chio-mercury architecture

## Responsibility and boundary

The `mercury` binary owns command parsing, local evidence assembly, and export
layouts. `chio-mercury-core` owns the package contracts it constructs.
The CLI reuses `chio_control_plane::CliError` for failures and has no public
library target. Its global `--json` flag controls result presentation.

`proof export` consumes existing Chio evidence. Pilot, qualification, and
review-package exports generate modeled workflow evidence from core fixtures.
The generated artifacts are persisted files; process state lasts for one
invocation. There is no long-running Mercury admission service in this crate.

## Structure

| Module | Role |
| --- | --- |
| `main.rs` | Clap command definitions, flags, and dispatch. |
| `commands.rs` | Shared imports, decision constants, and command re-exports. |
| `commands/shared/utils.rs` | Signed JSON decoding, file writes, empty-directory checks, and manifest filenames. |
| `commands/shared/builders.rs` | Core package construction and synthetic capability/receipt/checkpoint population. |
| `commands/shared/types.rs` | Export summaries and CLI-local decision records. |
| `commands/shared/population_configs.rs` | Fixed reviewer-population configurations. |
| `commands/core_cli/commands.rs` | Proof, inquiry, verification, pilot, capture, and review commands. |
| `commands/core_cli/exports.rs` | Receipt export pipeline and fixture qualification/review assembly. |
| `commands/core_cli/launch_commands.rs` | Assurance and distribution export/validation dispatch. |
| `commands/assurance_release/` | Assurance, OEM, witness, readiness, and distribution builders. |
| `commands/account_delivery/` | Account activation and continuity export/validation. |
| `commands/*_lane.rs` | Renewal, account expansion, program, and portfolio package chains. |

## Data and control flow

`build_proof_package` verifies the export through `chio-bundle-verify` against
the `--trust` file, validates bundle manifests, and
calls `MercuryProofPackage::build`. The export command invokes `verify` before
writing the resulting JSON. Current builds produce proof-package v2.

`cmd_mercury_verify` decodes a package and dispatches on the current proof or
inquiry schema. Core validation accepts legacy proof identities, but this
command only dispatches the current proof schema and inquiry v1 schema.
Its verification report describes package integrity without external trusted
kernel authority. The CLI has no trusted-key option on this command.

`export_mercury_run` writes input events, opens `receipts.sqlite3`, records a
capability snapshot, signs receipts, and seals their canonical bytes into a
checkpoint. It exports the store through the control plane, then writes proof
and optional inquiry packages alongside verification reports.

`export_pilot_scenario` generates primary and rollback runs.
`export_supervised_live_capture` validates the caller's capture and invokes
`ensure_export_ready` before exporting modeled receipts.
`export_supervised_live_qualification` uses a sample live-mode capture and the
pilot fixture. Review and distribution builders nest upstream exports, copy
selected evidence, and write typed package references and summaries.

## Trust and persistence invariants

Synthetic receipts are signed directly by `pilot_receipt`; their allow decision
is constructed from fixture events. This path does not perform an external tool
call or prove kernel admission. Capture gate approval and health information
are validated declarations supplied in the input.

`read_json_file` uses duplicate-aware signed decoding on the original input.
It first calls `fs::read`, so this helper places no size bound on allocation.
`bundle_manifest_file_name` rejects separators, colons, control characters,
padded IDs, and dot segments before creating filenames for multiple manifests.

Directory exports require an absent or empty directory. Individual JSON writes
create parent directories and replace the selected file. Multi-file exports
have no transaction or rollback wrapper; a later failure can leave earlier
output files for inspection. SQLite receipt/checkpoint state and exported JSON
persist in the chosen directory after the command exits.

Lane validation commands construct decision records with fixed scope and
rationale strings after assembling their artifacts. Their decision text is
predefined fixture output with no live policy evaluation.

## Dependencies and verification

`chio-store-sqlite` stores generated receipts and checkpoints.
`chio-control-plane` supplies evidence export/loading and CLI errors.
`chio-kernel` constructs checkpoints; the aliased `chio-core-types` dependency
supplies keys, receipts, capabilities, canonical serialization, and hashes.
Clap parses commands, Chrono provides date stamps, and Serde writes artifacts.
There are no package-defined Cargo features.

`tests/cli.rs` runs the actual binary against temporary filesystem exports.
Its proof/inquiry test checks successful verification and false verifier
equivalence; capture tests exercise exports and degraded-state rejection.
`tests/cli/signed_reader.rs` exercises duplicate keys in signed proof bytes.
Shared helper tests check unsafe manifest identifiers.
Run `cargo test -p chio-mercury` to exercise these local paths.

[README](README.md) links the executable pilot example and receipt contract.
