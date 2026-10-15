# chio-config architecture

## Responsibility and boundary

The public loaders return `ChioConfig`, whose fields describe kernel
settings, adapters, edges, receipts, logging, telemetry, guard
configuration, and WASM guard entries. Configuration is data until consumers
construct the corresponding runtime services. A receipt-store URI does not
open a database during loading.

`ChioConfig::to_kernel_config` creates a kernel configuration, resolves a
receipt signing key, and carries checkpoint interval, retention days, and
scalar hot-path deadlines into kernel types. It sets an empty
capability-authority list and disables ephemeral receipt logs and revocation
stores.

## Structure

`schema.rs` defines strict deserialization structs and default functions.
`loader.rs` owns file/string loading and YAML syntax-tab scanning.
`interpolation.rs` provides both public raw substitution and the restricted
loader path. `validation.rs` collects configuration problems into
`ConfigError::Validation`. Feature-gated `fuzz.rs` supplies fuzzing
entrypoints.

## Data and control flow

`load_from_file` uses `fs::read_to_string`, then delegates to
`load_from_str`. The string loader interpolates environment tokens, screens
tab syntax, decodes YAML with `yaml_serde`, and validates the typed result.
Missing environment variables without defaults fail before parsing. Literal
tabs inside quoted strings, comments, or block scalar bodies remain
accepted.

Default receipt settings use checkpoint interval 100 and retention 90 days.
Logging defaults to JSON at info level. Telemetry and advisory promotion
default off. WASM entries default to fuel 10,000,000 and priority 1000.

## Trust and invariants

The loader interpolation path rejects surrounding whitespace, control
characters, quotes, and hash signs in replacements. Public
`interpolation::interpolate` performs raw substitution and has a different
boundary. Schema structs reject unknown fields. Validation requires at least
one adapter and resolves edges against known adapter IDs.

`kernel.signing_key` must be nonempty at load time. `signing_keypair`
subsequently parses the seed or generates an ephemeral key. Callers must
invoke validation if they deserialize schema types directly. The file loader
has no bounded-read contract.

## Dependencies

`serde` and `yaml_serde` decode YAML. `regex` recognizes interpolation
syntax. `chio-core` supplies key material and `chio-kernel` supplies runtime
configuration, deadlines, retention, and memory budgets. `thiserror`
preserves separate I/O, interpolation, parse, validation, and
kernel-conversion errors.

## Verification

Unit tests in `loader.rs` cover minimal/full YAML, unknown fields,
interpolation injection, missing adapters, alias bombs, deep nesting, and
tabs. `schema.rs` tests receipt defaults and transfer of configured
deadlines and retention settings. `validation.rs` exercises references,
authentication headers, and deadline rejection. Run `cargo test -p
chio-config` for this scope. The README example uses default features and
performs no service startup.
