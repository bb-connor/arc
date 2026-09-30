# Product authority reader evidence

All checks run locally on Linux aarch64 with Rust 1.94.1. `source-manifest.json`
pins changed source, manifests and trust inventory against base
`7525fcdf0c83adf6fddb88063dd75485d91b2554`. The containing commit identifies the
complete candidate. `reviewed-readers.json` records all 28 original baseline
dispositions; `next-readers.json` pins the next 26-file batch.

Rust commands use `CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`,
`CARGO_INCREMENTAL=0` and `CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`:

```sh
cargo test --locked -p chio-api-protect -p chio-proof-room --lib
cargo test --locked -p chio-http-core --lib authority::
cargo test --locked -p chio-proof-room --doc VerifiedProofRoomBundle
cargo test --locked -p chio-cli --bin chio --no-run --message-format=json
```

The CLI test executable emitted by the last command runs these libtest filters
in one invocation, recorded in `cli-focused.log`:

```text
input::tests::
process_response_verify::
process_host::call_evidence::
process_host::native_broker::classification::
process_host::state::
process_host::runner::container::
replay_cli::
dispatch_cli::proof::
```

The CLI container tests use the existing engine double and exercise real local
supervision, journal and classification owners. They are not native Docker
qualification. The compile-fail doc test covers attempted proof-result
deserialization. Cargo's unused-patch warnings are retained in the logs.

Source checks use `scripts/check-trust-boundaries.py`,
`scripts/check-rust-file-hygiene.py`, `scripts/check-security-clocks.py`,
`scripts/check-accounting-arithmetic.py`, `scripts/check-negative-assertions.py`
and `scripts/check-wire-schemas.py`. Format checking explicitly covers all 53
changed Rust files with `rustfmt --edition 2021 --config skip_children=true
--check`, including CLI modules behind `include!` that package formatting skips.

Compressed raw logs under `earlier-attempts/` preserve failed compilation,
fixture-permission, changed-error-contract and module-size attempts. They are
not passing evidence. The execution record explains the corrections. No full
workspace build, workspace lint, hosted run or cloud qualification was started
for this batch.

Readable log files omit extra trailing blank lines. Where normalized, exact raw
bytes are retained compressed under `raw-logs/`. `SHA256SUMS` covers the retained
evidence files, excluding itself.
