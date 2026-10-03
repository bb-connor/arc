# Receipt evidence lifecycle command evidence

Base: `62ce6c65c3e9de306bc40d40102fe8c4a4dcf3d1`, isolated worktree
`/tmp/arc-security-launch`, branch `packet/3-retention-accounting`.

Rust toolchain: 1.94.1, aarch64-unknown-linux-gnu. Cargo uses
`CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=4`, and
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`.

Every log is retained as deterministic gzip; its sibling JSON records the exact
command, terminal exit and SHA256 of the uncompressed log. Failures remain failures,
including commands with optimistic labels. Exit zero qualifies only the actual
selected tests. Zero-test targets do not count as positive controls.

`final-owner-binaries.json` hashes the earlier union-built runtime executables;
`post-review-binaries.json` pins the review-fix owner suite. A later API-only
fixture helper/startup synchronization repair is independently rebuilt and qualified
by `readiness-qualified-owner-build`, `readiness-qualified-binaries.json` and
`readiness-qualified-api-owner`.
`review-source-files.json` and `review-staged.diff.gz` pin the independently reviewed
candidate; `final-source-files.json` pins source after required corrections.
[Source publication](source-publication.json) records the committed candidate,
verified remote SHA and qualified source-manifest hash.
`progress.md` contains decisions and failure dispositions. The independent review
records its original verdict, findings and the author's dispositions.

The original broad SQLite campaign was explicitly interrupted after unrelated
admission deadlines under load. The final combined wrapper later terminated with
exit 143 during SQLite, without recording the child terminal status; its
`.interrupted.json` preserves that uncertainty. A separate completed SQLite owner
run supplies acceptance. No full workspace runtime or hosted qualification is claimed.

| Command label | Terminal result | Exact command | Retained log |
| --- | --- | --- | --- |
| `archive-tail-diagnostic` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_store_sqlite-b2be040cdaea43ae retained_queries_ignore --test-threads=1 --nocapture` | [archive-tail-diagnostic.log.gz](archive-tail-diagnostic.log.gz) |
| `clock-contracts` | pass | `python3 scripts/check-security-clocks.py` | [clock-contracts.log.gz](clock-contracts.log.gz) |
| `duplicate-red-fixture-fixed` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core --lib --locked evidence_sink` | [duplicate-red-fixture-fixed.log.gz](duplicate-red-fixture-fixed.log.gz) |
| `final-cli-owners-terminal` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio-28240525c472faf7 types_cli::cli_env_tests runtime_local_error_domain_tests cli_entrypoint_parsing_tests --test-threads=2` | [final-cli-owners-terminal.log.gz](final-cli-owners-terminal.log.gz) |
| `final-format` | pass | `cargo fmt --all -- --check` | [final-format.log.gz](final-format.log.gz) |
| `final-negative-assertions` | pass | `python3 scripts/check-negative-assertions.py` | [final-negative-assertions.log.gz](final-negative-assertions.log.gz) |
| `final-owner-api-owner` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 --test-threads=2` | [final-owner-api-owner.log.gz](final-owner-api-owner.log.gz) |
| `final-owner-build-2` | pass | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-run` | [final-owner-build-2.log.gz](final-owner-build-2.log.gz) |
| `final-owner-http-owner` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_http_core-2be53cd925621628 --test-threads=2` | [final-owner-http-owner.log.gz](final-owner-http-owner.log.gz) |
| `final-owner-sqlite-owners` | interrupted; child status unavailable | `see interruption metadata` | [final-owner-sqlite-owners.log.gz](final-owner-sqlite-owners.log.gz) |
| `final-rust-file-hygiene` | pass | `python3 scripts/check-rust-file-hygiene.py` | [final-rust-file-hygiene.log.gz](final-rust-file-hygiene.log.gz) |
| `final-rust-hygiene` | failed (2) | `python3 scripts/check-rust-hygiene.py` | [final-rust-hygiene.log.gz](final-rust-hygiene.log.gz) |
| `final-sqlite-owners-terminal` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_store_sqlite-b2be040cdaea43ae receipt_store::tests:: receipt_query::tests:: evidence_export::tests:: capability_lineage::tests:: --test-threads=2` | [final-sqlite-owners-terminal.log.gz](final-sqlite-owners-terminal.log.gz) |
| `final-trust-contracts` | pass | `python3 scripts/check-trust-boundaries.py` | [final-trust-contracts.log.gz](final-trust-contracts.log.gz) |
| `fixture-qualified-api-owner` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 --test-threads=2` | [fixture-qualified-api-owner.log.gz](fixture-qualified-api-owner.log.gz) |
| `fixture-qualified-clippy` | pass | `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings` | [fixture-qualified-clippy.log.gz](fixture-qualified-clippy.log.gz) |
| `fixture-qualified-format` | pass | `cargo fmt --all -- --check` | [fixture-qualified-format.log.gz](fixture-qualified-format.log.gz) |
| `fixture-qualified-owner-build` | pass | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-run` | [fixture-qualified-owner-build.log.gz](fixture-qualified-owner-build.log.gz) |
| `lifecycle-api-runtime` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 --test-threads=2` | [lifecycle-api-runtime.log.gz](lifecycle-api-runtime.log.gz) |
| `lifecycle-cli-runtime` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio-28240525c472faf7 types_cli::cli_env_tests runtime_local_error_domain_tests main_tests_parsing --test-threads=2` | [lifecycle-cli-runtime.log.gz](lifecycle-cli-runtime.log.gz) |
| `lifecycle-http-runtime` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_http_core-2be53cd925621628 --test-threads=2` | [lifecycle-http-runtime.log.gz](lifecycle-http-runtime.log.gz) |
| `lifecycle-sqlite-runtime` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_store_sqlite-b2be040cdaea43ae receipt_store::tests:: receipt_query::tests:: evidence_export::tests:: capability_lineage::tests:: --test-threads=2` | [lifecycle-sqlite-runtime.log.gz](lifecycle-sqlite-runtime.log.gz) |
| `negative-assertions` | pass | `python3 scripts/check-negative-assertions.py` | [negative-assertions.log.gz](negative-assertions.log.gz) |
| `observation-red` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-6e41dc2b3ade5e44 submitted_observation` | [observation-red.log.gz](observation-red.log.gz) |
| `post-review-api-owner` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 --test-threads=2` | [post-review-api-owner.log.gz](post-review-api-owner.log.gz) |
| `post-review-cli-owners` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio-28240525c472faf7 types_cli::cli_env_tests runtime_local_error_domain_tests cli_entrypoint_parsing_tests --test-threads=2` | [post-review-cli-owners.log.gz](post-review-cli-owners.log.gz) |
| `post-review-format` | pass | `cargo fmt --all -- --check` | [post-review-format.log.gz](post-review-format.log.gz) |
| `post-review-http-owner` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_http_core-2be53cd925621628 --test-threads=2` | [post-review-http-owner.log.gz](post-review-http-owner.log.gz) |
| `post-review-hygiene` | pass | `python3 scripts/check-rust-file-hygiene.py` | [post-review-hygiene.log.gz](post-review-hygiene.log.gz) |
| `post-review-negative-assertions` | pass | `python3 scripts/check-negative-assertions.py` | [post-review-negative-assertions.log.gz](post-review-negative-assertions.log.gz) |
| `post-review-owner-build` | pass | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-run` | [post-review-owner-build.log.gz](post-review-owner-build.log.gz) |
| `post-review-sqlite-owners` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_store_sqlite-b2be040cdaea43ae receipt_store::tests:: receipt_query::tests:: evidence_export::tests:: capability_lineage::tests:: --test-threads=2` | [post-review-sqlite-owners.log.gz](post-review-sqlite-owners.log.gz) |
| `post-review-trust-contracts` | pass | `python3 scripts/check-trust-boundaries.py` | [post-review-trust-contracts.log.gz](post-review-trust-contracts.log.gz) |
| `post-review-workspace-clippy` | failed (101) | `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings` | [post-review-workspace-clippy.log.gz](post-review-workspace-clippy.log.gz) |
| `projection-red` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_http_core-9a238807bd050554 evidence_projection` | [projection-red.log.gz](projection-red.log.gz) |
| `qualification-toolchain` | pass | `rustc -Vv` | [qualification-toolchain.log.gz](qualification-toolchain.log.gz) |
| `qualified-api-owner` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 --test-threads=2` | [qualified-api-owner.log.gz](qualified-api-owner.log.gz) |
| `qualified-build-2` | pass | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-run` | [qualified-build-2.log.gz](qualified-build-2.log.gz) |
| `qualified-cli-owners` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio-28240525c472faf7 types_cli::cli_env_tests runtime_local_error_domain_tests cli_entrypoint_parsing_tests --test-threads=2` | [qualified-cli-owners.log.gz](qualified-cli-owners.log.gz) |
| `qualified-http-owner` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_http_core-2be53cd925621628 --test-threads=2` | [qualified-http-owner.log.gz](qualified-http-owner.log.gz) |
| `qualified-hygiene` | pass | `python3 scripts/check-rust-file-hygiene.py` | [qualified-hygiene.log.gz](qualified-hygiene.log.gz) |
| `qualified-owner-build` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-run` | [qualified-owner-build.log.gz](qualified-owner-build.log.gz) |
| `qualified-sqlite-owners` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_store_sqlite-b2be040cdaea43ae receipt_store::tests:: receipt_query::tests:: evidence_export::tests:: capability_lineage::tests:: --test-threads=2` | [qualified-sqlite-owners.log.gz](qualified-sqlite-owners.log.gz) |
| `qualified-trust-contracts` | pass | `python3 scripts/check-trust-boundaries.py` | [qualified-trust-contracts.log.gz](qualified-trust-contracts.log.gz) |
| `readiness-qualified-api-owner` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 --test-threads=2` | [readiness-qualified-api-owner.log.gz](readiness-qualified-api-owner.log.gz) |
| `readiness-qualified-clippy` | pass | `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings` | [readiness-qualified-clippy.log.gz](readiness-qualified-clippy.log.gz) |
| `readiness-qualified-format` | pass | `cargo fmt --all -- --check` | [readiness-qualified-format.log.gz](readiness-qualified-format.log.gz) |
| `readiness-qualified-owner-build` | pass | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-run` | [readiness-qualified-owner-build.log.gz](readiness-qualified-owner-build.log.gz) |
| `receipt-lifecycle-build` | pass | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-run` | [receipt-lifecycle-build.log.gz](receipt-lifecycle-build.log.gz) |
| `retained-boundaries-green` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast -- --test-threads=2 retained_ retention_policy scheduled_retention` | [retained-boundaries-green.log.gz](retained-boundaries-green.log.gz) |
| `retained-first-build` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite --lib --locked --no-run` | [retained-first-build.log.gz](retained-first-build.log.gz) |
| `retained-fixture-diagnostic` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_store_sqlite-b2be040cdaea43ae retained_pages --test-threads=1 --nocapture` | [retained-fixture-diagnostic.log.gz](retained-fixture-diagnostic.log.gz) |
| `retained-point-and-config-red` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast -- --test-threads=2 retained_point retained_native_point retention_policy_preserves` | [retained-point-and-config-red.log.gz](retained-point-and-config-red.log.gz) |
| `retention-cli-and-worker-red` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --locked --no-fail-fast retention_ -- --test-threads=2` | [retention-cli-and-worker-red.log.gz](retention-cli-and-worker-red.log.gz) |
| `retention-controls-red-2` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast retention_ -- --test-threads=2` | [retention-controls-red-2.log.gz](retention-controls-red-2.log.gz) |
| `retention-controls-red` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast retention_ -- --test-threads=2` | [retention-controls-red.log.gz](retention-controls-red.log.gz) |
| `review-findings-green` | pass | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast -- --test-threads=2 retained_projection_ native_redelivery_recognizes` | [review-findings-green.log.gz](review-findings-green.log.gz) |
| `review-findings-red` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast -- --test-threads=2 retained_projection_ native_redelivery_recognizes` | [review-findings-red.log.gz](review-findings-red.log.gz) |
| `rust-hygiene` | failed (1) | `python3 scripts/check-rust-file-hygiene.py` | [rust-hygiene.log.gz](rust-hygiene.log.gz) |
| `scheduled-worker-red-binary` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 scheduled_retention --test-threads=1` | [scheduled-worker-red-binary.log.gz](scheduled-worker-red-binary.log.gz) |
| `semantics-and-archive-first` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite --lib --locked --no-fail-fast evidence_` | [semantics-and-archive-first.log.gz](semantics-and-archive-first.log.gz) |
| `semantics-red` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core --lib --locked evidence_` | [semantics-red.log.gz](semantics-red.log.gz) |
| `shared-owners-first` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite --lib --locked --no-fail-fast` | [shared-owners-first.log.gz](shared-owners-first.log.gz) |
| `shared-writer-health-diagnostic` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_api_protect-ccd2b5c469a28190 shared_evidence_store_uses --test-threads=1` | [shared-writer-health-diagnostic.log.gz](shared-writer-health-diagnostic.log.gz) |
| `sink-first-build` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite --lib --locked --no-run` | [sink-first-build.log.gz](sink-first-build.log.gz) |
| `tail-snapshot-diagnostic` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked retained_queries_ignore_copied -- --nocapture` | [tail-snapshot-diagnostic.log.gz](tail-snapshot-diagnostic.log.gz) |
| `trust-contracts` | failed (1) | `python3 scripts/check-trust-boundaries.py` | [trust-contracts.log.gz](trust-contracts.log.gz) |
| `worker-control-red-2` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast scheduled_retention -- --test-threads=2` | [worker-control-red-2.log.gz](worker-control-red-2.log.gz) |
| `worker-control-red` | failed (101) | `cargo test -p chio-api-protect -p chio-http-core -p chio-store-sqlite -p chio-cli --lib --bins --locked --no-fail-fast scheduled_retention -- --test-threads=2` | [worker-control-red.log.gz](worker-control-red.log.gz) |
| `workspace-clippy` | failed (101) | `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings` | [workspace-clippy.log.gz](workspace-clippy.log.gz) |
