# Authenticated evidence package command evidence

Base: `0a455ac2c0fb9641b96d36bb2289bcd8047c325b`; isolated worktree
`/tmp/arc-security-launch`, branch `packet/3-retention-accounting`.

Cargo uses `CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=4`, and
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`. Toolchain output is retained.
Every command JSON records its arguments, terminal exit, elapsed time and SHA256
of its uncompressed log. Logs use deterministic gzip. Failures remain failures,
including assertion/fixture and gate-reconciliation failures. A passing build is
compile evidence; a runtime result qualifies only its selected tests/features.

`strict-owner-binaries.json` pins the unchanged core/kernel owner executables.
`current-build-binaries.json` pins the other initial union-built consumers;
`qualified-binaries.json` pins the corrected final test executables and native
CLI binaries. `review-source-hashes.json` and `review-candidate.diff.gz` retain the
reviewed candidate. `final-source-files.json` pins the final changed source and
configuration; fixture/gate changes after review are described in `progress.md`.
The independent review retains its original verdict and all declined boundaries.
This is local Linux qualification, not full-workspace runtime, hosted CI, merge,
release or operational acceptance.

| Command label | Terminal result | Exact command | Retained log |
| --- | --- | --- | --- |
| `affected-build-current` | pass | `cargo test -p chio-core-types -p chio-kernel -p chio-control-plane -p chio-cli -p chio-mercury -p chio-wall --lib --bins --test evidence_export --test cli --locked --no-run` | [affected-build-current.log.gz](affected-build-current.log.gz) |
| `affected-build` | pass | `cargo test -p chio-core-types -p chio-kernel -p chio-control-plane -p chio-cli -p chio-mercury -p chio-wall --lib --bins --test evidence_export --test cli --locked --no-run` | [affected-build.log.gz](affected-build.log.gz) |
| `affected-test-fixture-build` | pass | `cargo test -p chio-core-types -p chio-kernel -p chio-control-plane -p chio-cli -p chio-mercury -p chio-wall --lib --bins --test evidence_export --test cli --locked --no-run` | [affected-test-fixture-build.log.gz](affected-test-fixture-build.log.gz) |
| `anchor-self-claim-red` | failed (101) | `cargo test -p chio-core-types -p chio-kernel --lib --locked evidence_export_marks_bound_publication_as_trust_anchored -- --test-threads=2` | [anchor-self-claim-red.log.gz](anchor-self-claim-red.log.gz) |
| `control-package-owners-code-assertion` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_control_plane-6fe8d5ba7f503f63 evidence_export:: --test-threads=2` | [control-package-owners-code-assertion.log.gz](control-package-owners-code-assertion.log.gz) |
| `control-package-owners` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/chio_control_plane-6fe8d5ba7f503f63 evidence_export:: --test-threads=2` | [control-package-owners.log.gz](control-package-owners.log.gz) |
| `core-signature-owners` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_core_types-cd374e5d46da184b --test-threads=2` | [core-signature-owners.log.gz](core-signature-owners.log.gz) |
| `final-artifact-hygiene` | pass | `python3 scripts/check-rust-file-hygiene.py` | [final-artifact-hygiene.log.gz](final-artifact-hygiene.log.gz) |
| `kernel-evidence-owners` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_kernel-22b53e5b65c376c2 checkpoint:: evidence_export:: --test-threads=2` | [kernel-evidence-owners.log.gz](kernel-evidence-owners.log.gz) |
| `mercury-native-consumers` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/cli-9a056b28c094a5ed --test-threads=2` | [mercury-native-consumers.log.gz](mercury-native-consumers.log.gz) |
| `native-package-owners` | failed (101) | `/home/connor/chio-security-target-6d-final/debug/deps/evidence_export-cc9b3ab5dbda2341 --test-threads=2` | [native-package-owners.log.gz](native-package-owners.log.gz) |
| `native-package-trust-red` | failed (101) | `cargo test -p chio-cli --test evidence_export --locked package_trust -- --test-threads=2` | [native-package-trust-red.log.gz](native-package-trust-red.log.gz) |
| `package-accounting` | pass | `python3 scripts/check-accounting-arithmetic.py` | [package-accounting.log.gz](package-accounting.log.gz) |
| `package-clock-gate-initial` | pass | `python3 scripts/check-security-clocks.py` | [package-clock-gate-initial.log.gz](package-clock-gate-initial.log.gz) |
| `package-domains` | pass | `python3 scripts/check-domain-separation.py` | [package-domains.log.gz](package-domains.log.gz) |
| `package-format-current` | pass | `cargo fmt --all -- --check` | [package-format-current.log.gz](package-format-current.log.gz) |
| `package-format-qualified` | pass | `cargo fmt --all -- --check` | [package-format-qualified.log.gz](package-format-qualified.log.gz) |
| `package-hygiene-current` | failed (1) | `python3 scripts/check-rust-file-hygiene.py` | [package-hygiene-current.log.gz](package-hygiene-current.log.gz) |
| `package-hygiene-initial` | failed (1) | `python3 scripts/check-rust-file-hygiene.py` | [package-hygiene-initial.log.gz](package-hygiene-initial.log.gz) |
| `package-hygiene-ratcheted` | pass | `python3 scripts/check-rust-file-hygiene.py` | [package-hygiene-ratcheted.log.gz](package-hygiene-ratcheted.log.gz) |
| `package-negative-initial` | pass | `python3 scripts/check-negative-assertions.py` | [package-negative-initial.log.gz](package-negative-initial.log.gz) |
| `package-negative-qualified` | pass | `python3 scripts/check-negative-assertions.py` | [package-negative-qualified.log.gz](package-negative-qualified.log.gz) |
| `package-trust-gate-current` | pass | `python3 scripts/check-trust-boundaries.py` | [package-trust-gate-current.log.gz](package-trust-gate-current.log.gz) |
| `package-trust-gate-initial` | failed (1) | `python3 scripts/check-trust-boundaries.py` | [package-trust-gate-initial.log.gz](package-trust-gate-initial.log.gz) |
| `package-wire-qualified` | pass | `python3 scripts/check-wire-schemas.py` | [package-wire-qualified.log.gz](package-wire-qualified.log.gz) |
| `package-wire-schemas` | failed (1) | `python3 scripts/check-wire-schemas.py` | [package-wire-schemas.log.gz](package-wire-schemas.log.gz) |
| `package-wire-update` | pass | `python3 scripts/check-wire-schemas.py --update` | [package-wire-update.log.gz](package-wire-update.log.gz) |
| `qualification-toolchain` | pass | `rustc -Vv` | [qualification-toolchain.log.gz](qualification-toolchain.log.gz) |
| `qualified-control-package-owners` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_control_plane-6fe8d5ba7f503f63 evidence_export:: --test-threads=2` | [qualified-control-package-owners.log.gz](qualified-control-package-owners.log.gz) |
| `qualified-native-package-owners` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/evidence_export-cc9b3ab5dbda2341 --test-threads=2` | [qualified-native-package-owners.log.gz](qualified-native-package-owners.log.gz) |
| `qualified-owner-build` | pass | `cargo test -p chio-core-types -p chio-kernel -p chio-control-plane -p chio-cli -p chio-mercury -p chio-wall --lib --bins --test evidence_export --test cli --locked --no-run` | [qualified-owner-build.log.gz](qualified-owner-build.log.gz) |
| `receipt-backend-compatibility` | pass | `cargo test -p chio-core-types --features pq,fips --lib --locked receipt:: -- --test-threads=2` | [receipt-backend-compatibility.log.gz](receipt-backend-compatibility.log.gz) |
| `strict-signatures-red` | failed (101) | `cargo test -p chio-core-types -p chio-kernel --lib --locked --no-fail-fast identity_key_forgery -- --test-threads=2` | [strict-signatures-red.log.gz](strict-signatures-red.log.gz) |
| `unsigned-and-signer-red-fixture` | failed (101) | `cargo test -p chio-control-plane --lib --locked package_trust -- --test-threads=2` | [unsigned-and-signer-red-fixture.log.gz](unsigned-and-signer-red-fixture.log.gz) |
| `unsigned-and-signer-red` | failed (101) | `cargo test -p chio-control-plane --lib --locked package_trust -- --test-threads=2` | [unsigned-and-signer-red.log.gz](unsigned-and-signer-red.log.gz) |
| `wall-native-consumers` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/cli-32839b306107b9a3 --test-threads=2` | [wall-native-consumers.log.gz](wall-native-consumers.log.gz) |
| `wall-owner` | pass | `/home/connor/chio-security-target-6d-final/debug/deps/chio_wall-1113f1553764562e --test-threads=2` | [wall-owner.log.gz](wall-owner.log.gz) |
| `workspace-clippy-initial` | failed (101) | `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings` | [workspace-clippy-initial.log.gz](workspace-clippy-initial.log.gz) |
| `workspace-clippy-qualified` | pass | `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings` | [workspace-clippy-qualified.log.gz](workspace-clippy-qualified.log.gz) |
