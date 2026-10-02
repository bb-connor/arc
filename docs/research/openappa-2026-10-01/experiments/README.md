# Model-free experiments

These experiments use the pinned OpenAPPA source and real runtime/engine APIs. They make no LLM calls, send no email, create no remote issues, and do not exercise Linux confinement or a live coding-agent session.

## Reproduce

Use a separate checkout so this research does not modify the application or upstream source:

```sh
git clone https://github.com/archestra-ai/OpenAPPA.git /tmp/chio-openappa-lab
git -C /tmp/chio-openappa-lab checkout --detach a96f87d1fec900caf890f14342a089a32b3bfaff
CARGO_TARGET_DIR=/tmp/chio-openappa-target CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked --manifest-path /tmp/chio-openappa-lab/Cargo.toml -p appa
python3 docs/research/openappa-2026-10-01/experiments/run.py --source /tmp/chio-openappa-lab --binary /tmp/chio-openappa-target/debug/appa --target /tmp/chio-openappa-target --output /tmp/chio-openappa-results
```

Run the final command from the Chio documentation checkout. Rust dependencies require an initial download; the external probe uses `cargo run --offline` after that cache exists. The script verifies the source HEAD and builds the small probe in a temporary standalone crate. It does not establish which source produced an arbitrary supplied binary; for reproduction, build the binary from the pinned checkout as shown.

The actual captured source and target directories and binary digest are in [source-manifest.json](../evidence/source-manifest.json) and [experiments.json](../evidence/experiments.json). The probe's resolved dependency versions are retained in [probe-Cargo.lock](../evidence/probe-Cargo.lock). Debug builds were used; the elapsed times are execution records, not release-performance benchmarks.

## Authored policy trajectories

[policy.toml](policy.toml) declares deterministic tool contracts. [confidentiality.appa](confidentiality.appa) has nine actions, checking that a private read persists across a public read and unrelated approvals, while an authorized HR recipient remains usable. Each destructive call independently requires the simulated approver. [ordering.appa](ordering.appa) has five actions: deployment requires a successful backup, and migration can happen once.

Result: both files passed all 14 expectations. [Verbose log](../evidence/authored-replay.log).

The replay runner stubs outputs, simulates approval, and does not perform external effects. It exercises policy/runtime behavior; it does not test whether a provider actually delivered a message, whether a person approved it, or whether a sanitizer removed a secret. An unfinished dispatch cannot be represented by these two simple success traces; upstream engine reservation and runtime crash-recovery tests cover that separate path.

## File-ledger recreation

[file_restart.rs](file_restart.rs) uses `appa-eventlog::files::FileStore` directly:

1. Create a synthetic scratch file and a public initial label.
2. Replace the content with synthetic bytes under an HR-only restricted label.
3. Complete the operation and confirm the version retains that restriction.
4. Drop the ledger and create a fresh ledger over the same directory.
5. Read the file basis and compare its digest and label.

Result: the digest was identical, while the new label equaled the configured public starting label. [Structured result](../evidence/experiments.json), [run log](../evidence/file-ledger-recreation.log).

This reproduces the documented in-memory ledger limitation. It is a ledger API probe, not a full runtime restart or a security exploit against a supported feature. Starting with a restrictive initial label changes what the file is adopted as; the existing version and producer history are still absent from the fresh ledger.

## Selected upstream tests

The exact package/suite commands, counts, environment, and scope are in [test-results.json](../evidence/test-results.json). Retained full logs: [core](../evidence/core-tests.log) and [runtime](../evidence/runtime-tests.log).

The selected runs passed 1,502 tests, with two live TypeSafe tests ignored. The test selection is not a full workspace certification. No Chio runtime suite, live external classifier, PostgreSQL service, or Linux sandbox backend was run here.
