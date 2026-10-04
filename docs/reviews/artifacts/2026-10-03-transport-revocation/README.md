# Transport and revocation local evidence

`commands.json` retains exact terminal commands, exits, duration, log SHA-256 and
test summaries. Deterministic `*.log.gz` files retain original output. Initial
compile/fixture failures, genuine RED controls, the shutdown-test scheduling
failure and the first lint/negative-assertion failures remain failures; subsequent
passes do not rewrite them. The zero-test CLI filter is not acceptance.

`sources.json` hashes the qualified source/configuration/documentation snapshot
before commit. Evidence files and preexisting `output/` are excluded. `binaries.json`
identifies currently retained binaries; earlier executables may have been replaced,
so earlier campaigns establish log evidence only. The parent source commit and
final publication are recorded in Git, separately from hosted qualification.

`independent-review.md` retains the single review and dispositions.
`private-key-ownership.md` accounts for secret-bearing allocation ownership and
pins the inspected dependency sources. `progress.md` retains execution rulings.
`run-command.py` and `check-transport-cli.py` are local reproduction helpers.

Commands ran on Linux aarch64 with Rust 1.94.1 in `/tmp/arc-security-launch`, using
`CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=4`, and
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`. This is local source evidence,
not hosted CI, deployment, native-platform, upstream-audit or release acceptance.
