# Summary 316-11

Phase `316` added an eleventh coverage wave that stayed inside
`arc-acp-proxy` and closed most of the remaining lifecycle wrapper gap around
`AcpProxy` and `AcpTransport`.

The implemented coverage wave added more tests in:

- `arc-acp-proxy/src/tests/all.rs`

Verification that passed during this wave:

- `cargo test -p arc-acp-proxy`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-acp-proxy-llvm cargo llvm-cov -p arc-acp-proxy --json --summary-only --output-path /tmp/arc-phase316-acp-proxy-coverage.json`
- `git diff --check -- crates/arc-acp-proxy/src/tests/all.rs .planning/phases/316-coverage-push-and-store-hardening/316-10-SUMMARY.md .planning/phases/316-coverage-push-and-store-hardening/316-VALIDATION.md`

Measured local coverage from the refreshed `llvm-cov` lane:

- `arc-acp-proxy` crate total: `1036/1298` -> `1134/1298` lines (`+98`, `87.37%`)
- `arc-acp-proxy/src/proxy.rs`: `16/64` -> `63/64` lines (`98.44%`)
- `arc-acp-proxy/src/transport.rs`: `23/89` -> `53/89` lines (`59.55%`)

The new tests cover JSON send/receive round-trips through a real `sh -c cat`
subprocess, EOF handling, invalid JSON handling, process kill/wait lifecycle,
and the top-level proxy wrapper path for kernel-backed startup, interceptor
wrappers, transport forwarding, and shutdown.

With this follow-up wave, the cumulative `arc-acp-proxy` delta against the
isolated full-workspace `llvm-cov` baseline is now `483/1298` ->
`1134/1298` lines (`+651`). That moves the estimated local workspace total to
`96493/137683` (`70.08%`), so phase `316` still remains open.
