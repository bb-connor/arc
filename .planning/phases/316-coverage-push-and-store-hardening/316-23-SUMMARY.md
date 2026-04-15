# Summary 316-23

Phase `316` then took a broader trust-control runtime-wrapper coverage wave
and reran the comparable filtered full-workspace coverage lane.

The implemented tests updated:

- `crates/arc-cli/src/trust_control/service_runtime.rs`

Verification that passed during this wave:

- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave23 cargo test -p arc-control-plane service_runtime_tests --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace5-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace5-next-coverage.json`

This wave added two broader request-wrapper checks in
`service_runtime_tests`:

- GET trust-control client wrappers now prove bearer-auth, query encoding, and
  encoded path handling across the live HTTP surface
- POST trust-control client wrappers now prove JSON body forwarding and encoded
  path handling across issuance/evaluation requests

Those tests exercise weak production wrapper code, but they run under
`arc-control-plane`, which the comparable filtered workspace lane excludes.

Coverage-gate result:

- the comparable filtered full-workspace rerun moved from `109272/148732`
  (`73.47%`) to `109397/149044` (`73.40%`)
- that is `+125` covered lines against `+312` total counted lines
- net uncovered lines worsened by `187`
- at the current denominator, phase `316` still needs another `9839` covered
  lines to reach `80%`

The refreshed hotspot list confirms the next counted acreage is still the
`arc-cli` trust-control handler/config surface, led by:

- `crates/arc-cli/src/trust_control/http_handlers_a.rs` (`2123` uncovered)
- `crates/arc-cli/src/trust_control/http_handlers_b.rs` (`1825` uncovered)
- `crates/arc-cli/src/trust_control/config_and_public.rs` (`1610` uncovered)
