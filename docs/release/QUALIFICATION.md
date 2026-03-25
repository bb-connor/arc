# Release Qualification

This document defines the proof path for the scoped `v1` release candidate.

PACT now has two distinct gate types:

- the regular workspace CI lane, which keeps day-to-day development honest
- the release-qualification lane, which proves the closing-cycle guarantees, negative paths, and live interoperability claims

## Environments

Regular workspace CI:

- Rust stable with `rustfmt` and `clippy`
- Rust `1.93.0` for the explicit MSRV lane
- no external language runtimes required

Release qualification:

- Rust stable with `rustfmt` and `clippy`
- `node`
- `python3`

The live JS and Python conformance peers are mandatory for release qualification. If those runtimes are missing, release qualification must fail rather than silently skipping evidence.

## Commands

Regular workspace lane:

```bash
./scripts/ci-workspace.sh
```

Release-qualification lane:

```bash
./scripts/qualify-release.sh
```

The hosted workflow uses [`.github/workflows/release-qualification.yml`](../../.github/workflows/release-qualification.yml) and the same `./scripts/qualify-release.sh` entrypoint.

## Qualification Artifacts

The release-qualification script writes conformance evidence under:

- `target/release-qualification/conformance/wave1/`
- `target/release-qualification/conformance/wave2/`
- `target/release-qualification/conformance/wave3/`
- `target/release-qualification/conformance/wave4/`
- `target/release-qualification/conformance/wave5/`

Each wave directory contains:

- `results/` JSON result artifacts
- `report.md` generated Markdown summary

The release-qualification script also records the repeat-run trust-cluster proof at:

- `target/release-qualification/logs/trust-cluster-repeat-run.log`

The same artifacts can be fed into `PACT Certify` to produce a signed pass/fail
attestation for a selected tool server or release candidate. See
[PACT_CERTIFY_GUIDE.md](../PACT_CERTIFY_GUIDE.md).

## Evidence Matrix

| Release claim | Primary proving artifact | Qualification command |
| --- | --- | --- |
| HA trust-control is deterministic enough for the supported clustered control-plane flow | `crates/pact-cli/tests/trust_cluster.rs` repeat-run qualification plus the normal workspace lane | `cargo test -p pact-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture` |
| Roots are enforced as a real filesystem boundary for tools and filesystem-backed resources | `crates/pact-cli/tests/mcp_serve.rs`, `crates/pact-cli/tests/mcp_serve_http.rs`, `tests/e2e/tests/full_flow.rs` | `cargo test --workspace` |
| Hosted remote sessions are reconnect-safe, drain/expire deterministically, and expose operator diagnostics | `crates/pact-cli/tests/mcp_serve_http.rs` | `cargo test --workspace` |
| Task, stream, cancellation, and late async semantics are transport-consistent | `crates/pact-cli/tests/mcp_serve.rs`, `crates/pact-cli/tests/mcp_serve_http.rs`, `crates/pact-conformance/tests/` | `cargo test --workspace` plus live wave generation in `./scripts/qualify-release.sh` |
| Policy authoring, migration, and native adoption are coherent | `README.md`, `docs/NATIVE_ADOPTION_GUIDE.md`, `examples/hello-tool/`, `examples/policies/`, `crates/pact-cli/src/policy.rs` | `cargo test --workspace` |
| Malformed JSON-RPC, revocation/expiry, interrupted streams, and cancellation races are covered on the supported surface | `crates/pact-cli/tests/mcp_serve_http.rs`, `crates/pact-cli/tests/mcp_serve.rs`, `tests/e2e/tests/full_flow.rs` | `cargo test --workspace` |
| The public release story matches what the repo actually ships | `README.md`, `docs/release/RELEASE_CANDIDATE.md`, `docs/release/RELEASE_AUDIT.md` | doc review plus the same workspace and qualification gates |

## Former Findings To Release Evidence

| Former finding | Owning epic | Release evidence |
| --- | --- | --- |
| HA trust-control flake | `E9` | workspace lane plus repeat-run trust-cluster qualification |
| Roots not enforced | `E12` | tool/resource boundary regressions and end-to-end deny-receipt coverage |
| Split policy surface | `E13` | README policy guidance, canonical HushSpec example, YAML compatibility coverage, native adoption guide |
| Remote runtime not deployment-hard | `E10` | hosted HTTP lifecycle/reconnect/SSE regression coverage and release docs |
| Transport-dependent long-running semantics | `E11` | direct, wrapped, and remote cancellation/late-event tests plus live remote conformance waves |

## Release Rule

Do not tag the milestone from a green workspace run alone.

Release readiness for the scoped `v1` surface requires:

1. `./scripts/ci-workspace.sh` green
2. `./scripts/qualify-release.sh` green
3. the explicit MSRV lane in `.github/workflows/ci.yml` green on Rust `1.93.0`
4. [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md) and [RELEASE_AUDIT.md](RELEASE_AUDIT.md) updated together

If a hosted CI run cannot be observed from the current environment, record that as an explicit procedural note in the release audit instead of implying it happened.
