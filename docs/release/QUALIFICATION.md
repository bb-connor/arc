# Release Qualification

This document defines the production qualification lane for the current `v2.3`
milestone surface.

PACT now has two distinct gate types:

- the regular workspace CI lane, which blocks routine regressions quickly
- the release-qualification lane, which proves source-only release inputs,
  dashboard and SDK packaging, conformance-critical behavior, and the repeat-run
  HA control-plane path

## Environments

Regular workspace CI:

- Rust stable with `rustfmt` and `clippy`
- Rust `1.93.0` for the explicit MSRV lane
- `node`
- `python3`
- `go`

Release qualification:

- Rust stable with `rustfmt` and `clippy`
- `node`
- `python3`
- `go`

The dashboard build, TypeScript packaging, Python packaging, Go module
qualification, live JS/Python conformance peers, and repeat-run trust-cluster
proof are mandatory for release qualification. If one runtime is missing, the
lane must fail rather than silently skipping that evidence.

## Commands

Regular workspace lane:

```bash
./scripts/ci-workspace.sh
./scripts/check-sdk-parity.sh
```

Release-qualification lane:

```bash
./scripts/qualify-release.sh
```

Focused release-component lanes:

```bash
./scripts/check-release-inputs.sh
./scripts/check-dashboard-release.sh
./scripts/check-pact-ts-release.sh
./scripts/check-pact-py-release.sh
./scripts/check-pact-go-release.sh
```

The hosted workflow uses
[`.github/workflows/release-qualification.yml`](../../.github/workflows/release-qualification.yml)
and the same `./scripts/qualify-release.sh` entrypoint. The general CI workflow
uses [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

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

The release-qualification script also records the repeat-run trust-cluster
proof at:

- `target/release-qualification/logs/trust-cluster-repeat-run.log`

The same artifacts can be fed into `PACT Certify` to produce a signed pass/fail
attestation for a selected tool server or release candidate. See
[PACT_CERTIFY_GUIDE.md](../PACT_CERTIFY_GUIDE.md).

## Evidence Matrix

| Release claim | Primary proving artifact | Qualification command |
| --- | --- | --- |
| Release inputs come from source only and generated artifacts are not tracked | `scripts/check-release-inputs.sh`, root `.gitignore`, package-specific packaging manifests | `./scripts/check-release-inputs.sh` |
| The main Rust workspace is format-clean, lint-clean, and test-clean | workspace crates plus integration/e2e suites | `./scripts/ci-workspace.sh` |
| The dashboard is buildable and testable from a clean install | `crates/pact-cli/dashboard/package.json` and `dist/` output from a temp copy | `./scripts/check-dashboard-release.sh` |
| The TypeScript SDK can be built, packed, and consumed as a package | `packages/sdk/pact-ts/package.json`, packed tarball, and consumer smoke install | `./scripts/check-pact-ts-release.sh` |
| The Python SDK wheel and sdist are reproducible and install cleanly | `packages/sdk/pact-py/pyproject.toml`, built wheel/sdist, and clean venv smoke installs | `./scripts/check-pact-py-release.sh` |
| The Go SDK module qualifies as a module release and consumer dependency | `packages/sdk/pact-go/go.mod`, `go install ./cmd/conformance-peer`, and consumer-module smoke build | `./scripts/check-pact-go-release.sh` |
| HA trust-control remains deterministic on the supported clustered control-plane flow | `crates/pact-cli/tests/trust_cluster.rs` repeat-run qualification plus normal workspace coverage | `cargo test -p pact-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture` |
| Wrapped/runtime MCP compatibility remains truthful across live peer waves | live conformance results under `target/release-qualification/conformance/` | `./scripts/qualify-release.sh` |

## Release Rule

Do not tag or announce a production candidate from a green workspace run alone.

Release readiness for the current surface requires:

1. `./scripts/ci-workspace.sh` green
2. `./scripts/check-sdk-parity.sh` green
3. `./scripts/qualify-release.sh` green
4. the explicit MSRV lane in `.github/workflows/ci.yml` green on Rust `1.93.0`
5. [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md),
   [RELEASE_AUDIT.md](RELEASE_AUDIT.md), and
   [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) updated together
6. [OBSERVABILITY.md](OBSERVABILITY.md),
   [GA_CHECKLIST.md](GA_CHECKLIST.md), and
   [RISK_REGISTER.md](RISK_REGISTER.md) updated together

If a hosted CI run cannot be observed from the current environment, record that
as an explicit procedural note in the release audit instead of implying it
happened.
