# Continuous Fuzzing Runbook

This is the operational runbook for Chio's continuous-fuzzing program. Chio
runs a layered strategy: an in-tree `cargo +nightly fuzz` matrix on a nightly
cron, a ClusterFuzzLite bridge for PR-time and nightly soak coverage, and
OSS-Fuzz as the long-running primary once acceptance lands. The three lanes
overlap on purpose so no single failure mode (a flaky workflow, an OSS-Fuzz
acceptance lag, a budget cap-out) leaves the trust-boundary surface unfuzzed.

## Decision: OSS-Fuzz primary, ClusterFuzzLite bridge

Locked Wave 1 decision (`.planning/trajectory/decisions.yml`
`id=continuous-fuzzing-path`, mirrored at
`.planning/trajectory/README.md` decision 2):

- OSS-Fuzz is the primary continuous-fuzzing host once accepted.
- ClusterFuzzLite on GitHub Actions hosted runners is the bridge that carries
  coverage through the OSS-Fuzz acceptance window (typically 2-6 weeks) and
  remains the documented permanent fallback.
- Budget cap: 2,000 GHA runner-minutes per month for ClusterFuzzLite, with a
  hard halt at 1,800 min/30d to leave 200 min/month headroom inside the
  public-repo free tier. Enforced by `scripts/check-fuzz-budget.sh`.

OSS-Fuzz post-acceptance is free CPU on Google's hosts and the route to
sustained continuous fuzzing without burning the GHA cap. The bridge keeps
PR-time smoke coverage running indefinitely (it does not turn off when
OSS-Fuzz lands), so a PR diff that touches a fuzz target still gets a quick
verdict before it reaches the long-running OSS-Fuzz soak.

## GHA budget

The public-repo GitHub Actions free tier is 2,000 runner-minutes per month.
The continuous-fuzzing program self-caps at 1,800 min/30d for fuzz-related
runs (200 min/month headroom for everything else). Enforcement:

- `scripts/check-fuzz-budget.sh` queries the trailing-30d billed-second
  total for `cflite_pr.yml` and `cflite_batch.yml`, sums them, and exits
  non-zero when the sum crosses the cap.
- The script runs as a step inside `cflite_batch.yml` so the cap acts as a
  hard halt rather than a soft warning. Any future fuzz-budget-consuming
  workflow must invoke the same script.
- Override during incident triage: `GH_FUZZ_BUDGET_MINUTES=900` (or any
  lower value) in the workflow env. Do not raise the cap above 1,800
  without re-opening the locked decision.

Sizing intent (steady state, 18-target inventory after M02 P1 T8 lands):

| Lane              | Cadence             | Per-run cost         | 30-day cost (est.) |
|-------------------|---------------------|----------------------|--------------------|
| `cflite_pr`       | per PR (sampled)    | ~3 targets x 60-120s | ~300 min/month     |
| `cflite_batch`    | nightly rotation    | 1 target x 30 min    | ~900 min/month     |
| `fuzz` (in-tree)  | nightly matrix      | parallel, 30 min/job | runner-time only   |
| OSS-Fuzz          | continuous, free    | n/a (Google CPU)     | 0 GHA min          |

The in-tree `fuzz.yml` matrix runs on the GitHub-hosted pool but bills
against the same free tier; nightly wall-clock is bounded by the longest
single target rather than the sum because the matrix runs jobs in parallel.
The cap-check script counts only `cflite_*` minutes today; if
`fuzz.yml` minutes start crowding the cap, extend the script's workflow
filter rather than raising the cap.

## Workflow inventory

Current as of M02 P1 close.

| Workflow                                     | Owner | Trigger                                  | Per-run wall-time          |
|----------------------------------------------|-------|------------------------------------------|----------------------------|
| `.github/workflows/cflite_pr.yml`            | M02   | PR (changed-target sampling)             | 60-120s per selected target|
| `.github/workflows/cflite_batch.yml`         | M02   | nightly cron `17 2 * * *` UTC            | 1 target x 1,800s          |
| `.github/workflows/fuzz.yml`                 | M02   | nightly cron `23 3 * * *` UTC + dispatch | matrix, 1,800s/target ASan |
| `.github/workflows/mutants.yml`              | M02   | nightly + PR diff (advisory; M02 P3)     | 4-hour budget per crate    |

Notes:

- `cflite_pr.yml` defaults to changed-target sampling per `fuzz/target-map.toml`
  (1-6 targets per PR). Opt-in `fuzz: full` PR label runs all targets at 120s
  each (release-cut PRs and trust-boundary edits).
- `cflite_batch.yml` rotates one target per night across an 18-day full sweep.
- `fuzz.yml` is the in-tree `cargo +nightly fuzz` matrix authored in
  M02.P1.T6; it complements rather than replaces ClusterFuzzLite by running
  every target every night with ASan.
- `mutants.yml` lands in M02 P2 and is advisory for one release cycle per
  decision 12; see `docs/fuzzing/mutants.md` (M02 P3 deliverable) when it
  exists.

## Target inventory

Current as of M02 P1 close. The in-tree matrix in `fuzz.yml` enumerates
every target below; ClusterFuzzLite picks per-PR or per-night rotations
from `fuzz/target-map.toml`.

PR #13 baseline (seven targets):

| Target                     | Source                                                |
|----------------------------|-------------------------------------------------------|
| `canonical_json_roundtrip` | canonical-JSON serializer round-trip                  |
| `manifest_decode`          | tool-manifest decode                                  |
| `receipt_decode`           | signed-receipt decode                                 |
| `capability_decode`        | capability-token decode                               |
| `scope_decode`             | scope-string decode                                   |
| `policy_decision_decode`   | policy-decision decode                                |
| `signing_envelope_decode`  | signing-envelope decode                               |

M09 supply-chain (one target):

| Target          | Source                                          |
|-----------------|-------------------------------------------------|
| `attest_verify` | M09.P3.T5; supply-chain attestation parser      |

M02 P1 expansion (twelve targets, T8 included):

| Target                          | Source                                                                |
|---------------------------------|-----------------------------------------------------------------------|
| `jwt_vc_verify`                 | M02.P1.T1.a; JWT VC verifier                                          |
| `oid4vp_presentation`           | M02.P1.T1.b; OID4VP holder response                                   |
| `did_resolve`                   | M02.P1.T1.c; chio-did parser plus resolver                            |
| `anchor_bundle_verify`          | M02.P1.T2; anchor proof bundle plus checkpoint records                |
| `mcp_envelope_decode`           | M02.P1.T3.a; MCP NDJSON decode plus edge dispatch                     |
| `a2a_envelope_decode`           | M02.P1.T3.b; A2A SSE parse plus per-event fan-out                     |
| `acp_envelope_decode`           | M02.P1.T3.c; ACP NDJSON plus handle_jsonrpc dispatch                  |
| `wasm_preinstantiate_validate`  | M02.P1.T4.a; ComponentBackend, WasmtimeBackend, format detect         |
| `wit_host_call_boundary`        | M02.P1.T4.b; GuardRequest/Verdict serde deserialization               |
| `chio_yaml_parse`               | M02.P1.T5.a; chio-config YAML loader                                  |
| `openapi_ingest`                | M02.P1.T5.b; OpenApiMcpBridge::from_spec                              |
| `receipt_log_replay`            | M02.P1.T8; pre-included slot in fuzz.yml; binary lands in T8          |

Total: 7 (PR #13) + 1 (M09) + 12 (M02 P1) = 20 targets when M02 P1 closes.
The M02 P1 success-criteria floor is 11 new targets (7 baseline + 11 new =
18 in the matrix exit-test count); T8 lifts the count from 11 to 12 and the
total to 20.

## OSS-Fuzz application status

- Target submission window: M02 P2.
- Status as of M02 P1 close: pending.
- Infrastructure scaffolding lands under `infra/oss-fuzz/` in M02.P2.T5
  (`project.yaml`, `Dockerfile`, `build.sh`).
- Acceptance lag: typically 2-6 weeks. ClusterFuzzLite carries coverage
  through the lag.
- Backup contact slot: tracked in the M02 P2 follow-up issue (current
  primary contact: `whelan.connor11@gmail.com`; backup TBD before the
  application opens).
- On acceptance: repoint the bug-tracker integration in
  `.clusterfuzzlite/project.yaml` (`report_to_oss_fuzz: true`); keep
  ClusterFuzzLite running as the documented fallback.
- Triage SLO commitment to OSS-Fuzz upstream: 24h acknowledgement, 7d
  fix-or-defer for `Critical`, 30d for `High`. Tracked in
  `docs/fuzzing/triage.md` once that doc lands (M02 P4).

## Local development workflow

Run a single target locally against the in-tree corpus:

```bash
cd fuzz
cargo +nightly fuzz run <target> -- -runs=10000 -max_total_time=60
```

Smoke-test only the corpus seeds (no fuzzing, fast feedback during target
authoring):

```bash
cargo test --test smoke <target>_smoke
```

Reproduce a known crash from a minimized input:

```bash
cd fuzz
cargo +nightly fuzz run <target> path/to/crash-<sha>.bin
```

Build all target binaries without running them (CI parity check):

```bash
cd fuzz
cargo +nightly fuzz build --release
```

### macOS arm64 environmental note

`cargo +nightly fuzz run -- -runs=0` may hang in libFuzzer/ASan
initialization on macOS arm64. The hang is in the empty-run init path and
not a Chio bug. Workaround for local development: run with `-runs=N` for
N>0 (any positive value bypasses the affected init path). The authoritative
gate is CI on Linux x86_64; macOS is for fast local iteration only.

## Triage

Crash artifacts from CI:

- ClusterFuzzLite (`cflite_pr`, `cflite_batch`) writes crash artifacts
  into the workflow's GitHub Actions artifact store and (when OSS-Fuzz
  reporting is enabled post-acceptance) opens issues labelled `fuzz-crash`
  on `bb-connor/arc`.
- The in-tree `fuzz.yml` matrix uploads the libFuzzer crash file plus the
  raw stderr as a workflow artifact named `fuzz-crash-<target>-<run-id>`.

Pull a crash artifact and reproduce locally:

```bash
# List recent fuzz workflow runs
gh run list --workflow fuzz.yml --limit 10

# Download all artifacts from a specific run
gh run download <run-id> --dir /tmp/fuzz-crash

# Reproduce against the failing target
cd fuzz
cargo +nightly fuzz run <target> /tmp/fuzz-crash/<artifact>/crash-<sha>.bin
```

Minimize a crash for issue attachment:

```bash
cd fuzz
cargo +nightly fuzz tmin <target> /tmp/fuzz-crash/<artifact>/crash-<sha>.bin
```

Crash-to-issue automation, dedupe-by-input-hash, severity bands, and
seed-promotion-to-regression-test land in M02 P4
(`.github/workflows/fuzz_crash_triage.yml`, `scripts/promote_fuzz_seed.sh`,
`docs/fuzzing/triage.md`).

## Cross-references

- Source-of-truth milestone doc: [`.planning/trajectory/02-fuzzing-post-pr13.md`](../../.planning/trajectory/02-fuzzing-post-pr13.md)
- Locked decision (Wave 1, decision 2): [`.planning/trajectory/README.md`](../../.planning/trajectory/README.md)
  and [`.planning/trajectory/decisions.yml`](../../.planning/trajectory/decisions.yml)
  (`id=continuous-fuzzing-path`)
- Workflows: [`.github/workflows/cflite_pr.yml`](../../.github/workflows/cflite_pr.yml),
  [`.github/workflows/cflite_batch.yml`](../../.github/workflows/cflite_batch.yml),
  [`.github/workflows/fuzz.yml`](../../.github/workflows/fuzz.yml),
  [`.github/workflows/mutants.yml`](../../.github/workflows/mutants.yml)
- Budget enforcement: [`scripts/check-fuzz-budget.sh`](../../scripts/check-fuzz-budget.sh)
- Target-to-source mapping: [`fuzz/target-map.toml`](../../fuzz/target-map.toml)
