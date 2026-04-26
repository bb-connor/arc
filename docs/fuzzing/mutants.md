# Mutation testing with cargo-mutants

The M02 P2 mutation-testing lane runs [`cargo-mutants`](https://mutants.rs)
as an advisory companion to the libFuzzer corpus shipped in M02 P1.
libFuzzer searches for inputs that crash or panic; cargo-mutants searches
for *surviving mutants* -- code edits the test suite fails to notice. A
high libFuzzer corpus catch-rate plus a high cargo-mutants catch-ratio
together give a much stronger guarantee that the trust-boundary code is
actually exercised by tests.

This lane is owned by `agent-role: fuzz-rust` and lives alongside the
fuzz infrastructure in `docs/fuzzing/`.

## Pinned version

`cargo-mutants` is pinned to the **25.x** series (decision 12 in
`.planning/trajectory/02-fuzzing-post-pr13.md`). Do **not** float to
26.x without re-running the source-doc decision and updating the pin in
both this document and the CI workflow. The CI install line is:

```bash
cargo install cargo-mutants --version '~25' --locked
```

## Configuration layout

Two layers, both checked in:

| Path                                         | Role                                                  |
|----------------------------------------------|-------------------------------------------------------|
| `.cargo/mutants.toml`                        | Workspace defaults (timeout, minimum timeout, packages, workspace-wide skip list) |
| `crates/chio-kernel-core/mutants.toml`       | Per-crate `examine_globs` / `exclude_globs` for the kernel-core trust boundary |
| `crates/chio-policy/mutants.toml`            | Per-crate config for the HushSpec evaluator + compiler |
| `crates/chio-guards/mutants.toml`            | Per-crate config for the native guard set + pipeline   |
| `crates/chio-credentials/mutants.toml`       | Per-crate config for JWT VC, SD-JWT, OID4VP verifiers  |

Workspace-level knobs of note (in `.cargo/mutants.toml`):

- `additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]` --
  the C++ FFI crate ships through a separate vcpkg/conan lane and is not
  exercised by the default workspace test invocation.
- `timeout_multiplier = 3.0` -- cargo-mutants reruns the full test
  suite per mutant; the 3x guard prevents slow-test flakes from getting
  scored as TIMEOUT (which masquerades as a surviving mutant).
- `minimum_test_timeout = 60` -- floor in seconds, so the multiplier
  cannot collapse below the cold-cache build time on a CI host.

### Why per-crate `examine_globs`

cargo-mutants generates one or more mutants for every applicable
expression. Without scoping, that explodes into thousands of
candidates per crate; most of them in pure-data, logging, or generated
code where mutation has no semantic value. Each per-crate
`mutants.toml` narrows the examined source set to the trust-boundary
modules listed below.

#### `chio-kernel-core`

Examined: the pure-compute verdict path (`evaluate.rs`,
`capability_verify.rs`, `scope.rs`, `receipts.rs`, `passport_verify.rs`,
`guard.rs`, `normalized.rs`).

Excluded: `lib.rs` (re-exports), `clock.rs` / `rng.rs` (platform
adapters), `formal_*.rs` and `kani_*.rs` (formal-methods scaffolding),
`fuzz.rs` (libFuzzer entry points already covered by the M02 P1 lane).

#### `chio-policy`

Examined: the HushSpec evaluator state machine (`evaluate.rs` +
`evaluate/{engine,matchers,outcomes,context}.rs`), the compiler bridge
(`compiler.rs`), conditional activation (`conditions.rs`), regex-based
detectors (`detection.rs`, `regex_safety.rs`), `extends`-chain
plumbing (`merge.rs`, `resolve.rs`), schema validation (`validate.rs`),
and decision-receipt construction (`receipt.rs`).

Excluded: `models.rs` (pure data), `version.rs` (constant), embedded
YAML rulesets (`rulesets/**`).

#### `chio-guards`

Examined: the fail-closed `pipeline.rs` and the boundary-enforcing
guards -- `shell_command.rs` (PR #13 hardening lane), forbidden / allowlist
path checks, egress + internal-network filters, secret-leak,
patch-integrity, MCP tool gating, prompt-injection, jailbreak (both the
heuristic and ML detectors), input-injection, response-sanitization,
data-flow, behavioral-sequence, behavioral-profile, both velocity
guards, and the CUA / code-execution / browser-automation /
remote-desktop / content-review / memory-governance / post-invocation
guards.

Excluded: `action.rs` (pure types), `text_utils.rs` (pure helpers),
the advisory pipeline + `spider_sense.rs` (advisory by design), and
the `external/` adapter tree (remote-process bridges that need
integration testing, not mutation).

#### `chio-credentials`

Examined: portable JWT VC verify, SD-JWT VC verify, portable reputation
credential verify, the OID4VCI issuance flow, the OID4VP presentation
flow + verifier, presentation construction / verify, presentation
challenge binding, cross-issuer trust packs, the issuer / trust-anchor
registry, OID4VCI / OID4VP discovery, artifact normalization, passport
verifier glue, credential-side policy intersection, and trust-tier
synthesis.

Excluded: `lib.rs` (re-exports + constants) and `fuzz.rs` (libFuzzer
entry points covered by the M02 P1 lane).

## Local-developer workflow

```bash
# One-time install (or upgrade) - pinned to 25.x.
cargo install cargo-mutants --version '~25' --locked

# Run only the mutants generated against changed files in your branch.
# This is the same invocation the mutants-pr CI job uses.
cargo mutants --in-diff origin/main

# Full sweep on a single crate (slow; budget hours per crate).
cargo mutants --package chio-kernel-core
```

Tip: a clean `cargo test --workspace --exclude chio-cpp-kernel-ffi`
must pass and be deterministic before running cargo-mutants. Flaky
tests poison the report and surface as false TIMEOUT verdicts.

## CI lane

Workflow: `.github/workflows/mutants.yml` (lands in **M02.P2.T2**).
Two jobs:

- `mutants-pr` -- triggered on PR. Runs
  `cargo mutants --in-diff "$GIT_DIFF" --no-shuffle --jobs 4` against
  the PR diff and posts a comment via `scripts/mutants-comment.sh`.
  Always advisory; never blocks merge.
- `mutants-nightly` -- scheduled `cron: '0 5 * * *'` on a 4-hour
  budget per crate. Runs the full sweep, uploads `mutants.out/` as a
  workflow artifact, and gates against the per-crate 80% catch-ratio
  threshold via `scripts/mutants-gate.sh`.

The lane is **advisory** for one release cycle, then flips to
**blocking** automatically. The flip is driven by the `cycle_end_tag`
field in `releases.toml` at the repo root (also written by M02.P2.T2):
empty -> advisory, non-empty -> blocking. The next release-binaries run
after Phase 3 merges populates `cycle_end_tag` via
`chore(mutants): activate blocking gate after cycle <tag>`.

## Triage policy

Surviving mutants beyond a per-crate budget open an issue tagged
`mutants-survivor`. Per-crate budgets and the rolling catch-ratio target
(>= 80%) are recorded in `releases.toml` (M02.P2.T2). When the nightly
sweep crosses the budget the gate posts a single rollup issue rather
than one per mutant; subsequent nightly runs update the same issue
in-place to avoid noise.

A surviving mutant can be addressed in one of three ways:

1. **Add or strengthen a test** that catches the mutant. This is the
   default and preferred path -- the mutant has identified a real test
   gap.
2. **Refactor the code** so the mutant becomes equivalent (no behaviour
   change) and gets pruned by cargo-mutants. Acceptable when the test
   gap is genuinely uninteresting.
3. **Skip via `exclude_globs`** in the relevant per-crate `mutants.toml`,
   with a comment justifying the skip and a cross-reference to the
   triage issue. This requires CODEOWNERS sign-off on the crate's
   `mutants.toml`.

## Cross-references

- `.planning/trajectory/02-fuzzing-post-pr13.md`, sections "Mutation-testing
  approach (phase 3 deliverable)" and "Mutation-testing CI shape (Phase 3)".
- `.planning/trajectory/tickets/M02/P2.yml` -- atomic ticket spec for this
  lane (T1 = config, T2 = workflow + `releases.toml`).
- `.cargo/mutants.toml` -- workspace defaults.
- `crates/<crate>/mutants.toml` -- per-crate scope.
- `releases.toml` -- per-crate budgets and the advisory / blocking flip
  signal (lands with M02.P2.T2).
- `docs/fuzzing/continuous.md` -- complementary libFuzzer corpus lane.
- Upstream cargo-mutants documentation: <https://mutants.rs>.
