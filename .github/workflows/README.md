# GitHub Actions workflows

## The PR build/lint/test gate lives in `ci.yml`

The required gate that catches workspace-wide compile breakage is the
`check` job ("Build, lint, test") in [`ci.yml`](./ci.yml). It runs on
`pull_request` and `push` to `main`, on the toolchain pinned by the
repo-root `rust-toolchain.toml` (1.93.0), with `Swatinem/rust-cache` for the
cargo registry/target cache. The four gate steps are:

| Gate | Step in `ci.yml` | Command |
| ---- | ---------------- | ------- |
| Format | "Workspace format" | `cargo fmt --all -- --check` |
| Lint | "Workspace clippy" | `cargo clippy --workspace --all-targets -- -D warnings` |
| **Workspace build** | "Workspace build" | `cargo build --workspace` |
| Tests | "Workspace tests" + "Wasm guards library tests" | `cargo test --workspace --exclude chio-wasm-guards`, then `cargo test -p chio-wasm-guards --lib` |

The intended set of required check contexts is five contexts on the exact test
merge `M`, not one. The first four use distinct names and are trusted
default-branch mirrors of source jobs from the CI run bound to `E`; the
original workflow run, jobs, and Check Runs are authenticated on `E`. A
separate signed binding proves the exact test merge `M`:

- "Security mirror / Build, lint, test" (mirror of the `check` job)
- "Security mirror / MSRV build and test" (mirror of the `msrv` job; see below for its coverage caveats)
- "Security mirror / cargo-vet (locked supply-chain audit)" (mirror of the `cargo-vet` job)
- "Security mirror / cargo-deny (supply-chain bans/advisories/licenses)" (mirror of the `cargo-deny` job)
- "Security contract" from the dedicated `chio-security-authority` GitHub App.
  The App publisher refuses to create it unless the Actions aggregate
  `security-contract-required` job, which uses the same display name, and all
  of its security dependencies have succeeded.

Configure all five as required; workflow YAML does not create or enforce the
repository ruleset. Pin the first four contexts to the GitHub Actions App
integration ID `15368`, and pin only `Security contract` to the dedicated App
ID in the repository variable `CHIO_SECURITY_APP_ID`. The App ID is public
configuration used by both the unprotected secret-free revocation listener and
the protected publisher. Keep `CHIO_SECURITY_APP_INSTALLATION_ID` as an
environment variable and `CHIO_SECURITY_APP_PRIVATE_KEY_PEM` as an environment
secret only in `security-check-publisher`. Keep
`CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX` only in
`enterprise-evidence-signing`. A candidate-defined Actions job and the
intermediate Actions aggregate are both App `15368`; neither is an
authenticated merge mirror and neither satisfies the dedicated-App rule.
Cargo-vet, cargo-deny, and the security contract must not
be optional once that ruleset exists. The "Tokio console smoke" check is *not* a separate required context: it is a step inside
the "Build, lint, test" job (see the test-lane section below), so it surfaces
under that job's context rather than as its own check.

The reusable `enterprise-hardening.yml` accepts an exact source repository and
40-character source commit. Its first job checks out the exact event merge,
proves its ordered base and head parents, and emits canonical
`ci-merge-binding.json`. The same file is both the attestation subject and the
custom predicate. A run-and-attempt-scoped artifact carries that file and the
GitHub attestation bundle. The four
candidate-executing jobs check out the event test commit from the trusted GitHub
context (the synthetic merge on a pull request and the pushed commit on push),
so a candidate-controlled caller cannot redirect the pinned workflow to trusted
old code. The separate committed-evidence job checks out the configured
evidence commit and authorized checker source instead. Every checkout disables
credential persistence, no job receives a repository secret, and every job
runs on an ephemeral GitHub-hosted Ubuntu 24.04 runner. The caller must be
changed from the local reusable-workflow path to a same-repository path pinned
at the full commit that first lands the workflow on `main`. Until that bootstrap
commit exists and the caller is pinned to it, the introducing pull request has
not established an immutable required-workflow definition.

Mechanics evidence has four separate trust domains:

The four privileged default-branch workflows are additionally pinned by the
repository variable `CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA`. Set it to the
reviewed bootstrap commit `B` only after controller, capture, finalizer, and
revocation have landed together on `main`; pin the reusable workflow call in
`ci.yml` to the same full `B` SHA before use. A privileged run may execute at a
later default-branch commit only when its workflow file has the exact same Git
blob as the file at `B`. Unrelated `main` advances therefore do not disable the
authority, while any workflow-byte change fails closed. Rotate the variable and
reusable pin together only after the replacement definition set is reviewed.

1. `enterprise-evidence-controller.yml` is loaded from the default branch by
   `pull_request_target`. It revalidates the live owner, actor, workflow ID and
   path, run and attempt, default-branch definition, pull-request head and base,
   explicit `refs/pull/<N>/merge` commit and tree, and live labels. It dispatches only when
   `CHIO_AUTHORIZED_SECURITY_SOURCE_SHA` equals the head or the head is a
   linear descendant whose commits change only the three committed Linux
   evidence files. It performs no checkout and executes no candidate artifact.
   It generates a 256-bit capture nonce, binds the exact capture run and all
   dispatch inputs into a controller-owned artifact, and accepts only attempt
   one of the uniquely titled capture run.
2. `enterprise-linux-capture.yml` independently repeats authorization before
   candidate checkout, including the exact controller intent artifact and
   attempt-one capture identity. Enforcement checks out the explicit merge-ref commit;
   refresh checks out the exact head. Both disable persisted credentials, run
   on ephemeral hosted Linux, and receive no repository secret. Source-SHA
   concurrency cancels stale enforcement and refresh runs across both modes.
3. After enforcement upload, a no-checkout capture job with `actions: write`
   explicitly dispatches `enterprise-evidence-finalizer.yml` on the exact
   default-branch definition. It generates a 256-bit nonce, binds that nonce
   into the dispatch input and finalizer run title, and paginates until exactly
   one matching attempt-one run is visible. It uploads a capture-owned dispatch
   intent binding that run, nonce, source, merge, definition, and capture
   identity. The finalizer verifies the nonce-bound title and exact intent
   and uses a bounded multi-minute poll for the exact capture run to complete
   before binding the controller, capture, finalizer, runner job,
   GitHub-hosted runner group, exact singleton runner label inventory, run
   attempts, workflow definitions, artifact ID, digest, size, timestamps,
   merge tree, label state, and source allowlist. It then downloads the exact
   archive and performs bounded path-safe extraction with an exact file
   inventory. The protected `enterprise-evidence-signing` environment exposes
   the seed to one step only. That step uses a separately published verifier
   whose URL and SHA-256 are repository variables, creates the strict
   three-file migration-canary surface, invokes
   `verify-committed-linux-evidence`, and uploads no private material.
4. A secret-free publication-authorizer job requires the configured committed
   evidence SHA to equal the live pull-request head, runs checker bytes from
   the authorized source against that exact evidence commit, and authenticates
   the exact current `ci.yml` pull-request run on head `E`. The run title is
   exactly `CI N=<N> E=<E> B=<base> M=<M>`. It requires successful GitHub
   Actions checks for Build, MSRV, cargo-vet, cargo-deny, and the Actions
   security aggregate, including exact workflow, run, attempt, head, check
   suite, and App `15368` bindings on `E`, then verifies the canonical merge
   binding artifact and its GitHub certificate. The certificate must identify
   the pinned reusable signer, source `M`, merge ref, exact CI run and attempt,
   caller, repository, and GitHub-hosted runner. It seals those results together with every
   validated controller, capture, runner, artifact, and evidence binding. The
   protected main-branch publisher requires both that authorization and the
   protected migration-canary signing job to succeed before it can revalidate
   the exact live test merge `M`. It mirrors the four authenticated ordinary checks onto `M` as
   GitHub Actions App `15368` check runs and posts `Security contract` on `M`
   with the dedicated App. All five share the stable
   `(<PR>, <E>, <M>, <S>)` identity. Capture labels are not publication or
   revocation authority.
5. `security-contract-revocation.yml` is both the frozen manual revoker and a
   default-branch failure-only `workflow_run` projector. Any completed CI
   conclusion other than success, including an absent conclusion, is a failure
   signal. Each listener binds the immutable `workflow_run.run_attempt` from
   the event, fetches that exact historical attempt endpoint, and rejects a
   response whose run or attempt identity differs. It does not reclassify the
   event through the mutable current-run endpoint. The projector authenticates
   the exact run title and `E`, proves `M`
   directly from its ordered parents, verifies the signed binding when the
   builder succeeded, and binds
   `S` from the repository source variable and requires the committed-evidence
   variable to equal `E` before creating new tombstones. If the live PR has
   advanced from `(B1, M1)` to `(B2, M2)`, the listener may normalize existing
   authority on `M1` but cannot create a missing namespace and never touches
   `M2`. Only a failed finalizer publisher that follows successful validation,
   signing, and publication authorization is failure-authoritative. It is
   independently bound by its authenticated
   `N/E/M/S/nonce` title, trusted default-branch workflow blob, bot actors,
   ordered merge parents, exact four-job attempt state, authenticated dispatch
   intent, and the dedicated App success-check `details_url` for that run and
   attempt. Earlier failures are ineligible because they cannot have published
   dedicated authority. Definition or source-variable rotation does not erase
   an authenticated historical failure. This path can normalize only
   preexisting exact authority created by the failed publisher and can never
   create a namespace. Publication
   and revocation share the non-cancelling maximum-queue
   `security-check-authority-<M>` lock. Both jobs set `queue: max`, so a later
   authority mutation cannot replace an earlier pending member. The revoker
   creates missing failure tombstones or normalizes existing members while
   preserving their external IDs and source metadata. If duplicates exist, it
   retains the oldest member carrying the required external ID under the
   protected name and renames every other member to a unique failure-only
   superseded name, then proves an exact singleton failed namespace.
   The protected publisher is also an authority reconciler. Its success branch is
   POST-only, but before and after every success POST it paginates matching
   PR/E/M CI run identities, reads every exact historical attempt from one
   through the current maximum, and fails closed before GitHub's 1,000-result
   filtered-search ceiling. A completed non-success attempt dominates any
   newer incomplete attempt and immediately selects the failure-only branch;
   an incomplete history blocks publication when no bad completion exists. It
   compares the maximum attempt fingerprint across the current projection and
   exact attempt, then re-lists the run set and revalidates every maximum after
   the full scan. A bounded three-pass retry fails closed if the run set or any
   maximum advances. Any authenticated completed non-success attempt, including
   a failure followed by a successful rerun, selects a separate failure-only
   branch that creates or normalizes all five tombstones. If the PR tuple has
   drifted, that branch normalizes existing
   authority on the historical `M` but does not create a missing namespace.
   Manual authority withdrawal first freezes publication with the all-zero
   evidence SHA, then performs the same five-namespace operation. Any bad CI
   completion for the current tuple may permanently tombstone it even if a
   later rerun succeeds; recovery requires a new tuple.

The reusable lane verifies the committed canary in a fresh job that does not
execute candidate code. It checks out the detached commit named by
`CHIO_COMMITTED_LINUX_EVIDENCE_SHA` and runs checker bytes from the exact
`CHIO_AUTHORIZED_SECURITY_SOURCE_SHA` checkout against the separately pinned
verifier. The event test commit remains separate and is exercised by the other
enterprise jobs; it is not misused as the evidence-only commit. The only
bootstrap exception is an empty committed-evidence variable while the
independently bound source head exactly equals the authorized source.

Remove `refresh-linux-evidence` before committing the refreshed patch. Label
removal triggers ordinary CI and a new enforcement capture. The controller,
capture, and finalizer definitions must already exist on the default branch;
the pull request that first introduces them cannot use them as a trusted
default-branch control plane. Before use, configure the source allowlist,
committed evidence SHA, evidence policy JSON, public key, pinned verifier URL
and digest, and the protected signing environment. Except for the narrow
pre-evidence bootstrap above, a missing value fails the corresponding gate.

The publisher boundary is effective only after the private GitHub App,
repository-scoped public App ID, protected publisher environment, restricted
installation ID and private-key secret, and exact integration-bound ruleset in
`docs/security/committed-linux-evidence.md` are configured. The App must be
installed only on `bb-connor/arc`; the publisher rejects App ID `15368`, a
different installation or repository inventory, wrong permissions, a non-main
workflow ref, stale source/evidence variables, and any response not attributed
to `chio-security-authority`. Until that external state exists, the YAML alone
does not provide a required non-spoofable publisher.

### Why the build step MUST stay `--workspace`, not per-crate (`-p`)

A downstream-exhaustiveness break is a class of break a per-crate scoped gate misses: a new enum
variant compiles fine in its own crate but breaks an exhaustive `match` in a
*downstream* crate. A `-p <crate>` build only compiles that crate's tree, so
cross-crate breakage slips through; `cargo build --workspace` compiles every
member's `src/`, so the downstream non-exhaustive `match` fails the build.

Note this step does not pass `--all-features`, so it only compiles
default-feature source. Modules behind non-default features are not compiled
(for example provider-adapter-gated modules in
`crates/protocol/chio-openai-adapter/src/lib.rs`), so a downstream-exhaustiveness break that
lives behind an optional feature can still slip through this lane. Full
coverage of feature-gated source would require a separate all-feature build
lane.

Do not narrow the "Workspace build" step to `-p`/path-scoped invocations, and
do not delete it in favor of relying on clippy alone (clippy here is scoped to
`--all-targets` but still does not replace the ordinary workspace build).
Keeping the unscoped `cargo build --workspace` step is the invariant that
closes the downstream-exhaustiveness gap.

### The test lane: staged workspace coverage, then an exact full-workspace gate

The Rust tests are staged so the ordinary workspace can run before the Python
WASM fixture is built, then the complete workspace is run without exclusions:

- "Workspace tests" runs `cargo test --workspace --exclude chio-wasm-guards`.
  Across every other workspace member this compiles and runs `#[cfg(test)]`
  unit tests *and* the `tests/` integration targets, extending the
  build-breakage guarantee above to test code. Note this lane does not pass
  `--all-features`/`--features`, so it only exercises default-feature code:
  Cargo skips any `[[test]]` target whose `required-features` are not selected.
  For example `crates/kernel/chio-kernel` gates the `hybrid_receipt_sign`,
  `compliance_certificate_hybrid`, and `canonical_bytes_hybrid` integration
  targets behind the `pq` feature, and no PR lane selects `pq`, so those targets
  are not compiled or run by any gate. (The one feature-gated integration target
  that *is* covered is `tokio_console_smoke`: the separate "Tokio console smoke"
  step in `ci.yml` runs `cargo test -p chio-kernel --features tokio-console-smoke
  --test tokio_console_smoke`.) `chio-wasm-guards` is excluded from this early
  step because its integration suite needs the WASM fixture prepared later.
- "Wasm guards library tests" then runs `cargo test -p chio-wasm-guards --lib`.
  `--lib` is "test only this package's library", so this lane compiles and runs
  only `chio-wasm-guards`'s in-crate unit tests.
- CI builds the pinned Python guard WASM fixture and runs the explicit
  `py_guard_integration` round trip.
- "Exact workspace test gate" finally runs `cargo test --workspace` with no
  package exclusion. This compiles and runs the workspace integration targets,
  including `chio-wasm-guards`; tests that explicitly detect an absent optional
  external SDK artifact may still self-skip according to their own contract.

Do not remove the early carveout or the later exact gate. The former preserves
the fixture setup order; the latter is the required no-exclusion regression
guard.

### The MSRV job does not fully test the workspace

The "MSRV build and test" job (`msrv` in `ci.yml`) runs `cargo build
--workspace` on the pinned MSRV toolchain, but its test command does **not**
cover the whole workspace. It runs:

```
cargo test --workspace --exclude chio-conformance --exclude chio-wasm-guards --exclude chio-formal-diff-tests
cargo test -p chio-formal-diff-tests --no-run
cargo test -p chio-wasm-guards --lib
```

So MSRV test coverage is uneven:

- `chio-conformance` is **not tested on MSRV** at all (excluded from the
  workspace test run and never re-added).
- `chio-formal-diff-tests` gets only `--no-run`: its tests are compiled on MSRV
  but not executed.
- `chio-wasm-guards` gets only `--lib`: its in-crate unit tests run on MSRV, but
  its `tests/` integration targets do not.

Do not describe the MSRV job as testing the full workspace; it builds the full
workspace and tests it with the carveouts above.

> Note (firmware/console): the Chio workspace is Rust-only; the firmware and
> console build pipelines referenced by the PR build/lint/test gate live in their own repos and
> are out of scope for this workflow.

## The `chio-pheromone-*` gate family is kept as separate files

The 15 `chio-pheromone-*.yml` workflows look like near-duplicates but must not be
consolidated into a single matrix workflow. Two constraints rule out the obvious
collapses.

### The 15 files

Relay subsystem gates (each runs one `scripts/check-<name>.sh`):

- `chio-pheromone-relay.yml`
- `chio-pheromone-relay-ops.yml`
- `chio-pheromone-relay-observability.yml`
- `chio-pheromone-relay-alert-routing.yml`
- `chio-pheromone-relay-alert-delivery.yml`
- `chio-pheromone-relay-alert-handoff.yml`
- `chio-pheromone-relay-alert-assurance.yml`
- `chio-pheromone-relay-alert-assurance-archive.yml`
- `chio-pheromone-relay-alert-assurance-archive-package.yml`
- `chio-pheromone-relay-alert-assurance-archive-hardening.yml`
- `chio-pheromone-relay-alert-assurance-export.yml`
- `chio-pheromone-relay-alert-assurance-external-retention.yml`
- `chio-pheromone-directory-lifecycle.yml`
- `chio-pheromone-runtime.yml`
- `chio-pheromone-transit.yml`

### A single matrix workflow cannot path-scope per gate

Each file carries its own `on.paths` trigger (a different set of crate, spec,
script, and doc globs). A single matrix workflow has one `on:` block and cannot
express per-matrix-entry path filters, so collapsing them forces every gate to
run on every pheromone-related change, defeating the path-scoping these files
provide.

### The reusable-workflow (`workflow_call`) pattern does not fit either

Extracting the shared job body into one `workflow_call` reusable workflow with
thin path-triggered callers fails because the job bodies are not uniform. They
fall into four distinct shapes:

| Shape | Files | `permissions:` block | `Swatinem/rust-cache` | `setup-node` | node version |
| ----- | ----- | -------------------- | --------------------- | ------------ | ------------ |
| A | relay, relay-ops, directory-lifecycle, runtime, transit | none | no | no | - |
| B | relay-observability | none | no | yes | 22 |
| C | alert-routing, alert-delivery, alert-handoff, alert-assurance | `contents: read` | yes | yes | 24 |
| D | the five `...-assurance-archive` / `-export` / `-external-retention` | `contents: read` | yes | no | - |

`workflow_call` inputs could express these differences (booleans gating the
cache / node steps via `if:`, a string for the node version, strings for the
gate name and script path), but four constraints block the conversion, each on
its own sufficient:

1. The four shapes require conditional (`if: inputs.*`) steps. The resulting
   single file is harder to reason about than the 15 flat files it replaces.
2. Permissions posture differs. Shapes A and B set no `permissions:` block (they
   inherit the repository / org default token scope); shapes C and D pin
   `contents: read`. Under `workflow_call`, the effective token scope is governed
   by the called workflow plus the caller job's `permissions:`. Folding files
   with different permission postures into one reusable workflow risks silently
   changing the token scope for some gates, over-granting a fail-closed CI
   surface.
3. The node-version split (22 in shape B vs 24 in shape C) is not reconcilable
   from the YAML alone; collapsing to one version would change at least one
   gate's node runtime.
4. Required status-check matching. Branch-protection / ruleset config lives in
   GitHub settings outside this repo. Converting these to callers changes how
   each check surfaces (it appears as `caller / reusable-job` instead of the
   current top-level job name), which can silently break a required-check rule.

Any consolidation must be validated on a branch where GitHub Actions runs, with
Actions executing, against four invariants: the per-file `on.paths` triggers
still gate correctly on both `pull_request` and `push`; the effective token
permissions per gate are unchanged; the node version choice is deliberate; and
the surfaced check names still satisfy the required-status-check rules
configured in GitHub settings.
