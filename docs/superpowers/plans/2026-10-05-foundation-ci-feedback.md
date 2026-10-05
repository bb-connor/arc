# Foundation CI feedback and repair implementation plan

> **For agentic workers:** Use `superpowers:executing-plans` inline. Do not spawn subagents. Use the authorized GitHub Codex integration for independent review.

**Goal:** Repair the failing #1160 checks with reproducible component feedback before requesting complete hosted qualification.

**Architecture:** Diagnose the exact failed commands and every downstream skipped gate. Run cheap structural and evidence-input checks before compilation, reuse ordinary diagnostic build artifacts, and keep the isolated qualification boundary cold. Freeze one reviewed source only after the diagnostic matrix passes.

**Tech Stack:** Rust 1.95, Cargo, Python 3, Bash, GitHub Actions, isolated Linux x86_64 qualification.

**Spec:** `docs/security/foundation-acceptance-scope.md`, `docs/security/committed-linux-evidence.md`, and `docs/security/landing-ledger.md` remain authoritative.

## Global constraints

- Preserve every mandatory test, mutation, isolation boundary, time bound and source authorization check.
- No exemptions, skipped live acceptance, mutable qualification caches or synthetic outcomes.
- Keep diagnostic success separate from native, hosted, signed and merged acceptance.
- Preserve failed attempts and branches. Limit the landing queue to two PRs.
- Changes to trusted workflow definitions require their own reviewed prerequisite on main before the foundation consumes the new definition.
- Complete source and documentation changes before regenerating source-bound evidence.

## Review focus

- Tests included through Rust modules must appear in exact inventories.
- Missing native launch configuration must fail before builds and filesystem mutation.
- Every workflow that runs live conformance must qualify its host and supply reviewed authority.
- Failure diagnostics must remain bounded, untrusted data and cannot become imported evidence.
- Queued workflows retain old authorization values; a fresh event must follow authorization of the reviewed source.

### Task 1: Reproduce and repair exact inventory drift

**Files:** `scripts/check-deception-security.sh`, `scripts/tests/check-deception-security.test.sh`.

**Interfaces:** Consume exact Rust test listings; produce a complete mandatory inventory and a structural regression for the included materializer tests.

- [x] Strengthen the structural test to include the existing nested materializer regression. Run it and observe the omitted test failure.
- [x] Add the missing test to the gate and correct the reported total. Preserve all existing required names.
- [ ] Run the structural suite and actual deception targets. Inspect remaining active-defense target inventories and execute downstream gates before a hosted retry.

### Task 2: Supply native conformance prerequisites and early rejection

**Files:** `crates/tooling/chio-conformance/src/runner.rs`, its native launch module/tests, `scripts/check-native-protocol-ci.py`, its tests, and `.github/workflows/enterprise-hardening.yml`.

**Interfaces:** Consume the existing `enforced-native-fixture` action; produce a validated launch configuration before executable discovery and a trusted workflow that builds the enforcing CLI before all conformance targets.

- [x] Add a regression proving absent launch authority returns its specific error before a Cargo invocation or destructive result-directory preparation.
- [x] Validate and retain launch arguments at harness entry, then use that same validated configuration for provisioning.
- [x] Extend workflow contract coverage to the enterprise conformance consumer, observe failure, and add the existing host/authority fixture and enforcing CLI build in a separate prerequisite candidate.
- [ ] Execute the failing live target first on the native diagnostic host, followed by every conformance target and the remaining portable steps.

### Task 3: Make evidence failures diagnosable and qualify inputs first

**Files:** `scripts/run-security-execution-container.py`, its tests, owning CI commitments, and an ordinary diagnostic preflight entrypoint if needed.

**Interfaces:** Consume a terminated, identity-checked container; produce bounded escaped diagnostic text only. Successful evidence import remains the existing closed output schema.

- [x] Retain exact job logs, source/auth identities and the current native attempt. Reproduce freshness refusal without a full compilation campaign.
- [x] Add failure-diagnostic controls covering oversized output, control characters, collection failure and mandatory cleanup before changing the runner.
- [ ] Run cheap input/contract checks and all affected script tests before building the native image.
- [ ] Measure the full mutation campaign against its fixed bound. If scheduling cannot satisfy it, design and test complete, isolated campaign sharding before another full attempt; do not raise the bound or omit campaigns.

### Task 4: Freeze, review and run complete qualification

**Interfaces:** Consume passing component evidence, reviewed source S and trusted definition D; produce exact terminal hosted checks and the required signed evidence chain.

- [ ] Record repairs and evidence in the landing ledger; commit the complete source batch.
- [ ] Obtain independent GitHub Codex review. Land any trusted-definition prerequisite and consume its exact commit.
- [ ] Authorize the reviewed source before a fresh workflow event. Do not rerun an expired controller event.
- [ ] Regenerate complete genuine evidence, validate its exact import inventory, and publish only allowed derived outputs.
- [ ] Verify every required check on the final exact candidate and perform the protected foundation landing only when all acceptance gates pass.

## Initial diagnosis

CI run `37304205335`, source `89e4641f6df4a5846eff4640ec939e042928f6f9`:

- Deception executes 16 successful materializer tests, then rejects the omitted nested path-bound regression.
- Portable conformance reaches `auth_live` and rejects absent `CHIO_CAGE_INIT`, after an unnecessary CLI build.
- Both isolated evidence jobs captured authorized tooling `254fbd162fb5b3b75e5f53e57dca94d4665b5eb8`; container failure detail was discarded by cleanup.
- Controller `37304198175` also captured that older authorization and started outside its freshness window.
- The separate current-source native refresh is still running. Its completed campaigns are partial evidence only.

## Measured scheduling repair

The canceled source-89 diagnostic refresh completed four of 35 campaigns in
7,898 seconds. Every candidate command deliberately starts from an empty build
target. A serial refresh cannot reliably fit the existing 21,000-second bound.

Use seven fixed refresh shards of five campaigns, keeping every campaign for a
case together. Each shard runs the existing trusted checker inside the unchanged
4-CPU, 12-GiB, 512-PID execution boundary. No candidate build cache crosses a
command or shard. Each shard publishes an unsigned partial patch and a canonical
inventory bound to its source, exact campaigns, paths, checksum, image and trusted
file hashes. Partial success cannot satisfy complete-evidence acceptance.

A separate aggregation step requires all seven identities exactly once. It rejects
mixed source identities, missing or unexpected paths, nonregular files, changed
case definitions and inconsistent trusted tooling. It applies only each shard's
closed evidence paths in a disposable source checkout, combines manifest entries
from the resulting case bytes, and runs the existing complete evidence validator.
Only then may it publish the complete 35-outcome, 28-case, 64-path unsigned patch.
The final signing and native enforcement gates remain unchanged. Trusted workflow
matrix and aggregation definitions must land through the same prerequisite as the
native conformance fixture repair.

Additional downstream regressions reproduced during diagnosis:

- Response recovery retained a pre-module scheduler lease selector.
- Four consumer threshold fixtures signed unbound tool intents.
- Multi-hop federation evidence fixtures omitted the explicit exporter signing key
  and importer trust anchor required by the current evidence CLI.

## Local feedback checkpoint

- The exact deception inventory passes 85 tests; response recovery passes after
  restoring its module-qualified lease selector. Native conformance passes all
  targets after binding threshold intents and registering the sealed FROST kind.
- Federation evidence export/import now uses explicit trusted signing material.
  All 12 tests pass. Reputation, federation policy and passport fixture suites
  pass 40 tests after using private authority directories.
- The adapter scanner now honors exact file-level `cfg(test)` and continues to
  inspect `cfg(any(test, unix))`. Constructor and route-owner inventories match
  current clock-aware sources. The adapter and HTTP egress gates pass.
- Real Docker hostile probes pass as the non-root operator. Complete validation
  of deliberately stale source fails inside the container with bounded useful
  diagnostics and no accepted output. This is a negative control, not refreshed
  evidence acceptance.
- The diagnostic host denies Bubblewrap user namespaces through AppArmor. Three
  verified-fix tests fail at that environment boundary; no production sandbox
  rule has been changed. The CLI sweep retains its partial failures and continues
  through every target to expose later fixture drift before another hosted run.
- Trusted workflow prerequisite `938905ab9f` changes only the two workflow files.
  All 20 definition tests pass. Independent review, protected landing, definition
  activation, complete source-bound refresh and final hosted qualification remain
  open. No source has been newly authorized.

The complete CI contract mutation suite passes on frozen runner, entrypoint,
aggregator and workflow bytes. Cached portable tests and the native cage lane
cover all 35 baseline controls. The native lane passes all 82 required tests and
10 enforcement mutation controls. The diagnostic baseline wrapper's mistaken
filtered-target setting is corrected and retained separately from the passing
single-test run. These baselines do not replace genuine refreshed mutations.

The shared receipt-query directory helper now creates private directories
atomically; 79 tests pass across the affected report targets. Strict Clippy for
all CLI, conformance and xtask targets passes after correcting one existing
conformance test sort warning. PR #1175 is the workflow prerequisite. Its first
Codex integration attempt returned an error; a new independent review is running.
