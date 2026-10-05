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
- [x] Run the structural suite and actual deception targets. Inspect remaining active-defense target inventories and execute downstream gates before a hosted retry.

### Task 2: Supply native conformance prerequisites and early rejection

**Files:** `crates/tooling/chio-conformance/src/runner.rs`, its native launch module/tests, `scripts/check-native-protocol-ci.py`, its tests, and `.github/workflows/enterprise-hardening.yml`.

**Interfaces:** Consume the existing `enforced-native-fixture` action; produce a validated launch configuration before executable discovery and a trusted workflow that builds the enforcing CLI before all conformance targets.

- [x] Add a regression proving absent launch authority returns its specific error before a Cargo invocation or destructive result-directory preparation.
- [x] Validate and retain launch arguments at harness entry, then use that same validated configuration for provisioning.
- [x] Extend workflow contract coverage to the enterprise conformance consumer, observe failure, and add the existing host/authority fixture and enforcing CLI build in a separate prerequisite candidate.
- [x] Execute the failing live target first on the native diagnostic host, followed by every conformance target and the remaining portable steps.

### Task 3: Make evidence failures diagnosable and qualify inputs first

**Files:** `scripts/run-security-execution-container.py`, its tests, owning CI commitments, and an ordinary diagnostic preflight entrypoint if needed.

**Interfaces:** Consume a terminated, identity-checked container; produce bounded escaped diagnostic text only. Successful evidence import remains the existing closed output schema.

- [x] Retain exact job logs, source/auth identities and the current native attempt. Reproduce freshness refusal without a full compilation campaign.
- [x] Add failure-diagnostic controls covering oversized output, control characters, collection failure and mandatory cleanup before changing the runner.
- [x] Run cheap input/contract checks and all affected script tests before building the native image.
- [x] Measure the full mutation campaign against its fixed bound. If scheduling cannot satisfy it, design and test complete, isolated campaign sharding before another full attempt; do not raise the bound or omit campaigns.

### Task 4: Freeze, review and run complete qualification

**Interfaces:** Consume passing component evidence, reviewed source S and trusted definition D; produce exact terminal hosted checks and the required signed evidence chain.

- [x] Record repairs and evidence in the landing ledger; commit the complete source batch.
- [x] Obtain independent GitHub Codex review of the repair checkpoint. Land the trusted-definition prerequisite and consume its exact commit.
- [ ] Obtain exact-source review of the final composed candidate before authorization.
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


## Final component checkpoint

The cached native rerun on source repair `6a3a397c475bd2d4abbd403b605e5be1c20ec028`
passes all six stages: enforcing helper/discovery, privileged probe, independent
fixture provisioning, enforcing CLI build, every conformance target and the full
consumer-boundary gate. This remains diagnostic evidence, not isolated final
qualification. The owned worker was stopped after the logs were retained.

The remaining CLI cluster failures came from absent operator-provisioned
replication anchors. Private fixture directories and explicit public-anchor plus
signed-envelope provisioning now let all eight active cluster scenarios pass,
including 20 partition/heal samples, late joiners and stale-term rejection. The
three previously ignored scenarios remain recorded separately. Reputation
issuance passes its one test. Strict lint passes for the changed fixtures.

Executing the next portable step exposed a fifth generated-vector test omitted
from the workflow's exact list. All five tests pass; the old list fails with the
specific unexpected execution-binding regression, and the repaired list passes.
The trusted definition and its exact workflow contract now include that test.

Codex review of prerequisite #1175 found an S/E identity conflation after shard
execution. Aggregation now keeps candidate E separate from authorized tooling S
and independently enforces the controller's maximum 32 single-parent descendants
restricted to the three regular signed-output files. Ten controls pass, including
real-Git composition and rejection of source edits, deletion, executable outputs,
symlinks, empty commits and excess ancestry. The 64-path refreshed mutation patch
still requires its own review and source authorization. No ancestry rule is relaxed.

Ruling: the full CI-contract run begun before the vector inventory discovery was
cancelled, rather than mixing two workflow versions into a claimed result. One
final run covers the complete frozen repair. Prior failures and that cancellation
are retained. Exact-source review, prerequisite landing, all 35 genuine mutation
campaigns and final hosted/native/trusted qualification remain open.


## Protected definition landing checkpoint

Prerequisite #1175 passes its complete required CI and exact-head independent
review at `b1c99c494a67e767609a011528aadc5ea098b423`. Its protected main merge is `c009aced79d69f01880b5f7c53ed3c1754e3b7da`.
The final composition preserves this actual merge and pins the reusable workflow
to that same commit. The landing ledger retains the definition-only controller
refusal and the two canceled archive-tag SDK runs separately from required PR CI.

All 35 selected mutations are caught by cached diagnostic builds at repair
checkpoint `3a43737681aca26e45b5c2be471924a7c5eeeb73`. Zero are missed, timed out or unviable. The two native
controls run on x86_64; the other 33 run on Linux aarch64. An initial native probe
with group-writable permissions is rejected before mutation execution; correcting
only the fixture mode and umask restores the positive baseline and catches the
negative mutation. Original failure and successful rerun remain separate records.

Published verifier bytes match the configured SHA-256. Signing and publishing
environments permit only main and disable administrator bypass. Environment-scoped
installation configuration is omitted from the public audit record. Private App
metadata is unavailable through the ordinary operator API; the protected runtime
must still validate its identity and permissions. Final evidence policy and commit
variables remain absent pending genuine finalizer output.

These preparations do not complete isolated source-bound refresh, final native or
hosted qualification, signing, or foundation landing. Freeze all source and status
documents before authorizing the reviewed final composition and starting refresh.


### Final evidence event ordering

The source authority and the committed evidence authority are distinct. Keep the
independently reviewed source S fixed after importing and reviewing the complete
64-path mutation refresh. Signed-output descendant E may change only the three
closed regular evidence blobs. Its exact final review is still required before
protected landing.

1. Capture and sign genuine native evidence for S through the trusted controller,
   capture and finalizer. Retain the exact artifact identity, bytes and generated
   policy. The first publication authorizer cannot publish while no committed
   evidence descendant exists; retain that refusal separately from signing.
2. Authenticate the signed artifact and policy against their trusted run and the
   pinned verifier/key. Create a local single-parent evidence commit E containing
   only those three files. Run the strict committed-evidence checker on local E
   against S and the authentic generated policy, and verify the closed modes and
   ancestry before configuration. Do not create or alter canary values manually.
3. Configure the authentic policy and CHIO_COMMITTED_LINUX_EVIDENCE_SHA=E before
   the first push of E to the foundation PR. CHIO_AUTHORIZED_SECURITY_SOURCE_SHA
   remains S. This authorizes already authenticated output under reviewed source;
   it does not waive final independent review or any check. Publish E, request its
   exact GitHub Codex review, and let its first complete CI run execute with the
   correct immutable event inputs.
4. Keep E, its base, source and definition variables, policy and capture labels
   stable. The fresh E capture must validate native behavior and its finalizer
   must join the strict committed S evidence with successful exact E/M CI and the
   attested merge binding before publishing the five authority contexts.
5. The E capture also emits a newly signed canary for E. Retain that artifact as
   run evidence, without replacing the committed canary/policy for S. Publication
   independently verifies the already committed S evidence and fresh E capture;
   importing the second artifact would create another head and invalidate the
   candidate being qualified.
6. If a controller expires before a valid capture begins, preserve its failed
   attempt and use a fresh `labeled` event to request a new capture once capacity
   is available. Do not use `unlabeled` for that retry: CI also listens for that
   event and its concurrency policy can cancel the existing E run. Keep labels
   stable once the replacement capture is authenticated.
7. Do not cancel or casually rerun the final authorized E CI. A non-successful CI
   conclusion can create sticky failure authority for its exact merge M. If a
   real failure occurs, inspect the trusted revocation result before selecting a
   repaired, reviewed candidate. Never overwrite or bypass failed authority.

This order follows the existing workflow behavior: the publication authorizer
requires committed evidence SHA equal to live head E, verifies its policy source
against S, joins the E capture and exact CI independently, and requires signing
success before publication. The second signature artifact is not imported by the
publisher. No workflow change or relaxation of the source ancestry rule is needed.
