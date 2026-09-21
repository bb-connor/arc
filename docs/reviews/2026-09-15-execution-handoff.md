# Execution handoff: converge Chio and complete the supported runtime

Current implementation checkpoint: see the
[September 21 current qualification status](../security/process-security-qualification.md#current-checkpoint-2026-09-21).
Candidate `ce19d8f3f` includes the September 20 dependency and hygiene
continuations. Resume from that status before using the historical queue below.

Latest continuation: [September 16 review and execution directive](2026-09-16-execution-directive.md).
Read its current source identities, new foundation failure and ordered execution
queue before using the historical snapshot below.

Prepared September 15, 2026. Start with implementation and qualification; do not
repeat the entire PR audit or stop after producing another plan.

## Mission

Execute the completion program in [the PR portfolio audit](2026-09-15-pr-portfolio.md).
Use ARC PR #1160 as the common process/security foundation. Preserve the current
security and process capabilities, finish combined qualification, complete M5's
governed reference swarm, and carry the resulting foundation into one coherent
delivery path. Continue through the applicable M6-M10 preview requirements and
evidence-backed retirement of superseded PRs. Keep M11 operational promotion a
distinct milestone with its existing authority requirements.

The immediate engineering deliverable is **a qualified combined foundation and
a working, governed, confined reference swarm**. A passing transport test, a
new wrapper, another benchmark, a draft PR, or an updated checklist does not
finish that deliverable.

The user requested this handoff after accepting the audit's direction. The
existing integration plan records prior authorization to implement M5 locally
before the protected foundation merge. Do not re-request that authorization.
Actual release, deployment and protected-controller authority retain their
existing documented boundaries; this handoff does not invent a bypass.

## 1. Start here

Read, in this order:

1. This handoff.
2. [PR portfolio audit](2026-09-15-pr-portfolio.md), especially dependency
   relationships, blockers and the recommended completion order.
3. At the current #1160 candidate, `docs/security/process-security-integration.md`.
   Tasks 1-4 have recorded completion; resume Tasks 5-7. The latest M5 work is
   partially implemented even where its checklist remains unchecked.
4. `docs/security/process-security-qualification.md`.
5. `docs/security/process-security-review-dispositions.md` and its JSON sibling.
6. `docs/security/launch-status.md` and `launch-execution-plan.md`.
7. `docs/security/native-restart-safety.md`, `consumer-support.md`,
   `m4-consumer-qualification.md` and `m4-local-acceptance.md`, as needed for
   the owning acceptance gates.

These documents live on the candidate branch; many are absent from the old
top-level main checkout. Read them with `git show <candidate>:<path>` until the
execution checkout is ready. `launch-plan.md` is a long historical ledger.
Its old pending statements do not supersede the current milestone table.

The three original requirement contracts remain:

- `docs/superpowers/plans/2026-07-09-protocol-primitives.md`
- `docs/superpowers/plans/2026-07-09-security-active-defense.md`
- `docs/superpowers/plans/2026-07-09-enterprise-hardening.md`

Read the applicable AGENTS.md files. Keep one implementation owner and one
Cargo owner per checkout. The current integration plan explicitly records the
user's no-further-subagents instruction. Work as a single executing agent unless
the user subsequently changes that instruction. Do not call self-review
independent review. Independently verifying artifacts is still required.

The historical plan names `superpowers:executing-plans`; use it if available.
If that historical skill is unavailable, execute the substantive task sequence
directly with the tools available. Its name is not a reason to abandon the work.

## 2. Recover the correct checkout without disturbing other work

Workspace used for the audit:

`/Users/connor/Medica/backbay/standalone/arc`

At handoff, this checkout is on local main at
`f5a9d2ab238448b8a85b04e9d426c507a2e09929`, one commit ahead of its origin/main.
The local commit adds review tooling. It is not the runtime candidate.
Pre-existing modified files are:

- `.cursor/skills/review-pr-swarm/scripts/checkout.sh`
- `.cursor/skills/review-pr-swarm/scripts/lib.sh`
- `.cursor/skills/review-pr-swarm/scripts/post.sh`
- `crates/products/chio-cli/src/cli/dispatch/mod.rs`
- `crates/products/chio-cli/src/cli/types.rs`

The audit and this handoff are new uncommitted files under `docs/reviews/`.
Preserve all these files and the local main commit. Do not stash, reset, clean,
switch or rebase the user's primary checkout to begin this task.

The previous execution plan specifies `/tmp/arc-security-launch`, branch
`integration/process-security-m4`. **That directory no longer exists**, verified
while writing this handoff. `/tmp/arc-agent-workbench` is also absent. Recreate
the former execution checkout from verified source, or use a separate isolated
checkout if the environment requires it and record the location. Do not infer
that old `/tmp` logs or binaries still exist.

The local `/Users/connor/Medica/backbay/standalone/chio` checkout exists and was
clean, but remains at `eba8cdf3fb2e16501947c58415a4739a23cc12b3`, reporting 904
commits behind its tracked branch. It is not a current release starting point.

Initial read-only commands:

```sh
git status --short --branch
git remote -v
git worktree list
git show --stat b7211ce2d063ea36ea0f512b6f3c0253b65ecd71
git show b7211ce2d063ea36ea0f512b6f3c0253b65ecd71:docs/security/process-security-integration.md
```

Refresh the current heads and checks for #1160, #1117 and #1155 before editing.
Refresh #1156, #1159, #1161 and the public product PRs before integrating them.
Reconcile new commits; do not reset back to this snapshot. If another agent owns
the current execution checkout, choose an isolated candidate checkout and
coordinate ownership through available session mechanisms.

`gh` network access failed in the audit environment. The GitHub connector worked
for PR metadata, files, check runs, review threads and job logs. Use it as a
read fallback if needed. Network and Git-metadata permissions are environment
specific. Never claim a fetch, push, merge or hosted test succeeded when the
environment prevented it.

## 3. Exact starting identities and dependency traps

All identities below are the audited snapshot, not a promise that the branch
has not moved since September 15.

| Role | PR / branch | Audited SHA |
| --- | --- | --- |
| ARC main | `bb-connor/arc:main` | `f5566d9a765c21cb36652a99c79de64968a656bf` |
| Public main | `backbay-labs/chio:main` | `5b8bec41d32f3838b880576fe6123c983ecebf8d` |
| Primary candidate | [ARC #1160](https://github.com/bb-connor/arc/pull/1160), `integration/process-security-m4` | `b7211ce2d063ea36ea0f512b6f3c0253b65ecd71` |
| Pre-M5 qualification checkpoint | Same ancestry | `58c632ce0f9066a777e6b2e322e661dd18f198a2` |
| Current M4 parent | [ARC #1117](https://github.com/bb-connor/arc/pull/1117), `security/launch-integration` | `5d1a9ec0d900bd03ce55de903919d972be852d79` |
| Process-stack parent | [ARC #1155](https://github.com/bb-connor/arc/pull/1155) | `2e84f121273df7f205cc218739b86e93c91bdc37` |
| Native-agent release | [ARC #1156](https://github.com/bb-connor/arc/pull/1156) | `7059c71ca86239e1ba5fe7b63c391db2b2ded3bc` |
| Paper/runtime track | [ARC #1159](https://github.com/bb-connor/arc/pull/1159) | `2b3b5af8cbfbc6f16ce6005de3f97cd149803b81` |
| Funded-work sibling | [ARC #1161](https://github.com/bb-connor/arc/pull/1161) | `7755d3762baa5e0fda0d171835a9000c26de9033` |
| Original security omnibus | [ARC #1029](https://github.com/bb-connor/arc/pull/1029) | `cbbba8cf2178cbbdd7b6b38a121e59365eb452ac` |

Verify both parent relationships in the execution checkout:

```sh
git merge-base --is-ancestor 5d1a9ec0d900bd03ce55de903919d972be852d79 HEAD
git merge-base --is-ancestor 2e84f121273df7f205cc218739b86e93c91bdc37 HEAD
```

Known topology:

- #1160 contains 54 other open ARC PR heads. Do not replay the whole stack.
- #1131 is the earlier process/security integration and conflicts with current
  #1117. Its job has been superseded by the later #1160 integration.
- #1161 includes current #1117 and #1159, but not #1160 or the current process
  tip. Its title/body must not be read as proof that process integration is done.
- #1156 is separate and overlaps #1160 in 124 changed paths. Reconcile semantics
  at kernel, store, protocol and release boundaries, not just textual conflicts.
- #1136's descriptor fix was incorporated with provenance. #1140's xtask
  correction has an explicit disposition. Neither should be reapplied blindly.
- #1029 is not an ancestor of #1117. Keep requirement-level reconciliation before
  closing it; do not merge the old omnibus merely to tidy GitHub.
- Public Chio #1 is an ancestor of #4, which is an ancestor of #5. #9 is separate.
  #10 targets a retained integration branch whose public PR #2 closed unmerged.

## 4. What already works, and what must not be redone

M0-M4 have recorded local acceptance on the security branch, with M1 confinement
qualification explicitly deferred. The #1117 record reports 17,187 workspace
passes, 48 unchanged existing ignores, 45 exact M4 cases and 61 exact M3 cases.
These are source-bounded retained results, not fresh tests performed by this audit.

The combined candidate already has recorded passing installed process starter,
AI SDK 6/7 and Docker recovery profiles. The three complete installed qualifiers
used source `f0ff43b819` and binary SHA256
`82ba58ec8a8d742b9d22504ff4f0fd604ee6e0361b7f33df7d591163870b92a5`.
That was a Rust 1.94.1 Linux/aarch64 workspace-test build. It was not an optimized
release or Linux x86_64 confinement certificate. Verify any retained artifact
before reuse; reproduce it if the temporary material is gone.

The integration disposition JSON accounts for 109 inherited remote threads:

- 81 reproduced-and-repaired dispositions.
- 20 fixed-with-evidence dispositions.
- Eight technically-inapplicable-with-reason dispositions.

The audit checked uniqueness and matched all 109 comment identities against
retrieved GitHub comments. Those threads remain administratively unresolved.
Use the cited source and tests. Do not equate every open thread with a new bug,
or every old disposition with proof that later code still passes.

## 5. First execution milestone: finish the foundation

### Recover the interrupted state

At `58c632ce0f`, a serial queue completed workspace build, process features,
process host and signed lineage. It was deliberately interrupted during native
restart qualification so local M5 development could start. Exit 130 was not a
pass. Later queued gates did not execute.

An earlier workspace run stopped at nine proof-fixture discovery failures.
The repaired proof target passes all 147 cases; the remaining workspace was not
thereby qualified. The repair supplies the owned `CHIO_CHECKOUT_ROOT` to contract
fixtures with an external Cargo target. Preserve that authority boundary.

Latest commit `b7211ce2` adds M5 source changes. Its full runtime suite was
interrupted. Inspect its diff and resume the affected suites first:

```sh
git diff 58c632ce0f9066a777e6b2e322e661dd18f198a2..HEAD --stat
```

### Run the owning gates

Use the checkout's pinned toolchain, currently Rust 1.94.1. The existing plan
uses `umask 022`, `CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`, no custom
`RUST_MIN_STACK`, locked dependencies and one Cargo owner. Run offline only when
the needed dependency closure is actually available. Do not alter limits or
skip required inventories to manufacture a pass.

Start with cheap format/style/source checks and affected M5 suites. Then complete
the combined acceptance gates rather than repeatedly rebuilding everything after
documentation-only changes. Core entry points from the existing plan:

```sh
cargo fmt --all -- --check
cargo build --locked --workspace
cargo test --locked --workspace
cargo clippy --locked --workspace -- -D warnings
cargo test --locked -p chio-process --features worker-server,mailboxes
cargo test --locked -p chio-cli --test process_host
cargo test --locked -p chio-cli --test process_response_verify
cargo test --locked -p chio-kernel-core --test signed_lineage
```

Read each owning script/workflow's invocation contract before running it. Complete
the exact M1-M4 flow, native restart/caller crash and rollback inventories through
`scripts/check-flow-security.sh`, `scripts/check-native-restart-safety.sh` and
the current integration plan. Include affected Python/Node SDK tests, generated
wire bindings, proof coverage, selected feature builds and all required fuzz-bin
compilation. Compilation is not a fuzz campaign.

Keep command, source SHA, compiler, feature set, binary/package hashes, terminal
exit and retained logs together. Preserve failure logs. A changed executable or
package invalidates its affected installed-profile evidence.

### Close known dependency and execution blockers

1. **26 missing safe-to-deploy audits.** The exact #1160 hosted cargo-vet job
   confirmed them. Complete genuine source audits or consume records permitted
   by existing policy. Do not add unreviewed exemptions. Existing trusted feeds
   lacked exact records for five new TLS versions at the prior refresh; patched
   `sigstore-verify` ownership also needs the documented policy resolution.
2. **Execution-image lock digest mismatch.** The qualification record names
   current lock digest `47bf5b6fc16784c18104912b1d90ee1160c2e8e330baff34fde35478e66fdbce`
   versus required image input `a4e631319b00c54f2cbc6457ad0149198a4a367db8dec060fcce376c98728b49`.
   Recompute before acting. Prepare the actual reviewed image/input update;
   changing an assertion to today's digest alone does not supply qualification.
3. **Trusted capture authorization.** The current failed controller job used
   authorized source `f5566d9a` and candidate `b7211ce2`. Prepare the exact
   source/controller/image proposal through the existing authority mechanism.
   Do not weaken the controller or repeatedly enqueue unauthorized captures.
4. **Native enforcement platform.** Obtain the documented supported Linux x86_64
   profile, kernel 6.7 or newer with every cage prerequisite verified. Aarch64
   worker/container recovery does not satisfy the x86_64 native-tool claim.

Useful audited failures:

- [#1160 cargo-vet](https://github.com/bb-connor/arc/actions/runs/35006605537/job/104507814822)
- [#1160 enterprise capture](https://github.com/bb-connor/arc/actions/runs/35006601953/job/104507803258)

Refresh terminal results before treating these as current. Classify failures as
source, dependency policy, platform, resource budget or authority/configuration.
A job name alone does not diagnose its failed step.

## 6. Second execution milestone: finish M5

### Preserve the existing architecture

`chio-process` owns logical process identity, authenticated worker transport,
checkpoints and supervision. The existing kernel and durable authority own
dispatch, captured budgets, revocation, receipts and uncertain outcomes. Compose
them. Do not create a second worker runtime, replay owner or admission coordinator.

Never retry an unknown external effect merely because a worker, socket,
container attachment, logger or cleanup operation failed. Preserve M4's original
authority and custody requirements and the existing process ABI contracts.

### Resume the actual WIP

The latest commit contains portions of M5.1/M5.2:

- Authenticated worker transport carries governed intent through Python and
  JavaScript clients.
- A join reference is optional for fan-out and required for fan-in.
- Live swarm admission is separated from complete-run verification. Live
  admission must not require an invented terminal receipt claiming future tasks
  already completed. Complete-artifact verification remains strict.
- New worker, live-admission and runtime-composition tests exist.

Primary ownership paths:

- `crates/kernel/chio-process/src/worker.rs` and `tests/worker_protocol.rs`
- `sdks/python/chio-process/`
- `sdks/typescript/packages/process/`
- `crates/kernel/chio-swarm-authority/src/verifier.rs` and owning tests
- `crates/kernel/chio-runtime-core/src/admission_hook/` and runtime admission tests
- `examples/reference-swarm/`

The commit message reports 34 Python, seven JavaScript, 12 worker-protocol and
61 swarm-verifier tests passing before interruption. Treat these as historical
claims to reconcile with retained logs and current source, not completed M5.

### Finish the composition

1. Bind actual persisted root and child capability bodies/identities to the
   signed task graph, delegation witnesses, routes and continuation tokens.
2. Install verifier-owned live authority through `ChioRuntimeAdmissionHook`,
   the sealed runtime source and the existing SQLite admission participant.
   Worker-supplied context is input to verification, never authority by itself.
3. Enforce the real shared aggregate budget and single-use continuation custody.
   The process journal's logical-call ceiling remains a separate bound.
4. Wire the authenticated process host and supervised workers to that profile.
5. Provision signed native manifests and trusted evidence; launch actual
   Enforced tools. Unsupported platforms refuse. Preserve the existing Disabled
   smoke under its honest name and do not count it as confined acceptance.

### Acceptance matrix

| Scenario | Required observable result |
| --- | --- |
| Useful successful task | Real orchestrator/workers produce a checked result and bound receipts |
| Scope widening | Owning admission boundary refuses; protected resource unchanged |
| Forbidden filesystem/network | Real enforcement blocks the attempted effect |
| Cross-agent leakage | Unauthorized data cannot reach the other worker or caller |
| Shared-budget contention | Concurrent workers cannot overspend the authoritative aggregate |
| Continuation replay | Same continuation cannot authorize an additional effect or charge |
| Worker/host crash and restart | Retained authority and original operation identity survive; uncertain effects stay fenced |
| Revocation | Subsequent protected work is refused at the correct live boundary |
| Modified exported evidence | Independent verification rejects identity, signature and semantic substitutions |

Close M5 only when one reproducible run artifact joins task/capability/worker
identity, actual effects, durable accounting, confinement, signed receipts and
terminal outcomes. Use a clean documented command a recipient can run. Transport
support and local verifier tests alone do not satisfy this milestone.

## 7. Delivery and remaining roadmap

After the foundation/M5 composition is stable, execute M6-M10 using the current
accepted plan. These remain required for the full security preview:

- M6: keyring, broker, cage and receipts in one qualified process topology.
- M7: composed flow, active response and rollback in controlled profiles.
- M8: retention, scale, migration and operational recovery.
- M9: packaged dependency closure and clean external-consumer installation.
- M10: exact-candidate platform/hosted/release qualification.

Retain M11's observed pilot and signed promotion requirements. Preview completion
must not silently activate automatic production containment.

### Reconcile native hosts

Bring #1156 onto the common foundation with semantic review of overlapping
kernel/store/protocol changes. Its companion implementation PRs in bridge,
Claude, Codex, Cursor, Pi, OpenClaw and delivery harness already merged. Verify
their current versions rather than reopening historical work.

The #1156 record says zero of six hosts satisfy the entire I01-I08 contract.
Five completed useful workflows and a 33-command matrix, but installation,
compatible release and complete lifecycle evidence remain separate. Cursor's
supported restriction boundary remains unresolved. Do not silently reduce the
mandatory host set. Read `docs/strategy/chio-direction/19-priority-agent-integrations.md`
and the current acceptance PROGRAM/CANDIDATE-DELIVERY records on that branch.

Coordinate the CLI/SDK artifacts and [Chio World installer #148](https://github.com/backbay-labs/chio-world/pull/148).
Complete staged execution/version/identity checks and the applicable website
gates. A checksum-valid download is not proof that the new release runs.

### Choose and finish one product path

Public [Chio #5](https://github.com/backbay-labs/chio/pull/5) had 89 successful,
11 skipped and one failed advisory check. Its eight Builder examples jobs
passed. It is the best bounded application-preview completion candidate while
long foundation gates proceed. Preserve its scoped support claims.

[Megastart #9](https://github.com/backbay-labs/chio/pull/9) and
[#10](https://github.com/backbay-labs/chio/pull/10) are the candidate mission
interface for the eventual common runtime. Reconcile #10's retained-parent
dependency and #9's failing source checks. Choose the supported first product
based on actual integration and acceptance cost; do not expand both Workbench
and Megastart as independent runtimes. Keep existing useful features.

### Reconcile repository authority

Public Chio is the intended destination; preserve ARC intact. Public main is an
ancestor of ARC main at the snapshot, but public development branches also have
valuable independent changes. Prepare an ancestry-preserving candidate in the
destination and verify it before changing release routing. Do not mirror-force
or use #1056's old downstream-only assumption without reconciliation.

## 8. Close historical PRs only after their result is integrated

For each candidate closure, record:

1. Original PR and reviewed head.
2. Containing merged commit or explicit patch-equivalent implementation.
3. Disposition of its review findings and relevant current tests.
4. Remaining unsupported behavior or evidence limits.

Resolve the 109 mapped threads with their actual source/evidence when the
relevant review and delivery conditions hold. Do not fabricate reviewer
approval, resolve comments cosmetically, or claim local source repair means
the original PR already merged. Use normal protected merge controls.

Keep the following outside the immediate foundation integration:

- #1029: historical omnibus, pending requirement-level coverage reconciliation.
- #956-#959: older settlement/Pass/economy expansion unless the selected consumer
  demonstrably requires it.
- #1161: funded-work sibling; integrate later against the stable foundation and
  finish its interrupted transport/recovery/settlement qualification.
- #1162: outcome/A2A preservation checkpoint; inspect and test source separately
  from its large evidence corpus before integration.
- #1163: unadjudicated benchmark replacements; retain provenance and validate
  whether the cited paper results should change.
- #1164: untested Workbench Git-task checkpoint; decide its product role first.

Take runtime correctness repairs from #1159 when required, with owning tests.
Stabilize runtime semantics before repinning benchmarks or strengthening paper
claims. Review scores are not product-demand or release evidence.

## 9. Execution discipline and authority

- Continue useful implementation while a genuinely external prerequisite is
  pending. The existing M5-before-merge authorization specifically permits this.
- Do not ask for approval to repeat already-authorized local fixes, tests or
  preparation. Use existing session authorization when it applies.
- When a specific protected operation needs new authority, finish the concrete
  reviewable candidate first. Identify the exact source/image/controller or
  publication action, the exact rule requiring authority and the remaining
  decision. Do not substitute a broad permission question for engineering work.
- A rejected action or missing platform is not a passing gate. Record the
  precise blocker and continue independent authorized work.
- Preserve fail-closed behavior, canonical signed JSON, dependency policy,
  immutable evidence and the distinction between historical verification and
  permission for a new effect.
- Use conventional commits and no em dashes. Keep unrelated changes intact.
- Keep raw artifacts durable and indexed. Inspect them before public attachment;
  local full-fidelity host logs are not automatically a public evidence package.
- Give concise progress updates stating completed behavior, observed failures,
  current source and the next acceptance boundary.

## 10. Required output from the execution agent

Maintain a short current status file in the execution branch, preferably the
existing `docs/security/process-security-qualification.md`, with:

- Current candidate, parent SHAs, branch and checkout location.
- Completed implementation slices and exact commits.
- Gate table: command/job, source, platform, terminal result and evidence path.
- Remaining findings and external prerequisites.
- Current M5 scenario/artifact acceptance state.
- Delivery/version matrix and subsequent M6-M10 status as those tasks begin.
- PR disposition decisions backed by ancestry or source equivalence.

At each stopping point, distinguish implemented, locally verified,
hosted-qualified, merged, packaged, published and operationally accepted. Name
the next executable action and the real blocker if one exists. Do not replace
the original objective with a report about why completion would be useful.

### Completion criteria

- [ ] Current #1160-equivalent source preserves both full parent histories and
  all required behavior.
- [ ] Combined foundation gates and inherited review dispositions are current.
- [ ] Dependency audits and exact trusted execution inputs satisfy policy.
- [ ] M5 runs through actual Enforced tools with every required positive and
  negative scenario, and independently verified complete run evidence.
- [ ] Applicable M6-M10 requirements are completed for the claimed preview.
- [ ] The selected product, CLI/SDKs, native-host profiles and installer share a
  tested compatibility contract.
- [ ] Approved integration/publication actions are completed through their normal
  controls; published and installed behavior is verified when authorized.
- [ ] Superseded PRs are dispositioned from merged evidence and useful history
  remains available.
- [ ] M11 promotion is separately tracked and never implied by preview delivery.

## Evidence provenance

The portfolio audit used live GitHub PR/check/review APIs and local Git objects
on September 15. It did not rerun the full software test suite. This handoff
re-read the pinned integration plan and verified the local checkout/path state.
Refresh moving refs and jobs once at startup, then execute. Avoid another broad
inventory exercise unless new evidence shows the portfolio has materially changed.
