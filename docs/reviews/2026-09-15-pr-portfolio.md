# Chio PR portfolio and completion plan

Snapshot: 2026-09-15, live GitHub inspection completed around 18:46 UTC.

## Assessment

The project has substantial implemented and tested functionality, but no single qualified source tree contains all the current security, process, native-host and public-application work. The immediate problem is convergence and completion. Further horizontal feature work increases the integration burden.

Confidence: high on remote PR inventory, checked commit ancestry, review metadata and the inspected CI failures; moderate on implementation readiness inferred from committed acceptance records. This was a portfolio audit, not a fresh execution of the full test suite or a line-by-line security review of every changed file.

## Scope and method

- Inventoried all 81 open PRs in bb-connor/arc and all five in backbay-labs/chio. All 86 have entries below.
- Read live PR metadata, descriptions, check runs (including second pages), commit statuses, inline review threads and review submissions. Reviewed current roadmap and qualification records and representative failure logs.
- Verified ancestry using the live remote head SHAs and local Git objects, available for 85 of the 86 heads. Public Chio #10 was inspected remotely.
- Checked the seven repositories directly coordinated by ARC #1156: bridge, Claude, Codex, Cursor, Pi, OpenClaw and delivery harness. Each currently has zero open PRs; each implementation PR #1 merged on September 10.
- Checked the coordinated installer PR chio-world #148. It remains open. Unrelated Chio World/game/documentation PRs are outside this kernel portfolio audit.
- Preserved the pre-existing modified files and local main commit. No PR, review, branch, release, configuration or deployment was changed.

## Inventory totals and actual shipped state

| Repository | Open | Draft | Non-draft | Default branch |
| --- | ---: | ---: | ---: | --- |
| bb-connor/arc | 81 | 72 | 9 | f5566d9a, September 3 |
| backbay-labs/chio | 5 | 5 | 0 | 5b8bec41, September 2 |

Chio main is an ancestor of ARC main and is two commits behind. Those two commits affect 68 files (+7,051/-4,915), so this is more than a cosmetic synchronization gap. Public Chio also has its own unmerged development branches. Choose and document the integration/release authority before resuming mirror automation.

The premise that nothing shipped needs qualification:

- ARC has the older v0.1.0 release and an enterprise-evidence-verifier prerelease.
- Public Chio has v0.1.0 and the September 10 Agentic OS application prerelease, pinned to 9ffca8d6.
- The seven integration implementation PRs merged. Their source delivery does not establish complete six-host runtime acceptance.
- The current combined security/process runtime and compatible general CLI release remain unfinished.

There are 411 inline review threads across the 86 open PRs: 310 unresolved, including 68 marked outdated. The review API returned 343 COMMENTED submissions and no APPROVED submissions. These are GitHub metadata facts, not a count of live bugs or a denial that local reviews occurred.

## Dependency map

Arrows show parent/dependency direction. Ranges abbreviate the inventory below; the process graph has side branches and rewritten equivalents.

```text
ARC main
  |
  +-- #1029 old security omnibus (diverged; historical reconciliation source)
  |
  +-- #1117 current security M0-M4 foundation ------------------+
  |      |                                                    |
  |      +-- older security snapshot + #1130 -> #1131          |
  |                                      |                   |
  |                      coding/process extensions -> #1155 --+--> #1160
  |                                                               process + M4
  |                                                               repairs + M5 WIP
  |
  +-- #1098 -> ... -> #1130 process foundation
  |
  +-- #1158 paper review (separate PR)
  +-- #1159 paper/runtime evidence ----+--> #1162 outcome/A2A WIP
  |                                   +--> #1163 benchmark data WIP
  |
  +-- #1117 + #1159 + funded-work changes ---------------------> #1161
  |
  +-- #1156 protected native hosts and CLI release
  |
  +-- #1092 -> #1093 -> #1094 -> #1095 -> #1096 -> #1097 -> #1164 WIP
  |
  +-- #956 settlement; #957 -> #958 -> #959 Pass/market economy
  +-- #1043, #1046, #1056, #1073, #1136 smaller legacy/fix branches

Public Chio:
  #1 is an actual ancestor of #4 -> #5, although #4 targets main
  #9 Megastart is separate
  #10 targets the retained native-integration branch from closed, unmerged #2
```

### Verified integration relationships

- #1160 contains the current heads of both #1117 and #1155. It is 296 commits ahead of ARC main.
- #1160 contains 54 other currently open ARC PR heads by exact ancestry. Some additional functionality is present through rewritten/cherry-picked equivalents, so ancestry alone cannot decide all closures.
- #1160 does not contain the heads of #1156, #1159, #1161 or #1162.
- #1161 contains current #1117 and #1159. It does not contain #1160 or the current process-stack tip. It is a sibling requiring a real merge and qualification.
- #1131 is conflicted against the current #1117 base; its common integration was pinned to the earlier security revision 8b9f9243.
- Current-parent drift also exists at #959 versus #958, #1139/#1140 versus #1138, and #1141 versus #1139.
- #1160 and #1156 change 124 common paths relative to their shared base. #1160 and #1159 overlap 15 paths. #1160 and #1161 overlap 31 paths after their shared M4 ancestor. Overlap is an integration-risk indicator, not proof of a conflict.
- #1136's macOS descriptor fix is recorded as incorporated with provenance in the process ledger. #1140's xtask correction is explicitly reconciled in the integration disposition record. Reapplying either blindly is inappropriate.
- Keep ARC history intact while reconciling public Chio. The old #1056 assumption that nobody develops directly in the downstream repository no longer describes the open-branch portfolio.

## Security roadmap: where it actually stands

The current control documents are [launch status](https://github.com/bb-connor/arc/blob/5d1a9ec0d900bd03ce55de903919d972be852d79/docs/security/launch-status.md) and [execution plan](https://github.com/bb-connor/arc/blob/5d1a9ec0d900bd03ce55de903919d972be852d79/docs/security/launch-execution-plan.md). The approximately 9,000-line launch plan is a historical ledger; its old pending statements should not override the current milestone table.

| Milestone | Current recorded state | Remaining boundary |
| --- | --- | --- |
| M0 scope and candidate | Consolidated | Maintain one authoritative candidate |
| M1 secure native invocation | Local acceptance complete | Explicit Linux x86_64 confinement qualification deferral |
| M2 failure/restart safety | Local acceptance complete | Preserve contracts through later integration |
| M3 authenticated caller custody | Local acceptance complete | Complete integrated candidate still needs qualification |
| M4 constructors, protocols, SDKs | M4.0-M4.8 local acceptance complete | Not an exact-head hosted release certificate |
| M5 governed reference swarm | Implementation started in #1160 | Real capability/graph binding, shared budget, Enforced tools, complete runtime and effect checks |
| M6 enterprise topology | Components present | Integrated keyring/broker/cage/receipt topology unqualified |
| M7 active defense | Components present | Composed response, flow and rollback acceptance unqualified |
| M8 retention/scale/recovery | Unqualified | Retention, migration and operational campaigns |
| M9 distribution | Security entry packages/external consumer unqualified | Dependency closure and clean installation |
| M10 developer preview | Not release qualified | Exact candidate, hosted/platform gates, audits and release controls |
| M11 pilot/promotion | Not started | Observed pilot and signed promotion stages |

This does not mean "five twelfths complete." The remaining milestones include expensive system integration and operational evidence.

### The three large security PRs

| PR | Head | Scope | Disposition |
| --- | --- | --- | --- |
| [#1029](https://github.com/bb-connor/arc/pull/1029) | cbbba8cf | Original security/economy/enterprise omnibus; 2,321 files; 230 unique commits; merge conflicts | Historical source and coverage reconciliation. Do not use as today's release candidate. |
| [#1117](https://github.com/bb-connor/arc/pull/1117) | 5d1a9ec0 | Current M4 security foundation; 2,328 files; 134 commits ahead of main | Authoritative security milestone/evidence ledger. Current checks still fail. |
| [#1160](https://github.com/bb-connor/arc/pull/1160) | b7211ce2 | Combined process/M4 integration; 2,811 files; 296 commits; includes M5 WIP | Best candidate to converge and qualify next. Not merge-ready. |

#1029 is not an ancestor of #1117. The newer branch restores and integrates security work on modern main. Preserve requirement-level reconciliation before closing the historical omnibus; do not assume ancestry proves complete feature equivalence.

The #1117 record reports 17,187 local workspace passes, 48 unchanged ignores, 45 exact M4 cases and 61 exact M3 cases, with source boundaries recorded. These are retained local results. The current head has 107 successful, 14 skipped, seven failed and one cancelled check run in the retrieved API snapshot.

### #1160: real progress and remaining blockers

The [combined qualification record](https://github.com/bb-connor/arc/blob/b7211ce2d063ea36ea0f512b6f3c0253b65ecd71/docs/security/process-security-qualification.md) separates passing installed qualifiers from incomplete broad acceptance:

- Complete installed Python/Node starter, AI SDK 6/7 and native Docker recovery profiles passed on a retained Linux/aarch64 executable. Those were not optimized Linux x86_64 confinement/release binaries.
- The earlier full workspace run stopped at nine proof-fixture failures. The repaired target passes all 147 cases; that does not complete the rest of the stopped workspace.
- A later serial queue completed workspace build, process features, host and lineage, then was intentionally interrupted during native restart qualification.
- Latest commit b7211ce2 adds live swarm admission and worker governed-intent support. Its commit message explicitly says the full runtime suite was mid-run when execution stopped. Earlier passing qualifiers cannot qualify those new source changes.
- Locked cargo-vet has 26 unvetted dependencies, confirmed in the current [hosted job](https://github.com/bb-connor/arc/actions/runs/35006605537/job/104507814822).
- The execution-image lock digest constraint differs from current Cargo.lock. Completing the trusted image/source workflow is an explicit outstanding task.
- The current [enterprise capture job](https://github.com/bb-connor/arc/actions/runs/35006601953/job/104507803258) failed while AUTHORIZED_SOURCE_SHA remained f5566d9a and the PR head was b7211ce2. This is an authority/configuration boundary, not evidence that the functional tests passed or failed.
- Exact-head hosted qualification and the real supported x86_64 confinement profile remain open.

The [109-thread disposition record](https://github.com/bb-connor/arc/blob/b7211ce2d063ea36ea0f512b6f3c0253b65ecd71/docs/security/process-security-review-dispositions.md) records 81 reproduced-and-repaired, 20 fixed-with-evidence and eight technically inapplicable findings. It explicitly leaves GitHub threads unresolved. This is why mass-counting open review comments would misstate the engineering backlog. It is also why closing them without checking the cited current source would be premature.

## Other workstreams

### Durable processes and coding

The #1098-#1130 foundation covers process identity, attenuated child authority, authenticated Python/JavaScript workers, durable operations, LangGraph, mailboxes, supervision, AI SDK journals, shared state, resource accounting, relocation and recovery. #1131 connects its earlier form to security. The later stack adds containerized/native coding, repository snapshots, verified patch export, sessions, supervision, renewable leases and shared-resource caller binding through #1155.

This is a coherent runtime architecture. The [execution contract](https://github.com/bb-connor/arc/blob/2e84f121273df7f205cc218739b86e93c91bdc37/docs/architecture/SWARM_EXECUTION_CONTRACT.md) also states the strategic limit: both Chio and a competent direct baseline complete the synthetic tasks; independent adoption and lower integration effort remain unproven. The next product experiment should show useful application responsibility disappearing or a required cooperation boundary becoming possible.

### Native-host release: #1156

#1156 includes protected execution, Hermes, SDK support, release preparation and extensive evidence. 12,946 changed files are dominated by 8,174 paths under docs/integrations and 4,622 under sdks/python; 4,518 of the latter are Hermes evidence. File count is not an implementation-completion metric.

Its current description records useful four-tool workflows and a 33-command matrix for Claude, Codex, Hermes, Pi and native OpenClaw. It also explicitly records zero of six fully accepted under I01-I08. Cursor's protected execution restriction and compatible installed release/full per-host acceptance remain unresolved. The current core PR is separate from the already merged companion repositories.

The coordinated [installer #148](https://github.com/backbay-labs/chio-world/pull/148) remains open with website checks unresolved. Installation fixes, release binaries and native-host acceptance need one compatibility matrix.

### Public runnable applications: Chio #1, #4, #5

Actual ancestry is #1 inside #4 inside #5. #5 is the richest current application candidate and has 89 successful, 11 skipped and one failed check. Its eight Builder examples jobs passed; the remaining failure is an OSV advisory job. This is a plausible bounded deliverable to finish while foundation qualification proceeds, with an honest application-preview support boundary.

The examples span local agent applications, standard protocol clients/frameworks, service-mesh enforcement, commerce and a four-kernel Web3 work order. Their scoped evidence is valuable. They should consume the eventual common kernel rather than establish a second long-lived authority implementation.

### Megastart: Chio #9 and #10

#9 adds the mission operator, console, local approval/publication flow and companion release binary. Four checks fail. One inspected build failure is stale generated proof coverage; the other failures need their owning diagnosis.

#10 adds shared retained native-session authority and path constraints. It has 45 successful and nine skipped checks, but targets the retained native-integration branch whose public parent PR #2 closed unmerged. This is another concrete dependency closure problem.

Choose one flagship supported application for the first common-kernel release. Megastart can be the product face if its supported profile is integrated with M5. The current console/native-session tests do not by themselves satisfy the enforced reference-swarm contract.

### Paper/runtime research: #1158, #1159, #1162, #1163

#1159 is substantive runtime/formal/evaluation work plus paper rewriting, not prose-only. It has 15 unresolved review threads; current failures include advisories and a whitespace failure in the PostgreSQL-named job. Inspect the failing step rather than inferring a database defect from the job title.

#1162 preserves outcome continuation, unknown-release handling, A2A v1 and review/evidence work. Its description explicitly says it was not rebuilt/retested after the session stopped. 3,471 changed files are under paper review evidence. #1163 is an unadjudicated set of benchmark result replacements. Do not replace cited measurements simply because the files are newer.

Land source correctness repairs with runtime evidence; update claims and benchmark pins after the runtime tree stabilizes. Review scores are not proof of release readiness or product demand.

### Funded work: #1161

This branch combines #1117 and #1159 with escrow, funding admission, findings, claim/settlement recovery, operator custody and bilateral consent. Its last commit checkpoints authenticated TLS peer-verifier transport; recovery/settlement reruns were unfinished.

It is a credible later cross-organization application, but it is not the current combined process foundation. Its retained experiments should feed a specific next milestone after integration, not silently expand the first security release.

### Workbench: #1092-#1097 and #1164

The earlier six-PR chain implements MCP adoption/activation, clean preview distribution and delegated repair through Claude Code. #1164 preserves an untested Git task engine. Keep useful adoption/install machinery, but choose explicitly whether this UI or Megastart is the supported first product. Maintaining two growing repair consoles makes the release target less clear.

### Older economy and maintenance work

- #956 approval-bound settlement and #957-#959 Pass/market/netting work are distinct product scope with historical review and readiness boundaries. Do not make them prerequisites for finishing the current security runtime unless a selected consumer requires them.
- #1043 policy expansion design: recover/reassess against the implemented policy/roadmap before reviving it.
- #1046 old quickstart fixes: check whether modern consumers already carry equivalent repairs.
- #1056 mirror script: repository ownership assumption needs revision.
- #1073 release-budget repair: green historical checks coexist with current merge conflicts and one open thread. Reconcile its useful workflow changes against newer release machinery.
- #1136 is already recorded as incorporated with provenance; confirm the final merged implementation before administrative closure.

## Recommended completion order

### 1. Establish a single bounded integration target

Use #1160 as the foundation candidate, with its exact head and #1117/#1155 parent identities retained. Preserve #1029 and historical review slices. Retain the pre-M5 58c632ce checkpoint so M5 changes remain separately reviewable; do not reset or discard the latest WIP.

Document public Chio as the intended release destination and how the ARC candidate will be transferred with ancestry intact. Decide whether that transfer precedes or follows foundation merge; avoid ongoing independent core changes in both repositories.

Completion criterion: one candidate, one milestone table and an explicit include/defer/disposition for every related branch.

### 2. Finish qualification and outstanding trust inputs

Finish the interrupted workspace/native/runtime gates, reproduce actual code failures, complete the 26 dependency audits, and prepare the exact image/controller/source update through its existing trusted procedure. Acquire the correct x86_64 Linux execution profile for confinement evidence.

Run expensive qualification on the chosen candidate. Avoid triggering full campaigns on every historical PR merely to make the portfolio look green.

Completion criterion: all required gates terminal and tied to the reviewed source, with no skipped required platform test or undocumented waiver.

### 3. Finish M5 as a useful application

Use real persistent root/child capabilities, an authenticated task graph, one durable shared budget and Enforced tool launches. Demonstrate useful work, forbidden scope/filesystem/network refusal, cross-agent isolation, budget contention, continuation replay refusal, crash recovery and revocation. Export one independently verified run joining actual effects to graph, workers, receipts and accounting.

Reuse existing process/SDK/product work. Additional wrappers or benchmark variants should have a named user need and a falsifiable acceptance criterion.

Completion criterion: a recipient can run the supported workload and its failure scenarios from a packaged candidate, and verification makes the consequential guarantees observable.

### 4. Reconcile delivery and publish a bounded preview

Bring #1156 and the selected public product onto the foundation, close the installer compatibility loop and finish the documented M6-M10 release dependencies. Keep M11 active-response promotion separate. If the application suite #5 is finished earlier, publish it under its scoped application-preview contract; do not relabel it as the completed security roadmap.

Completion criterion: the released artifact, installed CLI/SDKs, selected native-host support and published documentation all name the same tested compatibility set.

### 5. Close the historical portfolio with evidence

After a qualified merge, resolve the 109 mapped threads with their actual evidence, close incorporated PRs, and inspect patch-equivalent branches separately. Preserve original history and retained artifacts. Reduce active feature scope to foundation completion, one product delivery path and one later research/application track.

Then prioritize funded cross-company work (#1161) and outcome continuation (#1162) against a real workload. Benchmark changes and paper claims follow stabilized runtime semantics.

## Practical priority

1. Foundation: #1160 and M5.
2. Release dependency work: audits, supported confinement runner, image/controller input procedure.
3. Bounded product delivery: public #5 or the chosen Megastart path, reconciled with #1156.
4. Runtime-relevant paper fixes; then funded/outcome application validation.
5. Older economy expansion and duplicate UI work remain outside the first foundation release.

The strongest product direction is applications and independently operated agents/systems cooperating under verifiable authority, with durable effects and recoverable outcomes. The next milestone should turn the existing mechanisms into one installable, useful, supportable result.

## Complete open-PR inventory

Sizes are GitHub PR diffs against each PR's base, not additive project totals. Check counts are the retrieved check-run snapshot and may include multiple workflows with the same display name. A green or clean row is not release acceptance; pending runs can change. There were no commit-status entries in the separate status API. Open-thread counts include outdated threads. All rows link directly to the PR.

### bb-connor/arc

| PR and title | Base | Draft | Files / + / - | GitHub merge state | Checks | Open threads | Recommended disposition |
| --- | --- | --- | ---: | --- | --- | ---: | --- |
| [#956 BAC-541: C2 approval-bound settlement (VerifiedApproval witness)](https://github.com/bb-connor/arc/pull/956) | main | No | 24 / +5,336 / -673 | dirty | 51 success, 1 failure | 27 | Older economy lane; defer unless selected release needs it. |
| [#957 M0: Chio Pass build (soulbound credential + 3 kernel controls)](https://github.com/bb-connor/arc/pull/957) | main | No | 34 / +10,363 / -33 | dirty | 58 success, 2 failure | 25 | Older economy lane; defer unless selected release needs it. |
| [#958 M1: Phase-0 launch (tokenless marketplace + Pass M0 wired)](https://github.com/bb-connor/arc/pull/958) | #957 | No | 67 / +12,603 / -332 | unstable | 41 success, 2 skipped, 2 failure | 57 | Older economy lane; defer unless selected release needs it. |
| [#959 M2: Phase-1 (off-chain netting + verifiability pricing + x402/EAS interop)](https://github.com/bb-connor/arc/pull/959) | #958 | No | 33 / +9,401 / -24 | unstable | 2 skipped, 47 success, 2 failure | 54 | Older economy lane; defer unless selected release needs it. |
| [#1029 BREAKING: feat(security): integrate agent economy and enterprise evidence authority](https://github.com/bb-connor/arc/pull/1029) | main | No | 2,321 / +1,035,094 / -189,352 | dirty | 25 failure, 86 success, 15 skipped, 32 cancelled | 0 | Historical omnibus; semantic coverage reconciliation before closure. |
| [#1043 Docs/policy expansion design](https://github.com/bb-connor/arc/pull/1043) | main | Yes | 8 / +1,362 / -0 | blocked | 16 success, 2 failure | 0 | Reassess policy design against current implemented roadmap. |
| [#1046 fix: unblock the MCP handshake, path_allowlist, and workspace packaging](https://github.com/bb-connor/arc/pull/1046) | main | No | 12 / +738 / -222 | dirty | 28 success, 3 failure | 2 | Check modern patch equivalents before reviving quickstart fix. |
| [#1056 chore(scripts): add the chio mirror sync script](https://github.com/bb-connor/arc/pull/1056) | main | No | 1 / +182 / -0 | blocked | 14 success, 3 failure | 0 | Revise repository ownership/mirror assumption before use. |
| [#1073 fix: split release qualification budget](https://github.com/bb-connor/arc/pull/1073) | main | No | 11 / +451 / -27 | dirty | 17 success | 1 | Reconcile release-budget fix; current conflicts and open review. |
| [#1092 feat: adopt existing agents into persistent Chio kernels](https://github.com/bb-connor/arc/pull/1092) | main | Yes | 98 / +9,588 / -201 | clean | 8 skipped, 81 success | 2 | Workbench chain; choose supported UI and reconcile native foundation. |
| [#1093 feat(mcp): activate and restore adopted client configurations](https://github.com/bb-connor/arc/pull/1093) | #1092 | Yes | 27 / +928 / -55 | clean | 39 success, 6 skipped | 2 | Workbench chain; choose supported UI and reconcile native foundation. |
| [#1094 feat: package verified agent developer previews](https://github.com/bb-connor/arc/pull/1094) | #1093 | Yes | 6 / +571 / -15 | clean | 10 success | 2 | Workbench chain; choose supported UI and reconcile native foundation. |
| [#1095 test: qualify agent previews in clean Linux runtimes](https://github.com/bb-connor/arc/pull/1095) | #1094 | Yes | 5 / +496 / -0 | clean | 10 success | 1 | Workbench chain; choose supported UI and reconcile native foundation. |
| [#1096 feat(workbench): run delegated repairs with Claude Code](https://github.com/bb-connor/arc/pull/1096) | #1095 | Yes | 27 / +1,317 / -26 | clean | 19 success, 4 skipped | 4 | Workbench chain; choose supported UI and reconcile native foundation. |
| [#1097 feat(preview): ship a verified native workbench](https://github.com/bb-connor/arc/pull/1097) | #1096 | Yes | 11 / +428 / -12 | clean | 13 success | 1 | Workbench chain; choose supported UI and reconcile native foundation. |
| [#1098 feat(runtime): add durable recursive agent processes](https://github.com/bb-connor/arc/pull/1098) | main | Yes | 32 / +2,653 / -90 | clean | 8 skipped, 68 success | 4 | Process stack: reconcile through #1160 and its disposition record. |
| [#1099 feat(process): add authenticated Python and JavaScript workers](https://github.com/bb-connor/arc/pull/1099) | #1098 | Yes | 33 / +1,966 / -19 | clean | 5 skipped, 23 success | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1100 feat(langgraph): recover tool calls through Chio processes](https://github.com/bb-connor/arc/pull/1100) | #1099 | Yes | 16 / +1,365 / -30 | clean | 14 success | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1101 feat(cli): run durable process hosts with existing MCP tools](https://github.com/bb-connor/arc/pull/1101) | #1100 | Yes | 23 / +1,436 / -10 | clean | 46 success, 7 skipped | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1102 feat(process): run repository reviews with verified receipts](https://github.com/bb-connor/arc/pull/1102) | #1101 | Yes | 23 / +1,926 / -18 | clean | 6 skipped, 39 success | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1103 feat(process): add durable capability-scoped mailboxes](https://github.com/bb-connor/arc/pull/1103) | #1102 | Yes | 32 / +1,656 / -137 | clean | 6 skipped, 46 success | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1104 feat(process): supervise durable worker applications](https://github.com/bb-connor/arc/pull/1104) | #1103 | Yes | 22 / +1,476 / -70 | clean | 6 skipped, 39 success | 4 | Process stack: reconcile through #1160 and its disposition record. |
| [#1105 feat: package native process starter and publishable worker SDKs](https://github.com/bb-connor/arc/pull/1105) | #1104 | Yes | 20 / +878 / -10 | clean | 50 success, 2 skipped | 4 | Process stack: reconcile through #1160 and its disposition record. |
| [#1106 feat(cli): inspect live process runs and retained worker logs](https://github.com/bb-connor/arc/pull/1106) | #1105 | Yes | 11 / +519 / -10 | unstable | 4 skipped, 52 success, 21 cancelled | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1107 feat: run adaptive child processes through kernel tools](https://github.com/bb-connor/arc/pull/1107) | #1106 | Yes | 40 / +2,699 / -296 | clean | 53 success, 4 skipped | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1108 feat: run repository reviews with adaptive child processes](https://github.com/bb-connor/arc/pull/1108) | #1107 | Yes | 21 / +2,180 / -1 | unstable | 4 skipped, 53 success, 21 cancelled | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1109 feat: package adaptive reviews with an offline runtime](https://github.com/bb-connor/arc/pull/1109) | #1108 | Yes | 10 / +2,399 / -5 | clean | 10 success | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1110 feat: execute AI SDK tools through native Chio processes](https://github.com/bb-connor/arc/pull/1110) | #1109 | Yes | 22 / +1,895 / -2 | clean | 15 success, 6 cancelled | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1111 feat: journal AI SDK model responses before tool execution](https://github.com/bb-connor/arc/pull/1111) | #1110 | Yes | 21 / +1,514 / -176 | clean | 15 success, 15 cancelled | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1112 feat: keep durable model responses outside process checkpoints](https://github.com/bb-connor/arc/pull/1112) | #1111 | Yes | 38 / +1,275 / -62 | clean | 5 skipped, 24 success, 29 cancelled | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1113 feat: resume AI SDK swarms across native child waits](https://github.com/bb-connor/arc/pull/1113) | #1112 | Yes | 18 / +942 / -14 | clean | 15 success | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1114 feat: benchmark AI SDK research swarms against local callbacks](https://github.com/bb-connor/arc/pull/1114) | #1113 | Yes | 10 / +1,477 / -1 | clean | 14 success, 14 cancelled | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1115 feat(process): attest mailbox senders with the kernel-selected process](https://github.com/bb-connor/arc/pull/1115) | #1114 | Yes | 12 / +222 / -43 | clean | 41 success, 2 skipped | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1116 feat(process): bound worker attempts with OS resource ceilings](https://github.com/bb-connor/arc/pull/1116) | #1115 | Yes | 6 / +198 / -7 | clean | 38 success, 6 skipped | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1117 feat(security): integrate durable custody and negotiated consumer boundaries](https://github.com/bb-connor/arc/pull/1117) | main | Yes | 2,328 / +625,163 / -37,364 | blocked | 7 failure, 14 skipped, 107 success, 1 cancelled | 12 | Current M4 ledger; current head contained in #1160. |
| [#1118 feat(process): export and import host state between locations](https://github.com/bb-connor/arc/pull/1118) | #1116 | Yes | 11 / +969 / -7 | clean | 3 skipped, 39 success | 4 | Process stack: reconcile through #1160 and its disposition record. |
| [#1119 feat(process): redispatch read-only tools after an unknown outcome](https://github.com/bb-connor/arc/pull/1119) | #1118 | Yes | 16 / +349 / -48 | clean | 36 success, 2 skipped | 4 | Process stack: reconcile through #1160 and its disposition record. |
| [#1120 perf(store): install the rollback anchor record with one durable write](https://github.com/bb-connor/arc/pull/1120) | #1119 | Yes | 25 / +627 / -113 | clean | 23 success, 5 skipped | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1121 feat(runner): bound cooperative suspensions separately from failures](https://github.com/bb-connor/arc/pull/1121) | #1120 | Yes | 12 / +170 / -55 | clean | 41 success, 2 skipped | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1122 perf(store): persist a recovery claim with the transition it protects](https://github.com/bb-connor/arc/pull/1122) | #1121 | Yes | 10 / +625 / -189 | clean | 27 success, 1 skipped | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1123 perf(store): persist recovery claims inside the joint transactions they precede](https://github.com/bb-connor/arc/pull/1123) | #1122 | Yes | 16 / +1,146 / -185 | clean | 39 success, 3 skipped | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1124 feat(process): declare and enforce the process ABI](https://github.com/bb-connor/arc/pull/1124) | #1123 | Yes | 11 / +134 / -4 | clean | 8 skipped, 53 success, 26 cancelled | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1125 feat(process): account resident memory and CPU per attempt](https://github.com/bb-connor/arc/pull/1125) | #1124 | Yes | 8 / +385 / -79 | clean | 36 success, 2 skipped | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1126 feat(mailboxes): delivery leases for competing consumers](https://github.com/bb-connor/arc/pull/1126) | #1125 | Yes | 10 / +539 / -35 | clean | 2 skipped, 36 success | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1127 feat(process): share worker slots fairly across subtrees](https://github.com/bb-connor/arc/pull/1127) | #1126 | Yes | 7 / +169 / -12 | clean | None recorded | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1128 feat(mailboxes): bounded waits for a send on receive](https://github.com/bb-connor/arc/pull/1128) | #1127 | Yes | 7 / +186 / -23 | clean | 36 success, 2 skipped | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1129 fix(cli): resolve the checkout at runtime so release builds reproduce](https://github.com/bb-connor/arc/pull/1129) | #1128 | Yes | 28 / +596 / -46 | clean | 58 success, 6 skipped | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1130 fix(process): repair durable recovery, relocation, and resource enforcement](https://github.com/bb-connor/arc/pull/1130) | #1129 | Yes | 20 / +629 / -208 | clean | 3 skipped, 39 success | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1131 feat(process): integrate durable hosting with security launch contracts](https://github.com/bb-connor/arc/pull/1131) | #1117 | Yes | 272 / +34,823 / -1,081 | dirty | 7 skipped, 76 success, 2 cancelled, 1 failure | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1132 feat(process): resume mini-SWE-agent commands through Chio](https://github.com/bb-connor/arc/pull/1132) | #1131 | Yes | 14 / +3,998 / -0 | clean | 12 success | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1133 feat(process): isolate Python workers from host administration](https://github.com/bb-connor/arc/pull/1133) | #1132 | Yes | 12 / +896 / -20 | clean | 12 success | 5 | Process stack: reconcile through #1160 and its disposition record. |
| [#1134 feat(process): recover native container workers after host loss](https://github.com/bb-connor/arc/pull/1134) | #1133 | Yes | 18 / +1,334 / -27 | clean | 42 success, 2 skipped | 4 | Process stack: reconcile through #1160 and its disposition record. |
| [#1135 feat: run native mini-SWE workers with durable model calls](https://github.com/bb-connor/arc/pull/1135) | #1134 | Yes | 22 / +1,738 / -51 | unstable | 12 success, 2 failure | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1136 fix(sqlite): inspect the open database descriptor directly](https://github.com/bb-connor/arc/pull/1136) | main | Yes | 3 / +104 / -12 | blocked | 6 skipped, 34 success, 3 failure | 0 | Process ledger records incorporation; verify final source then close. |
| [#1137 feat: package native coding operator workflows](https://github.com/bb-connor/arc/pull/1137) | #1135 | Yes | 26 / +2,232 / -13 | clean | 7 skipped, 50 success | 4 | Process stack: reconcile through #1160 and its disposition record. |
| [#1138 feat: add durable repository execution and verified patch export](https://github.com/bb-connor/arc/pull/1138) | #1137 | Yes | 31 / +3,486 / -72 | clean | 2 skipped, 42 success | 1 | Rewritten/side-branch equivalent; check dispositions, not ancestry alone. |
| [#1139 feat: verify received repository patches against trusted source](https://github.com/bb-connor/arc/pull/1139) | #1138 | Yes | 9 / +665 / -10 | clean | 12 success | 2 | Rewritten/side-branch equivalent; check dispositions, not ancestry alone. |
| [#1140 fix: select xtask workspace from the invocation directory](https://github.com/bb-connor/arc/pull/1140) | #1138 | Yes | 4 / +358 / -9 | clean | 29 success | 1 | Rewritten/side-branch equivalent; check dispositions, not ancestry alone. |
| [#1141 feat: add explicitly authorized coding task sessions](https://github.com/bb-connor/arc/pull/1141) | #1139 | Yes | 18 / +2,524 / -13 | clean | 34 success | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1142 fix: lease short worker sockets for deep process state paths](https://github.com/bb-connor/arc/pull/1142) | #1141 | Yes | 10 / +632 / -35 | clean | 2 skipped, 39 success | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1143 test: compare native coding recovery with upstream Docker agent](https://github.com/bb-connor/arc/pull/1143) | #1142 | Yes | 10 / +1,961 / -3 | clean | 14 success, 4 skipped | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1144 ci: qualify optimized mini-swe comparison builds](https://github.com/bb-connor/arc/pull/1144) | #1143 | Yes | 4 / +720 / -3 | clean | 10 success, 1 skipped | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1145 feat: deduplicate durable repository snapshots](https://github.com/bb-connor/arc/pull/1145) | #1144 | Yes | 10 / +735 / -15 | clean | 13 success, 3 skipped | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1146 feat: share immutable JSON checkpoint segments](https://github.com/bb-connor/arc/pull/1146) | #1145 | Yes | 9 / +828 / -15 | clean | 12 success, 1 skipped | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1147 feat: scope coding workspaces to committed repository paths](https://github.com/bb-connor/arc/pull/1147) | #1146 | Yes | 15 / +784 / -38 | clean | 12 success, 1 skipped | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1148 docs: route agent applications to native process profiles](https://github.com/bb-connor/arc/pull/1148) | #1147 | Yes | 4 / +66 / -21 | clean | 7 success | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1149 feat: continue independent workers after peer failures](https://github.com/bb-connor/arc/pull/1149) | #1148 | Yes | 9 / +686 / -9 | clean | 39 success, 3 skipped | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1150 feat: supervise dynamic child failures](https://github.com/bb-connor/arc/pull/1150) | #1149 | Yes | 27 / +1,635 / -61 | clean | 45 success, 3 skipped | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1151 feat: renew live mailbox delivery leases](https://github.com/bb-connor/arc/pull/1151) | #1150 | Yes | 9 / +870 / -10 | clean | 3 skipped, 39 success | 1 | Process stack: reconcile through #1160 and its disposition record. |
| [#1152 perf(kernel): omit unused custody issuer dependencies](https://github.com/bb-connor/arc/pull/1152) | #1151 | Yes | 5 / +107 / -8 | unstable | 29 success, 1 skipped, 1 failure | 2 | Process stack: reconcile through #1160 and its disposition record. |
| [#1153 feat(process): bind shared resource writes to kernel callers](https://github.com/bb-connor/arc/pull/1153) | #1152 | Yes | 85 / +9,604 / -83 | unstable | 52 success, 9 skipped, 2 failure | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1154 fix(process): bind recorded results to the requested invocation](https://github.com/bb-connor/arc/pull/1154) | #1153 | Yes | 21 / +1,146 / -53 | unstable | 43 success, 3 skipped, 2 failure | 3 | Process stack: reconcile through #1160 and its disposition record. |
| [#1155 docs(install): provide a usable path to the process preview](https://github.com/bb-connor/arc/pull/1155) | #1154 | Yes | 3 / +124 / -10 | clean | 7 success | 0 | Process stack: reconcile through #1160 and its disposition record. |
| [#1156 feat: add protected agent execution, Hermes support, and release qualification](https://github.com/bb-connor/arc/pull/1156) | main | No | 12,946 / +448,603 / -3,926 | unstable | 11 skipped, 78 success, 1 cancelled | 3 | Separate native-host release; reconcile with #1160. |
| [#1158 docs(papers): September 2026 whitepaper review](https://github.com/bb-connor/arc/pull/1158) | main | Yes | 14 / +7,078 / -0 | blocked | 16 success, 1 failure | 1 | Historical paper review; reconcile subsequent implementation. |
| [#1159 feat(paper): whitepaper roadmap phases 0 to 3](https://github.com/bb-connor/arc/pull/1159) | main | Yes | 275 / +54,007 / -1,832 | blocked | 6 skipped, 51 queued, 11 success, 2 failure, 5 in_progress | 15 | Runtime/formal/paper work; review code and evidence before merge. |
| [#1160 fix(security): integrate process custody and M4 consumer boundaries](https://github.com/bb-connor/arc/pull/1160) | main | Yes | 2,811 / +710,391 / -42,897 | blocked | 42 queued, 7 skipped, 13 in_progress, 38 success, 2 failure | 0 | Primary integration candidate; finish broad gates and M5. |
| [#1161 feat: funded native admission and authenticated peer verifier transport](https://github.com/bb-connor/arc/pull/1161) | main | Yes | 4,206 / +1,031,604 / -41,875 | blocked | 5 skipped, 98 queued, 1 failure | 0 | Sibling funded-work branch; recovery/settlement reruns unfinished. |
| [#1162 wip: outcome continuation, unknown release, A2A v1 edge, and paper review notes 15 to 35](https://github.com/bb-connor/arc/pull/1162) | #1159 | Yes | 3,688 / +520,068 / -612 | unstable | 5 skipped, 64 queued | 0 | Preservation checkpoint; split source from evidence and requalify. |
| [#1163 wip(bench): 2026-09-13 bilateral admission benchmark results](https://github.com/bb-connor/arc/pull/1163) | #1159 | Yes | 22 / +1,128 / -1,326 | unstable | 7 queued | 0 | Benchmark data; validate provenance and whether it should replace citations. |
| [#1164 wip(workbench): git task engine](https://github.com/bb-connor/arc/pull/1164) | #1097 | Yes | 20 / +1,065 / -157 | unstable | 11 queued | 0 | Untested workbench checkpoint; decide product role. |

### backbay-labs/chio

| PR and title | Base | Draft | Files / + / - | GitHub merge state | Checks | Open threads | Recommended disposition |
| --- | --- | --- | ---: | --- | --- | ---: | --- |
| [#1 Fix policy identity, receipt association, and atomic signed guard installation](https://github.com/backbay-labs/chio/pull/1) | main | Yes | 26 / +1,005 / -145 | clean | None recorded | 0 | Contained in #4/#5; review as part of their complete fixes. |
| [#4 Add runnable Agentic OS applications with governed effects](https://github.com/backbay-labs/chio/pull/4) | main | Yes | 149 / +25,616 / -315 | unstable | 10 skipped, 72 success, 7 failure | 0 | Contained in #5; application preview already exists. |
| [#5 feat: ship complete governed builder applications and protocol clients](https://github.com/backbay-labs/chio/pull/5) | #4 | Yes | 307 / +42,551 / -2,603 | unstable | 89 success, 11 skipped, 1 failure | 0 | Bounded application candidate; fix advisory gate, reconcile kernel. |
| [#9 feat(cli): launch the Megastart mission operator](https://github.com/backbay-labs/chio/pull/9) | main | Yes | 39 / +14,319 / -0 | unstable | 3 skipped, 47 success, 4 failure | 0 | Select product role; repair four failing checks and integrate. |
| [#10 feat(mcp): bind native sessions to retained shared authority](https://github.com/backbay-labs/chio/pull/10) | codex/required-agent-integrations-20260909 | Yes | 12 / +516 / -52 | clean | 45 success, 9 skipped | 0 | Close retained-parent dependency and qualify installed native profile. |

## Core head manifest

| Repository / PR | Exact inspected head |
| --- | --- |
| bb-connor/arc #956 | 2e52b7a2fe30249420cf53f77d1cef1fe7528fad |
| bb-connor/arc #957 | d7cce14cfe6746e697b850b3ceff4e04051bd280 |
| bb-connor/arc #958 | 813b1896f926ed4b57e35e5211e4691b21e13904 |
| bb-connor/arc #959 | ffaeb21d159e15259276bd805bd473f77adb69db |
| bb-connor/arc #1029 | cbbba8cf2178cbbdd7b6b38a121e59365eb452ac |
| bb-connor/arc #1043 | 9a3fd87867d6f3de0b8d6834dab6b3a434d5bf5c |
| bb-connor/arc #1046 | e693691ceab65ee73b03e8d23a2275f3227e7dcd |
| bb-connor/arc #1056 | 716e056c0dbafe8399a094a70ba640d0e2bd6a9c |
| bb-connor/arc #1073 | cae222b085229d0f8c7c363694cf409307e63a68 |
| bb-connor/arc #1092 | 30250dd109eb834f5a2aa5cdc49aad8c6fe00937 |
| bb-connor/arc #1093 | 9a84798adc38057c573e2dc54f16d43cdda74079 |
| bb-connor/arc #1094 | a345db2b0a3271bd1e01487d86606ac7290170e4 |
| bb-connor/arc #1095 | 4db368d98c3623b2d65a5e6914254afe3dc2af7d |
| bb-connor/arc #1096 | bec09e7ee386ed866b0c1ebce4ddd8175384e6d2 |
| bb-connor/arc #1097 | 80e586c77232dae66b0a852e5c016fd7f8f27027 |
| bb-connor/arc #1098 | 7b4fe03abe28d9dd08d0981e34660ec086a1a919 |
| bb-connor/arc #1099 | 1002146719b6ab87f8a588f25a7be13775c09ab3 |
| bb-connor/arc #1100 | 8940377cf7d93ac9bd170be607c51d95001d0208 |
| bb-connor/arc #1101 | fe45c50666e76ae09fb36d686fcd9a611a1db7e0 |
| bb-connor/arc #1102 | 2abeb9d524475acc54e3c72b28ea808324c4cbcf |
| bb-connor/arc #1103 | 43b4e62378910705c857294fe7b02b66773afded |
| bb-connor/arc #1104 | 4a5a2ff51f83980a03d6d0f620a504a694d33564 |
| bb-connor/arc #1105 | 3156e516fcead5c3582ce6dab71b26a8adb4d911 |
| bb-connor/arc #1106 | 1d777a62e2cc9a226549532219af95c47e0829ec |
| bb-connor/arc #1107 | cab6645d94bbea905e4d4724e7454912c7af075f |
| bb-connor/arc #1108 | b52440916a3007af0c04c7c4f8621211b1823e87 |
| bb-connor/arc #1109 | 354dbb515e6503e3c9ebefb8233c3a738c845e49 |
| bb-connor/arc #1110 | 2e7491a6046442e033e677e127c8cdbe69d30c29 |
| bb-connor/arc #1111 | 8be2f2d718f85b3755bdb93fe7a28b24e6d78418 |
| bb-connor/arc #1112 | 789d2617c37c075e894a6f5fad1e487982ab4fcf |
| bb-connor/arc #1113 | 2e2b45c4560a5b19214be1f47ccc2f2bba8359bc |
| bb-connor/arc #1114 | 2020939c1edb633a12f7b57db8ff3c68cb2f8d4f |
| bb-connor/arc #1115 | d63d7bcf45a533cdb7a0b2fc7f69f5ab18a27741 |
| bb-connor/arc #1116 | 92e6acc8058ae36634498b304e9067135fe3f80a |
| bb-connor/arc #1117 | 5d1a9ec0d900bd03ce55de903919d972be852d79 |
| bb-connor/arc #1118 | 7599eb9d1eb14a60d9d128a24f588f449458dd73 |
| bb-connor/arc #1119 | bca43783e15ebdb978083cfd83b627ff03d78be1 |
| bb-connor/arc #1120 | 760c23730d8257053df177d43e5d5839f89de2cd |
| bb-connor/arc #1121 | 1c07de944e7bfbf8d77e0cf23c8c247c9bda3aa8 |
| bb-connor/arc #1122 | 1e58a0dd59fea3e13e314db7e8df733603eeb5d2 |
| bb-connor/arc #1123 | b4e57e9cfa6ca8f228e785975ee770ad4a20c5de |
| bb-connor/arc #1124 | de2a086b56cc6449522e61830773a450dd3fbe8b |
| bb-connor/arc #1125 | 6535f35a4d1d964f63af10dd09fc5b6dde7160ab |
| bb-connor/arc #1126 | 048b868925e6d4f465c83ed121875fc06897f8c0 |
| bb-connor/arc #1127 | b2f87938c7ebe547d7c9d7ae9f4c490d977aca6e |
| bb-connor/arc #1128 | 2d0a89baa0f1fde3925bd2e7feda918cfc7cea61 |
| bb-connor/arc #1129 | dfd13be9563895613553024dd65f16baf08a1766 |
| bb-connor/arc #1130 | 752f7d7d5145a16b1c486381f4b61453f00189e6 |
| bb-connor/arc #1131 | 75d664822abf5f6e8da6e6f858cab5a6d81dc3bd |
| bb-connor/arc #1132 | 607620d99e82cdf230219889d3fbfe2ec3c40c04 |
| bb-connor/arc #1133 | dd6734f7447a2156289949ca4bafa31c34fdb9f6 |
| bb-connor/arc #1134 | db8d1c6ac9d6579074fc53c6f5899af17634683d |
| bb-connor/arc #1135 | e5e39993477bd7337287d5af736b617decfe91b4 |
| bb-connor/arc #1136 | dcd455f07e163abba68f61f42f131d29964bceee |
| bb-connor/arc #1137 | a5c93261db8741c822ad7e3152b1e68b5854a925 |
| bb-connor/arc #1138 | 23549b979f04a3d563a94499db4bd11b53425155 |
| bb-connor/arc #1139 | 0ccca5bca6e0c47fca16d11bee202512511bd9ac |
| bb-connor/arc #1140 | 90914a3e5288bc0094588bbf84a86422364c2af9 |
| bb-connor/arc #1141 | 10459274a3687ccbabafa9335344a8f9dfc24441 |
| bb-connor/arc #1142 | 5bba03333ff2c426a7b6e051d93ad6310999c07b |
| bb-connor/arc #1143 | 4064e31ddc630e1dff43b8c1c12b4a550157487c |
| bb-connor/arc #1144 | 515ee6fd05c3aef4c5151c47bf72e470cde1f618 |
| bb-connor/arc #1145 | 45a24f3c966eb26dfb787eb51c9e214af7fdeed1 |
| bb-connor/arc #1146 | 163c2e2ea898adddf87c0edad8d9fb0a843a615f |
| bb-connor/arc #1147 | 4c500826da2abf7151dab7acdaeaddf47dee0349 |
| bb-connor/arc #1148 | 8df43e7cb83288c06ed75980d064a33eb62921a9 |
| bb-connor/arc #1149 | edb4c94763f54089045a839334bf1ef12492439d |
| bb-connor/arc #1150 | e6f66cba20e9554d5d954a4f8d4b1b4423d1a2e7 |
| bb-connor/arc #1151 | 8a3b0bc2acb2633d635e20ac89201cf4dcc30a45 |
| bb-connor/arc #1152 | cfd608f79339129a9d810b6a62c28043beb13afb |
| bb-connor/arc #1153 | 3ca011d103c82ddaba88dc829680f248bafe28d6 |
| bb-connor/arc #1154 | d99e03027c57dc9c0929a5bca553e745c6286d99 |
| bb-connor/arc #1155 | 2e84f121273df7f205cc218739b86e93c91bdc37 |
| bb-connor/arc #1156 | 7059c71ca86239e1ba5fe7b63c391db2b2ded3bc |
| bb-connor/arc #1158 | 728abe498a6db4ab43814fcfd332458cacc0c1d7 |
| bb-connor/arc #1159 | 2b3b5af8cbfbc6f16ce6005de3f97cd149803b81 |
| bb-connor/arc #1160 | b7211ce2d063ea36ea0f512b6f3c0253b65ecd71 |
| bb-connor/arc #1161 | 7755d3762baa5e0fda0d171835a9000c26de9033 |
| bb-connor/arc #1162 | d4e2b1da9d6a6ca42b24c3b18f73616fae425243 |
| bb-connor/arc #1163 | 6e6aba76f4ba579cb16d807af930c370db6d26f5 |
| bb-connor/arc #1164 | 5bdf08fc3573eba00dd2be7b4fab1c22e48db1f7 |
| backbay-labs/chio #1 | 62ad984d0910d95698d1ca9ada045d45e3f231a7 |
| backbay-labs/chio #4 | 282eae168f6460f63837fe9cb1a3e3b4f809f137 |
| backbay-labs/chio #5 | 1346840e1192b5d6baf581c447cd37550e5c0144 |
| backbay-labs/chio #9 | a9225e45527e67ed3d400a27011a1f3d0e595e3a |
| backbay-labs/chio #10 | 6753edbc365f5ea820224b96a59940feedbfca94 |
