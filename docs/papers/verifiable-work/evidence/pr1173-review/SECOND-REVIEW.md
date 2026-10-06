# Additional production and evidence review

The external static review of `5dc7921d3c6437db40a01ceea20a9fdb1396ba31`
reported 37 additional findings (four P1, 30 P2 and three P3). This disposition
records the repairs separately from the earlier review. Source changes pass the current local source-bound package. Final hosted
candidate qualification remains pending; passing historical jobs do not qualify it.

## Runtime and protocol repairs

| Finding | Owning repair and acceptance boundary |
| --- | --- |
| Delegated permit expiry during execution or replay | Fresh dispatch uses current time; immutable output-contract validation uses the signed issuance interval. Expiry/restart regressions retain exact receipts and payment identity. |
| Definite payment decline becomes ambiguous | Persist cancellation only for the adapter's authoritative `Declined` or `InsufficientFunds` response. Unavailable or ambiguous authorization retains exposure. |
| Ordinary output denial wedges restart | Raw guards run before return retention. Post-transform denials retain output and hold under a checked recovery claim without blocking unrelated startup. All 15 delegation lifecycle tests pass, including both denial paths. |
| A2A conformance does not compile | Use canonical byte ingress in the actual conformance target. |
| Forged receipt identity tests expect success | Require strict signature failure for substituted weak identities. |
| Capture waiver is reported as failed payment | Completed contractual release is settled at zero monetary charge, preserving positive realized budget cost and signed successor authority. |
| Dispatch sealing commits before signing can fail | Validate, sign, insert and claim allocation in one immediate transaction; failed sealing rolls back and permits replacement. |
| Blocking A2A results exhaust global retention | Release blocking task custody on both success and failure; deferred custody is bounded globally and per capability subject. |
| Native launch-owner regression misses the call site | Retire the preparation Tokio runtime after the actual broker MCP preparation call, then require real confined TLS execution and receipts on x86. |
| Bilateral wire errors expose local details | Both refusal profiles emit fixed public codes/reasons; typed internal causes remain local. |
| Revocation sink mixes independent epoch domains | Pin one root verifier, construct its empty view locally and authenticate every root before selecting a batch epoch. Multi-origin aggregation is not supplied. |
| Underscore consistency aliases bypass the spec vocabulary | Reject underscore forms in both parsers; update active fixtures to the hyphenated vocabulary. |
| SQLite journal codec omits successor states | Decode resolving/resolved and contractual capture waiver exactly. |
| Presenter text overrides typed error prefixes | Prefer registered prefixes; recognize only the exact locally generated signer-independence diagnostic. |

## Qualification and supply-chain repairs

The main CI workflow now selects packet and integration bases. A new matrix
builds, lints and tests all five standalone research workspaces; their locked
graphs use the production patch set. Cargo Vet checks each graph, and Cargo Audit
checks the root, both generated deployment locks and all five standalone locks.
The Python participant uses hash-locked dependencies and all its unit tests.
Unfiltered OSV results are blocking even when a local suppression file exists.
Proof-room lock drift and registered-work schema controls run in structural CI.
Experimental escrow is excluded from production web3 compilation while retaining
its dedicated bytecode suite. No new audit exemption or advisory ignore is added.

The Vet policy checker rejects weakened criteria as well as new exemption rows.
Its sole explicit composite exception is the exact AWS-LC upstream-review
policy joined to the fork reconstruction, feature and lint gates. Cargo Vet
alone does not certify the published upstream crate as deployable.

CODEOWNERS now covers the source, audit, npm and Kani trust anchors using a valid
repository owner. The inspected repository ruleset requires selected status
checks but does not enforce code-owner approval. File ownership is consequently
review routing, not an independently enforced approval barrier. This repair does
not invent a branch-protection guarantee or change repository policy.

## Research and manuscript corrections

- The baseline excludes two unpaired agreement-version cases and a denial caused
  incidentally by the fixture approval record. Its selected comparison has three
  hardened survivors; it establishes no universal protocol limitation. The new
  diagnostic report disqualifies its own timing samples.
- The paper explicitly locates the cross-record joins in the fixed-profile
  example guard, including the 100-unit program. General runtime admission
  integration remains W1 work rather than an implementation claim.
- A real host canary replaces the machine-specific nonexistent path; the
  unconstrained positive control reads it. Existing retained files open without
  symlink following or FIFO blocking and must be regular files. Transient TLS
  accept errors back off and retry.
- Claim replay covers post-deadline Payable/Paid states and exact error reasons.
  Its source-bound record contains 270 traces, 738 matched SQL steps and 271
  passing bytecode tests; the expire-payable mutation produces nine failures.
  Historical 118-trace records are retained separately.
- The lab now mutates accepted knowledge clearing and rollback and independently
  checks release binding, read authority, scope and epochs. Seeded faults trigger
  the assertions. All 40 tests and five source-bound qualification commands pass.
  Initial knowledge remains supplied and garbage-collection payloads are outside
  the model. G2 records that the previous zero-violation counts did not establish
  these missing predicates.
- The partial-outcome subfinding is not confirmed: F06/F14 correctly withhold a
  partial result after a lost acknowledgement, then authenticated provider
  evidence establishes Partial. New assertions check both steps in both arms.
- Normative supplements specify execution-only receipts and monetary successors.
  DSSE co-signing requires reconstruction and party/fingerprint checks, without
  inventing independent policy evaluation. The receipt ALPN and bounded framing
  are specified; passport revocation is scoped to transport-directory removal.
- Canonical reproduction instructions use portable paths. Missing private
  historical observations are marked unverified and are not qualification
  inputs. Private session narration is removed from canonical design documents;
  authenticated historical artifacts retain their original bytes.
- Generated evidence is marked for review display. Current appendix counts are
  derived from authenticated terminal output, with optional chain results bound
  to their historical source inventory. Publication checks require frozen named
  evidence and claim-register agreement; changing status flags alone fails.
  Publication and foundational claims remain open.

## Local qualification

Source `d187d763f4879b358c8911e79e0fd3e1a25fe7a4` passes all 21 terminal native commands against 37,319 unchanged source files and 48 retained outputs. Earlier complete, failed and interrupted campaigns retain their original source and scope. Final-head hosted and external production acceptance remain separate.

Follow-up platform and structural repairs pass 9 outcome-ledger tests,
8 API-protect tests, 6 control-plane init tests, the complete 41-test
return-context inventory and 52 threat tests, with strict affected Clippy.
The 100-gate diagnostic retains its five initial failures; every failure
has a passing targeted recheck. Historical terminal labels are preserved
under an exact digest pin; mutable protocol descriptions use ACP-Client.
The actual AWS-LC composite gate passes without a new audit exemption or
advisory ignore. Both the real native broker regression and all x86
acceptance boundaries still require hosted execution.

The broker audit classification repair reuses the security lane's typed
client-fault handling. All 206 default broker tests pass across every target,
including both hostile-frame provisioning and SIGTERM/restart regressions.
Both regressions also pass in separate test processes. Strict all-target Clippy
with real Linux features passes. The earlier one-pass/two-failure reproduction
remains failed. Storage, invariant and authority errors retain their fatal path.

## Final acceptance

The replacement candidate still needs terminal main CI, research matrix, all
34 x86 fuzz targets, 53 selected Kani harnesses, the complete AWS-LC composite
gate, advisory scans, the actual native broker call-site regression and both
confined PostgreSQL trajectories with 23 independently verified receipts.
This record is not merge, deployment, external-operation or publication approval.

The full CI aggregate also requires the separately authorized committed Linux
evidence package. On October 5, the repository had no
`CHIO_COMMITTED_LINUX_EVIDENCE_SHA` or `CHIO_ENTERPRISE_EVIDENCE_POLICY_JSON`.
Another execution lane was rotating the authorized source and definition. This
PR does not replace those trust roots, self-authorize its source, or synthesize a
signed evidence package. The missing operational prerequisite remains open until
the protected capture and finalizer supply and verify the actual package.
The user confirmed that the security agent owns that package. This candidate's
CI caller uses the already merged, repository-authorized definition
`c009aced79d69f01880b5f7c53ed3c1754e3b7da`; repository authority variables remain
under that separate lane's ownership.

The first replacement at `28842e598e` exposed two additional qualification
defects: the publication freeze omitted four named claim sources, and the
composite build-custody test lacked a newly invoked shell-control fixture. Both
are repaired with retained reproductions. All 20 paper-tool tests and the
complete AWS-LC composite gate pass locally. Neither repair changes production
Rust behavior or weakens an acceptance check. Renewed source qualification and
replacement-commit hosted acceptance remain required.

The historical x86 run at `28842e598e` passed both actual PostgreSQL
trajectories. All 14 worker and nine claim-loss receipts verify independently;
the public reports, keys and authenticated archive bytes are retained under
`postgres-history/28842e598e`. The overall run remains failed because its
separate broker retirement regression lacked the key-log helper environment.
The prepared action now builds and atomically validates both candidate key-log
services, and the privileged regression receives their paths explicitly. All
20 native CI controls, the real export-script controls, 20 definition controls
and the complete security CI mutation checks pass locally.

The security lane's new authorized workflow also invokes closed-shard producer
controls absent from this candidate. Its reviewed supporting-source handoff
must be reconciled with the finalized definition and signed package before full
enterprise acceptance. The current pin preserves the authorized definition;
copying only a self-test, changing authority variables or bypassing that source
closure would supply no qualification. This operational integration remains
under the security lane's package responsibility.

The `acf34b0746` historical-artifact job failed because a current comparison
correction had changed the hash-bound archived README. The repaired README
agrees byte-for-byte with its original assembly; current correction navigation
now lives in `HISTORICAL_VALIDATION.md`. All 15 historical tests and the actual
read-only validator pass with unchanged archive pins, file hashes and tamper
assertions. The failed hosted job remains failed and requires a final-head rerun.


Final source `91373484e6feafce458de730c10e5f2e39af5168` repairs the reproduced A2A lifecycle defect by rejecting
unsupported background execution before accepting work. V1 GetTask observes
state without dispatch; task access binds both the retained caller label and
capability subject. Standard v1 task errors preserve local typed causes and
do not disclose another caller's task. All 116 edge tests, three real client-edge
HTTP scenarios and both strict Clippy commands pass. Blocking task results retire
after delivery; the legacy explicit execution-on-poll lifecycle remains bounded.

The other hosted repairs remove only obsolete dependency skips, restore the
portable test import, qualify an enforcing controller-specific nested-auditor
profile while proving leaf restrictions with an actual contrast, and update
six formal test anchors with all 16 real counterexamples reproduced. Formal
coverage retains 66 rows and 182 artifacts. The PostgreSQL lifetime fixture now
runs as its actual nonroot caller, with all privileged host checks unchanged.

The CLI authority fixtures reuse the existing private-directory helper and retain
RAII ownership until all service guards shut down. Cluster fixtures explicitly
pin authenticated authority anchors before starting peers, using the existing
replication API with separate signing custody and an independent recovery root.
Both snapshot scenarios moved to a private module with assertions and deadlines
preserved, meeting the unchanged frozen file-size cap. All 14 default lineage,
revocation and cluster integration tests and strict selected-target Clippy pass.
Three existing opt-in cluster cases remain ignored and are not counted as passes.
The original hosted failure, failed first permissions repair and compiler
lifetime failure retain their own raw records. Unenrolled endpoint refusals and
the interrupted broader cluster campaign are retained separately. Production custody checks,
quorum and receipt assertions remain enforced.

The acf34b campaign verifies all 34 actual AddressSanitizer fuzz targets,
53 actual Kani proofs and 23 public PostgreSQL
receipts. Its complete PostgreSQL gate remains failed because the lifetime
fixture selected root; neither successful trajectories nor proof history qualify
the replacement. Its terminal campaign has 108 successes, 13 failures and ten
skips. Raw failed jobs, authenticated public archives and independent
receipt verification are retained. Final-head hosted acceptance and the security
agent's coherent source and signed evidence package remain required.


## Newly reviewed JavaScript advisories

Source `9be968e6869d706fa5c42aef56ce47e52e17bed0` fixes the three advisories reported by the
failed `79d0c8a977` unfiltered scan. Exact published registry fixes replace
compression 1.8.1, proxy-addr 2.0.7 and source-map-js 1.2.1 in all eight affected
installation graphs. Package-manager regeneration changes only these identities
and compression's required edge. Existing private source repairs, upstream
monitors and advisory policy remain unchanged.

Three actual regressions fail against the originals and all six controls pass
against the installed fixes. A real aborted HTTP response releases its native
stream; hostile trust prefixes cannot forge a forwarded caller address; indexed
maps reject malformed and amplifying offsets. All 397 publishable SDK tests,
105 conformance tests and both builds pass. Recursive unfiltered OSV 2.3.6 has
zero findings. The failed job and authenticated public scanner archive remain
retained. All 21 source-bound native commands are renewed; final-head hosted and
separately owned signed security-package acceptance remain required.


## Nonterminal v1 task custody

Source `9b40dc9128b1c62849558af387c1bf918d9c40f0` retains successful nonterminal v1 tasks after blocking
SendMessage while releasing terminal results and execution/projection failures.
Existing caller quotas, authority deadlines and output modes govern retained
custody. V1 GetTask remains observational. Two real SQLite-backed cumulative
approval regressions fail against the original removal, then pass with signed
proposal and receipt authority, stable JSON/text task projections, caller
isolation, cancellation and no dispatch or additional receipts.

The full consumer run also finds four stale threshold fixtures. Bind their exact
tool invocation using the public approval context and install their explicit
approver roster. All successful capture and restart assertions are retained;
production approval validation is unchanged. All ten consumer tests, 116 edge
tests, three live HTTP tests, both strict Clippy commands and structural checks
pass. Formal selection remains 66 rows and 182 artifacts, with its input digest
renewed. Original failures and the preceding candidate's authenticated successful
advisory archive remain historical. Final-head hosted acceptance and the
security owner's coherent source and signed Linux package remain separate.

The preceding hosted flow job passes all 26 default security-type library tests,
then fails its stale twenty-name inventory. The repaired gate includes every
compiled clock and bounded-reader case, preserves the exact default library
target, and rejects each identity substitution through its actual validator.
Positive and negative information-flow models, both portable WASM checks and
all 71 composed test inventories pass in the preceding local campaign.
Its source scope precedes the final delegated-ceiling and revocation repairs;
fresh final-head hosted flow acceptance remains mandatory. Earlier failed checks retain
their actual outcomes. The security owner must still supply the coherent
closed-shard source closure and a fresh caught-only signed Linux package.

## Delegated cost and revocation epoch boundaries

An exact one-invocation dispatch binds the smaller of its signed per-call
and total ceilings. Both ceilings and their currency remain mandatory.
Actual SQLite execution admits the 20/100 and 20/20 grants for the same
20-unit offer, signs the result, captures exactly one 20-unit hold and
replays observationally. A 100/20 grant retains the ordinary worst-case
budget refusal before payment or dispatch. The original maximum rejects
the admissible 20/100 case; all 14 repaired delegation tests pass.

The pinned-origin revocation sink retains the kernel-core strict epoch
compare-and-swap. Identical projected snapshots and older roots remain
idempotent; conflicting installed-epoch hashes, issue times or locally
materialized subjects receive typed rejection without changing the view.
Conflicting signed root bodies inside a batch are rejected before its
single install, including conflicts below a valid highest epoch. Six
authentic-signature controls cover these cases, actual handler rejection
and concurrent duplicate/conflicting writers. Five controls fail against
the original acknowledgement while the replay/stale positive control
passes. The complete typestate-enabled transport campaign records 407
passes and 0 ignored tests. Both affected strict Clippy commands and
the renewed structural controls pass. No second authority registry or
same-epoch update protocol is introduced.

Legacy in-place preparation now retains its effective connection for
signed launch attribution. All ten delivery-revalidation cases and
strict kernel Clippy pass; actual x86 confinement and runtime retirement
remain a separate final-head hosted requirement. The certification
fixtures create private authority parents and live in normal modules
below 2,000 lines. All thirteen certification cases pass with the one
existing timing-sensitive ignore preserved. Complete workspace test compilation
and strict library/binary/example Clippy pass with unchanged captured
Rust/build inputs. The local consumer gate passes six inventories and
fifteen tests, then correctly refuses its first native MCP case on ARM.
That exit-101 campaign remains failed. Complete consumer and workspace
execution require the qualified final-head Linux x86 enforcing host.

The stub scanner distinguishes lint tokens from executable unfinished
macros and comments, admits only the three reviewed exact domain lines,
and removes stale exceptions. The whole repository and every contract
control pass. All 414 SDK/recovery tests pass under system CPython with
both Linux pidfd APIs. The original failed interpreter run is retained;
subsequent workspace/native qualification uses a separately prepared
locked system-CPython environment without changing the dependency lock.

The investigative x86 run at 4b7480c686 completes all five selected native
jobs successfully, including both installed operators, the original
65-second repository command, coding sessions, installed packages,
adaptive review, AI SDK 6/7 and the swarm benchmark. The conditionally
disabled optimized comparison is skipped. Its successful archive is
authenticated in memory; private worker files are not retained. The
earlier request timeout does not reproduce, and retains its failed
source scope. This investigative source precedes the final Rust repairs;
fresh final-head native, PostgreSQL retirement, complete consumer and
workspace qualification remain mandatory.

## Checked-output rejection and replacement graph

Qualified source `199c9cd8a714359eeaf06af3a95a6c26c9df6628` passes all 21 terminal native commands against 37,318 unchanged inputs and 48 retained outputs, including all 20 artifact-tool tests. Earlier qualification packages and all original failed, interrupted and successful campaigns retain their source and result.

The ordinary funded-work suite records 96 passes and six explicit private-chain ignores. Those six Rust tests are not counted as execution; the profile's participant drivers and every separately retained private-chain campaign keep their own command, source and result.

A contractual checker that rejected or panicked once could previously be evaluated again and upgraded to acceptance. All three real kernel regressions fail against that implementation. The repair preserves ordinary validation before persistence and defers opted-in checkers to authoritative durable evaluation, where a denial is retained before payment or release. Rejection remains monotone across the raw and transformed values. Signed redacted denial, one hold release, no output or capture, projection recovery and immutable replay all pass. The captured pre-dependency campaign passes 1,538 kernel tests, strict Clippy and all 72 flow inventories covering 741 tests, with formal and omission controls. Its kernel sources agree with this checkpoint; its earlier whole-input map is retained. Final-head hosted execution remains mandatory.

The publisher yanks iroh-blobs 0.103.0 during preceding-head CI. The replacement 0.103.1 restores per-request mask selection. Authenticated complete delta reviews cover that package and cfg_aliases 0.2.1 to 0.2.2, retaining the existing base acceptance boundaries and adding no exemptions. Actual admitted loopback peers demonstrate that both default and read-only protocols accepted unsolicited writes before the patch. The replacement rejects those writes while signed-root fetches and explicit push permission remain functional. Active root and generated deployment locks, complete affected suites, strict Clippy, six locked audit graphs and enforced deny policy pass on the replacement.

The preceding PostgreSQL job passes both confined worker trajectories; offline verification accepts 23 signed receipts and the existing crash, ownership, fencing and no-redispatch controls. Its retirement fixture then fails because it expects the local diagnostic spelling rather than the authenticated IPC namespace. Only that exact fixture expectation changes. The signed protocol and all canary, substitution, quota, launch and lifecycle assertions remain. Portable broker tests and strict Clippy pass; actual unignored final-head x86 retirement remains required before PostgreSQL acceptance.

The preceding workspace job stops at two stale delivery-readiness mirror hashes before workspace execution. Both complete abstractions have been reviewed against retained connection custody and revalidation. The checked-output repair adds a third reviewed raw-return anchor. Only those three review records change. No modeled action or invariant changes; concrete connection, native launch identity, stateful checker calls and external settlement remain outside these abstractions. Matching hashes are not a Rust refinement proof. Final-head hosted workspace, consumer and native acceptance, and the security owner's coherent source and signed Linux package, remain separate.

The preceding MSRV lane reaches the multi-hop federation fixture and fails because evidence export omits its required private signing-key file. Its subsequent import likewise needs an independently trusted kernel key. The fixture now supplies its existing private file and pins import to the authority key independently derived from that file. Its selected exported receipt is signed by that same private fixture key: the first command-repaired run correctly rejected an independently random receipt signer locally before remote dispatch, and that failed campaign remains retained. Production requirements and all delegation, imported-parent, lineage and replay assertions remain unchanged. Complete federation-issue and evidence-export suites and strict affected Clippy pass; final-head hosted MSRV and workspace acceptance remain required.

The preceding active-defense job passes all sixteen materialization cases then refuses a stale fifteen-name inventory. The repaired exact gate includes that existing bounded-path case and the sealed registry's existing cross-tenant restart case. The contract verifies both source closures and rejects omission or same-count identity substitution for each case. All twelve actual inventories and eighty-five tests pass without changing filtering policy or ignoring any case. External source closure and signed Linux evidence remain separate.

## Checked-output preparation failure closure

Source `d187d763f4879b358c8911e79e0fd3e1a25fe7a4` passes all 21 terminal native commands against 37,319 unchanged inputs and 48 retained outputs, including all 20 artifact-tool tests. All 550 preceding records retain their exact raw bytes, hashes and original result/source scope.

The preceding repair still invoked a contractual checker before later ordinary output checks and frozen transforms. If that preparation failed, recovery could re-run a checker that now accepted and release previously rejected output. Four actual old-source cases fail with Allow instead of Deny: refusal or panic followed by an ordinary-guard failure or a post-invocation contract violation. All four pass after the repair, requiring a signed redacted denial, one invocation, one hold release, no output or capture, and identical retained replay. Initial supervisory and inventory-count failures remain separately recorded.

The kernel borrows its installed guard/context selection, finishes all role probes, ordinary validation, frozen output preparation and result canonicalization before aggregating contractual raw/released rejections. It reuses the existing durable resolved outcome and settlement authority. No durable schema, public API, authority bypass or mutable denial cache is introduced. The resolved-outcome commit remains the durability boundary; an observation whose durable write never commits has no new persistence guarantee.

Complete kernel verification passes 1,542 tests with no ignores and strict all-target Clippy. All 72 flow inventories pass 745 exact cases, including all ten checked-output cases; actual omissions and same-count substitutions are rejected. All 230 formal mirrors already match. No new mirror blessing or modeled invariant change is needed. Coverage is regenerated and checked; mirror correspondence remains a review record rather than a concrete Rust refinement proof.

The renewed follow-up campaign passes complete broker/federation and affected CLI suites, strict Clippy, six locked Vet graphs and default/FIPS controls, enforced deny policy, generated deployment locks, and all twelve deception inventories (85 exact tests). The funded suite retains 96 passes and six explicitly ignored private-chain cases; separately executed participant drivers keep their own evidence. The receipt verifier is built from this source and authenticates its binary hash, without claiming physical x86 confinement.

Three actual owned hosted CI failures are also repaired. Both static security-image lock pins now require the genuinely audited workspace lockfile; actual lock-content and Docker-pin mutations remain rejected. The canonical module-qualified scheduler selector executes one real case, all 31 dispatch cases pass, and the complete recovery gate passes. The federation-policy fixture reuses the existing private temporary directory helper after a diagnostic HTTP500 proved the authority correctly rejected public fixture custody. Its typed HTTP200 response binds the requested subject. A complete broad CLI campaign remains failed with its actual 80-target result: 1,372 passes, 85 failures and seven ignores. Its 69 native MCP failures and one explicitly filtered live conformance case require the existing Linux x86_64 fixture. The 16 other failures reject public authority custody across ten targets. Existing private-directory helpers repair local reputation, issuance, passport rotation and the shared receipt-query fixture. All 19 affected targets pass on the final source, including all 15 shared-helper consumers, and strict all-target Clippy passes. Unchanged passing code retains its original coverage and every failed campaign retains its result. Final hosted workspace/MSRV must execute all locally unavailable native cases without these exclusions. No production custody or reputation policy is weakened.

The preceding full kernel/flow and follow-up campaigns preserve their original complete input maps. Their subsequent Rust deltas are five integration-only CLI fixtures or their shared fixture helper, which neither campaign compiles. All captured production, graph, flow, formal and audit inputs agree with the final source. The current-source CLI fixture campaign and native21 qualification cover the repaired fixtures and CI scripts separately; no prior campaign is retagged.

Hosted results for preceding candidate 2b608eb2d1 remain historical. Its security image rejects an authorized-source lockfile checksum mismatch; its portable security contract lacks the closed-shard fixture. The security owner retains the coherent approved source, definition, signed Linux package and policy handoff. No authority variable, evidence digest or qualification rule is bypassed. Fresh final-head workspace, MSRV, consumer, Kani, fuzz, supply-chain, advisories and actual unignored x86 PostgreSQL retirement acceptance remain mandatory.

## Approval-continuation and current advisory closure

Source `372552646f101d958c53114037eaadb728249962` passes all 21 terminal native commands against 37,322 unchanged source inputs and 48 retained outputs. All 697 preceding raw records retain their complete original entries, bytes and hashes. Previous full kernel, flow, CLI, audit and hosted campaigns remain scoped to their original source; they are not retagged as current.

The actual approval-blocked A2A v1 consumer exposed a liveness loss: GetTask correctly observed retained work, but SendMessage rejected the task reference needed to attach later signed approvals. The repaired profile reports INPUT_REQUIRED and accepts an explicit owner continuation of the frozen original work. It compares the existing complete canonical kernel request and bridge/source bindings after removing only approval artifacts. The original message, task, context, deadline, output mode and all other authority remain fixed. No background executor, mutable authority cache or durable schema is introduced. Authoritative terminal denial remains terminal. Polling remains read-only.

Actual old-source continuation and inaccessible/expired-task campaigns fail before the repair. The current complete edge 118, adapter 115 plus one golden, and consumer 14-case suites pass with no ignores. The signed SQLite consumer verifies one invocation and identical durable replay, owner isolation, refusal of changed frozen authority, cancellation and observational polling with fresh approvals. Strict Clippy passes for all edge/adapter targets and the consumer test. The producer verifies all 14 exact consumer cases, and independent fixture controls reject omission and same-count substitution of each new continuation case. The remaining consumer producer native MCP fixtures require physical Linux x86 and remain final-head hosted prerequisites.

The authenticated preceding 15d5 dependency artifact identifies newly indexed Sharp and shell-quote advisories. The generated root/SDK locks now select Sharp 0.35.5 with bundled librsvg 2.63.2 and shell-quote 1.11.0. Only those package families change; registry integrity is authenticated. Actual installed vulnerable-package controls fail and the fixed three-case suite passes, including post-comment shell line terminators and native SVG decoding. Both full filtered and unfiltered OSV scans exit 0 without findings; existing authenticated private-tooling repairs and advisory-gate refusal controls pass. No exception is added.

The current physical x86 PostgreSQL lifetime trajectory, Kani, fuzz, workspace/MSRV and all other required hosted checks still need terminal final-head acceptance. The security owner retains the approved source, definition, signed Linux evidence package and policy handoff. Local passing campaigns do not close those external production boundaries or the four independent publication requirements.

## Terminal continuation error closure

Source `2f20769dbdd024ca4b65137ed3ca727778e9f974` passes all 21 terminal native commands against 37,322 unchanged source inputs and 48 retained outputs. All 784 preceding raw records retain their original entries, bytes and hashes. Earlier source and hosted results retain historical scope.

Fresh candidate199 review identified an approval rollback after dispatch. The confirmed actual SQLite regression performs one invocation, commits outcome_unknown_after_dispatch and verifies a signed kernel cancellation; the preceding edge nevertheless returns INPUT_REQUIRED. The corrected edge keeps the approved frozen request and bounded failed protocol custody, preserving its deadline. It clears obsolete approval evidence and uses a fixed status message without inventing a kernel decision or receipt. Any terminal kernel response already projected remains intact. Prevalidation refusals still preserve pending custody.

The complete current edge118 and consumer15 suites pass without ignores, alongside strict all-target edge and consumer-target Clippy. Repeated GetTask is read-only, inaccessible owners cannot observe the failed task, terminal continuation/cancellation is refused, and retrying the original stable message leaves the effect count at one under kernel authority. The actual producer verifies all15 exact cases; independently derived controls reject omission and same-count substitution of all5 continuation cases. Formal mirrors, generated coverage, hygiene, format and diff checks pass. The initial unsupported wire-error assertion is retained as a diagnostic failure, not the accepted RED.

No kernel API, schema, authority cache, new dependency or qualification exemption is introduced. Earlier dependency/source audits remain scoped to their actual inputs; current hosted audit/advisory checks must qualify the final candidate. Physical x86 PostgreSQL lifetime, Kani, fuzz, workspace/MSRV and all other required hosted checks need final-head terminal acceptance. The security agent owns the signed Linux package and policy handoff. The four independent publication gates remain open.

## Retryable pre-evaluation preparation failure

Source `76a052c5b8ae519426584764552d84a941438cb7` passes all21 terminal native commands against 37,324 unchanged source inputs and48 retained outputs. All830 preceding raw records retain their original entries, bytes and hashes. Earlier source and hosted results retain historical scope.

Fresh candidate37 review identified a transient clock failure after continuation validation but before orchestration. The actual signed SQLite RED permits that validation clock read, fails the next deadline read, verifies zero dispatches and no new receipt, and observes the incorrect terminal task. The corrected private task-completion module records NotEvaluated or Evaluated at the existing orchestration call boundary; it does not infer physical dispatch from an error. The legacy complete_task wrapper and public response remain unchanged. Before evaluation, failure preserves the original pending response/request and deadline, and cannot recreate an expired removed task. After evaluation, the preceding signed-cancellation protection remains intact without restoring obsolete approval evidence or fabricating a kernel receipt.

Current edge118 and consumer16 suites pass without ignores. Both P1 regressions pass: transient clock recovery completes the same original task with a verified signed Allow and one invocation, while an actual post-dispatch cancellation remains failed and stable-message retry does not redispatch. Strict Clippy, all16 exact consumer identities, omission/same-count substitution controls for all6 continuation cases, formal mirrors, refreshed coverage, hygiene, format and diff checks pass. The initial stale coverage failure remains distinct from the separate5-command finish. Test support reuses the existing injected clock API; no new kernel API, schema, authority cache, dependency or qualification exemption is added.

Final-head physical x86 PostgreSQL lifetime, Kani, fuzz, workspace/MSRV, supply-chain and other hosted checks remain required. The security agent owns the signed Linux evidence package and policy. All four independent publication requirements remain open.

## Security source identity and prerequisite qualification

Source `feb12ee950fffda73787d2199a1c2677fd00a6da` passes all 21 terminal native commands against 37,333 unchanged source inputs and 48 retained outputs. All 870 preceding raw records retain their original entries, bytes and hashes. Earlier source and hosted results retain historical scope.

Real temporary Git repositories reproduced approved-commit, tree and blob substitution through replace refs; source clean filters, linked checkout smudge filters and configured signature programs also executed before the isolated boundary. The repaired controlled environment ignores replacement objects, suppresses configured signature programs and shares one data-only configuration guard between source identity and aggregation. Actual callbacks never run in the eight passing source regressions.

The complete repository-authorized prerequisite implementation is integrated with its seven case-preserving refresh shards, strict inventory and sidecars, reviewed-tool hashes, bounded diagnostics, signed-output source exclusion and isolated full validation before unsigned publication. Fourteen shard controls and the complete nine-command portable control campaign pass. Matching helper routing and CI source commitments are reconciled while retaining the audited image and dependency inputs. Wire and keyring inventories now cover their actual modules, vector families and existing security regressions. No Rust API, dependency or durable schema is changed.

The genuine full adversarial producer rejects the preceding native source binding after input binding v7. That failure is retained; no historical outcome is retagged. The preceding 9ca PostgreSQL run verifies 23 signed receipts, both native trajectories and one unignored broker lifetime regression. Its 53 Kani harnesses, all 34 crash-free ASan targets, zero-finding advisory artifact and candidate x86 image build pass in their original scope. The two enterprise jobs fail in the separately authorized d049 image APK inventory before execution. The security agent must hand off coherent authorized source, genuine v7 outcomes, signed Linux package and policy. Final-head CI and review remain required. All four independent publication requirements and both readiness flags remain open.

## Complete security image package closure

Source `a7e63ee93c4048621cbd14e67a3433243441e14c` passes all 21 terminal native commands against 37,335 unchanged primary inputs and 48 outputs. All 1,031 preceding raw records retain their original entries, bytes and hashes.

The genuine preceding x86 image build rejects the newly published zlib and zlib-dev 1.3.2-r1 packages at the complete inventory comparison. The reviewed Alpine packaging delta backports the upstream nonblocking gzwrite buffer-overflow repair for CVE-2026-85091. All other 223 package identities are unchanged. Two actual package-instruction regressions reproduce incomplete transitive constraints and inventory authentication after download; all three boundary cases pass after the repair.

The existing inventory is now authenticated before external I/O and supplies all 225 exact package-version constraints in one installation. The full installed-inventory comparison, APK signatures, CA archive checksum, pinned base and Rust/Cargo inputs remain mandatory. The real signed APK solver matches all 225 constrained identities, with no package scripts. Twelve seed files independently match the immutable x86 base without execution. The live CI contract and its complete test suite pass. This ARM package-resolution result does not establish physical x86 image or kernel acceptance. No Rust API, public protocol, helper module, authority variable, signed evidence or audit exemption changes.

The preceding image failure and local resolver setup failures remain failed in their original scopes. Final-head hosted image, native PostgreSQL lifetime, all mandatory CI and review remain required. The security agent must hand off coherent authorized source, genuine v7 outcomes, signed Linux package and policy. The four independent publication requirements and both readiness flags remain open.
