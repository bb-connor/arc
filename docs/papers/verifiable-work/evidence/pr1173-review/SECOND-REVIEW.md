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

Source `9b40dc9128b1c62849558af387c1bf918d9c40f0` passes all 21 terminal native commands against
37,314 unchanged source files and 48 retained outputs. Actual parent
SIGKILL, evolving funded work, all four earned-child payment cases and all 20
artifact-tool tests pass. Earlier complete, failed and interrupted campaigns
retain their original source and scope.

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
