# Security roadmap reconciliation and synchronization decision

Reviewed 2026-09-14. This extends the [first repository review](08-repository-review.md)
with the active security worktree, its process-runtime stack and live GitHub
state. The whitepaper remains **Chio: A Peer-to-Peer Economy of Verifiable Work**.

## Decision

**Yes, synchronize with the security work. Use a frozen, reviewed Security M4
checkpoint as the foundation for the next native funded-work implementation.**
Continue the independent funding model and contract analysis in parallel with
that dependency. Do not wait for the entire security launch roadmap or its
operational pilot to finish before doing research.

The preferred upstream sequence is qualified security integration into `main`,
then the reviewed paper changes on that base. If security's release work remains
open, an isolated integration branch can establish compatibility against its
pinned checkpoint before an upstream merge. That candidate remains experimental.
An upstream merge, a local integration result and a production release have
separate acceptance requirements.

Do not merge into either active dirty worktree. Do not merge legacy PR #1029
as the source of the security foundation. Preserve it as a requirements and
history reference until its remaining requirements have explicit dispositions.
This review neither closes that PR nor establishes that every old change has
been superseded.

Security milestone numbers below belong to the security roadmap. They are
distinct from the work program's M0-M7.

## Exact source and PR snapshot

The machine-readable [snapshot](09-security-sync-evidence.json) retains full
SHAs, conflict paths, selected source hashes and the observation time. GitHub
state and the other agent's working documents can change after this snapshot.

| Candidate | Observed state | Implication |
| --- | --- | --- |
| Remote `main` | `f5566d9a765c21cb36652a99c79de64968a656bf` | Common base of the committed paper and security branches |
| Local paper | `2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`, 123 porcelain entries before this review's edits | Includes uncommitted protocol, store, example and evidence work |
| [Paper PR #1159](https://github.com/bb-connor/arc/pull/1159) | Draft; remote head `e1d20158229619b401a10b193726a178c3b01827`, two commits behind local HEAD | The PR does not contain the complete local research candidate |
| [Security PR #1117](https://github.com/bb-connor/arc/pull/1117) | Draft; `8738bdfd7be8c43a0543ca0ce468541529c47add`; 2,324 files, +623,755/-37,349 lines | Active integration source; GitHub says mergeable but blocked |
| Security worktree | `/tmp/arc-security-launch`, same committed SHA as #1117; five modified documents and one untracked acceptance report | The other agent is finishing qualification; working documentation is not all in the PR |
| [Process PR #1131](https://github.com/bb-connor/arc/pull/1131) | Draft; `75d664822abf5f6e8da6e6f858cab5a6d81dc3bd`; 272 files against its recorded security base | Useful runtime work, but conflicts with the current security branch |
| [Legacy PR #1029](https://github.com/bb-connor/arc/pull/1029) | Open; `cbbba8cf2178cbbdd7b6b38a121e59365eb452ac`; 2,321 files, +1,035,094/-189,352 lines; conflicting | Historical integration, not a routine merge candidate |

The paper checkout has 163 workspace members. Security has 175, including ten
crates under `crates/security`, `chio-reference-tools` and `reference-swarm`.
The process stack also has 175 members: it adds `chio-process` and does not
contain the later `reference-swarm` workspace member. Equal counts do not mean
equal source or API inventories. The first review's 163-member inventory remains
a snapshot of the paper checkout, not the security worktree.

### What the merge probes actually show

These are local Git object calculations. No checkout, branch, working index,
commit history or source file was changed by the probes. The clone is not shallow.

| Comparison | Commits unique to left / right | Result |
| --- | --- | --- |
| Remote main / security HEAD | 0 / 129 | Main is an ancestor; zero conflicts |
| Committed local paper / security HEAD | 30 / 129 | One conflict: generated `docs/formal/COVERAGE.md` |
| Security HEAD / process HEAD | 27 / 55 | 13 conflicts, including admission, receipt/outcome stores and capture transactions |
| Remote main / legacy #1029 | 906 / 230 | 153 conflict paths |

Only five paths changed on both committed paper and security branches. That
does **not** describe the current working copy. Thirty tracked dirty paper paths
also changed on security. A separate per-file three-way probe of their current
bytes found nine conflicting paths:

- Kernel `admission_coordinator/terminal.rs` and two durable-admission test files.
- Runtime-core SQLite store and runtime-admission tests.
- SQLite `admission_operation_store.rs`, its `schema.rs`, and
  `serving_owner/global_commit_chain.rs`.
- A2A edge's included test index.

Twenty-one overlapping files merged textually in that diagnostic. None of the
current untracked paper files collides by pathname with the security commit.
This per-file probe does not resolve renames, compile the combined source or
prove semantic compatibility. Constructor changes already demonstrate a
compatibility break in a file Git would otherwise carry over without conflict.

## Source-backed additions to the plans

### S01. Reuse the authenticated start and delivery lifecycle

Security introduces `CallerStartResponse`, a host-pinned executor identity,
signed dispatch authorization and signed delivery reports. The kernel commits
and reads back original capture before publishing start authority. The executor's
`SqliteCallerExecutionLedger::execute_once` commits its claim before the callback,
checks the original authorization and persists the report before returning it.
An existing claim without a report remains unknown; it does not repeat the effect.

Reuse this for external executors in P44/P50. A quote, accepted work agreement,
escrow deposit, reservation nonce or evaluation receipt cannot itself authorize
an external effect. Bind agreement, allocation, invocation, executor identity
and attempt to the original native operation. The ordinary in-kernel path and
authenticated external-caller path keep their distinct ownership contracts.

Sources: [caller API](https://github.com/bb-connor/arc/blob/8738bdfd7be8c43a0543ca0ce468541529c47add/crates/kernel/chio-kernel/src/kernel/evaluation/caller_execution.rs),
[executor ledger](https://github.com/bb-connor/arc/blob/8738bdfd7be8c43a0543ca0ce468541529c47add/crates/platform/chio-store-sqlite/src/caller_execution_ledger.rs),
[delivery contract](https://github.com/bb-connor/arc/blob/8738bdfd7be8c43a0543ca0ce468541529c47add/docs/security/authenticated-caller-delivery.md).

### S02. Compose late reports with immutable unknown outcomes and payment release

Security's nonterminal `AwaitingCallerReport` retains capture after restart and
allows an authenticated late report to finalize the original operation. It does
not reopen a terminal `OutcomeUnknownAfterDispatch`. The paper's local
`unknown_payment_release_records` instead records an incident-bound financial
successor while preserving the original execution terminal. These mechanisms
address different states and must both survive integration.

P44 must define their interaction with pending F1 custody, claim and refund.
Exercise a late report racing a financial-resolution request, repeated signed
reports, current revocation, lost output-release acknowledgement and successful
child payment after parent failure. Recovery must not renew execution permission,
release raw executor output, silently refund captured exposure or rewrite a
previous terminal. Preserve the paper's agreed-output rejection and receipt
redaction through security's native output join and release-owner checks.

Sources: security `admission_coordinator/recovery/caller.rs`,
`return_context/caller/report.rs`, and the local
[unknown release](../../../crates/platform/chio-store-sqlite/src/admission_operation_store/unknown_release.rs)
and [terminal implementation](../../../crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs).

### S03. Design a real schema transition before combining the stores

The paper's dirty admission store advances version 9 to 10 to retain unknown
payment release. Security uses version 34 with accumulated credential, native,
caller and waiting-state custody. The same small schema number cannot identify
both histories. Choosing the larger constant or auto-merging SQL would not
preserve the catalog checks, original commit chain or serving-owner anchor.
Security already assigned version 10 to retained cumulative admission requests
in [commit bd94b09a7b](https://github.com/bb-connor/arc/commit/bd94b09a7b76b2066e135f0e58f7f7c00ce0f523).
The version collision is present in history, not merely a possible future conflict.

P40/P53 must record exact predecessor catalogs and supported transitions. Keep
the paper's version-10 research state distinguishable from security's historical
version-10 state. Use fresh stores for initial integration. Any required migration
must explicitly verify its predecessor and preserve original operation bytes,
unknown-payment successors, attachments, foreign keys and anchored history.
Do not add missing executor pins or claim episodes to old operations. Test
populated disposable fixtures; leave existing operator stores untouched.

Sources: both worktrees' `admission_operation_store.rs`, `schema.rs`, SQL catalog
and `serving_owner/global_commit_chain.rs`, pinned in the snapshot.

### S04. Migrate the actual example to verified manifests

The paper's [provider](../../../examples/federated-work/src/provider.rs) still
calls `ChioA2aEdge::new(config, vec![manifest])` and builds `chio.manifest.v1`.
Security's production constructor requires `&VerifiedManifestRegistry`; its
unsigned vector constructor is available only inside unit-test compilation.
This is a source-visible API mismatch, not a freshly executed compiler result.

P46/P50 must migrate, review and re-sign the selected manifest, register it under
the receiver's selected publisher and topology, then construct the edge from
that registry. Keep discovery and enrollment separate from publisher trust.
Do not enable a compatibility surface or inject a remote signing root to make
the research example build. Retain altered-manifest, wrong-publisher and required
flow-without-host tests alongside a successful mediated exchange.

Sources: [production A2A constructor](https://github.com/bb-connor/arc/blob/8738bdfd7be8c43a0543ca0ce468541529c47add/crates/protocol/chio-a2a-edge/src/edge.rs),
[consumer migration contract](https://github.com/bb-connor/arc/blob/8738bdfd7be8c43a0543ca0ce468541529c47add/docs/security/m4-consumer-migration.md).

### S05. Negotiate complete authority through supported transports

Security retains peer authorization negotiation across MCP session recovery and
threads selected profiles through A2A/ACP. Legacy profiles do not gain stronger
features after restart. Its bounded provider-fabric lowering rejects aggregate
or cumulative authority that the envelope cannot represent. SDK caller helpers
carry messages; they do not become cryptographic verifiers or durable executors.

P43/P50 must specify which work artifacts use which negotiated envelope, reject
unsupported combinations before acquisition/effect, and preserve all original
proof bindings. Reuse signed aggregate invocation roots for local invocation
limits without confusing a `u32` invocation ceiling with a monetary allocation.
Do not infer joint aggregate/cumulative support from separate positive cases.
Include receipt `tool_origin: chio_internal` and current attachment limits in
wire compatibility checks while retaining independent-verifier authorship rules.

Sources: security `provider_verdict.rs`, `capability/aggregate_invocation.rs`,
[consumer support ledger](https://github.com/bb-connor/arc/blob/8738bdfd7be8c43a0543ca0ce468541529c47add/docs/security/consumer-support.md)
and `scripts/check-consumer-boundaries.sh`.

### S06. Use native flow, declassification and secret custody where selected

Security adds actual flow admission, output-label joins, egress fences and
single-use declassification. Its keyring, secret broker and authenticated IPC
provide richer local custody options than a worker holding raw service keys.
The broker's supported composition injects provider credentials inside its
process and has durable attempt/reconciliation state.

P48/P49/P51 should choose a qualified composition for the honest company's
model, tool and artifact routes. Bind a disclosure to data owner, destination,
purpose and original operation; a paid agreement is not a declassification grant.
Ensure that new work permissions cannot exercise administrative key or broker
operations. Preserve guards on the actual released bytes. This local TCB does
not protect a remote machine from its own malicious administrator or make an
independent company trust the broker's financial backing.

Sources: security `chio-flow/src/{engine,declassification}.rs`,
`chio-cage/src/lib.rs`, `chio-keyring/src/lib.rs`, and the
[broker contract](https://github.com/bb-connor/arc/blob/8738bdfd7be8c43a0543ca0ce468541529c47add/crates/security/chio-secret-broker/README.md).

### S07. Keep confinement and automatic response as explicit deployment choices

The cage compiles signed, registry-bound launches and implements Linux enforcement
mechanisms. Security's designated Linux x86_64 confinement acceptance is still
deferred, and the inspected host is not evidence for that target. The reference
swarm explicitly runs a signed `Disabled` profile. Neither code presence nor
that smoke qualifies an enforced company node or hostile checker sandbox.

P51/P52 must name the actual selected sandbox and qualify its process, filesystem,
network and credential boundaries. Preserve the existing bounded research
isolation as its own profile until a replacement is demonstrated. Active-response
authority remains local and operator-governed; a counterparty's dispute or
negative result cannot directly activate containment. Security's M7/M10/M11
campaigns are not automatically prerequisites for an unrelated experimental
profile, but its required isolation cannot inherit their deferrals as a pass.

### S08. Reuse the process runtime after updating its security base

The [process runtime](https://github.com/bb-connor/arc/blob/75d664822abf5f6e8da6e6f858cab5a6d81dc3bd/crates/kernel/chio-process/src/lib.rs)
has durable logical operation keys, delegated process trees, checkpoints and
kernel-owned recovery. Its host requires signed launch policies and uses
`chio.process.abi.v2`. It rejects manifests requiring an information-flow runtime
that this host does not install. Process-local worker credentials and mailboxes
are useful inside a company; they are not the intercompany protocol.

P42/P43/P50 should evaluate this as the live-agent host before writing another
runner. First update #1131 against the chosen security checkpoint and review its
13 conflict paths, especially fused capture, nonce ownership and unknown outcomes.
Do not copy the old stack's admission implementation over the later caller fixes.
The existing process host cannot be advertised as the native flow host through
a configuration flag. Cancellation does not undo admitted effects or earned
child claims. Bounded read-only redispatch must not replay a paid/side-effecting
obligation or change a request-bound authorization artifact.

Security's reference swarm also lacks complete binding between its task graph
and edge-issued capabilities, and does not establish a shared task-pool ceiling.
P43 still owns that binding. Two separate local demonstrations do not establish
one composed, independently funded market.

### S09. Retention becomes a near-term implementation dependency

The authenticated executor ledger explicitly supports only 1-64 retained
operations, with no eviction or implicit rotation. Missing stores and exhausted
capacity fail closed. This is useful bounded custody, but cannot serve the
planned 1,800-attempt trial as one continuously accumulating executor ledger.
The finding pool's rollback qualification does not automatically qualify this
different ledger against privileged rollback or identity reuse across stores.

P53 must define a retention/reclamation or separately qualified epoch transition
before sustained workloads. Trial sizing must include retries, denials and
uncertain attempts. Do not erase stores, rotate identities without a protocol,
or give each restart a fresh budget to reach the sample count. P52 must observe
capacity and recovery under the actual chosen node topology.

### S10. Qualification must cover the combined source

Security provides exact caller, native restart, consumer and flow inventories.
Use these in P55 together with the paper's three standalone Cargo workspaces,
Python verifier/process cases, output-contract and unknown-release regressions,
pool/rail tests and any selected process-runtime suite. The formal source map
and generated coverage must be rebuilt after semantic conflict resolution;
matching hashes are not new proofs of the combined protocol.

At observation, #1117 had 12 unresolved GitHub review threads. The working
acceptance report distinguishes repaired receipt-origin/attachment issues,
addressed caller-schema documentation, disputed profile/credential suggestions,
and open classifier/release work. An unresolved thread is not automatically an
unfixed defect; a local disposition is not reviewer approval.

Exact-head workflow inspection found failures in
[cargo-vet](https://github.com/bb-connor/arc/actions/runs/34811945865),
[CVE Monitor](https://github.com/bb-connor/arc/actions/runs/34811945802), and the
[enterprise evidence controller](https://github.com/bb-connor/arc/actions/runs/34811943914),
all attempt 1. The vet log names 22 dependencies lacking `safe-to-deploy` audit
coverage. CVE Monitor reports a non-ignored advisory. The controller fails at
source/controller authorization and does not perform the qualified capture.
Other workflows were still pending, queued or running. The paper PR also has
failing checks. None of these candidates is merge/release qualified by this review.

The other agent's local M1-M3 evidence and earlier broad M4 passes are valuable
inputs. Its current-source M4 reruns and acceptance document are still in
progress. This pass inspected source, tests, gate definitions and reported
evidence; it did not rerun the Rust workspace, mutate its stores, dispatch
hosted qualification or interfere with that agent's test processes.

## Concrete synchronization sequence

1. **Freeze both inputs (P40).** Finish the security M4 checkpoint and record
   source, test inventories and remaining deferrals. Independently checkpoint
   the selected paper code, experiments and plan changes without bundling unrelated
   user work. Preserve report 35 and all historical source hashes as old evidence.
2. **Rehearse in isolation (P40/P44/P53).** Start from that security checkpoint
   and integrate the reviewed paper change set. Use the ordinary shared ancestry
   where practical; resolve the dirty semantic overlaps by their invariants.
   Record schema/ABI predecessors and the exact diff. Do not resolve with a
   wholesale preference for either branch or bypass new constructors.
3. **Migrate and test consumers (P46/P50/P55).** Register signed manifests,
   select negotiated profiles, compose the two terminal/financial lifecycles
   and rerun all affected native and standalone suites. Generate current schema,
   error, SDK and formal-index artifacts only after the source is settled.
4. **Add the process stack if selected (P42/P43/P50).** Have its owner update
   #1131 against the same security checkpoint and qualify the fused stores and
   signed-launch host. Fold it into the rehearsal after the core combination
   passes. A minimal trusted executor can keep the funded-work slice moving
   without claiming the unfinished process/flow composition.
5. **Qualify the reviewed upstream candidate (P52/P55).** Reconcile current
   review threads, audit/advisory results, required CI and exact source/run
   attempts. Land security first when its merge requirements are met, then
   dependent changes. Recompute if any input advances. Deployment, real funds
   and operational promotion retain their separate existing requirements.

The immediate dependency is a shared, tested execution contract. No new general
scheduler, credential broker, capability tree or delivery journal is justified
by the whitepaper plan. The remaining research contribution is funded,
independently verifiable work across company boundaries, composed on this
security foundation and measured against an equally provisioned alternative.
Keep the normative intercompany profile small. Reusing the 175-member reference
workspace does not require an independent provider to adopt all those crates,
its native sandbox or `chio-process`. Specify the externally observable work,
authority, acceptance and funding decisions separately from each company's
implementation of its trusted local host.
