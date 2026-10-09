# Computer and the completed Chio roadmap

Status: proposed architectural crosswalk, revision 2. Parent: [PROPOSAL.md](PROPOSAL.md).

## Assumption and precedence

This design assumes completion of the unified roadmap and constituent programs,
including their declared post-success-test scope. Completion establishes those
contracts at supported profiles. Explicit experimental exclusions and unresolved
profile choices do not become universal support by assumption.

Use this order when documents disagree:

1. Unified owner decisions and frozen lane contracts.
2. Later owner-aligned amendments in the constituent specifications.
3. Constituent architecture and acceptance contracts.
4. Concrete source for existing mechanisms and integration seams.
5. Older research where the above do not supersede it.

These are pinned research views, not statements about today's merge or release
status. The kernel and work specifications use internal historical names where
necessary; public Computer examples retain the approved product vocabulary.

## Pinned program heads

| PR | Inspected head | Role |
| --- | --- | --- |
| [#1196](https://github.com/bb-connor/arc/pull/1196) | `c32c460fae67c6f21386ab3cffa425cd06f0433b` | Unified contracts, lane owners, gates and superseding decisions |
| [#1174](https://github.com/bb-connor/arc/pull/1174) | `7419d56e98e84ee57212e293e5f2658f7fef7642` | FTL lessons and all eleven kernel specifications |
| [#1173](https://github.com/bb-connor/arc/pull/1173) | `cafdc970e4f89bddf810647e4228a605ed9f498a` | Delegation/graph code and W1-W4 work architecture |
| [#1170](https://github.com/bb-connor/arc/pull/1170) | `666274baef7a503a6bf4791816483cbc6eb1b4ed` | Strategy research, subject to unified decisions |
| [#1160](https://github.com/bb-connor/arc/pull/1160) | `fd8bfdc947bbaf070b39457a9190f032a018e55a` | Process/security foundation and adjacent programs |
| [#1172](https://github.com/bb-connor/arc/pull/1172) | `de84fc306efbb4c8dd6de748d0ad2a8d695fd30e` | Recovery architecture and contract catalog |
| [#1179](https://github.com/bb-connor/arc/pull/1179) | `0e03db2d7395c544701ac02015046613b1115e56` | Recovery implementation and native owner seams |
| [#1177](https://github.com/bb-connor/arc/pull/1177) | `01666b33b439d9e488ad7de6295a01eed25292c4` | Native host program and independent receiver model |
| [#1171](https://github.com/bb-connor/arc/pull/1171) | `1a6f7bfccb1030c620eb7a2f9e3a06620196076b` | Protocol publication context |
| [#1197](https://github.com/bb-connor/arc/pull/1197) | `3ab02761b9859be81e858ce3d6ef14da309f764c` | Internal development coordination, potential application consumer |

## Unified lanes and contracts

The eight frozen-contract workstreams constrain Computer as follows:

| Contract | Reuse in Computer |
| --- | --- |
| CT-ABI | Closed kernel operation census, process ABI and contract/codegen discipline; facade methods do not each require a new kernel operation. |
| CT-WORK | Existing WorkClient/Handle/View and unpaid Agreement path; preserve allocation, acceptance and exact invocation bindings. |
| CT-SETTLE | One paged native reconciliation/classifier composition; retain different known/unknown financial successors. |
| CT-COOP | Configured partner identity, key history/status, trust and federated proof of possession; a Computer name cannot enroll a peer. |
| CT-CTRL | Authenticated route-specific operator scope for stop/control; no universal facade administrator credential. |
| CT-CROSS | HTTPS with mTLS or signed bodies by default; optional self-hosted iroh lane. |
| CT-REL | Supported installed profiles, source/release evidence, development repo and distribution mirror boundaries. |
| CT-WIRE | Closed exact-byte contracts and one schema ledger allocated in landing order. |

### Lanes

| Lane | Inherited result | Computer obligation |
| --- | --- | --- |
| WORK | Prepared and admitted work, owner services, developer facade, beta convergence | Compile to it; no second scheduler, verifier store or signing builder. |
| REC | Original-operation recovery, semantic contracts, artifacts/checkpoints, confined returns | Preserve identities, knowledge and custody across branches and transfer. |
| KERNEL | Shared admission/crossing/closure/stop/integrity machinery | Use it for every new native resource mutation and release path. |
| SHARE | One consumption owner, durable family limits, brokered model reserves, multi-harness support | Bind actual operations; no Computer balance or fresh per-session counters. |
| COOP | Independent peers/keys, local doors, co-signing and evidence delivery | Source rights and receiver consent remain independent. |
| REL | Qualified installation and supported host/provider distributions | Publish exact profile support, not source-only demonstrations. |
| OUT | Outside operators and claim/evidence discipline | Qualify the two-computer application with genuinely independent operation. |

Post-success-test scope also supplies sender-funded cross-organization holds,
multi-hop independent keys, N-organization cooperation, witnessed evidence,
reputation, additional native hosts, and the kernel keystones. Computer still
needs exact supported profile bindings to use these capabilities.

Primary source: [unified roadmap](https://github.com/bb-connor/arc/blob/c32c460fae67c6f21386ab3cffa425cd06f0433b/docs/operations/UNIFIED_ROADMAP.md).

## Constituent program crosswalk

| Program | Completed capability | Implication |
| --- | --- | --- |
| Security protocol primitives | Aggregate limits, exact approvals, reservations, replay and canonical contracts | Fork/compile cannot duplicate authority, approval consumption or spending. |
| Security active defense | Labels, exact release, scoped containment, revocation and bounded response | Branches preserve classification/observation history; response stays with its admitted owner. |
| Enterprise hardening | Key custody/history, brokered secrets, exact native launch and authenticated IPC | Images carry authorized references instead of keys, provider secrets or unverified host claims. |
| Unrepresentable defects | Checked types and evidence-bound transitions | Decoding a Computer description cannot construct live authority. |
| W1 runtime | Public facade, checked contracts and concrete owner service | Add Computer at the same facade/core/composition boundaries. |
| W2 owners | Independent receiver offers, peer transport, unpaid/optional funded agreements | No global source-owned process tree or automatic foreign capability import. |
| W3 developer surface | Shared language/CLI contracts and canonical vectors | Keep wrappers thin; operator syntax lowers to the common contract. |
| W4 convergence | Reuse across applications and evidence-based acceptance | Two consumers must avoid custom retry/signature/ledger implementations. |
| REC P0-P2 | Closed contracts, original-operation recovery and bounded advisory explanation | Reconnection recovers native operations; preview cannot grant rights. |
| REC P3 | Connector semantics, exact transformation/ACL/endorsement evidence | Resource aliases and transfers bind actual semantic generations. |
| REC P4 | Labeled immutable artifacts, checkpoints, context and release | Equal bytes do not erase provenance; restoring a context joins retained knowledge. |
| REC P5 | Qualified confined observation and constrained return | A separate process or typed summary is not sufficient evidence of a safe return. |
| REC P6 | Common host/policy integration | Reuse the supported host/owner path for Computer applications. |
| HOST-M1/M2/M3 | Independent admission, shared local root across harnesses, cross-organization work | Each recipient owns local processes; host OS isolation and Chio admission have distinct jobs. |
| Reliability | Deadlines, unwind, dispatch journals, bounded memory, durability, retention, supervision, shutdown, replication, transport and money paths | New queues/records need bounds, serving fences, recovery and safety headroom. |
| Transparency | Anti-equivocation, claim/child completeness and declared witness policies | A run evidence manifest must include membership/completeness basis, not selected successful receipts alone. |
| Formal | Source/model-scoped verification and negative/mutation testing | New compiler/resource preservation needs new evidence; inherited proofs do not automatically cover it. |
| Earlier four-direction/economy plans | Optional adapters, metering, payment and market infrastructure | Reuse optional owners; default Computer operation remains independent of web3. |
| Internal development coordination #1197 | Development worktrees/build coordination | Potential Computer workload, not the product runtime/authority implementation. |

Primary sources:

- [security launch](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/security/launch-plan.md).
- [protocol primitives](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/superpowers/plans/2026-07-09-protocol-primitives.md).
- [active defense](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/superpowers/plans/2026-07-09-security-active-defense.md).
- [enterprise hardening](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/superpowers/plans/2026-07-09-enterprise-hardening.md).
- [checked-type design](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md).
- [W1 runtime](https://github.com/bb-connor/arc/blob/cafdc970e4f89bddf810647e4228a605ed9f498a/docs/superpowers/specs/2026-10-03-work-runtime-design.md).
- [W2 owners](https://github.com/bb-connor/arc/blob/cafdc970e4f89bddf810647e4228a605ed9f498a/docs/superpowers/specs/2026-10-03-work-owner-services-design.md).
- [W3 surface](https://github.com/bb-connor/arc/blob/cafdc970e4f89bddf810647e4228a605ed9f498a/docs/superpowers/specs/2026-10-03-work-developer-surface-design.md).
- [W4 convergence](https://github.com/bb-connor/arc/blob/cafdc970e4f89bddf810647e4228a605ed9f498a/docs/superpowers/plans/2026-10-03-work-beta-convergence.md).
- [recovery architecture](https://github.com/bb-connor/arc/blob/de84fc306efbb4c8dd6de748d0ad2a8d695fd30e/docs/architecture/recoverable-agent-runtime/README.md).
- [artifacts and memory](https://github.com/bb-connor/arc/blob/de84fc306efbb4c8dd6de748d0ad2a8d695fd30e/docs/architecture/recoverable-agent-runtime/06-artifacts-memory.md).
- [confined returns](https://github.com/bb-connor/arc/blob/de84fc306efbb4c8dd6de748d0ad2a8d695fd30e/docs/architecture/recoverable-agent-runtime/07-confined-returns.md).
- [native host ADR](https://github.com/bb-connor/arc/blob/01666b33b439d9e488ad7de6295a01eed25292c4/docs/adr/ADR-0038-native-host-program.md).
- [program map](https://github.com/bb-connor/arc/blob/01666b33b439d9e488ad7de6295a01eed25292c4/docs/architecture/PROGRAM-MAP.md).
- [reliability program](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/architecture/reliability/README.md).
- [transparency program](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/architecture/transparency/README.md).
- [formal roadmap](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/formal/ROADMAP.md).
- [four-direction roadmap](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/superpowers/specs/2026-07-07-chio-next-directions/ROADMAP.md).
- [economy roadmap](https://github.com/bb-connor/arc/blob/fd8bfdc947bbaf070b39457a9190f032a018e55a/docs/superpowers/plans/2026-07-10-agent-economy-roadmap.md).
- [internal development tooling](https://github.com/bb-connor/arc/blob/3ab02761b9859be81e858ce3d6ef14da309f764c/docs/superpowers/specs/2026-10-06-agent-swarm-design.md).

## All eleven kernel specifications

| Spec | Inherited contract | Computer consequence |
| --- | --- | --- |
| [KSPEC-01: Closed ABI](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-closed-kernel-abi-design.md) | Closed ABI | Compose existing operations where sufficient; keep networking and language authoring out of kernel core. |
| [KSPEC-02: Authority faults](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-authority-faults-design.md) | Authority faults | Expose structured refusals and authorized recovery links; recommendations do not grant or escalate. |
| [KSPEC-03: Typed reservations](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-typed-reservations-design.md) | Typed reservations | Discharge every post-effect obligation through native durable outcomes; commitments and refundable holds have different dispositions. |
| [KSPEC-04: Authority-space teardown](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md) | Authority-space teardown | Fence new work before drain, preserve historical effects/claims/knowledge and use the shared classifier. |
| [KSPEC-05: Event queue](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-unified-event-queue-design.md) | Event queue | Original-ID reconnect, stable subscription acknowledgement and advisory hints; no replay-triggered dispatch. |
| [KSPEC-06: Adapter binding](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-opaque-adapter-context-design.md) | Adapter binding | Keep namespace, capability, invocation, provider/model context and delegated permit bindings through lowering. |
| [KSPEC-07: Confinement evidence](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md) | Confinement evidence | Name actual qualified host enforcement and P5 evidence; unknown kinds are unconfined. Exploratory FTL remains excluded. |
| [KSPEC-08: Durable stop](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md) | Durable stop | Restart preserves stop/closure; safety controls retain headroom; cancellation and revocation remain separate. |
| [KSPEC-09: Pure admission machine](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-pure-admission-machine-design.md) | Pure admission machine | Use the common transition/decision machine and operation classes; no Computer effect reducer. |
| [KSPEC-10: Crossing primitive](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-crossing-primitive-design.md) | Crossing primitive | Use durable intent/return/outcome and restrictive commit rules; multiple owners do not form one transaction. |
| [KSPEC-11: Integrity admission](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-integrity-gated-admission-design.md) | Integrity admission | Bootstrap and observations contribute influence; exact endorsement/action contracts govern privileged apply. |

Umbrella and cross-spec decisions: [FTL lessons program](https://github.com/bb-connor/arc/blob/7419d56e98e84ee57212e293e5f2658f7fef7642/docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md).

## Decisions preserved across owners

- Unknown effect settlement and a known return with pending capture use different
  successors. Only the applicable financial owner may release/waive/capture;
  Computer cancellation does not select a cheaper disposition.
- Signer rotation uses the current signer while preserving original identity and
  validated key history. Output delivery follows the final qualified release
  contract; an open or withholding profile cannot be overridden by the facade.
- D1 allocations, process slots and sealed commitments are not automatically
  refundable balances. SHARE makes consumption binding explicit.
- Work acceptance uses the original evaluator/procedure and exact producer
  artifact. Result release and apply authority are independently current checks.
- Current predicates and held reservations are revalidated at dependent
  commitment. Historical evidence only establishes its exact historical fact.
- Pinned boot code identifies bytes. Trusted bootstrap and exact integrity
  endorsement require their separate admitted evidence.
- Key-history witness policy and receipt-log witness policy remain distinct.
- Schema versions are allocated under the shared ledger lock when landing; this
  proposal assigns symbolic new contract names only.

## Strategy dispositions and exclusions

The unified roadmap supersedes older #1170 recommendations to freeze native
components or make a particular external isolation runtime mandatory. Native
cage/broker/host contracts remain active. External host backends are supported
only through their qualified enforcement profiles. Identity-provider integration
applies where configured; a DID or signature alone does not install trust.

HTTPS with mTLS or signed bodies is the default cross-organization lane. iroh
remains optional. Default builds keep web3 and finding-market off as specified
by SHARE, and network clients move to their proper service/adapter boundaries.

#1171 informs interoperable publication; it is not evidence that the installed
Computer API already exists. #1197 is internal development automation and may
become a consumer. Reputation/pheromone signals can rank already eligible work
profiles, but cannot issue rights, establish trustworthy code or bypass the
receiver. Browser/mobile/FFI paths keep their actual qualified scope.

Static Computer descriptors do not imply universal VM migration, a universal
atomic snapshot, a global process tree, or arbitrary external-tool rollback.

Strategy source: [strategy and roadmap](https://github.com/bb-connor/arc/blob/666274baef7a503a6bf4791816483cbc6eb1b4ed/docs/research/nvidia/06-strategy-and-roadmap.md).

## Source and coverage accounting

[source-evidence.json](source-evidence.json) separates the original inspection
from the revision-2 selected program/owner corpus and manifest inventory. Hashes
are reproducible against the pinned Git objects. Recording a source is not a
claim that every line was reviewed or that a branch is merged or qualified.

[CODEBASE-COVERAGE.md](CODEBASE-COVERAGE.md) inventories every crate manifest in
the union of the pinned #1160/#1173/#1179 views and records per-crate architectural
relationships. SDK and non-crate topology were considered; external plugin
repositories and every vendored dependency were not independently audited.

The research captured a larger local corpus. This PR retains the sources needed
for its contracts and coverage without committing all captured source copies.
The existing 39-file snapshot remains historical evidence for revision 1.
