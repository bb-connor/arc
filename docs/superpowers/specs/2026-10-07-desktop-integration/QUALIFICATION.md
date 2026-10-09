# Native host acceptance and release evidence

Status: specified. `planning_status: ready_after_adr` under ADR-0038. Every
proposed execution profile is unavailable until its exact tuple passes.
Document checks, mock data and historical host runs cannot satisfy runtime
gates. Cases are defined in [CASES](CASES.md); this document explains the
surrounding design.

## Evidence identity and authority

A qualification record binds the owner source commit, public release revision,
host and plugin versions, client builds, OS version and architecture, backend
and policy digest, artifact hashes, commands, raw outputs, expected outcomes and
the reviewer decision. A prerequisite's green test does not qualify a different
installed artifact. Public instructions reference only revisions that exist in
the public repository.

Authoritative evidence stays with the owner under test; the release manifest
references it without restating it. Omitted cases, zero evaluated profiles,
skipped commands, stale logs, unknown evidence kinds and missing signatures
cannot yield a ready state. [RELEASE](RELEASE.md) assigns the native-profile
schema, verifier and activation gate to shared packet 2a; platform installed
delivery cannot close until that gate exists and its activation call sites are
exercised (Q18).

`boundary_class` and `planning_status` follow ADR-0011 separately. Hook activity
is `detect_only`, local effects outside mediation are `cannot_see`, UI guidance
is `advisory_only`, and only a proven pre-effect gate is `prevent`.

## Profile coverage

| Profile | Mandatory cases | Runtime gate |
| --- | --- | --- |
| Observe | Q04, Q10, Q11, Q16, Q17, Q21; Q09 for exposed streams; Q15 for an exposed budget view; Q02 for every exposed effecting mutation; Q01 and Q03 only for exposed W1 views or recovery | Authenticated bounded non-persisting owner reads and truthful hook attribution. W1 and M20 are not basic observation gates. |
| Approve | Q02 to Q06, Q09, Q10, Q16, Q17 | Native approval owner, S28 identity, production verifier and the exact installed approval route; no stop implied. |
| Per-task stop | Q02 to Q04, Q07, Q09, Q10, Q16, Q17, Q19 | S4 process closure and its route authorization; approval is not a prerequisite. |
| Kernel stop | Q02 to Q04, Q08 to Q10, Q16, Q17; Q19 for any claimed process cleanup | S8 phase-1 scope, durability and route authorization; no implied process termination. |
| Sealed work | Q01 to Q22 applicable to the backend, with owner-justified exclusions; Q22 mandatory | W1, recovery, restricted host, runner, S7 and the installed release tuple. |
| Protected interactive | Q02 to Q13, Q15 to Q22, plus doc 19 I01-I08 | Each host tuple individually; native-shell removal and Q22 enforced. |
| Boundary interactive | Q02 to Q13, Q15 to Q22 as applicable; no mediated-local-effect claim | Deferred; independent backend evidence required. |
| Managed endpoint | The platform annex's ES/NE matrix plus Q02, Q16 to Q20 | Deferred; restrictive-only authority. |

Every row expands to an executable case manifest at implementation time. The
manifest names each owner-approved exclusion; an unclassified case fails.
Release qualification removes each required case in turn from a passing
manifest and proves the affected surface cannot promote. The Q identifiers do
not replace the consumed owner contracts: source reconciliation maps every
HOST-CONTRACT, CAPABILITIES and CONSUMERS obligation (and OPERATOR's when the
projection is selected) to an owner, packet, command, positive control and
independent negative.

## Effects without blanket keystone dependencies

Not requiring the whole S9, S10 and S11 redesign before every host capability
waives nothing. Each selected effect owner proves current-authority admission
before dispatch, exact request and scope binding, atomic reservation, required
persistence before acknowledgement, post-effect uncertainty handling, closed
native dispatch and guarded artifact release. A path missing any of these stays
unavailable; no client substitutes a weaker path.

Sealed qualification includes the evaluator whenever it executes candidate
code: Q12 and Q19 probes apply to it separately from the agent, hostile hooks
must not reach files, credentials, egress, inherited descriptors or the
acceptance channel, and failed or unknown evaluation never becomes accepted
work.

Execution lifetime uses the native owner's boot-bound elapsed deadline, which
includes suspend, and the authority-issued absolute expiry. Test each bound
separately while the other stays valid, then realtime jumps, missing clock and
boot changes alone and combined with suspend. Rollback never revives an expired
operation, uncertainty never authorizes continuation, restart never replenishes
a lifetime, and already-dispatched outcomes stay distinct from forbidden new
dispatch (Q12, Q19, Q31). Basic Observe keeps its own read-freshness gates
without a task-lifetime dependency.

## Tracked owner defects

These issues were verified open on 2026-10-09. An open issue is a recorded
handoff, not a repair; each affected profile stays unavailable until its case
passes on the installed binary.

| Issue | Obligation |
| --- | --- |
| [chio-bridge#3](https://github.com/backbay-labs/chio-bridge/issues/3) | Repair `approval-decide` decision and approval-ID binding, replace the packaged archive and pass installed Q05, including direct invocation. Pi wrapper refusal is not a fix. |
| [#1180](https://github.com/bb-connor/arc/issues/1180) | Emergency stop custody, route mounting, constant-time token check and S8 phase-1 durability (Q08). |
| [#1181](https://github.com/bb-connor/arc/issues/1181) | Non-persisting recovery observation that never drains the settlement reserve (Q09, Q21). |
| [#1182](https://github.com/bb-connor/arc/issues/1182) | Host-plugin and tool-server boundary wording against ADR-0011 (Q11). |

Live process control, roster attribution and production endorsement keep their
own owner gates in NORTH-STAR-FLOWS section 9.

## Performance, privacy and operations

Use the S10 call classes and measurement conventions; mediate policy
boundaries rather than adding a paid kernel call per HTTP fragment. Publish
measured cold and warm latency, idle CPU and memory, stream buffer limits,
restart recovery time and stop acknowledgement versus completed closure
separately. Platform plans set numeric limits from those experiments before
beta. Exceeding a bound degrades observation or refuses new work, never weakens
authority or isolation. Logs and support bundles redact secrets, prompts,
private paths and artifact contents by default; export is previewed and
consented. Tokens never enter UI URLs, argv, notifications or support bundles.
Deleting UI caches neither erases owner receipts nor cancels work.

## Required provider limits

Where the selected grant or claimed profile requires an inference dimension,
the exact route enforces it before admission (Q15, Q27, C04). Unknown limits
shown for display cannot pass. Cover route, model and account substitution,
missing or ineffective ceilings, concurrent reservation exhaustion and
post-dispatch loss with retained obligations. Removing required-limit evidence
refuses the bounded profile and never silently selects a narrower one.

## Release sequence

1. Freeze the source tuple and obtain each predecessor's native acceptance.
2. Freeze each owner binding only after its real schemas and queries exist, and
   run independent consumer conformance against installed owners.
3. Build signed candidates and publish clean-host install inputs on a labelled
   candidate channel.
4. Install on clean supported machines and run positive, negative, restart,
   update and uninstall controls, plus accessibility checks for selected
   graphical clients.
5. Verify public artifact availability and checksums, then promote the exact
   tuple. A rebuilt artifact restarts the artifact gates.
6. Record local tests, hosted CI, bot review, release publication and native
   qualification as separate statuses.

A protected host needs its own foundation, I01-I08, boundary, resource, release
and installed evidence; it does not need an earlier sealed-coding release. A
passing cell never qualifies another host, resource, principal or platform.

## Full product claims

A release claiming the full ambition passes Q23 plus coordination (Q25, Q26 and
W1 acceptance), shared resources (Q27) and independent cooperation (Q28), in
addition to every native profile obligation. Passports (Q24) are mandatory when
advertised. The completion record names actual capability coverage, independent
applications, harness tuples and separately administered owners; unavailable
dimensions stay open and never merge into one green status.
