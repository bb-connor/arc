# Native host acceptance and release evidence

Status: specified. `planning_status: ready_after_adr` under ADR-0038. Every
proposed execution profile is unavailable until its exact tuple passes.
Document checks, mock data and historical host runs cannot satisfy runtime
gates. Cases are defined in [CASES](CASES.md); this document explains the
surrounding design.

## Evidence identity and authority

A qualification record binds the source commit, release revision, host and
plugin versions, OS and architecture, backend and policy digest, artifact
hashes, commands, raw outputs and the reviewer decision (CONSUMERS lists the
manifest). A prerequisite's green test does not qualify a different artifact.

Authoritative evidence stays with the owner under test; the release manifest
references it without restating it. Omitted cases, zero evaluated profiles,
skipped commands, stale logs, unknown evidence kinds and missing signatures
cannot yield a ready state. [RELEASE](RELEASE.md) assigns the native-profile
schema, verifier and activation gate to shared packet 2a; platform installed
delivery cannot close until that gate exists and its activation call sites are
exercised (Q18).

ADR-0011 fields are defined in STATUS-GLOSSARY; only a proven pre-effect gate
is `prevent`.

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

Each row expands to an executable case manifest; release qualification removes
each required case in turn and proves the surface cannot promote. The Q cases
do not replace owner contracts: source reconciliation maps every HOST-CONTRACT,
CAPABILITIES and CONSUMERS obligation (OPERATOR's when selected) to an owner,
packet, command, positive control and independent negative.

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

Open owner issues are linked from their CASES rows: chio-bridge#3 (Q05), #1180
(Q08), #1181 (Q09, Q21) and #1182 (Q11). An open issue is a handoff, not a
repair; the affected profile stays unavailable until its case passes on the
installed binary. For chio-bridge#3, refusing `approval-decide` in the Pi
wrapper is not a fix: the utility itself, its packaged archive and direct
invocation must pass Q05.

## Performance, privacy and operations

Use the S10 call classes. Publish measured latency, idle CPU and memory, stream
buffers, restart recovery time and stop acknowledgement versus completed
closure separately, and set numeric limits from them before beta. Exceeding a
bound degrades observation or refuses new work, never weakens authority or
isolation. Logs and support bundles redact secrets, prompts,
private paths and artifact contents by default; export is previewed and
consented. Tokens never enter UI URLs, argv, notifications or support bundles.
Deleting UI caches neither erases owner receipts nor cancels work.

## Required provider limits

HOST-CONTRACT's model-provider boundary applies wherever a grant or profile
requires an inference dimension (Q15, Q27, C04). Removing required-limit
evidence refuses the bounded profile and never silently selects a narrower one.

## Release sequence

1. Freeze the source tuple and each predecessor's native acceptance.
2. Freeze owner bindings only once their real schemas exist, and run
   independent consumer conformance against installed owners.
3. Publish signed candidates on a labelled candidate channel.
4. Install on clean machines and run positive, negative, restart, update and
   uninstall controls, plus accessibility checks for selected graphical clients.
5. Verify public availability and checksums, then promote the exact tuple; a
   rebuilt artifact restarts the artifact gates.

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
