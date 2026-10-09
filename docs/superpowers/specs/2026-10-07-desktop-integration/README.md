# Chio native host program

Status: accepted planning direction, amended 2026-10-08 UTC. The specifications
do not qualify an implementation, installed profile or release.
`planning_status: ready_after_adr`; `boundary_class` belongs to each operation.
Consumer presentation and the optional operator projection are `advisory_only`.

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.**

**Authority that only narrows. Work that survives. Evidence that travels.**

[NORTH-STAR-FLOWS](NORTH-STAR-FLOWS.md) governs this program (approved
2026-10-08). Other documents reference its flows instead of restating them.
HOST-M1 code (Lane COOP in the unified roadmap) does not wait on this document
restructure (roadmap section 7).

## Three flows

- **HOST-M1 Cooperate-0.** Two independently operated hosts run the shipped
  passport, challenge, federated-issue and evidence loop; each admits at its
  own door. [Flow M1](NORTH-STAR-FLOWS.md#3-flow-m1-cooperate-0).
- **HOST-M2 One root grant, many agents.** Claude Code, Codex, Pi and Hermes
  workers draw on one owner-metered pool and leave one authority tree that
  survives restart. [Flow M2](NORTH-STAR-FLOWS.md#4-flow-m2-one-root-grant-many-agents).
- **HOST-M3 Work that crosses an organization boundary and comes back
  verified.** Co-signed work under #1173 W1/W2, run in the executing owner's
  HOST-M2 tree and verified offline. [Flow M3](NORTH-STAR-FLOWS.md#5-flow-m3-work-that-crosses-an-organization-boundary-and-comes-back-verified).

## Platform order

From [NORTH-STAR-FLOWS section 6](NORTH-STAR-FLOWS.md#6-platform-delivery):

1. HOST-M1 on both platforms together, server-first: portable Rust services
   plus OS key custody and service packaging.
2. HOST-M2 on Omarchy with Pi first, then Linux launchers one host at a time,
   each promoted on its own doc 19 I01-I08 evidence.
3. HOST-M2 on macOS after the success test (roadmap section 11), once the
   Darwin runner, broker and resource backend land.
4. HOST-M3 pairs platforms that have reached HOST-M2; until macOS does, the
   executing organization runs Linux.

## Read in order

1. [NORTH-STAR-FLOWS](NORTH-STAR-FLOWS.md): north star, identity model, the three flows, exit criteria and the owner change register.
2. [ADR-0038](../../../adr/ADR-0038-native-host-program.md): the decision and its 2026-10-08 amendment.
3. [CASES](CASES.md): every acceptance case, by milestone.
4. [CAPABILITIES](CAPABILITIES.md): verb, owner, status and platform matrix.
5. [HOST-CONTRACT](HOST-CONTRACT.md): deployment profiles, native ports and the systems boundary.
6. [PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md): pinned sources and owner gates.
7. The [Omarchy annex](../2026-10-07-omarchy-integration/ANNEX.md) and the [macOS annex](../2026-10-07-macos-integration/ANNEX.md).

Supporting documents: [FIRST-CLASS-INTEGRATIONS](FIRST-CLASS-INTEGRATIONS.md)
(required harnesses and Herdr), [CONSUMERS](CONSUMERS.md) (independent consumer
design), [QUALIFICATION](QUALIFICATION.md) (profiles and release evidence),
[RELEASE](RELEASE.md) (verifier and activation), [OPERATOR](OPERATOR.md)
(optional operator projection), the [shared plan](../../plans/2026-10-07-desktop-integration.md),
[product research](research/product-grounding.md) and [review records](REVIEW.md).

## Boundaries

Hook-mode host activity is `detect_only`; hook failure does not block the host.
Isolation always comes from the host backend (bubblewrap, Seatbelt, containers
or VMs) and is credited through its #1174 S7 evidence kind; Chio grants, the
host denies. A receipt can be missing after a tool has already been dispatched
(#1174 KDEF-D1), so a missing receipt is not evidence that no effect occurred.
Nothing in this program is qualified or released until its CASES rows pass on
real hosts.
