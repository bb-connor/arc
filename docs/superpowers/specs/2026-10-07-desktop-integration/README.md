# Chio native host integration program

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.**

This program makes that kernel useful as a native systems layer on Linux/Omarchy
and macOS. External applications, agent harnesses and Herdr own their workflows
and interfaces. Chio supplies reusable authority, process/resource custody,
work evidence and recovery through qualified owner contracts above the OS.

Status: accepted planning direction, amended 2026-10-08 UTC. The specifications
do not qualify an implementation, installed profile or release.
`planning_status: ready_after_adr`; `boundary_class` belongs to each operation.
Consumer presentation and the optional operator projection are `advisory_only`.

The required first-class integrations are **Claude Code, Codex, Pi and Hermes**,
plus **Herdr as a workspace/plugin consumer**. Each uses its existing integration
owner and receives separate native acceptance. Mini-swe is an optional
reference/test workload; it does not set platform requirements or harness
priority. See [required integration scope](FIRST-CLASS-INTEGRATIONS.md).

## Read in order

0. [North-star flows](NORTH-STAR-FLOWS.md): proposed governing design, pending owner review. It turns the three verbs into the M1, M2 and M3 flows that the other documents will be restructured around.
1. [Accepted native host decision](../../../adr/ADR-0038-native-host-program.md).
2. [Product research and alternatives](research/product-grounding.md).
3. [Capability and roadmap traceability](CAPABILITIES.md).
4. [Native host contract and architecture](HOST-CONTRACT.md).
5. [Pinned source owners and dependency gates](../../../architecture/PROGRAM-MAP.md).
6. [Independent consumer acceptance](CONSUMERS.md).
7. [Optional operator projection](OPERATOR.md).
8. [Native qualification and release evidence](QUALIFICATION.md).
9. [Qualification verifier and native activation](RELEASE.md).
10. [Shared delivery plan](../../plans/2026-10-07-desktop-integration.md).
11. [Omarchy/Linux annex](../2026-10-07-omarchy-integration/ANNEX.md).

The [macOS annex](../2026-10-07-macos-integration/ANNEX.md) and its
[implementation plan](../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md)
are the dependent platform change included in this composed branch. The shared
directory name is retained for review continuity, not as a requirement to ship
a Chio desktop.

## What a valuable integration proves

Install the native candidate. Start the selected owner services or embed the
qualified library profile. Connect an external harness and a materially different
application without a Chio UI. Each performs useful authorized work, encounters
an independently observed refusal, reconnects after a lost reply without duplicate
effects, and reads the same owner evidence. Remove the frontend and repeat.

Then prove the ambition's three dimensions through their proper owners:

- **Coordinate work:** stable agent/process identities, bounded delegated authority,
  accepted dependencies and original-operation recovery let applications divide
  work without implementing a second authority or recovery machine.
- **Share resources:** concurrent agents use one authoritative allowance/resource
  owner, current assignment fences and explicit limits. Native resource denial
  remains effective if clients crash or misreport their counters.
- **Cooperate across organizations:** enrolled independent owners retain their
  keys and policy, verify the other's evidence, refuse unauthorized work or
  disclosure, and reconcile loss without inventing new rights or effects.

Basic Observe, process/control and other narrow capabilities can ship independently
with truthful scope. They do not alone complete the above ambition. Two local
clients prove reuse; two independent organizations prove a separate trust boundary.
Passports are credentials, OS identity identifies a local peer, and a current
capability authorizes a specific action. The integration must preserve all three.

## Deployment and consumer scope

Embedded, user-session and separately enrolled service-principal profiles have
different trust, credential and lifecycle requirements. Headless means a frontend
is unnecessary; it does not automatically mean work may survive logout or boot.
Platform plans own those distinctions and their tests.

Existing Rust/SDK/CLI/native owner surfaces come first. `chio.operator.v1` is an
optional view composition, not the generic kernel API or a required daemon.
Megastart and Herdr demonstrate the application/host split; their mission API,
coordinator logic and task layout remain application-specific. Workbench, menu
bar, Omarchy plugin and notifications may consume qualified contracts later.

Selected graphical clients retain keyboard/screen-reader access, inert artifact
rendering, private notifications, exact native approvals and browser-origin
security. Selected coding workloads retain evaluator confinement, safe patch
export and separate publication authority. Those obligations do not become
prerequisites for unrelated headless resource or process capabilities.

## Coverage and change discipline

| Concern | Governing artifact |
| --- | --- |
| Product direction, trusted core, external application role | ADR-0038 and HOST-CONTRACT |
| Passports, recursive delegation, swarm authority, work, recovery and competitive choices | CAPABILITIES, product research and PROGRAM-MAP |
| Real APIs/ABI, native owners, current versus proposed status | PROGRAM-MAP; owner source controls |
| Native deployment, OS ports, credentials, IPC, lifecycle, resource custody | HOST-CONTRACT plus platform annexes |
| Required Claude Code, Codex, Pi, Hermes and Herdr support | FIRST-CLASS-INTEGRATIONS, per-platform H01-H08 and existing I01-I08 |
| Harness/application reuse, shared resources and independent-owner cooperation | CONSUMERS and QUALIFICATION |
| Optional view correlation, approval display and browser/native clients | OPERATOR; only for consumers selecting this projection |
| Native adversarial cases, measured budgets, release/update/removal | QUALIFICATION and platform executable case manifests |
| Dependency order, owner handoffs and acceptance evidence | Shared and platform implementation plans |

Every addition names its owner, native boundary, consumer benefit, selected
profile, source status and independent acceptance. Missing owner semantics go
back to that owner. A UI need cannot create a second signer, ledger, scheduler
or retry model. [Review records](REVIEW.md) distinguish document validation from
runtime and public release evidence.
