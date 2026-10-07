# Chio macOS implementation plans

Status: proposed execution plans, 2026-10-07. The current change produces specifications, plans and document validation only. Product implementation and installed qualification are future work.

Each plan uses the Superpowers writing-plans structure, proposed/current file ownership, checkbox tasks, concrete test fixtures or snippets, commands, expected outcomes, and commit boundaries. Read the [specification index](../../specs/2026-10-07-macos-integration/README.md) and [dependency roadmap](../../specs/2026-10-07-macos-integration/19-roadmap-decisions.md) first. Missing native contracts remain owned prerequisites, never permission to invent controller authority.

| Track and plan | Depends on | Deliverable |
| --- | --- | --- |
| [M0 Kernel prerequisites](00-kernel-prerequisites.md) | Pinned source audit and north-star implementation owners | Exact delivered native contracts, ABI/crossing census and unavailable-state reports |
| [M1 Native operator](01-native-operator.md) | Read-only source contracts; M2/M6 for installed mutation/recovery UI | SwiftUI/AppKit app, Services/menu bar, safe review and permission states |
| [M2 Protocol/controller](02-protocol-controller.md) | M0 for actual mutation; codec component work can start earlier | Shared closed operator contract, authenticated XPC and actual native adapter |
| [M6 Recovery/evidence](06-recovery-evidence.md) | M0, M2 | Original-operation recovery, native stop/closure, stable event identity and freshness gates |
| [M3 VM project](03-vm-project.md) | M0, M1, M2, M6 and M4 foundation tasks | Exact guest backend, broker transport and useful-task composition with M4 |
| [M4 Resources/publication](04-resources-publication.md) | Foundation: M0/M2/M6; integrated output/publication: M3 backend | Immutable input, protected tests, sealed artifact and exact publication |
| [M5 Native enforcement](05-native-enforcement.md) | M0, M2, M6 and Apple entitlements/selected SDK | Separately tested ES/NE restrictions and native/managed profile gates |
| [M7 Adapters/delegation](07-adapters-delegation.md) | M3, M4, M6; optional M5 for claimed native enforcement | Exact framework adapter tuples, attenuated delegation and selective Clawdstrike components |
| [M8 Distribution/qualification](08-distribution-qualification.md) | Applicable completed tracks selected in a pre-run manifest | Signed installed composition and independent profile-specific qualification result |

Numeric track IDs are identifiers, not an execution order. A VM-only release does not require an optional ES/NE track, but it cannot advertise it. Read-only app and codec development may proceed while native prerequisites remain unavailable. No installed execution profile closes before its actual recovery, authority and isolation gates pass.

Resource/VM task order is explicit: M4 tasks 1, 3, 2 and 5; M3 task 0 preparation; M3 tasks 1 through 7 with task 0 integrated boot probes after tasks 2 through 4; M4 task 4; M3 task 8 and M4 tasks 6/7; M4 task 8; then M8. Each step observes its M0/M1/M2/M6 prerequisites. This separates foundation construction from installed qualification and avoids a whole-track circular dependency.

Future command examples assume implementation files have been created by the earlier steps. Missing commands or native APIs are not evidence of passing acceptance; their delivered artifacts are prerequisites. Tests that use injected peers, fake clocks or fixtures remain component evidence. Final profile qualification uses independently observed installed signed artifacts.

The [requirements manifest](../../specs/2026-10-07-macos-integration/requirements.json) provides primary-plan traceability. The immutable applied-profile manifest in spec 17 provides runtime case applicability and cannot be replaced by a plan label or a successful document check.
