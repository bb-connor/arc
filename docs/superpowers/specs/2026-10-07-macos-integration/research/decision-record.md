# Research decision record

> Historical research snapshot retained for provenance. [ADR-0038](../../../../adr/ADR-0038-desktop-operator-program.md), the [program map](../../../../architecture/PROGRAM-MAP.md) and [macOS annex](../ANNEX.md) supersede this document's former implementation choices. Old NK identifiers and platform methods below are historical proposal labels, not current APIs or blanket desktop prerequisites. The shared program retains the needed admission, crossing and ABI safety properties through their owning contracts; it does not require all three redesign keystones before the first product.

Researched 2026-10-07. This program expands the user-approved Mac research direction and the Omarchy specification method. The earlier local research brief is an input, not a current runtime qualification or normative specification. Current source findings below and in the sibling research files take precedence over that earlier snapshot.

## Approaches considered

| Approach | Benefit | Cost or limit | Decision |
| --- | --- | --- | --- |
| Native operator, one kernel, typed brokers, separate execution profiles | Useful existing-workspace workflow; shared authority across Mac/Linux; narrow review and recovery semantics | Requires kernel prerequisite delivery and platform-specific qualification | Selected |
| System-wide endpoint product first | Broad observations and organizational posture | Permissions, global failure effects, attribution ambiguity and a temptation to duplicate authority; OS events do not prove semantic agent intent | Optional managed profile later |
| Native process wrapper plus MCP hooks | Quick adoption around existing CLIs | Direct networking, subprocesses, plugins and inherited credentials may bypass hooks; launch wrapping alone does not supply confinement | Observation-only until full declared routes are mediated and qualified |

The selected workflow is a fixed portable project task from a committed source generation, a sealed task objective, an isolated worker, protected tests and a review artifact. Exact publication is an added capability with its own destination and recovery contract. This gives the platform an indispensable use before asking for full-machine permissions.

## Source-backed conclusions

1. The north-star documents call for one pure admission machine, one crossing mechanism and integrity-gated authority. Current main has useful admission/store/approval infrastructure but not the complete target contracts. See [readiness](chio-readiness.md).
2. macOS supplies supported platform primitives for user-space services, XPC, virtualization, system extensions, Endpoint Security and Network Extension. Their permission, lifetime and coverage models differ. See [Apple platform](apple-platform.md) and [distribution](distribution.md).
3. The descendant-scoped ES client is strategically relevant to a Chio-owned launcher. Newly fetched DocC metadata identifies macOS 27.0 and reports non-beta, while rendered/search documentation still carries beta markings. The research records this discrepancy; exact final SDK and OS runtime behavior remain unqualified. The current detailed Apple page also describes coverage of existing descendants, correcting the earlier brief's narrower creation-time summary. See [the recorded source](apple-platform.md).
4. Clawdstrike has real ES/NE components, a HushSpec compiler, detectors, health state and qualification machinery. Its observed AUTH_OPEN tool and host/port egress restrictions do not establish complete per-task mediation. Specific process-incarnation and installed-provider proof gaps require remediation. See [Clawdstrike audit](clawdstrike.md).
5. The initial Mac app can use Services and native views without treating Finder Sync as a generic launcher or implying OS permission equals agent approval. Screen-capture protection is not inferred from view flags. See [workflow research](macos-workflow.md).

## Confidence and experimental boundaries

Confidence is high in inspected-source distinctions and the need for one authority owner. Confidence is moderate in component placement until integration experiments run. Entitlement availability, final native descendant behavior, full local guest qualification, battery/performance thresholds and final release support remain unknown until measured.

A Linux VM supplies neither Darwin-only developer tools nor automatic transfer of x86_64 Linux confinement evidence to Apple Silicon. A sensor event supplies neither a signed kernel decision nor proof that a missing event means no effect. A code signature supplies software identity, not trustworthy task content. An internally consistent restored log supplies no independent proof that authority is current.

The resulting program preserves those boundaries through normative requirements and explicit negative cases. Primary sources, immutable public source links and implementation paths are retained in the research files and [source identity registry](source-pins.json).

## Accepted consolidation amendment

A restricted launcher can provide a useful OS boundary, but only qualified gateway-routed operations are Chio-mediated. Permitted local shell/file effects inside the workspace remain `cannot_see`, not per-write receipts. Hook-only observation remains `detect_only`. The native Seatbelt candidate is retained alongside a VM evaluation; boundary-interactive use remains deferred pending its distinct evidence. The first execution product stays sealed W1 work through existing owners, and `chio run` is not a general coding-agent launcher. No acceptance boolean from the desktop replaces W1's configured evaluator evidence.
