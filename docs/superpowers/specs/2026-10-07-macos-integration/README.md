# Chio for macOS: research and specification program

Status: proposed architecture, contracts and implementation plans, researched 2026-10-07. This change supplies documents, synthetic contract fixtures and a document validator. It delivers no app, installs no extension, changes no Mac permissions and qualifies no runtime release.

Chio.app makes the modern Rust kernel for agentic operating systems useful from the Mac desktop: bounded jobs in existing workspaces, typed resource access, exact review, durable stop and recoverable evidence. The selected architecture is a native SwiftUI/AppKit operator, a per-user Rust controller, the same native authority kernel, resource brokers and independently qualified execution profiles.

The first workflow is **Run with Chio** through Finder/Services or the app: select a committed project generation, seal the task objective, execute a fixed portable recipe in a qualified worker, run protected tests and review the resulting artifact. No-replace local artifact publication is the first exact release effect. Git publication, native app actions, general GUI control and managed endpoint coverage have separate gates.

Confidence is high in the cited source findings and authority ownership requirements, moderate in the proposed integration design, and unknown for final installed platform qualification. The kernel north-star program remains a design dependency; current source does not implement all of its contracts. Apple's retrieved descendant-ES metadata has changed since the initial research and differs across documentation surfaces; the platform research preserves that evidence without claiming final runtime qualification.

## Read in this order

1. [Scope](01-product-scope.md) and [native experience](02-native-experience.md).
2. [Current source readiness](research/chio-readiness.md) and [kernel contract crosswalk](03-kernel-contracts.md).
3. [Architecture](05-host-architecture.md), [authority/integrity](04-authority-integrity.md) and [recovery](11-state-recovery.md).
4. [Roadmap and decision gates](19-roadmap-decisions.md), then the [implementation plans](../../plans/2026-10-07-macos-integration/README.md).
5. [Qualification](17-qualification.md), [machine contracts](contracts/README.md), and the actual [document validation record](reviews/validation.md).

## Complete specification map

| Specification | Scope |
| --- | --- |
| [01 Product scope](01-product-scope.md) | Audience, first useful task, alternatives, profile scope, adoption and exclusions |
| [02 Native experience](02-native-experience.md) | App/menu bar/Services/Intents, review, permissions, accessibility, localization and safe failure states |
| [03 Kernel contracts](03-kernel-contracts.md) | Pure admission, crossing census, native ABI descent, writer ownership and missing contracts |
| [04 Authority and integrity](04-authority-integrity.md) | Principals, grants, budgets, exact endorsement, input influence, key custody and revocation |
| [05 Host architecture](05-host-architecture.md) | Process boundaries, authenticated IPC, trusted brokers, provider restrictions and component ownership |
| [06 Operator protocol](06-operator-protocol.md) | Closed methods, shapes, bounds, retries, original identity, hints and versioned Omarchy migration |
| [07 VM execution](07-vm-execution.md) | Guest architecture, devices, no-NIC profile, broker transport, launch identity and containment |
| [08 Endpoint Security](08-endpoint-security.md) | Descendant/global scope, deadlines, identity, coverage, caches, client death and evidence |
| [09 Network Extension](09-network-extension.md) | App/process attribution, egress restrictions, existing flows, ambiguity and failure behavior |
| [10 Project resources](10-project-resources.md) | Immutable import, sealed input, protected tests, local review, publication and app resource boundaries |
| [11 State and recovery](11-state-recovery.md) | Durable stop, original operation, closure, stable subscriptions, restore freshness and uncertain effects |
| [12 Distribution](12-distribution.md) | Signed bundles, entitlements, notarization, activation, updates and managed deployment |
| [13 Privacy and performance](13-privacy-performance.md) | Data inventory, disclosure, redaction, retention, diagnostic export, latency and battery measurement |
| [14 Operations](14-operations.md) | Multi-user sessions, lock/logout/sleep, health, degraded behavior, update/removal and support |
| [15 Host adapters](15-host-adapters.md) | Framework compatibility, credentials, model release, transport and truthful mediation coverage |
| [16 Delegation](16-delegation.md) | Child authority, hierarchical budgets, remote custody, partitions, stop and evidence aggregation |
| [17 Qualification](17-qualification.md) | Independent oracles, attacks, profile applicability, source/installed evidence and release decisions |
| [18 Clawdstrike reuse](18-clawdstrike-reuse.md) | Source audit, policy projection, sensors, response gaps, coexistence and ownership |
| [19 Roadmap](19-roadmap-decisions.md) | Decisions, dependencies, owners, go/no-go experiments and release claim discipline |

## Research and executable document checks

- [Decision record](research/decision-record.md): selected architecture and alternatives.
- [Chio readiness](research/chio-readiness.md): inspected current implementation versus native north-star dependencies.
- [Apple platform](research/apple-platform.md): primary-source API, isolation, provider and lifecycle findings.
- [Mac workflow](research/macos-workflow.md): native affordances and UX constraints.
- [Distribution research](research/distribution.md): platform packaging, signing, approvals and operations.
- [Clawdstrike](research/clawdstrike.md): immutable public source audit and selective reuse.
- [Source identity registry](research/source-pins.json): source roles and inspected identities, not public checkout instructions.
- [Requirements](requirements.json): every normative requirement, same-file acceptance procedure and primary plan; all acceptance is initially specified, not executed.
- [Contracts](contracts/README.md): six schemas, a closed method catalog, synthetic positive/negative examples and response-binding checks.

```bash
python3 docs/superpowers/specs/2026-10-07-macos-integration/verify.py --self-test
```

Python/dependency setup is documented in [contracts](contracts/README.md). The validator checks the documents and synthetic contract corpus. It does not execute any installed acceptance procedure, validate native signatures, or qualify a Mac profile.

## What remains unavailable until implementation and evidence exist

Current main does not provide the complete north-star pure admission/crossing, integrity endorsement, durable-stop, lineage/recovery and Mac backend contracts. A Mac controller cannot substitute local mechanisms. Exact contract prerequisites are owned in the source crosswalk and M0 plan.

The proposed execution profiles are `observe-v1`, `brokered-v1`, `vm-project-v1`, `remote-project-v1`, `native-descendant-v1`, and `managed-endpoint-v1`. Each qualifies independently against its installed tuple. `publication-v1` is an added feature with its own cases. App development can begin with read-only unavailable states; neither a successful UI prototype nor a signed provider opens an execution gate.

This set is a complete design program for the declared product scope, including optional tracks and rejection rules. It is not a promise that all OS mechanisms or every future integration are already possible or implemented.
