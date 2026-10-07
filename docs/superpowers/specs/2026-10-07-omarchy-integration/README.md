# Chio for Omarchy: research and specification set

Status: Proposed architecture and implementation plan, researched 2026-10-07.
This change supplies documents, synthetic contract examples and a document
validator. It implements no runtime, installs no plugin and qualifies no release.
Confidence: high in the cited source findings and selected separation of roles;
moderate in the proposed delivery design until the named native/Linux gates close.

Chio can supply Omarchy with a modern Rust kernel for agentic operating systems:
durable task authority, bounded resource access, exact review and recoverable
execution evidence. The useful desktop product is a native place to launch,
observe, interrupt, review and recover those tasks. Shared homepage styling is
not a technical integration point. Omarchy's actual QML plugin model is.

The selected design is a native `computer.chio.desktop` QML plugin, a thin Rust
controller and existing Chio kernel/authority behind protected host/resource
adapters. The first execution workflow is one confined Pi project task with a
fixed recipe and a sealed local review artifact. Exact approved publication,
bounded desktop tools, configuration repair and delegation are separate phases.
There is no shell fork, replacement authority or implicit agent CLI wrapper.

## Read in this order

1. [Scope and first useful workflow](01-product-scope.md).
2. [Source readiness and missing native contracts](research/chio-readiness.md).
3. [Controller architecture](04-controller-architecture.md), [authority](06-authority-approvals.md)
   and [durable state](14-state-evidence-data.md).
4. [Roadmap and prerequisite owners](16-roadmap-decisions.md).
5. [Implementation plans](../../plans/2026-10-07-omarchy-integration/README.md)
   and [verification program](15-verification-release.md).

## Complete specification map

| Spec | Scope |
| --- | --- |
| [01 Product](01-product-scope.md) | Audience, concrete workflow, alternatives, non-goals and adoption experiment |
| [02 Desktop experience](02-desktop-experience.md) | Enrollment, status, task/review flows, keyboard, accessibility, privacy and empty/error states |
| [03 Omarchy plugin](03-omarchy-plugin.md) | Manifest, QML lifecycle, service injection, panel/bar, IPC, theme and release compatibility |
| [04 Controller](04-controller-architecture.md) | Rust ownership, native adapters, launch pipeline and failure boundaries |
| [05 Operator protocol](05-operator-protocol.md) | AF_UNIX framing, methods, idempotency, concurrency, errors, events and bounds |
| [06 Authority and approvals](06-authority-approvals.md) | Threat model, capability custody, exact review, revocation and native decision blocker |
| [07 Host/provider adapters](07-host-provider-adapters.md) | Restricted Pi, provider routing, truthful limits, private input, continuation and native prerequisites |
| [08 Linux confinement](08-linux-confinement.md) | Runtime closure, namespaces, syscall policy, cgroups, sockets, credentials and session lifecycle |
| [09 Project resource](09-project-resource.md) | Enrollment/import, immutable generations, closed tools, fixed tests and local review publication |
| [10 Desktop tools](10-desktop-tools.md) | Closed compositor resource, bounded metadata, workspace effect and excluded risky surfaces |
| [11 Configuration repair](11-configuration-repair.md) | Scalar parser, exact diff, writer exclusion, backup, reload and partial/unknown outcomes |
| [12 Distribution and operations](12-distribution-operations.md) | Arch packages, provenance, user units, upgrades, rollback, backup, support and removal |
| [13 Delegation and multiple hosts](13-delegation-multihost.md) | Native child custody, attenuation, budgets, failure aggregation and host admission |
| [14 State and evidence](14-state-evidence-data.md) | State machine, native vs local truth, SQLite transactions, replay, quotas and recovery |
| [15 Verification and release](15-verification-release.md) | Independent oracles, fault campaigns, profile matrix and evidence classes |
| [16 Roadmap and decisions](16-roadmap-decisions.md) | P0-P7 ordering, named blockers, ADRs and experiment rejection rules |
| [17 Privacy and performance](17-privacy-observability-performance.md) | Data inventory, disclosure, diagnostics, redaction, lock races and measured budgets |

## Source research and machine contracts

- [Omarchy upstream](research/omarchy-upstream.md): released v4.0.4 and inspected
  development source, native extension surfaces and compatibility differences.
- [Chio readiness](research/chio-readiness.md): actual public/base/candidate source
  inventory and missing deliverable contracts.
- [Linux platform](research/linux-platform.md): kernel/systemd/Arch primary sources
  and limits of the existing ARM64 container evidence.
- [Desktop ecosystem](research/desktop-ecosystem.md): OMCP baseline, compositor,
  configuration effects and reuse decisions.
- [Source identity registry](research/source-pins.json): inspected identities and
  source-map relationships, not install instructions or supported-version claims.
- [Machine contracts](contracts/README.md): six schemas, method/fixture catalogs
  and positive/negative synthetic examples.
- [Requirements traceability](requirements.json): every numbered requirement and
  proposed acceptance definition. `planning_phase` organizes work; profile release
  applicability must pass `P0-PROFILE-MATRIX` before qualification.

## What prevents an execution release today

Public source trees and developed native candidates do not yet identify one
qualified, distributable Omarchy tuple. Pi's recorded Linux evidence is an ARM64
container composition, not non-root x86_64 Omarchy. The candidate approval command
deliberately refuses because the native decision path must validate the requested
decision before retention. Dirty project staging needs a trusted consistent
importer. Configuration apply needs enforceable writer exclusion and bounded
reload effects; ordinary hash-then-rename does not supply that contract.

These are work items with owners and acceptance artifacts, not reasons to add
local authority substitutes. Read-only integration can progress independently.
See the [prerequisite register](16-roadmap-decisions.md#prerequisite-register)
and the [verification record](reviews/validation.md) for this PR's actual checks.

## Validate this package

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py --self-test
```

Requires Python 3.11+ and `jsonschema==4.21.1`; isolated setup is documented in
[contracts](contracts/README.md). The validator checks local links, requirement
coverage, closed example shapes and response substitution. It does not run any
acceptance test named by an `AT-*` identifier.

When editing a normative requirement, regenerate its traceability explicitly:

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py --write-traceability --self-test
```
