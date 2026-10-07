# ADR-0038: One desktop operator program

- Status: Accepted for planning, 2026-10-07; not implemented or qualified.
- Decision owner: program owner, who instructed "Apply the broader architecture proposal now" after the cross-program review.
- `boundary_class`: `advisory_only` for the controller and its displays; authority belongs to the referenced kernel owners.
- `planning_status`: `ready_after_adr`; individual release gates below remain mandatory.
- Scope: desktop integration only. This decision does not ratify unrelated NVIDIA strategy decisions or change Chio's public positioning.
- Number allocation: ADR-0023 through ADR-0037 remain reserved for the strategy candidates indexed by input N in PROGRAM-MAP; choosing 0038 does not accept those candidates.

## Decision

Build one operator surface over Chio's work, recovery, process and security
programs. The workbench is the first client. Omarchy QML, the macOS menu bar
and CLI entry points are additional clients of the same controller and proposed
`chio.operator.v1` projection. The controller is an S1 C-layer component outside
the trusted computing base, in a separate process from the gateway and process
host. It holds no authority signing keys, asserts no trusted facts, issues no
capabilities and maintains no competing ledger.

The first execution product is **sealed, single-owner work**: select a project,
review a fixed recipe and acceptance contract, run an eligible host using
kernel-owned tools, inspect the resulting artifact, inspect evaluator-derived acceptance, then separately approve or reject patch
application and authorize any publication. A human click does not set W1
acceptance; the original configured evaluator and evidence contract do. Reuse the W1 work contract,
`chio-mini-swe`, restricted host sessions and the workbench. A new desktop task
runtime is out of scope. Pi is first because of existing evidence; the contract
must support doc 19's Claude Code, Codex, Cursor, Hermes, Pi and OpenClaw hosts.
Historical Pi evidence does not qualify a new version tuple.

Existing hook sessions are useful immediately as observation, with their actual
boundary displayed. No hook plugin or `chio run` launcher becomes an isolation
boundary through this decision. `chio run` speaks the native framed protocol;
it is not a general-purpose launcher for existing coding agents.

## Isolation denies, Chio grants

Use replaceable, thin isolation adapters. Do not expand `chio-cage`, a restricted
tool-server profile, into a general-purpose Node agent sandbox. Chio continues
to own the grant path: gateway, model relay, secret broker, kernel resources,
approvals, receipts, work and recovery. An external runtime's policy or approval
does not issue a Chio capability or count as an operator endorsement.

For the desktop program, this scopes the proposed ADR-0023 layer decision:
OS adapters remain allowed where a qualified runtime is unavailable. The
strategy owner must reconcile that amendment in ADR-0023; the unamended proposal
must not be cited as permission to freeze the secret broker or remove a grant
gate. No broader F-1 to F-17 decisions are implied.

The S7 owner must add and qualify evidence kinds for Linux agent-host bubblewrap,
macOS Seatbelt and any selected macOS VM runtime before they may render as
confined. These names are design candidates, not existing wire enum values.
`ProcessContainer` already has an owner; reuse it for the existing container
runner. Unknown kinds continue to render "not confined by Chio".

On macOS, retain Seatbelt as a lower-assurance native profile. Evaluate existing
VM runtimes before authoring a VZ supervisor or guest distribution. Apple
Containerization and OpenShell MicroVM are candidates, not selected or qualified
dependencies. Backend selection requires the annex's executable experiments.
An unsuccessful evaluation leaves the VM feature unavailable, not silently
replaced by Seatbelt.

## Product profiles and claims

`planning_status` is planning permission under ADR-0011, never runtime readiness.
Each session shows its exact host, backend, policy, software revisions, evidence
age and receipt kind beside the boundary class. One global "protected" badge is
insufficient.

| Profile | `boundary_class` by operation | `planning_status` | Required owner evidence |
| --- | --- | --- | --- |
| Observe | `detect_only` for hook activity; `cannot_see` for uninstrumented activity | `ready_after_adr` | S5 Part B and source-attributed observations; gaps shown |
| Approve and stop | `prevent` at the native pre-effect gate; display remains `advisory_only` | `ready_after_adr` | Approval: S28 identity, production endorsement verifier and exact decision binding. Independently gate per-task stop through S4 and Kernel stop through S8 with their own native authorization; absent approval prerequisites do not disable a qualified stop. |
| Sealed work | `prevent` for kernel-owned tools; isolation coverage separately attested | `ready_after_adr` | W1, recovery fixes, restricted host and runner, S7 backend evidence |
| Protected interactive | `prevent` only for qualified mediated tools; native shell removed | `ready_after_adr` | Host-specific doc 19 I01-I08 acceptance |
| Boundary interactive | `prevent` at qualified routed grant points; `cannot_see` for permitted local shell/file effects | `deferred` | Qualified isolation/egress/descendant coverage and S7 kind; no per-write receipt claim |
| Managed endpoint | `detect_only` for observations; restrictive OS control separately identified | `deferred` | ES/NE entitlements, consent or MDM, independent containment evidence |

Retire the former macOS `native-descendant-v1` proposal. It is not renamed to
Seatbelt and its ES/NE gates are not removed from a continuing release profile.
Reintroducing that design requires a separate decision and its original
restriction and network-containment evidence. ES/NE remain a managed-endpoint
track, not a shortcut to complete mediation.

## Reference before redefine

[PROGRAM-MAP](../architecture/PROGRAM-MAP.md) names the source owners and pinned
inputs. [OPERATOR](../superpowers/specs/2026-10-07-desktop-integration/OPERATOR.md) defines the desktop projection and
the conditions for a future wire freeze. The owner contracts control task
observations, recovery, events, stop, identity, IPC, processes, credentials,
host qualification and confinement. Missing owner functionality is a dependency
to implement there, not a desktop-private substitute.

Specifically:

- Work status preserves execution, acceptance, result, recovery, settlement and
  delivery as independent observations. Completion does not imply acceptance.
- Per-task stop uses S4 closure. S8 emergency control retains its own scopes and
  result kinds. A UI timeout is not proof of either stop.
- Stable subscriptions belong to S5 Part B. Events are hints, not grants;
  reconnect and retention gaps require owner reconciliation. Repeated paid
  `InspectWorkflow` polling is not a desktop event transport.
- Approvals require the S28 roster, a production verifier and exact requested
  decision/approval-ID binding in the installed native utility. The Pi wrapper's
  refusal is useful containment, not proof that its bundled utility is fixed.
- Reuse `chio-secure-ipc`; implement Darwin peer authentication in that owner.
  Reuse `chio-process` and the secret broker/model relay rather than parallel
  supervisors, key stores or proxies.

## Scope removed and retained

Remove Omarchy compositor tools and configuration repair. Delegation belongs to
the kernel/process/work programs and is not a desktop phase. Preserve platform
research, plugin packaging, compatibility experiments, failure/recovery UX,
accessibility, privacy and release acceptance in the two annexes.

Retire the two proposed platform protocols and their synthetic schema corpora.
Their correctness findings become owner acceptance obligations in the shared
projection and qualification plan. They are not compatibility commitments or
evidence of working software. Git history retains the repaired proposals and
validation records; the replacement is intentionally smaller.

The shared-program/Omarchy change owns this ADR and the common documents. The
macOS annex is reviewed as a dependent change on that branch. No merge or
runtime rollout is authorized by documentation approval. The PRs remain open
for review; bot verdicts are documentation-review evidence, not product qualification.

## Positioning and alternatives

Preserve Chio's positioning as a modern Rust kernel for agentic operating
systems. This change also aligns README, AGENTS and their public diagrams with
the boundary classes in [ADR-0011](ADR-0011-boundary-taxonomy-product-wording.md).
The opening leads with capability, scopes the described operations once, and
links to a consolidated account of boundaries and current limits. Platform
rows retain their specific qualification status. Public captions explain
authorization directly rather than using internal program-map vocabulary.

Track a receipt-copy follow-up against [S3 phase 1 in PROGRAM-MAP](../architecture/PROGRAM-MAP.md):
only after the D1 closure is implemented and its production conformance is
qualified may the affected paths claim a signed terminal receipt or explicit
retained uncertainty. Landing a plan or source change alone does not justify
that stronger claim; current copy preserves possible effects after receipt
failure. Onboarding follows the same capability-first, evidence-bound rule.

Rejected: two independent controllers and task models; hook-based protection
claims; a mandatory bespoke VM before evaluating existing runtimes; changing
Omarchy's upstream launch defaults; and treating all north-star keystones as
desktop blockers. Accepted instead: explicit owner sequencing and narrowly
scoped platform adapters. The consequence is genuine predecessor work before
some UI controls can be enabled, rather than a second implementation of it.
