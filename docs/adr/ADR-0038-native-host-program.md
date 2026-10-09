# ADR-0038: Native host program

- Status: Accepted for planning, 2026-10-07; amended 2026-10-08 UTC after the product-direction review. Not implemented or qualified.
- Decision owner: program owner, who approved the combined program and then explicitly required the systems-layer direction grounded in Chio's public documentation and kernel roadmaps.
- `boundary_class`: per native operation/profile; consumer projections are `advisory_only`.
- `planning_status`: `ready_after_adr`; every selected owner and installed-profile gate remains mandatory.
- Scope: shared native host integration, Linux/Omarchy and macOS platform ports, and external consumer acceptance. This amendment replaces the workbench-first and sealed-coding-first delivery order.
- Number allocation: ADR-0023 through ADR-0037 remain reserved for strategy candidates indexed by input N in PROGRAM-MAP. This decision does not accept those candidates wholesale.

## Product decision

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.**

Implement reusable userspace systems services above the existing OS kernel.
Applications, agent harnesses, Herdr and domain schedulers use Chio's native
contracts for identity, authority, resource custody, work/evidence and recovery.
They retain planning, model/context management and UX. A useful qualified native
profile must work with every Chio graphical frontend and optional operator
projection absent. A user-presence approval policy can still require its
specified interaction; headless deployment cannot bypass that policy.

The [host contract](../superpowers/specs/2026-10-07-desktop-integration/HOST-CONTRACT.md)
defines embedded, user-session and service-principal profiles. They are separate
identity, credential and lifecycle contracts. No new universal daemon is
required. Reuse existing owner processes where their custody model requires
separation; an embedded consumer that holds authority or trusted ports is part
of the declared TCB. Removing a UI does not remove login, lock, expiration or
revocation checks from a user-session profile.

The first product proof is independent installed consumers performing useful
work through qualified native owners without a Chio frontend. Early Observe,
process, resource and control slices have independent gates. Durable verifiable
work, shared resources and independently administered cooperation extend that
proof through their own owner gates. A complete cross-organization claim needs
the cooperation acceptance, not merely two local interfaces. Sealed coding is
one workload. It is not a prerequisite for every host integration or resource.

## Required integration scope

The user amendment requires first-class Claude Code, Codex, Pi and Hermes
support through their existing integration repositories/owners, plus the Herdr
workspace plugin. [FIRST-CLASS-INTEGRATIONS](../superpowers/specs/2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md)
defines source handoffs and installed acceptance on both native platforms.
Herdr support is required; its installation is optional. Each host/platform can
ship when individually qualified, while full coverage remains an explicit open
program obligation. Cursor/OpenClaw obligations in the broader six-host roadmap
remain intact. Mini-swe is optional reference/test infrastructure, never a
mandatory backend, architecture dependency or default product priority.

## Existing technology controls the design

[PROGRAM-MAP](../architecture/PROGRAM-MAP.md) pins the implementation and roadmap
owners. [CAPABILITIES](../superpowers/specs/2026-10-07-desktop-integration/CAPABILITIES.md)
traces product decisions to passports, recursive delegation, swarm authority,
processes, verifiable work, shared resources, federation, recovery and evidence.
Each capability has a consumer benefit and a qualification obligation.

- L0 admission, capability validation, native policy/guards, receipt and current
  authority owners retain their semantics. L1 process identity/custody, L2
  planned work and L3 recovery compose those owners. R11 lowering and R12
  declared layer descent prevent a new desktop or application kernel dialect.
- Portable agent identity and passport verification inform relying-party
  policy. Neither a passport, discovery result, application account nor an OS
  process identity independently grants tool, resource or result access.
- Recursive attenuation, revocation, allocation and swarm graph/join authority
  stay at their actual owners. Application task trees cannot stand in for
  verified authority chains. Unsupported chain depth or shared-budget forms
  fail closed; the Megastart direct-worker example grants no multi-hop waiver.
- External applications choose task assignment and acceptance procedures. The
  work owner binds the original contract and validates the configured evaluator
  evidence. Six work observations remain independent; a UI click or process
  exit cannot create acceptance or disclosure authority.
- Shared allowances and mutable resources have an authoritative admission or
  resource owner. Local consumer counters, OS scheduling quotas and portable
  receipts cannot replace that owner or imply globally atomic fleet budgets.
- Independent organizations retain separate keys, policy, stores and refusal.
  Federation and scoped owner services require enrolled peers, current native
  admission, audience checks and loss-safe evidence. Unpaid cooperation does
  not require the full market/funding stack; the selected W2 transport and
  cooperation gates still apply.

Public documentation and Megastart/Herdr supply product and application evidence.
Their application-specific API is not the kernel ABI. Existing code, planned
interfaces, historical exercises, installed acceptance and public availability
remain separate evidence classes.

## Native OS ports and isolation

Chio owns grant semantics and trusted custody. macOS/Linux supply process,
identity, IPC, filesystem, network, timing and service-management mechanisms.
Implement thin qualified adapters in the existing owners, with independently
observed denial, cleanup and recovery. Do not expand the restricted tool-server
`chio-cage` into a general Node-agent sandbox. No hook or launcher becomes an
isolation boundary through this decision. `chio run` retains its native framed
protocol meaning.

The strategy's proposed ADR-0023 must be reconciled with this split: reusable
external containment and thin native OS adapters are allowed, while secret
brokering, native authority and resource/evidence joins stay in Chio's owners.
An external policy approval is not a Chio grant. OpenShell and other runtimes
are candidates to qualify at an explicit seam, not mandatory dependencies or
proof of a native profile. NVIDIA research supplies strategic alternatives and
historical measurements; it does not justify current exclusivity claims.

S7 must own and qualify new agent-host bubblewrap, Seatbelt or selected macOS VM
evidence kinds before any confinement claim. `ProcessContainer` has an existing
owner. Unknown kinds remain unconfined. macOS Seatbelt stays a separate lower
assurance profile; evaluate existing VM runtimes before a bespoke supervisor.
Failed VM evaluation leaves that profile unavailable. ES/NE remain a separately
qualified managed-endpoint track. The retired `native-descendant-v1` design is
not revived under a new name.

## Optional consumers and controls

`chio.operator.v1` remains a proposed bounded C-layer projection for applications
that choose shared operator views. It is outside the TCB, holds no authority
signer or competing ledger, and does not become a universal execution ABI.
Workbench, Omarchy QML, macOS menu bar and notifications are optional consumers.
Their browser, accessibility, privacy and native approval obligations remain
mandatory when selected. Their absence cannot disable a qualified owner stop,
recovery query, resource operation or harness binding.

The existing `chio` CLI is a required diagnostic/admin consumer for the native
host release, using the actual selected owner bindings. Packet 4a retains
source and installed CLI acceptance. No command is advertised before it exists.
No failure may fall back to a more privileged CLI path.

Approval, per-task stop and kernel stop qualify separately. S28 and the production
endorsement verifier gate attributable approval; the installed approval utility
must bind exact decision and approval ID. S4/process closure gates task stop;
S8's selected scope/durability gates kernel stop. Missing approval never disables
an independently authorized qualified stop. UI timeout is no stop evidence.

## Delivery and retained obligations

1. Reconcile pinned sources, real API/ABI and selected deployment capability set.
2. Qualify native identity, IPC, custody, storage, time and selected owner actions.
3. Bind existing Rust/SDK/native contracts; freeze only implemented surfaces
   against independent consumers and owner conformance.
4. Deliver headless external harness/application acceptance and the existing CLI.
5. Prove selected coordination, shared resources and independent-owner cooperation;
   sealed coding and funded settlement are separately selected workload profiles.
6. Qualify exact native packages, upgrades, recovery and removal. Add optional
   presentation independently with its complete selected-surface matrix.

[QUALIFICATION](../superpowers/specs/2026-10-07-desktop-integration/QUALIFICATION.md)
retains the prior native adversarial obligations and adds headless/product tests.
S1/S9/S10/S11 remain the kernel simplification, admission/crossing and integrity
roadmaps. Whole-program completion is not a blanket gate for every host read,
but selected admission, persistence, current authority, crossing, ABI and
post-effect uncertainty invariants cannot be waived. Tests and owner-approved
exclusions, not prose scope changes, decide each release claim.

Omarchy compositor tools and configuration repair remain removed. Delegation is
a kernel capability consumed by this program, not a desktop-owned implementation.
The old independent platform protocols and synthetic corpora remain retired;
their native safety findings survive in owner acceptance. Existing paths and
packet IDs remain for continuity and do not imply a desktop-led architecture.

Documentation review, hosted CI, runtime qualification and public release remain
separate. The shared/Omarchy change owns this decision; macOS remains a dependent
annex. No merge, runtime rollout or public-site publication follows from this ADR.

## Amendment 2026-10-08: north star and flows

Status: accepted by the program owner on 2026-10-08, together with the unified
roadmap (#1196) that schedules this program.

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.** Supporting
line: **Authority that only narrows. Work that survives. Evidence that travels.**

1. **Kernel.** Chio is a userspace authority and work-state kernel. Isolation
   always comes from the host (bubblewrap, Seatbelt, containers or VMs) and is
   credited per S7 evidence kind: isolation denies, Chio grants.
2. **Retired phrases.** "The kernel your agents answer to", "Agents that pay
   each other", "only protocol" claims, "kernel for building agentic operating
   systems" and unscoped "every call" are retired.
3. **Identity.** The units are organization principal, then domain, then agent
   subject, then operator. Key custody uses OS-native storage through key
   references, built on #1160's `signing_custody`; plaintext seed files are a
   labelled development profile.
4. **Order.** Cooperate comes first. Cross-document references use the
   `HOST-` prefix (roadmap section 12):
   - HOST-M1 Cooperate-0 runs on two independently operated hosts. It is cut
     server-first: headless services and the door first, desktop review
     moments as optional follow-ons.
   - HOST-M2 runs one root grant across Claude Code, Codex, Pi and Hermes on
     Linux, Omarchy first. macOS HOST-M2 (Darwin process runner, Keychain and
     XPC broker, `LOCAL_PEERTOKEN` IPC) comes after the success test (roadmap
     section 11); macOS keeps HOST-M1 scope until then.
   - HOST-M3 is co-signed cross-organization work under #1173 W1/W2.
5. **Megastart.** Its aggregate allowance moves onto kernel holds.
6. **Isolation layer scope.** Thin OS adapters are allowed. The credential
   broker, `chio-cage` and the harness launchers are not frozen. #1170's
   candidate ADR-0023 is scoped to this decision.
7. **Governance.** [NORTH-STAR-FLOWS](../superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md)
   governs the program. Other program documents reference it instead of
   restating it.
