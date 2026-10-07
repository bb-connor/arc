# Chio desktop operator program

`boundary_class: advisory_only` for the desktop projection; `planning_status: ready_after_adr`. Native actions retain the per-profile boundaries in ADR-0038.

Status: accepted architecture for planning, 2026-10-07. No desktop runtime,
backend, native approval path or release is qualified by this package.

Chio gives an operator a consistent view of agent work: what was requested,
what was authorized, what ran, what evidence was produced, and whether the
result was accepted. The desktop makes the existing kernel contracts usable;
it does not create another runtime or authority.

## Read in order

1. [Accepted decision](../../../adr/ADR-0038-desktop-operator-program.md).
2. [Program map and pinned source owners](../../../architecture/PROGRAM-MAP.md).
3. [Shared operator projection](../../../../spec/OPERATOR.md).
4. [Qualification and acceptance](QUALIFICATION.md).
5. [Delivery plan](../../plans/2026-10-07-desktop-integration.md).
6. [Omarchy annex](../2026-10-07-omarchy-integration/ANNEX.md).

The [macOS annex](../2026-10-07-macos-integration/ANNEX.md) and its
[implementation plan](../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md)
are a dependent review change on the shared-program branch.

## First complete workflow

Observe existing sessions with truthful boundary labels. When the owner gates
are qualified, create a sealed single-owner work commitment from the workbench:
choose a project, fixed recipe, host/profile, limits and acceptance rules;
review the exact scope; launch using an eligible restricted host; inspect the
artifact and independent work observations, including acceptance derived from
the original evaluator contract. Human patch-application approval and publishing
to any external destination are separately scoped operations; neither sets W1
acceptance by a caller-provided boolean.

The CLI, Omarchy plugin and macOS menu bar open or control this same workflow.
They share recovery and status semantics. They never infer acceptance from a
successful process exit, authorize an operation from a notification click, or
turn a lost reply into a fresh execution.

## Product and interaction requirements

- Show sessions, pending native approval requests, work results, receipt links,
  resource budgets, recovery state and service health. Keep all six work
  observations distinct; unavailable data must be labeled, not represented by
  zero or success.
- Show the boundary before launch and alongside activity. Hook-mode sessions
  are observations; allowed local effects inside a boundary sandbox are not
  individually mediated. No generic "secure" status joins unlike profiles.
- Disable a control with the exact failed prerequisite and a useful next action.
  Observation remains available when an execution profile is unavailable.
  A missing backend never launches the task without confinement.
- Native approval presents exact project, operation, destination, identity,
  policy/version, limits, expiry and review artifact. Changing any bound input
  invalidates the decision. OS consent, Chio authority and operator endorsement
  remain separate facts.
- Background notifications reveal no project content, prompt text, paths,
  credentials or artifact bodies. Opening a notification reauthenticates and
  re-reads owner state. It cannot execute or approve directly.
- Support keyboard-only operation, screen readers, explicit focus and text
  status independent of color. Confirm the scope of destructive actions in the
  native owner flow. Loss of the UI cannot prevent an owner stop command.
- Local-first operation is the default. Cloud accounts, commercial settlement,
  telemetry, external publication and managed-device enrollment are separate
  opt-ins. W1's unpaid work does not require the W2-W4 market stack.

## Coverage and ownership

| Concern | Governing artifact |
| --- | --- |
| Product scope, authority, isolation, host ladder, retired scope | ADR-0038 |
| Work/status, recovery, events, cancellation, identity, process and secret custody | PROGRAM-MAP and OPERATOR owner references |
| Request correlation, exact decisions, lost replies, concurrency, stale state | OPERATOR |
| Threat cases, host/version tuples, source evidence, safe export, limits, release gates | QUALIFICATION |
| Implementation order, predecessor handoffs, protocol freeze, common client | Delivery plan |
| Native UI, IPC adapter, service lifecycle, packaging, compatibility, update/uninstall | Platform annex and platform plan |
| macOS Seatbelt/VM selection, consent, signing/notarization, ES/NE, Clawdstrike reuse | Dependent macOS annex and retained primary-source research |

## Research and supersession

This package supersedes the two independent October 7 programs. Their numbered
specifications, private protocol schemas, synthetic fixture validators and
P0-P7/M0-M8 style implementation breakdowns are retired. The new plan references
existing owner work instead of carrying forward hundreds of duplicate
requirements. The platform research remains historical evidence, with explicit
amendments where direction changed.

The architecture review is retained as input, not a competing normative plan.
The accepted ADR controls conflicts. Historical validation results apply only
to the old document/schema proposals and never qualify the replacement.
