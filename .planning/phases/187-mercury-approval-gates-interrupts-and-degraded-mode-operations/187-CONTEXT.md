# Phase 187: MERCURY Approval Gates, Interrupts, and Degraded-Mode Operations - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Make the supervised-live bridge safe enough for controlled production review.
This phase adds explicit approval-gate, interruption, and degraded-mode
semantics on top of the same supervised-live workflow from phase `186`, plus
the operator runbooks that define key, monitoring, and recovery posture.

</domain>

<decisions>
## Implementation Decisions

### Explicit Control Contract
- keep the approval, interruption, and degraded-mode contract inside
  `arc-mercury-core` so MERCURY's app layer consumes a typed safety boundary
  rather than ad hoc CLI flags
- require the supervised-live capture to declare release and rollback control
  state explicitly, even though ARC remains the generic substrate underneath
- make successful supervised-live export surface the captured control state so
  approval posture is auditable in the generated artifact set

### Fail-Closed Export Behavior
- allow degraded or interrupted supervised-live situations to be represented in
  the capture contract, but do not let the export command silently produce
  proof claims for them
- treat unhealthy intake, retention, signing, publication, or monitoring as a
  fail-closed condition for supervised-live proof export
- require interruption records whenever coverage is interrupted or degraded so
  operator intervention is explicit rather than implied

### One Canonical Ops Runbook
- document key management, monitoring, degraded mode, and recovery in one
  canonical Mercury operations runbook rather than scattering operational truth
  across product and GTM docs
- update the supervised-live bridge and technical architecture docs only enough
  to point to that runbook and the typed control-state contract

### Same Workflow Boundary
- keep the work scoped to the existing controlled release, rollback, and
  inquiry workflow
- do not turn phase `187` into mediated in-line control, connector sprawl, or
  generic production orchestration

</decisions>

<code_context>
## Existing Surfaces

- `crates/arc-mercury-core/src/supervised_live.rs`
- `crates/arc-mercury/src/commands.rs`
- `crates/arc-mercury/src/main.rs`
- `crates/arc-mercury/tests/cli.rs`
- `docs/mercury/SUPERVISED_LIVE_BRIDGE.md`
- `docs/mercury/SUPERVISED_LIVE_OPERATING_MODEL.md`
- `docs/mercury/TECHNICAL_ARCHITECTURE.md`
- `docs/mercury/README.md`

</code_context>

<deferred>
## Deferred Ideas

- partner-facing qualification corpus and proceed/defer/stop close-out remain
  phase `188`
- broader governance workbench, downstream-consumer integrations, and mediated
  in-line control remain later roadmap tracks

</deferred>
