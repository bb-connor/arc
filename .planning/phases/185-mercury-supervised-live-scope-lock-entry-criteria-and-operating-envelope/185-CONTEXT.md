# Phase 185: MERCURY Supervised-Live Scope Lock, Entry Criteria, and Operating Envelope - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Freeze the supervised-live bridge for the same controlled release, rollback,
and inquiry workflow. Define the entry criteria, human operating envelope,
explicit non-goals, and required proceed/defer/stop decision artifact before
any supervised-live runtime work lands.

</domain>

<decisions>
## Implementation Decisions

### Same Workflow Only
- keep the supervised-live bridge locked to controlled release, rollback, and
  inquiry evidence for AI-assisted execution workflow changes
- keep existing customer execution systems primary; MERCURY observes and
  proves the workflow around them rather than replacing them
- treat broader connectors, multi-workflow coverage, browser surfaces, and
  mediated in-line control as deferred expansion work

### Controlled Operating Envelope
- supervised-live entry requires explicit proof-boundary acceptance, corpus
  reproducibility, verifier success, rollback understanding, and agreed
  retention and disclosure duties
- human ownership must be explicit across workflow owner, MERCURY operator,
  compliance or risk reviewer, and infrastructure or security support
- degraded mode pauses MERCURY coverage and escalates; it must not silently
  widen authority or imply proof continuity that the system cannot support

### Decision Closure
- the bridge must end in one explicit proceed, defer, or stop artifact rather
  than a vague expansion list
- that decision artifact must bind the qualification evidence, operating
  assumptions, open risks, and next funded step
- if the answer is not proceed, the output remains a bounded defer or stop
  rather than sideways connector sprawl

### Documentation First
- freeze the boundary first in Mercury docs before building supervised-live
  intake or operator controls
- keep the ARC-versus-MERCURY separation explicit: ARC stays generic,
  MERCURY stays opinionated and product-specific

</decisions>

<code_context>
## Existing Surfaces

- `docs/mercury/SUPERVISED_LIVE_BRIDGE.md`
- `docs/mercury/POC_DESIGN.md`
- `docs/mercury/GO_TO_MARKET.md`
- `docs/mercury/README.md`
- `docs/mercury/IMPLEMENTATION_ROADMAP.md`

</code_context>

<deferred>
## Deferred Ideas

- supervised-live intake implementation belongs to phase `186`, not this
  scope-lock phase
- executable approval or interrupt controls, degraded-mode drills, and
  qualification packages belong to phases `187` and `188`

</deferred>
