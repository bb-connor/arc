# Phase 211: Control-Path Guard Surface and Companion-Product Packaging Path - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Implement one ARC-Wall app surface that evaluates the bounded control-path
guard scenario, exports ARC evidence, and packages the result for buyer review.

</domain>

<decisions>
## Implementation Decisions

### App Boundary
- create a dedicated `arc-wall` CLI crate rather than adding ARC-Wall commands
  to `arc-mercury`
- expose one `control-path export` and one `control-path validate` command

### Guard and Packaging Path
- reuse ARC's tool-guard mechanics for the bounded deny scenario
- export ARC evidence through the generic evidence-export path
- package the result as one buyer-review bundle and one top-level control package

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- Mercury already proves the export/validate command pattern and ARC evidence
  export helpers
- ARC guard crates already expose tool-allowlist mechanics that can back the
  first ARC-Wall deny scenario

</code_context>

<deferred>
## Deferred Ideas

- browser-first UI
- multiple control surfaces
- merging ARC-Wall packaging into MERCURY

</deferred>
