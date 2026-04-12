# Phase 203: MERCURY Partner Packaging Surface and Embedded Distribution Path - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Implement one repo-native `embedded-oem` export path that stages a bounded
partner bundle from the validated assurance lane.

</domain>

<decisions>
## Implementation Decisions

### CLI Surface
- add one top-level `embedded-oem` Mercury command with `export` and `validate`
  subcommands
- keep the new surface in `arc-mercury`, not ARC-wide generic tooling

### Export Shape
- generate the full assurance-suite subtree first
- copy one bounded counterparty-review bundle into a partner bundle directory
- write one embedded OEM profile, one partner manifest, one delivery
  acknowledgement, and one embedded OEM package

### Validation Posture
- cover the export path with CLI tests
- keep the bundle manifest-based and fail-closed

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `export_assurance_suite()` already produces the upstream Mercury artifacts
  needed for OEM packaging
- `main.rs` and `commands.rs` already expose consistent Mercury expansion
  command patterns

### Established Patterns
- validation commands create a nested export directory plus
  `validation-report.json` and `expansion-decision.json`
- CLI tests verify generated files and decision semantics against real command
  output

</code_context>

<deferred>
## Deferred Ideas

- multiple partner bundle variants
- generic client libraries
- live partner runtime integration

</deferred>
