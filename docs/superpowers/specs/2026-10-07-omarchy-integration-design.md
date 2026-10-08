# Chio native host integration design

Status: accepted planning direction, amended 2026-10-08 UTC; no runtime qualification.
`planning_status: ready_after_adr`; each native operation retains its boundary.

The [shared native host program](2026-10-07-desktop-integration/README.md) implements
the product ambition: Chio is a Rust kernel for agentic operating systems that
coordinate work, share resources, and cooperate across organizational boundaries.
[ADR-0038](../../adr/ADR-0038-desktop-operator-program.md) records the headless
systems-layer direction and optional presentation scope.

Start with the [native host contract](2026-10-07-desktop-integration/HOST-CONTRACT.md),
[capability crosswalk](2026-10-07-desktop-integration/CAPABILITIES.md) and
[independent consumers](2026-10-07-desktop-integration/CONSUMERS.md) and
[required first-class integrations](2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md).
The [Omarchy/Linux annex](2026-10-07-omarchy-integration/ANNEX.md) owns native
ports, service profiles, lifecycle, packaging and optional Omarchy presentation.
Its [implementation plan](../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md)
builds on the [shared delivery plan](../plans/2026-10-07-desktop-integration.md).

External applications and harnesses consume native owner contracts before any
Chio frontend. Claude Code, Codex, Pi and Hermes each require native installed
acceptance; Herdr is a separate required workspace/plugin consumer for all four
selections. Cursor/OpenClaw remain in the broader doc 19 program. Mini-swe is an
optional reference/conformance workload, never a default harness or native-readiness
prerequisite. Hook activity
remains observation-only. The old P0-P7 program, platform protocols, compositor
tools, configuration repair and desktop-owned delegation remain superseded.
[Review evidence](2026-10-07-desktop-integration/REVIEW.md) does not qualify runtime.
