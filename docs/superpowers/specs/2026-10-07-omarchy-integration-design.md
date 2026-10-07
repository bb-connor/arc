# Chio desktop integration design

Status: accepted architecture for planning, 2026-10-07; no runtime qualification.
`boundary_class: advisory_only`; `planning_status: ready_after_adr`.

The [shared desktop operator program](2026-10-07-desktop-integration/README.md)
owns the common architecture, operator projection, predecessor map and
qualification obligations. [ADR-0038](../../adr/ADR-0038-desktop-operator-program.md)
records the owner-approved consolidation.

The [Omarchy annex](2026-10-07-omarchy-integration/ANNEX.md) owns platform
presentation, lifecycle, packaging and compatibility. Its [implementation plan](../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md)
builds on the [shared delivery plan](../plans/2026-10-07-desktop-integration.md).
The independent P0-P7 design, two unshipped platform protocols, compositor
tools, configuration repair and desktop-owned delegation are superseded.

The workbench is the first common client; sealed W1 work using existing owners
is the first execution product. Hook sessions remain observation-only.
[Review and verification](2026-10-07-desktop-integration/REVIEW.md) distinguishes
source/document checks from native runtime and release evidence.
