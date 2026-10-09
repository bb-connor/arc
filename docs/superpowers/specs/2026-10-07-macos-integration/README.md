# Chio macOS native host integration

`boundary_class: advisory_only` for this navigation index. `planning_status:
ready_after_adr` for HOST-M1 on macOS; `planning_status: deferred` for macOS
HOST-M2 (after the success test, unified roadmap section 11) and the
managed-endpoint track. No runtime qualification is implied.

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.** This
platform program delivers Chio's native services on macOS, organized by the
[north-star flows](../2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md):

- **HOST-M1:** `chio trust serve` and the door behind `chio api protect` as a
  headless LaunchAgent, with Keychain key custody and Touch ID passkey
  approval. Review windows and the menu bar are optional follow-ons.
- **HOST-M2:** deferred until after the success test. Until then a macOS-only
  organization takes part in HOST-M3 as the requesting organization.
- **HOST-M3:** the Mac requests work, co-signs and verifies evidence offline;
  it executes work only after macOS HOST-M2.

Read in order:

1. [Platform annex](ANNEX.md): HOST-M1, HOST-M2, HOST-M3, services, custody and
   IPC, packaging and lifecycle, managed endpoint.
2. [Implementation plan](../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md):
   packets grouped by flow.
3. Shared program: [README](../2026-10-07-desktop-integration/README.md),
   [ADR-0038](../../../adr/ADR-0038-native-host-program.md),
   [CASES](../2026-10-07-desktop-integration/CASES.md),
   [HOST-CONTRACT](../2026-10-07-desktop-integration/HOST-CONTRACT.md),
   [FIRST-CLASS-INTEGRATIONS](../2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md)
   and [PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md).

Research inputs (source evidence, not normative ordering):
[native services](research/native-host-services.md),
[Apple platform](research/apple-platform.md),
[distribution](research/distribution.md),
[Clawdstrike prior-art review](research/clawdstrike.md) and the
[historical architecture review](reviews/2026-10-07-architecture-review.md).

The former numbered specifications, private protocol and synthetic fixtures are
superseded. `native-descendant-v1` remains retired; Seatbelt cannot stand in
for its former ES/NE gates.
