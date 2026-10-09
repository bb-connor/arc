# Linux native host and optional Omarchy integration

`boundary_class: advisory_only` for this planning index; `planning_status: ready_after_adr`. Nothing here is implemented, installed, qualified or released.

**Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries.** This platform work supplies Linux services, custody, IPC, isolation evidence and packaging for the [north-star flows](../2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md). Linux is the executing platform for HOST-M2 and HOST-M3 before the success test. Omarchy QML, notifications, Walker entries and the workbench are optional consumers.

The [annex](ANNEX.md) is organized by flow:

1. HOST-M1 on Omarchy: server-first `chio trust serve` and `chio api protect` units, Secret Service and `systemd-creds` custody, optional review moments.
2. HOST-M2 on Omarchy: process host, broker, resource owner, Pi bubblewrap first, then Linux launchers and the Megastart Linux port.
3. HOST-M3 on Omarchy: executing-owner requirements.
4. Services, custody and IPC.
5. Packaging and lifecycle.
6. Herdr.

Related documents:

- [Implementation packets](../../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md)
- [Acceptance cases](../2026-10-07-desktop-integration/CASES.md) and [required harness scope](../2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md)
- [Native host contract](../2026-10-07-desktop-integration/HOST-CONTRACT.md), [ADR-0038](../../../adr/ADR-0038-native-host-program.md) and [PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md)
- Research: [native Linux findings](research/native-host-services.md), [upstream Omarchy](research/omarchy-upstream.md), [Chio readiness and approval handoff](research/chio-readiness.md), [Linux isolation and distribution](research/linux-platform.md), [desktop ecosystem](research/desktop-ecosystem.md), [source pins](research/source-pins.json)
- [Historical architecture review](reviews/2026-10-07-architecture-review.md)

Earlier workbench-first and Pi-first orderings in retained research are historical. The former platform protocol, fixtures and P0-P7 program stay retired; compositor control and configuration repair stay outside this program.
