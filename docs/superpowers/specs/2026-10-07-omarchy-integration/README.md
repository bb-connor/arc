# Linux native host and optional Omarchy integration

`boundary_class: advisory_only` for this planning index; `planning_status: ready_after_adr`. Implementation and installed qualification remain open.

Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries. This platform work supplies reusable Linux bindings and native services for existing harnesses, applications and Herdr. Omarchy QML and workbench are optional consumers; installation and advertised native capabilities must work with all Chio graphical clients absent.

The [required first-class integrations](../2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md), [native host contract](../2026-10-07-desktop-integration/HOST-CONTRACT.md) and [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md) govern the direction. Headless user-session operation retains lock/logout/enrollment fences. Login-independent service operation requires a distinct native service principal, credentials and boot/restart acceptance. Neither lingering nor root grants authority.

- [Linux host and Omarchy annex](ANNEX.md)
- [Implementation packets and independent profile gates](../../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md)
- [Native application/harness acceptance](../2026-10-07-desktop-integration/CONSUMERS.md)
- [Shared acceptance matrix](../2026-10-07-desktop-integration/QUALIFICATION.md)
- [Optional operator projection](../2026-10-07-desktop-integration/OPERATOR.md)
- [Dated native Linux findings and source gaps](research/native-host-services.md)
- [Retained upstream research](research/omarchy-upstream.md)
- [Chio readiness and native approval handoff](research/chio-readiness.md)
- [Retained Linux isolation/distribution research](research/linux-platform.md)
- [Desktop ecosystem source research](research/desktop-ecosystem.md)
- [Source pins](research/source-pins.json)
- [Historical architecture review](reviews/2026-10-07-architecture-review.md)

Claude Code, Codex, Pi and Hermes are required first-class harnesses, each with native installed H01-H06/H08 and I01-I08 acceptance for at least one scoped protected Linux profile. Herdr is a separate required workspace/plugin consumer with H07/H08 acceptance for each of those four selections. A passing harness cannot substitute for another or for Herdr. Cursor and OpenClaw retain the broader doc 19 six-host obligations. Profiles may promote independently, but Linux first-class completion requires all four harness cells and the Herdr selection matrix. Mini-swe is optional reference/conformance only; it has no required backend, native-readiness, default-ordering or first-product role. Coordination, shared-resource and independent-organization claims require their actual native owners and CONSUMERS evidence.

Earlier workbench-first recommendations in retained research are historical. The current host contract, annex and plan supersede that product ordering while preserving applicable native authority, recovery, confinement, clock, resource, lifecycle and installed-client obligations. Shell/browser cases apply when that consumer is selected. The former numbered platform protocol/fixtures and P0-P7 program remain retired. Compositor control/configuration repair stay outside this delivery; selected native delegation uses its owner/C10/Q25 gates; cross-host custody transfer and live migration are separate deferred owner extensions.
