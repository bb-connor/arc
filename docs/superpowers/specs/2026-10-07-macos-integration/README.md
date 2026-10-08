# Chio macOS native host integration

`boundary_class: advisory_only` for this planning/navigation index; `planning_status: ready_after_adr`. Profile and implementation-packet metadata lives in the annex and plan. No runtime qualification is implied.

**Chio is a Rust kernel for building agentic operating systems.** This platform program delivers native services and Darwin ports for applications, agent harnesses and Herdr to coordinate work, share resources and cooperate across organizations. Their frontends remain optional consumers.

The [shared native host program](../2026-10-07-desktop-integration/README.md) and [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md) own the accepted planning direction. This branch depends on the shared-program branch; it does not redefine common native contracts.

- [Platform design and qualification](ANNEX.md)
- [Implementation plan](../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md)
- [Native host contract](../2026-10-07-desktop-integration/HOST-CONTRACT.md)
- [External consumer acceptance](../2026-10-07-desktop-integration/CONSUMERS.md)
- [Kernel capability and owner map](../2026-10-07-desktop-integration/CAPABILITIES.md)
- [Shared acceptance matrix](../2026-10-07-desktop-integration/QUALIFICATION.md)
- [Optional operator projection](../2026-10-07-desktop-integration/OPERATOR.md)
- [Native service and deployment research](research/native-host-services.md)
- [Apple platform research](research/apple-platform.md)
- [Distribution research](research/distribution.md)
- [Clawdstrike research](research/clawdstrike.md)
- [Historical architecture review](reviews/2026-10-07-architecture-review.md)

User-session headless services and login-independent service hosts have separate identity, authority, credential, consent, lifecycle and installed qualification. A signed GUI-less bundle or package need not contain a graphical frontend. A partial user-session release cannot claim the machine-service profile. Workbench, menu bar, Finder Services and sealed coding are optional consumers/resource profiles, with all applicable native and delivered-client safeguards preserved.

Q23-Q30 supplement the existing native acceptance matrix. Passport, recursive delegation and swarm claims add C09-C11 when selected. Broad program completion also requires the actual coordination, shared-resource and independent-cooperation outcomes; a narrower passing host release must name dimensions still unavailable.

The former numbered specifications, private protocol, synthetic fixtures and independent implementation phases are superseded. `native-descendant-v1` remains retired; its ES/NE restrictions cannot be replaced by renaming it Seatbelt. Historical research is source input, not normative superseded product ordering or runtime evidence.
