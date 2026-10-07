# Chio Omarchy platform annex

`boundary_class: advisory_only` for this planning/navigation index; `planning_status: ready_after_adr`. Profile and implementation-packet metadata lives in the linked annex and plan; no runtime readiness is implied.

Status: accepted for planning under [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md); no runtime qualification.

This is a platform annex of the [shared desktop operator program](../2026-10-07-desktop-integration/README.md).

- [Platform design and qualification](ANNEX.md)
- [Implementation plan](../../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md)
- [Shared operator projection](../../../../spec/OPERATOR.md)
- [Shared acceptance matrix](../2026-10-07-desktop-integration/QUALIFICATION.md)
- [Upstream research](research/omarchy-upstream.md)
- [Chio readiness and native approval handoff](research/chio-readiness.md)
- [Linux isolation research](research/linux-platform.md)
- [Desktop ecosystem research](research/desktop-ecosystem.md)
- [Source pins](research/source-pins.json)
- [Historical architecture review](reviews/2026-10-07-architecture-review.md)

The former numbered specifications, private protocol, fixtures and P0-P7 plans
are superseded. Compositor tools and configuration repair are removed;
delegation remains with its kernel/process owners. The accepted ADR and shared
owner contracts control any conflicting historical research recommendation.
The corrected old proposal is retained in Git history at `9aba33295`; its
document/schema validation is not runtime or replacement-program evidence.
