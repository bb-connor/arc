# Chio macOS platform annex

`boundary_class: advisory_only` for this planning/navigation index; `planning_status: ready_after_adr`. Profile and implementation-packet metadata lives in the linked annex and plan; no runtime readiness is implied.

Status: accepted for planning under [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md); no runtime qualification.

This annex extends the [shared desktop operator program](../2026-10-07-desktop-integration/README.md). Its review branch depends on the shared-program/Omarchy branch so the operator contracts have one owner.

- [Platform design and qualification](ANNEX.md)
- [Implementation plan](../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md)
- [Shared operator projection](../2026-10-07-desktop-integration/OPERATOR.md)
- [Shared acceptance matrix](../2026-10-07-desktop-integration/QUALIFICATION.md)
- [Apple platform research](research/apple-platform.md)
- [Distribution research](research/distribution.md)
- [Clawdstrike research](research/clawdstrike.md)
- [Historical architecture review](reviews/2026-10-07-architecture-review.md)

The former numbered specifications, private protocol, synthetic fixtures and
independent implementation phases are superseded. In particular,
`native-descendant-v1` is retired, not relabeled as the new Seatbelt profile.
Its ES/NE restrictions are not waived for a continuing release.
The corrected old proposal is retained in Git history at `1525c1326`; its
validation is not evidence of a working desktop or of the replacement program.
