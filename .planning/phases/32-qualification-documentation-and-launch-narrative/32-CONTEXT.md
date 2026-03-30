# Phase 32 Context

## Phase

- **Number:** 32
- **Name:** Qualification, Documentation, and Launch Narrative
- **Milestone:** v2.5 ARC Rename and Identity Realignment

## Goal

Close the ARC rename by proving the renamed surface end-to-end and making the
public, operator, and release docs tell one coherent ARC-centered story.

## Why This Phase Exists

Phase 30 made ARC the primary package/CLI identity. Phase 31 made ARC the
primary schema/env contract while keeping legacy PACT compatibility. Phase 32
must now remove the narrative split where core docs, release docs, and launch
materials still describe ARC as the primary product.

## Inputs

- `docs/research/DEEP_RESEARCH_1.md`
- `README.md`
- `docs/VISION.md`
- `docs/STRATEGIC_ROADMAP.md`
- `docs/release/*.md`
- `docs/standards/*.md`
- `spec/PROTOCOL.md`
- qualification scripts and conformance tooling

## Locked Decisions

- ARC is the primary product identity
- `arc` remains only as an explicit compatibility surface during the rename
  window
- `did:arc` remains the currently shipped DID method
- ARC should be framed as a trust-and-economics control plane, not merely an
  MCP wrapper

## Risks

- README / vision / roadmap drift can quietly overclaim if the release docs and
  protocol contract are not updated in the same pass
- qualification is expensive, so the milestone should not claim completion
  without real evidence
- narrative cleanup can accidentally erase important compatibility caveats
