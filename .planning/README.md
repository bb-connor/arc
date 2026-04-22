# Chio Planning Directory

This directory is tracked project management infrastructure for the Chio
repository under the GSD workflow. Everything here is version controlled on
purpose: state, roadmap, and milestone audits are part of the repo history.

## Contents

- `STATE.md`: current milestone state, progress metrics, accumulated
  decisions, and session continuity pointers.
- `PROJECT.md`: project reference document covering core value, scope, and
  long-horizon framing.
- `ROADMAP.md`: active roadmap of phases and milestones across current and
  planned versions.
- `REQUIREMENTS.md`, `MILESTONES.md`, `EXECUTION-MATRIX.md`: supporting
  planning artifacts referenced by `STATE.md` and `ROADMAP.md`.
- `POST_V3_18_EXECUTION_TRACKER.md`: the most recent post-milestone closure
  tracker.
- `config.json`: GSD tooling configuration for this repository.
- `vX.Y-MILESTONE-AUDIT.md`: per-version milestone audits (one per shipped
  milestone). The recent window is kept at the top level; older audits live
  under `archive/`.
- `codebase/`: parallel-mapper codebase maps (architecture, structure,
  conventions, stack, testing, concerns, integrations).
- `milestones/`: milestone-scope working directories.
- `phases/`: numbered subdirectories holding per-phase plans
  (`NN-<phase-slug>/`).
- `research/`: research notes that feed future phase plans.
- `debug/`: persistent debug state used by `/gsd:debug`.
- `archive/`: cold milestone audits and other retired planning artifacts.

## Maintenance

- Keep milestone audits for the 3 most recent shipped milestones live at the
  top level. Current retained window: v2.23 and later.
- Archive older audits to `.planning/archive/` when they go cold; prefer
  `git mv` so history is preserved.
- When a milestone directory under `milestones/` or a phase directory under
  `phases/` goes cold, move it into `archive/` rather than deleting it.
- Update `STATE.md` whenever the active milestone, phase, or accumulated
  decisions change; it is the source of truth for "where are we".

## Current version

Active milestone: `v3.18 Bounded Chio Ship Readiness Closure` is complete
locally and pending archival. Further parallel lanes (`v4.0`, `v4.1`, `v4.2`)
are planned; see `STATE.md` for the authoritative snapshot.
