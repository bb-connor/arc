# Phase 175: Generated Runtime Reports and Exercisable Emergency Controls - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Replace example-only web3 operations evidence with generated runtime reports,
persisted control-state artifacts, append-only control traces, and one staged
incident-audit package that operators and hosted reviewers can inspect
directly.

</domain>

<decisions>
## Implementation Decisions

### Generated Ops Evidence
- generate live ops artifacts from an `arc-control-plane` qualification test
  instead of hand-authoring another JSON family
- write the local evidence under `target/web3-ops-qualification/` so the
  bundle sits next to the broader runtime and promotion qualification outputs
- keep the checked-in `docs/standards/*_EXAMPLE.json` files as schema
  references only

### Persisted Control Surfaces
- add explicit control-state and control-trace records for `arc-link`,
  `arc-anchor`, and `arc-settle`
- export the anchor and settlement control-state types through the crate
  boundary so qualification and downstream tooling can use the same runtime
  contract
- exercise real operator methods where they already exist (`arc-link`) and
  use the same control models for anchor/settlement posture changes

### Hosted Bundle Alignment
- make `./scripts/qualify-web3-runtime.sh` call the dedicated ops-control
  qualification entrypoint
- stage the generated ops subtree under
  `target/release-qualification/web3-runtime/ops/`
- update runbooks, readiness docs, partner proof, and qualification matrices
  to reference generated evidence paths rather than example-only JSON

</decisions>

<code_context>
## Existing Code Insights

- `arc-link` already had operator pause/disable methods and a runtime report,
  but no persisted audit trail for those posture changes
- `arc-anchor` and `arc-settle` already modeled emergency modes and fail-closed
  operation gating, but no generated runtime bundle proved those controls were
  exercised or recorded
- hosted release qualification already staged web3 runtime and promotion
  artifacts, making an `ops/` subtree the least disruptive extension point

</code_context>

<deferred>
## Deferred Ideas

- integrated FX-backed, dual-sign, reorg-recovery, and partner-facing end-to-end
  proof in phase `176`
- broader release-governance and planning-tool truth repair in `v2.42`

</deferred>
