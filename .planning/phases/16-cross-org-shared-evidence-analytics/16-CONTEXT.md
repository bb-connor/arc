# Phase 16: Cross-Org Shared Evidence Analytics - Context

**Gathered:** 2026-03-24
**Status:** Completed

<domain>
## Phase Boundary

Phase 16 turns imported federated evidence from an internal continuation-only
substrate into an operator-visible analytics surface. Shared remote evidence is
still kept out of native local receipt tables, but operators can now query the
reference graph directly, see which local receipts were attributed through
remote shares, and inspect that provenance in operator reports, reputation
comparison, and the dashboard.

</domain>

<decisions>
## Implementation Decisions

### Shared-Evidence Model
- Imported evidence packages remain isolated in their own federated-share
  tables.
- Phase 16 does not merge foreign receipts into `pact_tool_receipts`.
- The operator-facing contract is a reference report over imported share
  metadata plus locally observed downstream receipt usage.

### API Surface
- Trust-control now exposes a dedicated shared-evidence query endpoint.
- Operator report embeds a `sharedEvidence` section rather than requiring the
  dashboard to reconstruct provenance client-side.
- CLI gains `pact trust evidence-share list` for direct operator inspection of
  shared references.

### Reporting Semantics
- Shared-evidence rows are grouped by `(share_id, remote capability_id)`.
- Counts reflect local downstream activity only; remote package metadata is
  surfaced as reference context, not re-attributed as local receipt history.
- Reputation comparison now includes the same shared-evidence report so drift
  views stay aligned with operator reporting.

### Deferred
- No live cross-cluster remote share discovery in this phase
- No merge of imported foreign receipts into local analytics tables
- No automated partner-to-partner propagation of shared-evidence indexes

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 16 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `FED-03`, `XORG-01`, `XORG-02`
- `crates/pact-kernel/src/receipt_store.rs` -- federated-share persistence and
  combined lineage substrate
- `crates/pact-kernel/src/operator_report.rs` -- operator-facing report types
- `crates/pact-cli/src/trust_control.rs` -- HTTP surfaces
- `crates/pact-cli/src/reputation.rs` -- comparison reporting
- `crates/pact-cli/dashboard/src/` -- operator UI surfaces

</canonical_refs>

<code_context>
## Existing Code Insights

- Imported evidence shares and federated lineage bridges already existed and
  were sufficient for multi-hop federated issuance.
- Operator reports already computed truthful local activity and cost
  attribution across combined delegation chains, but did not expose which
  remote shares were involved.
- Reputation comparison already had a stable backend contract and dashboard
  panel, making it the right place to add shared-evidence provenance rather
  than inventing a second comparison path.

</code_context>

<deferred>
## Deferred Ideas

- Remote-share discovery without any local import step
- Cross-cluster replication of verifier challenge state and shared-evidence
  references
- Downstream commercial/insurer analytics beyond operator provenance

</deferred>

---

*Phase: 16-cross-org-shared-evidence-analytics*
*Context gathered: 2026-03-24*
