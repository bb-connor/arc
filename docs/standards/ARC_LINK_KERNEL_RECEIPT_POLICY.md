# ARC Link Kernel Receipt Policy

## Purpose

This note defines how ARC attaches oracle provenance to kernel receipts without
turning receipts into mutable market ledgers.

## Canonical Rule

The ARC receipt remains canonical truth for the invocation itself: action,
decision, content hash, policy hash, and signed receipt identity are unchanged.
Oracle evidence is additive metadata for economic reconciliation, not a
replacement truth source.

`financial.oracle_evidence.authority` is always `arc_link_runtime_v1`. The
`source` field names the concrete backend `arc-link` used, such as Chainlink,
Pyth, or an explicitly degraded cached variant.

## Applied Conversion

When a tool reports cost in a different currency than the matched monetary
grant and `arc-link` can justify a conversion:

- the kernel converts the reported units into the grant currency
- the conversion uses the oracle-provided conservative margin
- `financial.cost_charged` records the converted grant-currency amount
- `financial.oracle_evidence` records the explicit oracle provenance with
  `authority = arc_link_runtime_v1`
- `financial.cost_breakdown.oracle_conversion.status` is `applied`

## Degraded Conversion

If the operator has explicitly enabled degraded mode for the pair and the last
cached rate is still inside the bounded stale-grace window:

- `arc-link` returns the stale cached rate with an increased margin
- the oracle source is marked as degraded
- receipt financial metadata still records explicit oracle provenance
- the conversion remains reviewable because the evidence carries the widened
  max-age and the degraded source label

Sequencer downtime or sequencer recovery grace never uses degraded mode. Those
conditions fail closed.

## Failed Reconciliation

When cross-currency reconciliation cannot be justified because the oracle is
missing, stale beyond the allowed window, unsupported, paused, chain-disabled,
or otherwise invalid:

- the kernel keeps the conservative provisional charge
- `financial.settlement_status` is `failed`
- `financial.oracle_evidence` remains absent
- `financial.cost_breakdown.oracle_conversion.status` is `failed`

This preserves fail-closed spend behavior without silently undercounting cost.
