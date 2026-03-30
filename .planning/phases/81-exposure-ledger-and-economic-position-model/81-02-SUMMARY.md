# Summary 81-02

Implemented the signed exposure-ledger export and CLI surface.

## Delivered

- added `/v1/reports/exposure-ledger` and `arc trust exposure-ledger export`
- signed the export with canonical receipt, settlement, metered-billing, and
  underwriting-decision provenance
- projected per-receipt reserve, settlement, and provisional-loss posture plus
  per-currency position totals

## Notes

- contradictory per-row currency truth now fails closed instead of producing a
  blended exposure row
