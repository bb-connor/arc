# Plan 150-02 Summary

Integrated cross-currency approval and failed-reconciliation behavior into the
receipt metadata surface.

## Delivered

- `crates/arc-kernel/src/lib.rs`

## Notes

Successful conversions now attach `financial.oracle_evidence`, while failed
cross-currency reconciliation now leaves the provisional charge in place and
marks the settlement path failed with explicit receipt-side conversion details.
