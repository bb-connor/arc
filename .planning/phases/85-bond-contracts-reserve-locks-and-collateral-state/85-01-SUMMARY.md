# Summary 85-01

Defined ARC's signed bond and reserve-state contract.

## Delivered

- introduced typed bond disposition, lifecycle, reason-code, prerequisite, and
  collateral-term contracts
- made `lock`, `hold`, `release`, and `impair` explicit operator-visible bond
  outcomes instead of implicit facility-side interpretation
- preserved a conservative support boundary: ARC is authoritative for reserve
  accounting and bond state, but not yet for external escrow execution or
  autonomy gating in this phase
