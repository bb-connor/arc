# Summary 85-03

Closed fail-closed reserve-accounting validation for phase 85.

## Delivered

- made mixed-currency reserve accounting reject with `409 Conflict` instead of
  inventing blended reserve state
- added regression coverage for `hold`, `lock`, `release`, and `impair`
  semantics across remote trust-control and CLI list surfaces
- documented that phase `85` introduces reserve-state truth, not autonomy-tier
  enforcement, slashing, or external capital execution
