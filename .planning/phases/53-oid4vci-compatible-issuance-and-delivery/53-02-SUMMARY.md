# Summary 53-02

Shipped the replay-safe issuance flow across local CLI and trust-control.

## Delivered

- durable issuance-offer registry with single-use pre-authorized-code and
  access-token state transitions
- local CLI commands for metadata, offer creation, token redemption, and
  credential redemption
- trust-control routes and client methods for public issuer metadata plus
  remote offer, token, and credential exchange

## Notes

- remote issuance requires `--advertise-url` and
  `--passport-issuance-offers-file`
- offer creation stays on the authenticated operator plane; token and
  credential redemption are holder-facing
