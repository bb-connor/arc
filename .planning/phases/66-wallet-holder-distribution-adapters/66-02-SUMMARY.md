# Summary 66-02

Published same-device and cross-device launch artifacts over one verifier
flow.

## Delivered

- encoded same-device launch as `openid4vp://authorize?request_uri=...`
- encoded cross-device launch as one HTTPS URL that resolves back to the same
  verifier transaction
- kept both launch modes tied to the same signed request-object truth

## Notes

- cross-device launch remains verifier-controlled HTTPS transport, not a
  wallet directory or marketplace

