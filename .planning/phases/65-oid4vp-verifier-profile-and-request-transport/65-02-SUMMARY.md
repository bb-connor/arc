# Summary 65-02

Added replay-safe verifier transaction storage plus public request transport.

## Delivered

- persisted OID4VP verifier transactions in the existing verifier SQLite
  state store
- exposed signed `request_uri` fetch plus distinct same-device and
  cross-device launch artifacts over one verifier transaction truth
- kept expired and consumed verifier transactions fail closed

## Notes

- cross-device launch is an HTTPS bridge back to the same signed request
  rather than a second mutable request store

