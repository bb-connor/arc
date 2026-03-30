# Summary 97-03

Documented the neutral wallet exchange behavior and its bounded failure
semantics.

Updated:

- `spec/PROTOCOL.md`
- `docs/CREDENTIAL_INTEROP_GUIDE.md`
- `docs/AGENT_PASSPORT_GUIDE.md`
- `docs/release/QUALIFICATION.md`

The docs now state that ARC's wallet exchange descriptor is a neutral wrapper
over the existing verifier transaction, that relay delivery reuses the HTTPS
cross-device launch URL, and that contradictory or replayed exchange state
fails closed.
