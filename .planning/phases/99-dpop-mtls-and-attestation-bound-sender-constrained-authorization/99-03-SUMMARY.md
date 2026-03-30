# Summary 99-03

Documented ARC's sender-constrained boundary, proof types, and negative-path
rules for the hosted authorization surface.

Updated:

- `spec/PROTOCOL.md`
- `docs/standards/ARC_OAUTH_AUTHORIZATION_PROFILE.md`
- `docs/CREDENTIAL_INTEROP_GUIDE.md`
- `docs/AGENT_PASSPORT_GUIDE.md`
- `docs/release/QUALIFICATION.md`

The docs now state that ARC supports one bounded sender-constrained contract
over DPoP, mTLS thumbprint binding, and one attestation-confirmation profile,
that attestation never widens authority by itself, and that missing or
contradictory sender proof fails closed.
