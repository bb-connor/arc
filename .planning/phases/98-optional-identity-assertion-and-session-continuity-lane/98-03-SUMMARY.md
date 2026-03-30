# Summary 98-03

Documented the optional identity-assertion boundary, replay rules, and
standards-facing continuity semantics.

Updated:

- `spec/PROTOCOL.md`
- `docs/CREDENTIAL_INTEROP_GUIDE.md`
- `docs/AGENT_PASSPORT_GUIDE.md`
- `docs/standards/ARC_OAUTH_AUTHORIZATION_PROFILE.md`
- `docs/release/QUALIFICATION.md`

The docs now state that identity assertions are verifier-scoped continuity
metadata only, that they remain optional, and that stale or mismatched
assertions fail closed across wallet and hosted authorization flows.
