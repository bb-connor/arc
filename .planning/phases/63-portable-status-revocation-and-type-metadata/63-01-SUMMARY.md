# Summary 63-01

Published portable issuer and type metadata for ARC's projected passport
profile.

## Delivered

- kept the portable issuer metadata rooted at the same OID4VCI
  `credential_issuer` surface as the native ARC lane
- published portable issuer `JWKS` and ARC passport SD-JWT VC type metadata at
  stable `/.well-known/` endpoints
- kept those metadata surfaces fail closed when no authority signing key is
  configured

## Notes

- the HTTPS issuer metadata and `JWKS` endpoints are transport or discovery
  identifiers, not a second ARC trust root
- the projected metadata is bounded to ARC's documented SD-JWT VC profile
