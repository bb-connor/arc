# Summary 62-01

Implemented ARC's first standards-native SD-JWT VC issuance lane over the
external passport projection.

## Delivered

- added the `arc_agent_passport_sd_jwt_vc` configuration to OID4VCI issuer
  metadata when a signing key is configured
- minted deterministic compact `application/dc+sd-jwt` credentials bound to
  the holder's `did:arc` subject key through `cnf.jwk` and `sub`
- preserved the existing native `AgentPassport` issuance path without
  changing its trust model

## Notes

- the SD-JWT VC lane is still a projection over ARC passport truth
- unsupported profile combinations fail closed instead of silently
  downgrading into another format
