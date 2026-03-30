# Summary 61-01

Defined ARC's first standards-native external credential projection and its
identity strategy.

## Delivered

- chose one projected portable credential profile with configuration id
  `arc_agent_passport_sd_jwt_vc` and format `application/dc+sd-jwt`
- kept the native `AgentPassport` artifact as the ARC source of truth
- bound projected issuer identity to the HTTPS `credential_issuer` plus
  issuer-published `JWKS`, while keeping issuer and subject trust semantics
  inside ARC truth anchored to `did:arc`

## Notes

- the projected credential is a verified derivative of passport truth, not a
  replacement identity system
- ARC still does not claim generic wallet or verifier compatibility outside
  the documented profile
