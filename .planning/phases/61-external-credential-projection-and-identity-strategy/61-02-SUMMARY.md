# Summary 61-02

Threaded the external projection through ARC credential and issuance surfaces.

## Delivered

- added typed portable credential models, issuer `JWKS`, and type metadata in
  `arc-credentials`
- extended OID4VCI metadata and response models so one issuer can advertise
  both the native ARC lane and the projected portable lane
- wired local CLI and trust-control issuance to mint either the native
  `AgentPassport` response or the projected compact credential fail closed

## Notes

- portable issuance still reuses the existing passport truth and offer state
- missing signing-key configuration or unsupported configuration ids are
  rejected rather than silently downgraded or widened
