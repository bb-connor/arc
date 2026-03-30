# Summary 53-01

Defined the ARC-specific OID4VCI-compatible issuance contract in
`arc-credentials`.

## Delivered

- typed issuer metadata, offer, token, and credential request/response models
- fail-closed validation for issuer metadata, configuration ids, subject
  binding, and delivered credential format
- one conservative ARC passport issuance profile with configuration id
  `arc_agent_passport` and format `arc-agent-passport+json`

## Notes

- the delivered credential remains the existing `AgentPassport`
- issuer and subject trust anchors inside the credential remain `did:arc`
