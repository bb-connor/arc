# Summary 62-02

Defined the bounded selective-disclosure contract for ARC portable
credentials.

## Delivered

- made the always-disclosed claim set explicit in the signed payload:
  `iss`, `sub`, `vct`, `cnf`, `arc_passport_id`, `arc_subject_did`, and
  `arc_credential_count`
- made the supported disclosure claim set explicit:
  `arc_issuer_dids`, `arc_merkle_roots`, and
  `arc_enterprise_identity_provenance`
- documented the claim catalog in the protocol and portability docs so
  operators and reviewers can see the supported profile boundary

## Notes

- ARC still does not claim generic verifier-request negotiation beyond this
  fixed SD-JWT VC profile
- OID4VP transport and wallet request semantics remain later milestone work
