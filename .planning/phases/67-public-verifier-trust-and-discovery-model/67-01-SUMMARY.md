# Summary 67-01

Defined ARC's first public verifier identity and trust-bootstrap profile.

## Delivered

- chose one HTTPS verifier identity model rooted at the verifier `client_id`
- published one ARC verifier metadata document at
  `/.well-known/arc-oid4vp-verifier`
- made unsupported verifier identity schemes and malformed metadata fail
  closed

## Notes

- the verifier metadata is a transport and trust-bootstrap contract, not a
  public verifier marketplace

