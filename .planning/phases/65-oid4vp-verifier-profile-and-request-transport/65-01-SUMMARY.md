# Summary 65-01

Defined ARC's narrow OID4VP verifier profile over the projected passport lane.

## Delivered

- added one signed OID4VP request-object contract for the ARC SD-JWT VC
  profile
- constrained the verifier surface to `client_id_scheme=redirect_uri`,
  `response_type=vp_token`, and `response_mode=direct_post.jwt`
- kept unsupported credential formats, disclosure claims, and request shapes
  fail closed

## Notes

- this is a profile-bound verifier bridge, not a claim of generic OID4VP
  ecosystem support

