# Summary 63-02

Mapped ARC lifecycle truth into portable status, revocation, and supersession
artifacts.

## Delivered

- projected lifecycle distribution into issuer metadata and credential-response
  sidecars without copying mutable lifecycle state into the credential itself
- preserved the read-only public resolve surface as the operator-facing source
  of portable lifecycle truth
- proved that `active`, `superseded`, and `revoked` resolve states stay tied
  to the existing lifecycle registry instead of inventing a second mutable
  status plane

## Notes

- only `active` is a healthy portable lifecycle state
- `superseded` remains explicit and is not silently collapsed into revocation
