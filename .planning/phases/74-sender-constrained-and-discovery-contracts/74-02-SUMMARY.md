# Summary 74-02

Published machine-readable discovery metadata for ARC's enterprise
authorization profile.

## Delivered

- extended protected-resource metadata with `arc_authorization_profile`
- extended authorization-server metadata with the same profile payload
- added fail-closed validation so the two `.well-known` documents cannot drift
  on ARC profile id, schema, sender binding, or advertised issuer

## Notes

- discovery remains informational only and does not become a second mutable
  trust source
