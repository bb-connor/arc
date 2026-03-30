# Summary 77-02

Implemented conformance evidence profiles in ARC Certify's signed publication
and verification path.

## Delivered

- added explicit evidence-profile, generated-report media-type, and
  provenance-mode fields to signed certification artifacts
- made signed certification verification reject incomplete or unsupported
  criteria and evidence bundles fail closed
- preserved publisher provenance while making artifacts comparable across
  operators

## Notes

- listing presence remains informational until a consumer applies local policy
