# Summary 105-02

Made cross-issuer migration and activation semantics explicit instead of
implicit.

Implemented:

- fail-closed portfolio verification over duplicate migration ids, mismatched
  lifecycle projections, unknown migration refs, and duplicate passport ids
- explicit per-entry activation results over issuer allowlists, profile-family
  allowlists, entry-kind allowlists, certification refs, and lifecycle state
- subject rebinding that only succeeds when one signed migration artifact links
  the entry subject to the portfolio subject

ARC still does not synthesize a cross-issuer trust score or global issuer
equivalence from those results.
