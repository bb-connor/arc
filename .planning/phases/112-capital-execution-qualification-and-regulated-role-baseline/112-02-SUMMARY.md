# Summary 112-02

Defined ARC's regulated-role baseline for the live-capital surface across the
protocol, agent-economy, release-candidate, and partner-proof docs.

Implemented:

- explicit language that live-capital instructions and allocations require one
  named source-owner approval, one named custody-provider execution step, and
  one bounded execution window
- explicit language that ARC now proves live capital-book, instruction, and
  simulation-first allocation contracts without claiming ARC itself is the
  regulated custodian, settlement rail, or insurer of record
- explicit non-goals that still reject automatic external capital dispatch,
  reserve slashing, autonomous insurer pricing, and open-market capital
  execution from `v2.25` alone

This gives ARC an honest live-capital claim without silently widening into a
regulated-actor or insurer-of-record claim.
