# Summary 74-01

Defined ARC's explicit sender-constrained semantics for the enterprise
authorization profile.

## Delivered

- added a per-row `senderConstraint` block to authorization-context reports
- resolved sender truth from receipt attribution plus persisted capability
  lineage instead of inferring it from report filters
- made DPoP requirement explicit from the matched scope grant and surfaced
  runtime-assurance and delegated call-chain binding alongside it

## Notes

- the profile still treats governed receipts as authoritative; sender
  semantics explain how ARC projects that truth for reviewers
