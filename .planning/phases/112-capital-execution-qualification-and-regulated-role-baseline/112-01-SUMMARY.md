# Summary 112-01

Qualified ARC's live capital-book, capital-instruction, and
capital-allocation surfaces as one reproducible `v2.25` matrix.

Implemented:

- one release-qualification row that covers capital-book, capital-instruction,
  and capital-allocation behavior together in
  `docs/release/QUALIFICATION.md`
- one updated release-audit evidence set that carries the capital-book,
  capital-instruction, and capital-allocation commands in
  `docs/release/RELEASE_AUDIT.md`
- one explicit closeout path that treats mixed currency, stale authority,
  missing reserve backing, and ambiguous selection as qualified fail-closed
  behavior rather than loose implementation detail

This makes the live-capital claim reproducible for operators and reviewers
instead of leaving `v2.25` as a partially qualified local implementation.
