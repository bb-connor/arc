# Chio Federation Profile

This profile defines Chio's bounded cross-operator federation lane over the
existing listing, trust-activation, governance, open-market, and portable-
reputation surfaces.

## Artifact Family

- `chio.federation-activation-exchange.v1`
- `chio.federation-quorum-report.v1`
- `chio.federation-open-admission-policy.v1`
- `chio.federation-reputation-clearing.v1`
- `chio.federation-qualification-matrix.v1`

## Bounded Claim

Chio may exchange trust-activation and reputation evidence across operators only
when:

- remote trust activation is carried as one explicit federation exchange
  contract with attenuation and local import controls
- mirror and indexer visibility is summarized as one quorum report with
  freshness, conflict, and anti-eclipse evidence
- open admission stays subordinate to explicit review, governance, and
  bond-backed participation policy
- shared reputation clearing preserves local weighting and independent-issuer
  corroboration instead of becoming a universal oracle

## Validation Rules

- federation exchange contracts fail closed on missing local activation or
  manual-review requirements
- quorum reports fail closed on missing origin or indexer observation,
  insufficient distinct operators, stale publisher state, or missing conflict
  evidence
- open-admission policies fail closed if bond-backed participation lacks an
  explicit slashable bond requirement
- shared reputation clearing fails closed on duplicate accepted summary
  issuers, excessive per-issuer inputs, missing local weighting, or
  uncorroborated blocking negative events
- qualification must cover `TRUSTMAX-01` through `TRUSTMAX-05`

## Non-Goals

This profile does not claim:

- permissionless or auto-trusting federation
- mirror or indexer visibility as ambient runtime trust
- open admission that bypasses local review or governance
- shared reputation as a universal trust oracle
- ecosystem-wide identity or wallet routing beyond the documented federation
  boundary
