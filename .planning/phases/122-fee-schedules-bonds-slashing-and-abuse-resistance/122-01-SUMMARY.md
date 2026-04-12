# Summary 122-01

Implemented one signed open-market fee-schedule artifact family over the
generic listing and trust-activation substrate.

## Delivered

- added `OpenMarketFeeScheduleArtifact` and
  `OpenMarketFeeScheduleIssueRequest`
- bound market economics to explicit namespace, actor-kind, publisher-operator,
  and admission-class scope
- defined explicit publication, dispute, and market-participation fees plus
  per-bond-class collateral requirements
- exposed authenticated trust-service issue routes for signed fee schedules

## Result

Marketplace economics are now explicit signed artifacts instead of informal
operator policy or undocumented listing-side conventions.
