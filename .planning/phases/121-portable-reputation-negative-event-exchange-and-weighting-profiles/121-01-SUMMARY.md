# Summary 121-01

Implemented one signed portable reputation-summary and negative-event artifact
family over ARC's existing local reputation truth.

## Delivered

- added `PortableReputationSummaryArtifact` and
  `PortableNegativeEventArtifact`
- added signed issue request and response contracts for portable reputation
  summaries and portable negative events
- bound imported reputation to explicit issuer, subject, freshness, evidence,
  and issuance state
- added trust-service issue and evaluate HTTP surfaces for portable reputation
  exchange

## Result

Portable market-discipline signals are now explicit signed artifacts instead of
ad hoc exported score snippets or implicit foreign trust.
