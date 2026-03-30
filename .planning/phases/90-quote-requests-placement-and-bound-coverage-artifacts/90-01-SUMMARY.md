# Summary 90-01

Defined ARC's canonical liability quote and bind contract.

## Delivered

- introduced typed quote-request, quote-response, placement, and
  bound-coverage artifacts in `arc-core`
- bound every artifact to one signed provider-risk package plus explicit
  provider-policy, jurisdiction, currency, and effective-window truth
- made stale-provider, expiry, mismatch, and unsupported bound-coverage state
  explicit validation failures instead of deferred operator interpretation
