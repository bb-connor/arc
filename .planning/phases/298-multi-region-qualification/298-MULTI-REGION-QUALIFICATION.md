# Phase 298 Multi-Region Qualification

## Scenario

- Environment: local simulated 3-region trust-control cluster
- Nodes:
  - `region-a` -> `http://127.0.0.1:55924`
  - `region-b` -> `http://127.0.0.1:55925`
  - `region-c` -> `http://127.0.0.1:55926`
- Cluster sync interval: `200ms`
- Evidence artifact:
  `target/trust-cluster-qualification/298-multi-region-qualification.json`

This qualification deliberately models three regions with three local
trust-control nodes. The resulting lag numbers are useful for bounded local
qualification, but they are not hosted WAN or production cloud-region latency
claims.

## Consistency Result

- Leader remained stable on `region-a` during the qualification lane
- Minority partition writes failed closed with `503`
- No split-brain decisions were observed
- Healing the partition restored quorum and made the isolated region converge
  on the majority receipt state

## Measured Replication Lag

Measured value: post-heal catch-up latency from partition heal until the
isolated region observed the expected replicated receipt.

- Sample count: `20`
- Min: `255ms`
- p50: `358ms`
- p95: `450ms`
- p99: `567ms`
- Max: `567ms`

Samples in milliseconds:

`310, 346, 359, 376, 450, 354, 567, 446, 308, 363, 382, 400, 255, 358, 325, 445, 374, 300, 304, 305`

## Interpretation

- The shipped clustered runtime now has executable evidence that a local
  simulated 3-region deployment can survive a minority partition without
  split-brain writes and recover the isolated region within sub-second lag in
  this qualification environment.
- The percentile numbers are good enough to document the current bounded ARC
  cluster behavior, but they should not be promoted as production network SLOs
  without a real external multi-region environment.
