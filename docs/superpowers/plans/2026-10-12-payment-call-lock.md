# Release admission custody across external payment calls (F020)

Compose the preserved `a8222f8789` repair once. It incorporates the original
F020 series and retains the newer trusted-clock refresh after oracle I/O.

1. Run the three external-call lock probes on current production source with
   only the preserved tests added. Retain the genuine RED results.
2. Apply the producer's production hunks. Journal intent under the admission
   lock, release it for the external call, then reacquire and validate the exact
   operation, original recovery claim and newly sampled trusted time. Preserve
   duplicate-operation exclusion and fail closed after expiry or owner rotation.
3. Run the lock and regression controls, existing pricing/clock tests, and the
   acknowledged-capture restart test. Run strict kernel Clippy and formatting.
   Ask Claude to review current composition and publish separately on main.

Price quotes remain bound to units, currencies and freshness. A stale or
unavailable quote must not increase capture above the existing exposure.
No recovery-claim renewal may hide expiry during an external call. No schema,
authorization, repository-setting or formal-proof change is part of this repair.
