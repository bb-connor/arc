# SQLite report and authorization measurements

These are local aarch64 Linux measurements, not hosted qualification or a release
performance guarantee. Other qualification jobs ran concurrently on this shared
development machine; these are not isolated hardware latency guarantees. The
receipt append scale campaign cannot establish that
authorization scales; the authorization store composition is measured separately.

## Verified analytics report

The original candidate silently clamped attempted costs through SQLite's signed
integer JSON path. Schema v6 stores exact big-endian attempted costs, and both
aggregates use checked unsigned arithmetic. Review then found that reports trusted
mutable projections and that sparse subject filters could evade a matched-row
ceiling. The accepted repair verifies signed receipts and their cost projections
inside the report snapshot, and bounds SQL instructions across all statements.

The before source is `0ad3c88bf05849744b2aa53f24a162e2b1d664dd`; the repaired
source is `414aaea0b1`. Both include the release overflow-check setting. The same
dedicated target, benchmark, fixture and Criterion options were used: 20 samples,
one-second warmup, three-second requested measurement time (Criterion extended
slow cases). The fixture has 20,000 signed receipts, 97 subjects, 500 capabilities,
seven servers and 13 tools, including missing financial fields. The time window
covers about one tenth of that history.

| Query | Before | Verified report |
|---|---:|---:|
| Unfiltered | 397.51 ms | 4,858.7 ms |
| One capability | 0.94049 ms | 3.2592 ms |
| Time window | 38.256 ms | 482.28 ms |
| Server and tool | 3.5706 ms | 53.510 ms |
| Agent subject | 3.6864 ms | 50.807 ms |

These results are a performance regression. Verifying each selected signed
receipt adds material work. The earlier 137.07 ms unfiltered result predates the
integrity repair and is not qualification evidence for the accepted source.
Removing signature verification or trusting the projections again would reopen
the reproduced corruption defect. A future optimization needs an authenticated
projection/cache design that still detects external modification while an open
handle is reused. Statement caching alone is not justified as a remedy for this
measured verification cost.

The report refuses more than 250,000 matches and interrupts after a shared
100,000,000 SQLite-instruction budget, checked every 1,000 instructions. The latter
also covers scans that find no matches. Neither limit is a wall-clock deadline;
signature verification and receipt size also affect latency. Callers should use
selective filters for interactive reports.

Evidence is retained locally under `/tmp/chio-resume-20260926/`:
`c-baseline-custody.json`, `c-benchmark-before.log`,
`c-benchmark-verified.log`, `c-report-integrity-green.log`, and
`c-report-integrity-clippy.log`. The full receipt subset passed 367 tests before
the report-integrity additions; the final report suite passed all 17 tests.
Independent review accepted the integrity and SQL-work-limit repairs.

## Authorization store composition

`store_authorization_path` now includes `authorization_store_composite_populated`.
Its fixture populates 20,000 admissions, budget hold/release pairs and receipts before timing,
across 512 capability identifiers, plus 2,000 real suspension records. A sequence
begins and reads back a durable V1 admission under a provisioned serving owner,
checks suspension state, authorizes and
releases a budget hold bound to that admission, signs a receipt and appends it.
Admission, hold, capability and receipt identifiers agree, and the budget request
carries the same active owner fence. Setup omits read-only checks while preserving
all mutation counts and row contents. Setup and final flush
are outside the timer; signing, store validation and synchronous append are inside.

This measures the composed persistence operations. It does not run kernel policy,
guards, a broker, a tool, or a committed-admission lifecycle. Separate component
benchmarks remain for budget hold/release, legacy admission create/read and
suspension denial/allow reads. They use their own fixtures; their sum is not the
composite measurement.

The run on source base `414aaea0b1` plus this benchmark completed successfully in
`c-composite-owned.log`, with the same 20-sample, one-second warmup and
three-second requested measurement settings:

| Operation | Criterion estimate |
|---|---:|
| Budget hold/release | 7.7754 ms |
| Legacy admission create | 3.1718 ms |
| Legacy admission read | 21.262 us |
| Suspension denial read | 61.588 ms |
| Suspension allow read | 62.948 ms |
| Complete store composition | 108.39 ms |

The composite confidence interval was 106.37 to 110.92 ms. This is one populated
history point, not a scaling curve or an end-to-end kernel latency result. It
also predates integration of the separate signed-JSON reader repair. The first
composite attempt was refused because it lacked the required provisioned budget
owner; `c-authorization-composite.log` retains that failure and is not acceptance
evidence for the composite. Strict Clippy for the completed benchmark passed in
`c-composite-owned-clippy-retry.log`.

Reproduce the measurement with:

```sh
cargo bench --locked -p chio-store-sqlite --bench store_authorization_path -- \
  --save-baseline authorization-owned-composite --sample-size 20 \
  --warm-up-time 1 --measurement-time 3
```
