# P5 source review and acceptance boundary

Review date: October 4-5, 2026. The fresh final reviewer (GPT-6 Astra, high)
independently read and verified all 74 authored inputs in the retained original
source package. Its immutable report is [FRESH-REVIEW.md](FRESH-REVIEW.md), with
original binding and hashes in `evidence/fresh-review-package.json`.

The reviewer found two Important issues: parent cancellation ordering and the
ordinary depth-64 regression. The primary executor addressed both in one
verified test-first fix pass, then reviewed the complete final delta, including
four additional Rust paths and the real Linux fixture corrections. The final
inventory contains 42 authored Rust sources and 36 other inputs. Exact paths,
hashes, original review identity and fix evidence are in
[review-manifest.json](review-manifest.json) and [RESOLUTIONS.md](RESOLUTIONS.md).
There was no second reviewer pass and no independent human review.

The independent package auditor rejects all 13 declared evidence mutations and
passes 15 restored positive audits. No known P0/P1 source finding remains in that reviewed scope. Confidence is high
for the exact supported profile and the actual native Linux acceptance. All 46 local gates pass on the final binding. The authoritative commands, hashes,
statuses, limitations and phase exit flag are in
[verification.json](verification.json). This prose never overrides a stale,
missing or failed gate.

## Task coverage

| Task | Implemented and reviewed behavior | Acceptance |
|---|---|---|
| P5-01 | Closed contracts, exact disclosure and independent integrity signatures | Cross-language/schema/signature vectors and useful authorized native return |
| P5-02 | Host-issued IDs, live ancestry, permanent aggregate counts and immutable seed pins | Native forgery/quota/inheritance cases, ordinary depth 64, real enforced observation |
| P5-03 | Affine retained preparation, measured cage launch, pidfd deadline and exit custody | Unsupported-host refusal, strict cross lint, actual cage runtime probes |
| P5-04 | Exact immutable Boolean and fresh native parent admission before bytes | Exact authority, independent SQL first-byte assertion, original-writer restart |
| P5-05 | Finite private channels, withheld alternatives, cancellation and reconciliation | Every enabled channel, held deadline, launch/return cutpoints, three cancellation orderings |
| P5-06 | Fresh source review, one test-first fix pass and source-bound gate package | All 46 local gates and ten real Linux recovery cases required |

All ten ISO obligations have concrete native/portable anchors in
[requirements-coverage.json](requirements-coverage.json). All 118 sealed P4
artifact hashes and the 598-source predecessor archive remain unchanged. P5
changes are compared to that archive, never retroactively resealed as P4.

## Native Linux evidence

The actual final campaign ran on the task-owned OCI Ubuntu 24.04 x86_64 VM,
Linux 6.17.0-1020-oracle, Rust/Cargo 1.94.1. It used the native GNU toolchain for
host/cage tests, musl for eleven measured interpreter-free static PIE images,
and debug profiles with debug information disabled. The record retains compiler,
C compiler, readelf, kernel, runtime challenge, image and log identities.

All ten required recovery cases passed, zero failed or ignored. The strict cage
campaign also passed all 72 original inventory tests, including 27 required runtime probes,
and ten actual helper mutants. The controlled profile permits exactly the host-
fixed environment `LANG=C`, `LC_ALL=C`, `TZ=UTC`; additions/mutations refuse.
The positive return uses known imported native provenance. The paired unknown-
provenance case exits with a correct projection but still withholds admission.

Cancellation completed before the final serialized process activity read
withholds delivery. Cancellation after that authorization point cannot retract
an already authorized crossing. The native commit retains knowledge and stable
return intent, including when a subsequent activity check withholds bytes. No
cross-store transaction or lock spans arbitrary sink I/O.

All unsuccessful fixture/environment attempts needed to interpret the final
result remain in `evidence/diagnostics/`. Temporary diagnostic source was restored
byte-for-byte and its compilation refreshed before the final source-bound run.
No enforcement or unknown-provenance check was weakened to make a positive pass.

## Supported boundaries

The qualified profile is the bounded model-disabled Boolean cage described in
[OPERATIONS.md](OPERATIONS.md). Non-Boolean returns, nested launches, provider
context reuse, enabled provider/tool egress, covert channels and recipient effect
exactly-once are outside this profile and require separate work. The sink is a
bounded parent return, not an arbitrary external exactly-once effect service.

TypeScript SDK and generator checks now use isolated frozen npm lockfile installs.
Lifecycle scripts were disabled. The failed cached-workspace attempts are retained
and do not count as passing SDK evidence.
The full kernel listener suite now runs with full access; prior sandbox listener
skips were removed. The unchanged separate-device SQLite anchor cases remain
explicitly unavailable on macOS; no same-device substitute is claimed.
Hosted CI, human review and production deployment are not claimed. Actual live
host/model comparisons and product qualification belong to P6.

Next phase after the complete P5 package audit: P6 guided setup, classified policy
feedback/review, two-host integration, reserved reconciliation overload and
matched comparative workloads.
