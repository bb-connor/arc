# September 22 dependency transition

The main-branch prerequisite for the security workflow transition repairs the
inherited Rust and JavaScript dependency closure before introducing new capture
authority. PR #1168 contains this prerequisite; PR #1167 contains the separate
workflow definitions. Neither change authorizes a new source or publisher.

## Dependency and source identity

| Dependency | Selected version | Reason |
| --- | --- | --- |
| rustls | 0.23.45 | RUSTSEC-2026-0285 repair |
| rustls-webpki | 0.103.15 | Compatible patched certificate verifier |
| der | 0.8.2 | Replace yanked 0.8.0 |
| aws-lc-rs | 1.18.1 plus the documented Chio patch | rustls dependency update with retained DES key validation |
| Wasmtime | 48.0.5 | RUSTSEC-2026-0316 and RUSTSEC-2026-0327 repairs |
| Rust workspace and builders | 1.95.0 | Patched Wasmtime's minimum supported Rust version |
| js-yaml | 4.3.2 | GHSA-2883-xcg3-v3hh repair |
| vitest and @vitest/mocker | 4.1.11 | GHSA-82fw-gwwq-j7x9 repair |
| sharp | 0.35.4 | GHSA-rgj7-g3m4-5g8c repair |
| Elysia dev and peer floor | 1.4.29 | GHSA-9643-4qgh-g8mx form-data complexity repair |
| Metro build tools | 0.84.5 | Remove the vulnerable image-size parser from the mobile build dependency chain |
| Next.js peer and example requirement | >=15.5.24 <16 | GHSA-2xp9-vwfh-vxw4 and GHSA-p293-qw3h-jr36 repairs |

The AWS-LC source is extracted from the security integration rather than
reimplemented. [CHIO-PATCH.md](../../third_party/aws-lc-rs-chio/CHIO-PATCH.md)
identifies the registry archive, the tracked source patch, the restored fixture
hashes and the vector normalization. Root and generated Docker manifests retain
the same source patch; affected Docker builders copy the vendor directory.
The native sys crates have exact-source audits. Cargo Vet's earlier success
missed this local Rust fork because it treated a path dependency as first-party.
The completed source review found six unsafe partial AES-key initialization
sites and a private unsafe C-string conversion in the published wrapper, in
addition to the DES parity defects. The fork repairs all of them. The published
archive is explicitly not certified safe to deploy. Its non-implying review
criterion is only one part of the mandatory combined supply-chain gate: exact
fork audit and source inventory, authenticated archive reconstruction, Cargo
source/feature resolution, native/transitive deployment audits, and regressions.
See the [source audit](audits/aws-lc-rs-1.18.1-fork.md). Both required Cargo Vet
jobs and release qualification call `scripts/check-supply-chain.sh`.
No new exemption or unsupported certification was added. The upstream cipher file has
an exact-size, expiring source-hygiene allowance; other file limits remain
enforced.

JavaScript workspace lockfiles include the process SDKs and preserve the public
Metro, Next.js, Rolldown and Rollup updates. The Elysia adapter requires the patched
1.4.29 peer and development version. Node HTTP validates receipt schemas through
its production Ajv dependency. Express and Fastify conformance fixtures use the
shared signed receipt fixture and verify the exact issued receipt and pinned
signer before returning an accepted verdict. The verdict matrix checks all 72
canonical scenario identifiers.

## Qualification and ordering

Earlier local checks passed for cargo-deny, 385 AWS-LC library cases, three DES
regressions, Docker manifest/context checks, frozen Bun resolution, the complete
publishable TypeScript build and test commands, and 75 private conformance cases.
The first hosted run exposed inherited JavaScript advisories and missing vendor
source classification. A later current-head CVE run exposed Elysia 1.4.28 in
the adapter's separate nested lock; its package, nested lock and workspace lock
now select 1.4.29. Those failures remain in PR #1168's history.
The earlier missing-AWS-LC audit failure remains retained. The October 4 source
repair passed native Memcheck (original: 48 uninitialized-value errors; repaired:
zero), 386 library tests with DES enabled, three DES regressions, 36 doctests
(one ignored), and 491 FIPS tests on both the earlier Rust 1.94.1 harness and
the candidate's Rust 1.95.0 toolchain. The patched Wasmtime passed 151 library
tests and 27 escape tests; advisories pass. The source gate validates all six
deployment workspace resolutions and nine source/output/policy regression tests,
plus workflow and port-rendering contract tests with prerequisite-removal and
mutable-source mutations.
The inherited cpp_demangle exemption remains debt: its genuine 0.4.5-to-0.5.1
delta review preserves baseline acceptance and does not claim a complete audit.
Exact-head hosted checks and independent PR review remain required before merge.

Independent review of `4bc1332617` rejected that candidate because direct
publishers could omit the composite gate, default Cargo output contaminated the
audited tree, a hosted contract assertion and generated coverage were stale,
and the reduced Proof Room builder lacked native packages. The repaired
candidate makes the shared gate a prerequisite for Rust binary, sidecar, C++
and npm/Wasm producers, isolates build output, updates the contract/coverage,
and supplies the builder's native dependencies. Negative controls exercise
missing/conditional prerequisites and source-tree contamination. Two consecutive
combined invocations with the default target selection pass.

The next review found that C++ registry publishing still downloaded a mutable
version tag after qualification. The source archive and generated registry ports
now bind the qualified repository and immutable event commit; published ports
cannot select a moving branch. Conan release publication checks the same commit.
Real port templates and changed/missing identity controls exercise the renderer.

Rust 1.95 exposed two ordinary Clippy improvements, retaining checked overflow
and payment rejection semantics. The Aeneas scalar helper preserves its exact
body with a function-scoped lint allowance; its mirror digest records that
reviewed attribute-only change. Workspace production-target Clippy and all
Cargo Deny categories pass locally. Zed's separate extension ABI requires the
older 0.227 component tools alongside Wasmtime's 0.254 family; only those exact
duplicate versions are allowed, without changing advisory or source policy.

A regression in the initial payment match cleanup rejected valid current
disputes. A failing replay control reproduced it; an explicit valid-dispute arm
restores the previous behavior while retaining missing-state rejection. The
container's real native link also exposed absent static OpenSSL archives, now
included in both Alpine Rust builders. Their failed campaigns remain evidence;
builder commands require a separate terminal rerun before qualification.

The October 4 JavaScript scan initially reported 25 advisory IDs. Patched
versions remove 23. Two unpatched Expo/React Native peer-tooling dependencies
have a separate, scoped and expiring disposition; they remain release debt,
not repaired upstream vulnerabilities. See
[the tooling advisory record](npm-peer-tooling-advisories-2026-10-04.md).

Review the vendor provenance, dependency/audit closure, container inputs, SDK
compatibility and qualification documentation as separate slices. Require terminal
hosted checks and independent review before integration. Then update the workflow
definition change onto the repaired main branch. Source authorization, execution
image publication and capture-policy rotation remain separate operations with
their own exact identities and evidence.
