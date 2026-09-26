# September 22 dependency transition

This change updates the Rust and JavaScript dependency closure used by the
public CLI, SDKs and Docker builds. The source patch and lockfiles are retained
in the public repository so external builds use the same reviewed source.

## Dependency and source identity

| Dependency | Selected version | Reason |
| --- | --- | --- |
| rustls | 0.23.45 | RUSTSEC-2026-0285 repair |
| rustls-webpki | 0.103.15 | Compatible patched certificate verifier |
| der | 0.8.2 | Replace yanked 0.8.0 |
| aws-lc-rs | 1.18.1 plus the documented Chio patch | rustls dependency update with retained DES key validation |
| js-yaml | 4.3.2 | GHSA-2883-xcg3-v3hh repair |
| vitest and @vitest/mocker | 4.1.11 | GHSA-82fw-gwwq-j7x9 repair |
| sharp | 0.35.4 | GHSA-rgj7-g3m4-5g8c repair |
| Metro build tools | 0.84.5 | Remove the vulnerable image-size parser from the mobile build dependency chain |
| Next.js peer and example requirement | >=15.5.24 <16 | GHSA-2xp9-vwfh-vxw4 and GHSA-p293-qw3h-jr36 repairs |

[CHIO-PATCH.md](../../third_party/aws-lc-rs-chio/CHIO-PATCH.md)
identifies the registry archive, the tracked source patch, the restored fixture
hashes and the vector normalization. Root and generated Docker manifests retain
the same source patch; affected Docker builders copy the vendor directory.
The native sys crates have exact-source audits. Cargo Vet's earlier success
missed this local Rust fork because it treated a path dependency as first-party.
The corrected policy now requires an audit of the published 1.18.1 base and
fails closed until that audit is completed. Cargo Vet cannot authenticate the
fork delta, which requires separate review against the tracked patch. No new
exemption or unsupported certification was added. The upstream cipher file has
an exact-size, expiring source-hygiene allowance; other file limits remain
enforced.

JavaScript workspace lockfiles include the process SDKs and preserve the public
Metro, Next.js, Rolldown and Rollup updates. The Elysia adapter requires the patched
1.4.29 peer and development version. Node HTTP validates receipt schemas through
its production Ajv dependency. Express and Fastify conformance fixtures use the
shared signed receipt fixture and verify the exact issued receipt and pinned
signer before returning an accepted verdict. The verdict matrix checks all 72
canonical scenario identifiers.

## Qualification

The retained DES regression exercises key parity validation against the patched
source. Earlier cargo-deny, Docker source-input, frozen JavaScript-resolution,
TypeScript build and conformance checks have source-bound records.
The corrected `cargo vet check --locked` reports `aws-lc-rs:1.18.1` missing
`safe-to-deploy`; that is an open security gate, not a passing check.
Passing results must identify the public source revision that was checked.

Review the vendor provenance, dependency/audit closure, container inputs, SDK
compatibility and qualification documentation as separate slices. Require terminal
hosted checks and independent review before integration.
