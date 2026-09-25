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
| js-yaml | 4.3.2 | GHSA-2883-xcg3-v3hh repair |
| vitest and @vitest/mocker | 4.1.11 | GHSA-82fw-gwwq-j7x9 repair |
| sharp | 0.35.4 | GHSA-rgj7-g3m4-5g8c repair |
| Elysia dev and peer floor | 1.4.29 | GHSA-9643-4qgh-g8mx form-data complexity repair |
| Next.js peer and example requirement | >=15.5.24 <16 | GHSA-2xp9-vwfh-vxw4 and GHSA-p293-qw3h-jr36 repairs |

The AWS-LC source is extracted from the security integration rather than
reimplemented. [CHIO-PATCH.md](../../third_party/aws-lc-rs-chio/CHIO-PATCH.md)
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

JavaScript changes are extracted from integration commit
`da23d8b55db49b842ed24a7e7d5d374648fc674f`; the main workspace lockfiles are
resolved for main's own package membership. Express and Fastify conformance
fixtures now answer the existing receipt-verification endpoint with typed receipt
roles, and include rejection cases. The verdict matrix checks all 72 canonical
scenario identifiers. These transport fixtures do not establish cryptographic
acceptance.

## Qualification and ordering

Earlier local checks passed for cargo-deny, 385 AWS-LC library cases, three DES
regressions, Docker manifest/context checks, frozen Bun resolution, the complete
publishable TypeScript build and test commands, and 75 private conformance cases.
The first hosted run exposed inherited JavaScript advisories and missing vendor
source classification. A later current-head CVE run exposed Elysia 1.4.28 in
the adapter's separate nested lock; its package, nested lock and workspace lock
now select 1.4.29. Those failures remain in PR #1168's history.
The corrected `cargo vet check --locked` reports `aws-lc-rs:1.18.1` missing
`safe-to-deploy`; that is an open security gate, not a passing check.

Review the vendor provenance, dependency/audit closure, container inputs, SDK
compatibility and qualification documentation as separate slices. Require terminal
hosted checks and independent review before integration. Then update the workflow
definition change onto the repaired main branch. Source authorization, execution
image publication and capture-policy rotation remain separate operations with
their own exact identities and evidence.
