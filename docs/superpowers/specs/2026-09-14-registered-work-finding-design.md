# Registered funded work and Finding acceptance

This delivery builds on local commit `946e9f1cc7a16edc12a44d87960ed87c49348faa`.
The user authorized execution of the next registered-artifact and Finding-facet
block through local verification and commit. Work remains in the existing
`arc-funded-integration` worktree.

## Contract

Register the bounded native funded agreement, submission, dependency and decision
formats in the existing signed-artifact registry. Preserve the original agreement,
request, operation, hold, allocation, output and transaction bindings. The new
agreement and decision receive v2 schema identities because they add mandatory
acceptance authority. Submission and dependency retain their v1 encodings.

The agreement commits the receiver's exact pre-provisioned Finding acceptance
context digest and ordered required facets. The context contains an actual
governance-signed reusable Finding verifier profile, authenticated governance
standing and separately pinned authorities. It exists before funding. Default
W0 requires artifact integrity and guarantee consistency, then independently
checks original input, custody and the pinned Python checker as before.

Evaluate through `chio-finding-verifier::verify_finding_evidence`, not through a
parallel facet implementation. Retain its thirteen derived facet results. Missing
required evidence is unavailable; requirements this implementation cannot enforce
are unsupported; a failed facet rejects even if optional. The Finding's own claims
add their existing required facets. An independent W0 match cannot override any
of these outcomes. No on-chain positive or negative decision is minted from an
unavailable or unsupported assessment; the original timeout/refund path applies.

The signed v2 decision binds the complete assessment, exact context, Finding and
original submission. Downstream verification rechecks the original agreement's
requirements and assessment consistency before preparing a transaction. A
decision signature cannot migrate to another context or weaker requirements.

## Wire boundary

All signed bytes use canonical JSON with raw-first duplicate-key detection,
typed-byte equality, closed object fields and explicit bounds. Reject nulls for
omitted optional values, unsafe integers, alternate decimal/hex encodings,
unknown schema identities and cross-artifact signature substitutions. Keep
resource limits at 256 KiB per artifact and I-JSON safe integer maxima. Publish
positive and malformed vectors checked by Rust and an independent Python parser.
Schemas describe wire shape; successful schema validation alone grants no trust.

Use the existing example as the bounded profile implementation and the existing
Finding verifier as the shared authority implementation. Do not duplicate market
bid/ask/acceptance, verified-fix, purchase, reimbursement or challenge artifacts.
Document the mapping and the remaining unsupported roles explicitly.

## Qualification

Exercise strict parser disagreement, changed profiles, missing required facets,
unsupported facets, changed Finding claims and altered signed decisions. Re-run
native funding, settlement/refund, contractual waiver and earned-child crash
witnesses on the resulting executable. Retain hashes of source and public
evidence, run affected Rust/schema/generated checks and independent code review,
then commit locally. Original paper, research and security worktrees stay intact.

This adds explicit acceptance policy and wire interoperability to the existing
one-host private-chain profile. It does not claim full evidence backing, remote
operator isolation, public finality, hosted CI or release qualification.
