# Foundation authority containment

This records bounded source repairs for the October 4 foundation landing.
The [landing ledger](landing-ledger.md) owns remaining acceptance and landing
order. These repairs are committed locally and independently reviewed. They do
not establish a qualified foundation, a merge, native evidence or activation.

| Original obligation | Source checkpoint | Repaired boundary |
| --- | --- | --- |
| KG4 | `5546fdc325c4e8a2a6a6c4a7ba50607dfd8ad85c` | Reject seven constraint variants without established grant-specific enforcement at issuance, authenticated external admission and direct matching. |
| KG6 | `5546fdc325c4e8a2a6a6c4a7ba50607dfd8ad85c` | Bind the complete resolved effective policy and approval material to canonical runtime identity v2; reject nonfinite values before serialization. |
| KG5, automatic default grants | `7c64074009a396beb5a1f93602b81549b34b6b11` | Missing, empty, guard-only and disabled tool rules issue no default tool capability. Explicit permissive and inherited finite grants retain their behavior. |
| KG7/KG8 and portable report endorsement | `91087234fa2f3c3e51e81ef31a28f7a82033b94c` | Raw normalized claims cannot establish authenticated assurance. Signed verification requires a locally selected signer pin and the complete canonical signed body. Raw report exports remain rejected observations through import. |

The original review identities, source line hashes and historical observations
remain in the ledger. Their inclusion here does not close the broader original
requirements.

## Compatibility and authority limits

KG4 retains the wire variants but rejects `TableAllowlist`, `ColumnDenylist`,
`MaxRowsReturned`, `OperationClass`, `ContentReviewTier`,
`MaxTransactionAmountUsd` and `RequireDualApproval`. A globally configured guard
does not prove that it enforces the narrower constraints of a particular grant.
Future support needs grant-bound enforcement and production-constructor tests.

Runtime policy hashes intentionally change under `chio.runtime-policy.v2`.
Historical hashes and approval evidence retain their original meaning. The
identity includes resolved approval inputs, excluding only its self-referential
policy-hash field. It does not turn an identity digest into issuer authority.

KG5 contains automatic default issuance. The pure evaluator retains its
no-additional-restriction behavior when a tool rule is absent. A present empty
`tool_access: {}` still uses the existing enabled/Allow schema defaults. The
development `permissive` builtin opts in explicitly; `remote-desktop` remains
guard-only. Existing independently issued tokens are not revoked by this change.
HushSpec TTL configurability and the MCP wrapper's constant identity remain
separate open limbs of KG5.

Higher-assurance live issuance and dispatch remain disabled where only raw
normalized claims are available. A future authenticated live ingress must bind
the authorized verifier, subject, fresh request, audience, replay state and
revocation standing before restoring that capability. The new signed verifier
authenticates a pinned authority's assertion; it does not verify a fresh hardware
quote. Its current production caller is finding verification, which retains
authority/status checks and producing-receipt bindings. A public deserializable
`VerifiedRuntimeAttestationRecord` remains data, not an unforgeable proof object.

Raw report exports preserve signed observations and normalized values, with
Rejected/None outcomes and Derived confidence. Import rejects those exports.
Separately pinned, signed exporter assertions retain Allow, attenuation and
freshness controls. Signing caller-supplied observations does not endorse them
as verified hardware evidence.

## Retained verification

The compressed [evidence bundle](audits/foundation-containment-20261004.json.gz)
contains exact source hashes, independent review records, command metadata and
the retained focused logs. Each embedded record has its own SHA-256. Failed
campaigns remain failed records, including setup failures and later fixture
corrections; a later pass does not relabel them.

- KG4/KG6: 12 constraint, 12 matching, 78 policy and two downstream approval
  controls passed. Strict Clippy passed for the four modified boundary packages.
- KG5: all 298 policy-package tests and 82 control-plane policy tests passed;
  strict two-package Clippy and formatting passed. The Clippy snapshot's 24
  disappearing changed-file entries were independently reconciled to identical
  committed bytes, with the original diagnostic retained.
- KG7/KG8: 41 appraisal, 17 governed-assurance, 21 issuance, one real HTTP,
  81 finding-verifier and three report-export tests passed. Three real HTTP/CLI
  integration tests passed after retaining their original and intermediate
  failures. Signer pins, signatures, provider values, import rejection,
  attenuation and stale-result controls remain asserted.

These runs use Rust 1.95.0 and an external Cargo target with an explicit checkout
root. The broader affected-package campaign ended with 1,437 passed, one failed
and one ignored. The failing weak-key test still expected an obsolete permissive
verifier result; its corrected strong/weak controls passed with all 83
finding-verifier package tests. The original campaign remains failed and never
reached kernel whole-package testing. See the
[retained review and campaign records](audits/foundation-review-reconciliation-20261004.json.gz).
Full source,
feature, native, trusted hosted and exact-commit landing requirements remain in
the ledger. The eventual landing candidate must preserve these source repairs
and recheck its composition against the merged prerequisites.
