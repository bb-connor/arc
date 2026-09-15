# Registered funded work and explicit Finding acceptance

This delivery registers the existing funded-work wire surface and connects its
decisions to Chio's actual Finding evidence verifier. The original agreement now
commits the verifier context and required facets before funding. A correctly
signed decision cannot replace that policy or invent verified backing.

The candidate starts at `946e9f1cc7a16edc12a44d87960ed87c49348faa` on
`feat/funded-native-admission`. The [evidence manifest](24-registered-work-evidence.json)
binds selected local qualification to source objects, executable bytes and public
results. Prior [resolution and child-survival evidence](21-native-resolution-earned-child.md)
retains its historical identity.

## Four registered envelopes

| Artifact | Current schema | Binding |
| --- | --- | --- |
| Agreement | `chio.experimental.native-funded-w0-agreement.v2` | Both parties sign the exact policy, request, native authority, funding terms, Finding context digest and ordered requirements. |
| Submission | `chio.experimental.native-funded-submission.v1` | Provider binds original work/custody identities and input/output digests to an existing Finding. |
| Dependency | `chio.experimental.native-funded-dependency.v1` | Parent provider commits separately funded parent and child agreements, requests, authorities and shared input. |
| Decision | `chio.experimental.native-funded-decision.v2` | Independent verifier commits the original submission and observed claim, checker and complete derived Finding assessment. |

Agreement and decision v1 remain historical encodings; they cannot acquire the
new authority fields under their old identities. Submission and dependency v1
preserve their valid encodings. The core signed-artifact inventory, JSON registry,
closed schemas and deterministic manifest agree on the four current families.
The existing SDK generators select `chio-wire/v1`; this separate family does not
change that generator input set.

Both raw parsers reject duplicate keys, including escaped aliases, noncanonical
bytes, unknown fields/schema versions, explicit nulls for omitted fields, unsafe
integers, alternate hex/decimal encodings and incompatible facet order. Limits
are 256 KiB per artifact, 512 UTF-8 bytes per identifier and safe unsigned I-JSON
integers. The profile accepts Ed25519 keys/signatures only. Original files and
journal agreement/request rows now use the same raw-first typed canonical check.

The [57 shared byte vectors](../../../../examples/federated-work/fixtures/registered-work/README.md)
are consumed by Rust and Python. The Python implementation uses the existing
hashed buyer environment and an offline schema interpreter whose supported
vocabulary is checked against the standard JSON Schema implementation. Neither
parser claims signer authority, current eligibility or a payment from shape
validation. Positive vectors contain generated public fixture artifacts; their
unit claim inputs are explicitly not chain proofs.

## Original Finding policy and historical decisions

Before writing the receiver policy, fixture provisioning creates a reusable
governance-signed Finding verifier profile and independently signed governance
standing. Distinct generated authority keys identify the roles. The complete
public context is persisted, hashed into the bilateral agreement and additionally
bound by the existing policy digest and journal identity. Bootstrap private keys
are discarded, so the context cannot silently renew its own standing.

New native admission checks the independently held receiver verifier/kernel pins,
profile signature, governance standing, role separation, required floor and
one-day validity window before new work or reservation. Historical operation
recovery precedes fresh-context admission checks. Previously earned claims retain
their original evaluation window; context expiry denies fresh admission rather
than reclassifying a retained accepted decision.

The funded verifier invokes `chio-finding-verifier::verify_finding_evidence` with
the exact canonical Finding and an explicitly empty external-evidence bundle.
All thirteen results come from its immutable draft. The agreement explicitly
requires artifact integrity and guarantee consistency, plus any additional
ordered facets. Existing `required_finding_facets` adds every requirement induced
by the Finding's own claims. No new parallel claim-floor implementation exists.

| Assessment | Financial decision behavior |
| --- | --- |
| Accepted | Still requires exact original input, custody retrieval and independent pinned Python W0 agreement before positive decision. |
| Rejected | An actual failed facet or independently checked result contradiction can deny the work. |
| Unavailable | Required evidence was not established. No positive or negative on-chain decision is minted; existing timeout/refund remains available. |
| Unsupported | The verifier cannot enforce an agreed requirement, such as issuer lineage in this profile. No financial decision is minted. |

An optional failed facet also rejects. Optional unavailable/asserted facets remain
visible and never become verified through successful W0 checking. The current
Finding remains asserted-class; there is no receipt/checkpoint, bond, status or
runtime-assurance evidence bundle in this profile.

Decision verification recomputes the entire assessment from the original context,
Finding, requirements and retained evaluation time, then compares exact canonical
bytes. This validates outcomes, reasons, evidence references and bundle digest,
including optional facets. It performs no network resolution or fresh signing.
Signed decision mutations cannot substitute a new context, weaker requirement
set, invented backing or later evaluation. The existing original-operation and
observed-claim checks still govern transaction preparation and recovery.

## Qualification and review

The final executable passes 45 owned-chain and process scenarios, including
36 SIGKILL events. Selected Rust suites pass 713 tests: 55 standalone funded-work
and interoperability tests, 390 core-type tests, and 268 Finding/verifier tests.
Two Finding fixture-regeneration helpers remain intentionally ignored.

The built Rust CLI and independent Python parser agree on all 57 shared vectors.
The schema differential check passes 126 cases, Python regressions pass 74 tests,
and Node passes 19 contract/inventory plus two canonical wire tests. Independent
review fixes are covered by the retained regressions. Standalone and workspace
Clippy pass with warnings denied; every fuzz target compiles. Formatting, schema
registration, Rust file hygiene, formal mirrors and generated proof coverage
checks pass. The manifest records exact commands, normalized logs, source objects
and the final executable digest.

Independent review found two issues during implementation: signed assessment
rows were initially checked for aggregate consistency without re-deriving optional
facets, and whitespace-only reasons differed between Rust and Python. Both paths
now reject those inputs, with targeted regressions and a shared malformed vector.
Schema review additionally aligned explicit Ed25519 widths, nested Finding
signature shape and byte/nonblank limits.

The live payout regression exposed the Node transaction encoder's scalar-only
assumption when the decision acquired facet arrays. Recursive ordered-array
encoding now matches all four Rust artifact vectors byte for byte. Unsupported
numeric values and null remain rejected. Strict Clippy also caught a provisioning
helper used only by unit tests; that helper is now compiled only for tests.

The added private-chain negative cases require unavailable receipt authenticity
or unsupported issuer lineage in the original agreement. They check the intended
assessment failure, no retained decision, no on-chain decision or payment, and
refund of the original allocation after timeout. Existing funding, payout/refund,
capture-waiver and earned-child crash witnesses remain regression gates.

Generated proof coverage only refreshes its source-inventory digest. Formal
mirrors are unchanged. No new formal proof, full workspace test run, fuzz campaign,
hosted CI, public-chain finality or release qualification is claimed.

## Existing commerce and remaining gates

This is a bounded funded-work contract, not a second market bid/ask/acceptance
system. Its submission carries `chio.finding.v1`; W0 authentication review is not
a verified-fix submission. Work acceptance does not create a Finding purchase
record, failed-delivery reimbursement, collateral allocation, challenge outcome,
venue admission or standing authorization. Those roles retain their existing
artifacts and separate verification requirements. Funding escrow is not Finding
bond backing. A dependency is not capability attenuation or a procurement permit.

This advances the registered-artifact and explicit acceptance mapping portions of
P45. Full Finding evidence qualification, W1/verified-fix linkage, disclosure and
signer-rotation adversaries, sustained capacity, an independent implementation and
independently administered operators remain open. All roles and chain actions in
these witnesses belong to one local fixture.

The next evidence step must establish execution before settlement. Requiring the
same operation's later payment receipt in order to authorize that payment would
create a circular dependency. Reuse the existing signed execution and checkpoint
primitives, bind them to the original operation, and keep financial finalization
as a separate successor.

The original paper checkout is preserved. No other worktree was changed or merged.
This delivery ends at a local commit, without push, PR, deployment or real funds.
