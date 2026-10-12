# Architecture

## Responsibility and boundary

The crate assembles a fixed refund workflow across three vendors and exports
matching verifier material. It re-exports the buyer core and federation
authority document APIs so test harnesses can construct and verify artifacts
through one library. It owns fixture orchestration and runtime-input checks.

Public constants pin workflow identity and generation time. Public keypair
helpers expose committed buyer/vendor seeds. This trust environment belongs
to repository tests and the bounded loopback harness.

## Structure

| Module | Responsibility |
| --- | --- |
| `lib` | Vendor fixtures, authority documents, proof generation, public API |
| `package` | Receipt/lease/DSSE/step assembly and aggregate signing |
| `runtime_validation` | Supplied receipt, envelope, and workflow-step checks |
| `tests` | Accepted fixture and semantic negative cases |
| `fixtures/` | Serialized package, trust bundle, context, verifier report |

The in-memory input selector distinguishes generated fixtures, supplied
receipts, and supplied `RuntimeProofArtifact` records. The latter holds a
receipt, bilateral envelope, and workflow step for each vendor.

## Data and control flow

Assembly starts from the three vendor definitions and buyer key. Supplied
inputs must have exactly three entries and pass fixture identity validation.
Authority issuance creates capability leases, scope bindings, and governance
receipts; the destructive refund step requires governance authorization.

For receipt-only input, assembly constructs bilateral DSSE and workflow
steps. For artifact input, it retains supplied envelopes and steps after
checking them against issued material and the preceding step hash.
The aggregate workflow receives the buyer signature and vendor cosignatures.

`fresh_proof_package` first assembles with an empty disclosure placeholder,
then derives a BBS proof over the final workflow projection and fixed context.
`build_proof_package` accepts a supplied proof and checks its subject.
Neither subject check replaces full verification by the buyer core.

## Trust and invariants

Runtime receipt validation checks tool server, tool name, lease id, allow
decision, action parameter hash, workflow/case/tool fields, workflow/vendor
metadata, fixture public key, and receipt signature. Artifact validation adds
DSSE hash and workflow step linkage to lease/governance material.
The accepted runtime inputs therefore remain specific to this workflow.

Trust-bundle assembly pins the generated intersection, fixed authority
profiles, peer/vendor keys, disclosure policy, and signed revocation material.
Choosing those same generated pins is useful for tests. It does not establish
an independent trust root for a deployment. The fixed timestamps require
matching context; freshness against a current clock is outside this harness.

`write_signed_negative_case_inputs` writes package, trust, and context files
under a caller-selected directory. It regenerates signatures and disclosure
after changing step links, output hashes, DSSE hashes, or consistency anchors.

## Dependencies

`chio-federation-authority` issues the fixture authority bundle and assembles
trust documents. Federation, governance, workflow, selective disclosure, and
core types supply the same signed artifact implementations used by the buyer
core. The crate delegates final acceptance to that core verifier.

## Verification

Run `cargo test -p chio-attest-loopback` and
`cargo test -p chio-attest-loopback --doc`.
`src/tests.rs` covers fresh/committed packages, supplied runtime artifacts,
wrong action payloads, stale leases, step linkage, vendor signatures,
unsupported claims, and denied bilateral verdicts.
The README example creates an in-memory package without generating fixture files.

[README](README.md) | [Protocol](../../../spec/PROTOCOL.md#9-trust-control-contract)
