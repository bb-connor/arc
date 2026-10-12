# Architecture

## Responsibility and boundary

`chio-attest-buyer` owns the public packet, review, lineage, and runtime
manifest shapes consumed by buyer-facing clients. It exposes JSON readers,
canonical hash helpers, verification entrypoints, and report serialization.
The underlying runtime checks remain in `chio-runtime-core`; cryptographic
proof replay remains in `chio-attest-buyer-core`.

A packet relates capability and treaty references to continuation, admission,
lineage, bilateral invocation, DSSE, workflow receipt, proof, and report hashes.
The packet is an evidence index. Its hashes alone cannot authenticate the
referenced DSSE or establish execution authority.

## Structure

| Module | Responsibility |
| --- | --- |
| `api` | Readers, verification dispatch, report output, core replay |
| `types` | Chio-owned DTOs and borrowed review trust context |
| `schemas` | Supported public packet and report schema strings |
| `validation` | Packet fields, artifact hashes, safe relative paths |
| `runtime_manifest` | Runtime-core manifest validation and projection |
| `conversions` | Explicit mapping into runtime-core inputs and outputs |
| `input`, `error` | Bounded signed JSON and public error-code mapping |

## Data and control flow

Packet and review JSON first pass `input::decode`, then their named boundary
validator. Review references must have unique roles and relative paths,
nonzero byte counts, and SHA-256 hexadecimal hashes. The parser permits an
empty artifact collection; verification decides whether required roles exist.

`verify_buyer_attestation_review_package` delegates hydrated artifact checks.
The `with_trust` variant supplies borrowed verifier-owned JSON material.
The `with_proof_replay_json` variant first runs that trusted runtime review,
then locates the `proof_package` source and calls the core verifier.
A rejected replay clears acceptance and adds a structured failed check.

`verify_proof_package_json` independently parses package, trust bundle, and
context through their core readers. It returns an acceptance flag, optional
failure code, and serialized core report. Callers must inspect acceptance:
a successfully constructed rejection report is a valid API result.

## Trust and invariants

Original JSON is bounded to 16 MiB before typed signed decoding. Duplicate
members are rejected before projection. Packet validation checks schema,
required text, and hash syntax; verification adds semantic evidence binding.
Relative review paths reject absolute paths, traversal, backslashes, colons,
repeated separators, and surrounding whitespace.

`runtime_evidence_manifest_from_json` validates the runtime-core manifest
before copying entries into the public type. Hash helpers delegate canonical
encoding to runtime-core. Neither parsing nor hashing selects trust roots.
The review caller supplies the trust bundle and challenge context explicitly.
The protocol also requires kernel-side pre-dispatch denial for runtime closure.

## Dependencies

`chio-runtime-core` supplies review and lineage semantics. The buyer core
supplies strict bilateral, governance, workflow, and selective-disclosure
proof verification. `chio-core-types` supplies the original-input reader;
Serde carries the public wire shapes and report JSON.

## Verification

Run `cargo test -p chio-attest-buyer` and
`cargo test -p chio-attest-buyer --doc` from the workspace root.
`buyer_packet` exercises unresolved hash-only evidence and public schemas.
`buyer_review` checks owned types, malformed readers, and review rejection.
`runtime_manifest` covers missing artifacts and duplicate original fields.
These repository fixtures exercise the local API and its delegated checks.

[README](README.md) | [Protocol](../../../spec/PROTOCOL.md#9-trust-control-contract)
