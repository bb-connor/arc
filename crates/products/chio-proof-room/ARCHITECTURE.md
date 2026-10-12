# chio-proof-room architecture

## Responsibility and boundary

Proof Room owns bundle verification, fixture report recomputation, and an HTTP
inspection surface. It consumes existing signed artifacts and verification
policies. It does not mint runtime authorization or mediate the tool executions
those artifacts describe.

`verify_proof_room_bundle` returns `VerifiedProofRoomBundle`, an opaque result
that retains the exact authenticated manifest hash and bundle ID. Its fields
are private, and it has no Serde constructor. This result identifies the
verified manifest; it does not freeze later changes to files served from disk.

## Structure

| Module | Role |
| --- | --- |
| `lib.rs` | Public entrypoints, schema definitions, domain routing constants, and environment-based trust. |
| `verified` | Verified manifest identity with read-only accessors. |
| `bundle_a` | Manifest/artifact checks, authority bindings, DSSE verification, negatives, and doctor reports. |
| `bundle_b` | Schema/report checks, path resolution, bounded tree copying, and negative mutations. |
| `receipt_coverage` | Covered/excluded categories, status bindings, and receipt signatures. |
| `source_verifier` | Passport reconstruction and routing required claims to domain verifiers. |
| `fixture_a`, `fixture_b` | Fixture catalogs, embedded files, and generated fixture reports. |
| `crypto_context` | BBS crypto-context report recomputation. |
| `input`, `error`, `environment` | Bounded signed JSON, typed errors, and scoped environment overrides. |
| `server` | Axum routes, asset allow-lists, uploads, and graceful shutdown. |
| `main.rs` | Argument parsing and verification/serving exit codes. |

`build.rs` includes the shared `proof_fixture_build.rs` generator. The focused
binary embeds the single-call-authority fixture subtree. A configured fixture
root can supply additional catalog entries from disk.

## Data and control flow

The verifier first checks the bundle tree, reads bounded manifest bytes, and
validates the schema and hash algorithm. It verifies detached DSSE signatures,
loads referenced passport and graph bytes by hash, and recomputes the source
verifier report. Authority evidence, claim bindings, receipt coverage, negative
cases, listed artifacts, and the dashboard report are checked before success.

The source verifier derives required claim families from the verifier policy.
It checks passport artifact digests, scopes graph subsets for domain verifiers,
merges verified reports, and requires each demanded claim to be satisfied.
Unknown required claim routes reject. Runtime report handling also checks
proof-parity and regeneration artifacts against graph and workflow bindings.

`verify_proof_room_quickstart` optionally writes a doctor report from the
verified result. The report includes declared receipt exclusions and replayed
negative-case results. Its output parent must already exist.

`serve_proof_room` checks the UI index and full bundle before binding, builds
routes, applies server hygiene and connection limits, and drains on shutdown.
`proof_room_router*` constructors build route state and manifest-derived path
allow-lists without the full verifier. Library hosts must verify independently.

Uploads pass multipart parsing and path validation before a temporary tree is
written. The upload handler calls the full verifier and returns a stable public
verdict; its temporary directory is removed on drop. There is no persistent
upload catalog or receipt database owned by the server.

## Trust and invariants

DSSE pre-authentication encoding signs the exact manifest bytes. Every detached
signer must belong to both declared trust roots and the independently configured
operator key set. Hash references bind original artifact bytes; canonicalization
is applied by domain contracts where their signed formats require it.
Receipt coverage checks use a separate trusted kernel-key set and distinguish
covered categories from explicit exclusions.

`validate_bundle_relative_path` rejects absolute paths, dot segments,
backslashes, colons, whitespace, controls, and decoded traversal/separators.
Path resolution canonicalizes the root and target and requires containment.
Tree validation rejects symlinks and special files. `input::read` checks regular
files and reads at most 16 MiB plus one byte; Unix opens reject a final symlink.
Signed JSON decoding rejects duplicate object keys before typed projection.

Collectors charge a maximum of 4,096 entries, depth 64, and 128 MiB cumulatively.
The upload route caps the HTTP body at 32 MiB. These limits cover different
stages; verification errors retain typed local causes while HTTP responses
project public error information.

Trust configuration is process environment data. The source quickstart helper
exports fixture keys and replay timing for local inspection. Domain-specific
verifiers require their own authority keys. Public-settlement verification may
use an independent-chain-head JSON value or a configured RPC URL; RPC requests
pass through `HttpEgressContract`. The README's single-call example uses local
fixtures and opens no network listener.

## Dependencies and verification

Transaction-passport and domain crates implement evidence verification for
runtime, swarm, commerce, enterprise, risk, trust-market, web3, disclosure, and
agent-web claims. Selective-disclosure enables BBS support. Core types provide
cryptography and strict JSON; Jsonschema checks artifact shapes. Axum, Tokio,
Tower HTTP, and `chio-http-serve` provide routing, static files, connection
limits, and shutdown. SHA-256 hashes raw manifest and artifact bytes.
There are no package-defined Cargo features.

`src/tests/core.rs` checks the authority fixture, receipt coverage, negatives,
and runtime regeneration bindings. `source.rs` checks report drift, required
claims, signer rejection, and BBS material. `catalog.rs` exercises fixture and
asset routes. Input tests check allocation bounds and JSON-RPC response IDs.
`tests/cli.rs` checks help, verify-only reports, and missing UI rejection before
binding. Run `cargo test -p chio-proof-room` for these local verifier and HTTP tests.

[README](README.md) contains the source-checkout verification command.
