# Trust reader boundary execution

Base: `6ef28e8f4ddccb7f344a179d2415844a3410f815`, branch
`packet/3-retention-accounting`, checkout `/tmp/arc-security-launch`.
Implements the [approved four-task plan](../superpowers/plans/2026-09-30-trust-reader-boundaries.md)
for all 35 reader paths pinned by the provider batch, with shared helpers and
direct consumers needed to enforce their contracts.

## Completed tasks

1. Attestation, credentials and buyer imports: bounded original JSON is checked
   before projection, native signed integers retain their full domain, and local
   parser causes survive redacted public errors. Existing credential and FROST
   custom decoders were reviewed against their separate authentication gates;
   already constrained decoders were not needlessly rewritten. Sigstore bundles
   and both TUF root inputs validate original external I-JSON before projection.
2. Custody, TEE, remote signing and federation: canonical capability/model-card
   imports require exact typed canonical bytes; SQLite challenges are bounded
   before copying/decoding; WebAuthn and Play Integrity check original external
   JSON before crypto projection. TEE NDJSON reads are bounded before allocation.
   Remote signer replies and treaty imports preserve their verification gates.
   The misleading mobile shape-only verifier/type is replaced by explicit
   receipt-envelope inspection in Rust and UDL, without compatibility aliases.
3. Pheromone and exchanged/persisted evidence: bounded native readers cover
   runtime, relay, archive, directory, finding, reputation and replay inputs.
   HTTP and Iroh now share a delivery-report gate that binds the exact sent
   batch, recipient, schema and complete accepted frame results before durable
   delivery. HTTP also binds the expected sender. Failure bodies are not retained.
   Duplicate, incomplete or unrelated acknowledgements cannot retire the batch.
4. One independent source review completed and material findings resolved;
   focused qualification, inventory, source/binary hashes and roadmap records
   completed. Work is delivered as a local conventional commit on this branch.

## Qualification and limits

**1,964 tests pass, zero fail, and three existing tests are ignored**, across
20 packages, 125 test binaries and 20 doctest groups. CLI consumers compile with
`--tests --features iroh`. Trust inventory, file hygiene, negative-assertion,
wire-schema and changed-file formatting checks pass without increasing limits
or exemptions. The [artifact record](artifacts/2026-09-30-trust-reader-boundaries/README.md)
contains exact commands, terminal results, retained failed attempts and hashes.
The compiler also exposed a missing receipt import in an existing CLI test; it
is fixed and the consumer check rerun successfully.

The raw decoder baseline falls from 166 to **131 workspace files**, with no
remaining trust, protocol or CLI baseline files. This is a semantic reader-review
count, not a vulnerability count or completion of mechanisms B/C. The mobile
kernel's other capability/passport readers remain in that baseline.

Local tests do not qualify live device attestation, hosted release acceptance or
native enforcement. Play Integrity production validation still rejects the
committed fixture root. Apple XCFramework binaries/headers require a separate
rebuild to match the source API; the Rust/UDL migration does not update those
packaged artifacts. Broader error taxonomy, arithmetic, retention, formal/runtime
correspondence, supply-chain audits and M5/operator acceptance remain open.
No push, merge, publication or activation occurred.

## Next substantial chunk

Execute the [33 pinned guard and security readers](artifacts/2026-09-30-trust-reader-boundaries/next-readers.json):

1. Guard loading and decisions: registry/cache/OCI/marketplace input, external
   verdict responses, embedding/classification inputs, and WASM manifest,
   blocklist, hot-reload and backend readers.
2. Security execution and recovery: sandbox bootstrap/plan/Linux launch,
   quarantine rules/state/simulation/effect journals, keyring checkpoints/events,
   and decoy materialization/registry/watermarks.
3. Security-type deserialization: flow, declassification, deception, bounded
   ports and identifiers. Preserve their invariants and authority checks, reject
   ambiguous original input, retain native causes behind safe public errors,
   and qualify changes through production-linked negative controls.

This continues mechanisms B/C and remaining-security-work item 2. It protects
the inputs that select guard behavior and drive security effects and recovery;
classification must follow each owner's actual contract.
