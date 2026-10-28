# Durable nonce signing identity

Status: Root-2 design for NONCE-DURABLE-PQ-ISSUER. Implementation not started. Base c5888c4053650172f04c04c0d2f6a091aac3a268 includes #1823.

## Intent

Operation-owned execution nonces must use the boot-selected receipt signing authority through issuance, reservation, restart and caller return. A hybrid signing backend must not be refused merely because its key is not a bare Ed25519 string. Wrong signing identity, malformed persisted keys, stale ownership and changed original signer still refuse.

## Approach

Use one bounded coordinator claimant derived from the complete canonical signing key. The claimant is `kernel:` followed by lowercase SHA-256 of `chio.admission-coordinator-signing-identity.v1` followed by a NUL byte and `PublicKey::to_hex()` bytes. The full issuer stays in the nonce artifact and bounded SQL column for signature checks. Every issuer-to-claimant comparison uses the shared helper.

Alternatives considered: increasing SQL bounds alone leaves claimant and caller-return failures; embedding the full key exceeds AdmissionIdentifier's 512-byte bound; identifying only the classical component loses the PQ identity distinction. The full-key digest keeps identity bounded without collapsing distinct hybrid keys. This is Root's design choice under the delegated implementation instruction.

## Binding and setup

Durable runtime attachment freezes the current readable receipt signing public key into its claimant. A failed identity read refuses attachment with a typed error, without installing partial state. Backend configuration must precede durable attachment. A later backend identity change cannot issue a nonce under the old claimant; it refuses before durable issuance. Existing original-signer recovery checks remain authoritative: this change does not add witnessed rotation or permit a replacement signer to finish an old operation.

The three retained caller nonce checks compare against the receipt signing identity, not config.keypair. Preserve exact operation binding, retained-request checks, current fence, trusted time, signature, nonce profile and original authority checks. Never take an untrusted token's issuer as the coordinator trust root.

## Persistent representation

Both admission_execution_nonce_issuances and admission_execution_nonce_reservations store canonical PublicKey text up to 4129 bytes, the existing crypto parser maximum (hybrid overhead24 + maximum classical wire201 + ML-DSA-65 key3904). Both SQL readers bound text before allocation, parse it and require to_hex() equality with stored text. Reject alternate spellings instead of adopting them. Keep nonce artifacts bounded at16384 bytes; tests must establish supported hybrid envelopes fit.

Fresh-only v1 catalog changes replace the old issuer constraint. Existing catalogs with the old shape refuse open. No migration, dual claimant or compatibility alias.

## Acceptance

- Valid Ed25519 and hybrid identities produce deterministic bounded distinct claimants; changing only the PQ component changes the claimant.
- Durable hybrid issuance, restart/redelivery, reservation and terminal cleanup preserve the exact nonce and authority. Wrong key, classical-only signature under PQ floor and mismatched claimant refuse.
- Caller return/reconciliation uses the actual receipt signer and refuses a substituted signer.
- Both SQL tables accept canonical supported keys and reject malformed, oversized, noncanonical and old-catalog inputs with exact refusal checks.
- Readable identity is required before runtime installation; changing backend identity after attachment cannot mutate issuance state.

Native packets, Lean, lake, Aeneas and Kani are outside execution scope on ws2. Every Cargo command uses cslot and CARGO_INCREMENTAL=0; ws2 free-space floor45GiB remains mandatory. Native thread only; lead owns merges.
