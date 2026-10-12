# chio-federation-authority architecture

## Responsibility and boundary

This crate owns authority input documents, local signing-key custody, issuance
of leases and governance receipts, revocation checkpoint construction, and
verifier trust-bundle assembly. It also exposes FROST distributed key generation,
local signer operations, and coordinator aggregation through `lib.rs`.

The public surface returns artifact values and cryptographic transitions.
Callers own operator approval, transport, persistent custody, checkpoint
history, roster publication, and runtime execution. Signing an artifact does
not install it into a kernel or establish its issuer as trusted.

## Structure

| Source | Responsibility |
| --- | --- |
| `lib.rs` | Document types, requests, seed custody, validators, issuance, and assembly. |
| `profile.rs` | Authority identity, key ID, validity, status, and role validation. |
| `input.rs` | Bounded JSON readers, public serializers, explicit private-key export. |
| `frost_ceremony.rs` | Configuration, authenticated DKG transitions, and transcripts. |
| `frost_ceremony/packages.rs` | Round-one package wire boundary. |
| `frost_ceremony/sealing.rs` | Recipient-bound sealed round-two envelopes and opening. |
| `frost_ceremony/sealing/keys.rs` | X25519 public-key validation and sealing-key custody. |
| `frost_signer.rs` | Key inspection, fresh commitments, nonce custody, signature shares. |
| `frost_coordinator.rs` | Sorted threshold signing sets, share checks, and aggregation. |

## Data and control flow

1. Public JSON readers pass supplied bytes through `UntrustedJsonText` with a
   sixteen-MiB limit and duplicate-aware signed decoding, then validate the
   resulting documents. This bounds supplied text; callers must bound file or
   network reads before constructing that text.
2. `issue_authority_bundle` validates all inputs and locates named lease and
   governance authorities. It derives local keypairs from secret seeds and
   checks their public keys against the profile pins.
3. Each step becomes a `LeaseScopeBindingArtifact`. Its digest binds workflow,
   grant, step, tool, peer, subject, arguments, action class, and lease interval.
   A signed lease commits to that digest. Destructive steps additionally emit a
   signed governance receipt bound to the lease, workflow, and step hash.
4. `publish_revocation_checkpoint` signs the requested epoch and revoked-key
   fingerprints within the revocation authority's validity interval.
5. `assemble_verifier_trust_bundle` combines profile roots, peer/vendor/action
   pins, a canonical workflow-intersection digest, disclosure policy, and the
   supplied checkpoint, then runs `ChioVerifierTrustBundle::from_document`.
6. FROST participants begin round one, authenticate the full transcript,
   advance to sealed recipient-specific round-two packages, and complete DKG
   using the validated transcript and successfully opened local inbox.
7. Signers prepare commitments, consume nonces to sign a bound package, and
   return shares. The coordinator selects a sorted threshold subset, checks
   shares against roster verification shares, and aggregates the authorization.

## Trust and invariants

`AuthorityProfileDocument::validate` requires nonempty issuer and authority
collections, unique authority identities, key IDs matching public keys,
validity intervals, statuses, and allowed operations. Runtime policy issuer
keys must be unique and distinct from lease, governance, and revocation keys.
BBS key strings are checked for hexadecimal shape; profile validation does not
perform a BBS proof or authenticate the profile itself.

Issuance additionally requires selected authorities to be active and local
seed-derived keys to match their pins. It validates action authorization and
contains artifact intervals within authority intervals. Destructive governance
intervals must also fit within their associated leases. Caller-supplied issue
times are used; issuance does not read a wall clock or maintain replay state.

`RevocationPublicationRequest::validate` compares the requested epoch to
`previous_epoch_height` when present. No stored high-water mark is maintained.
An empty revoked-fingerprint list is permitted. The optional previous height
is an input check and is not included in the signed checkpoint body.

Assembly hashes the supplied workflow intersection and validates the resulting
bundle through the buyer verifier. It does not independently re-run workflow
intersection construction. The caller must authenticate the checkpoint against
the intended revocation authority and maintain its freshness and history.

Local signing documents deserialize into `SecretString` fields and expose
neither general serialization nor cloning. `signing_keys_json` is an explicit
canonical custody export returning `Zeroizing<String>`. FROST secret and nonce
bytes use `Zeroizing`; authenticated round-two plaintext has no public serde
construction and wipes initialized plaintext on drop.

Ceremony configuration requires sorted unique participant IDs, independent
Ed25519 transport keys, separate sealing key IDs, valid X25519 keys, and
thresholds between two and the participant count. Rotated epochs require a
predecessor roster digest. Sealing uses X25519, HKDF-SHA256, and
ChaCha20-Poly1305, with signed metadata binding sender, recipient, ceremony,
participant set, epoch, and transport key.

`create_frost_signature_share` consumes its Rust nonce object. Custody bytes
can be explicitly exported and reopened, so crash-safe single use requires
caller-enforced durable consumption. Aggregation produces a cryptographic
proof; `chio-federation` execution verification separately checks current
roster, epoch, slot, action, and time bindings.

## Dependencies

`chio-attest-buyer-core` supplies workflow claims, authority roots, disclosure,
and trust-bundle validation. `chio-governance` supplies lease and governance
receipt artifacts; `chio-core-types` supplies canonical JSON and signing.
`chio-federation` supplies FROST authorization and roster contracts.
`frost-ed25519` and `frost-core` supply DKG, signing, share verification, and
aggregation. AWS-LC supplies X25519 and HKDF; `chacha20poly1305` supplies AEAD.
`secrecy` and `zeroize` protect owned secret buffers; `rand_core` supplies the
cryptographic random-source interfaces.

## Verification

Run `cargo test -p chio-federation-authority` from the workspace root.
Unit tests exercise verifier-compatible issuance, authority/key mismatches,
action restrictions, interval containment, profile roots, checkpoint epochs,
input decoding, and trust-bundle assembly.

`tests/frost_ceremony.rs` covers exact custody restoration, participant drift,
duplicate/tampered packages, recipient-only opening, and bounded mutations.
`tests/frost_signer.rs` checks message/commitment binding and fresh-nonce retries.
`tests/frost_coordinator.rs` checks sorted signing sets and share verification.
Compile-fail doctests cover private document serialization/cloning and
round-two plaintext construction boundaries.
