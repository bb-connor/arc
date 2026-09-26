# FROST DKG round-2 packages: sealing design

Status: design note, precondition for the Wave 3 lane named in the hardening
spec (H7) and the dispatch plan. Reviewed against
`crates/trust/chio-federation-authority/src/frost_ceremony.rs` at integration
`3788269c6a`.

## What the code does today

A FROST distributed key generation runs in two rounds. Round 1 broadcasts a
commitment package that is public by construction. Round 2 sends each
participant a `frost_ed25519::keys::dkg::round2::Package`, which carries the
recipient's signing share: a secret scalar that, combined with the recipient's
own round-1 secret, becomes its long-term threshold share. The FROST
specification requires round-2 packages to travel over a channel that is both
authenticated and confidential.

`frost_ceremony.rs` provides the first property and not the second. Both rounds
are wrapped in the same type:

```rust
pub struct FrostAuthenticatedDkgPackage {
    schema: String,
    ceremony_id: String,
    participant_set_digest: String,
    key_epoch: u64,
    round: FrostDkgRound,
    sender_participant_id: String,
    recipient_participant_id: Option<String>,
    package_digest: String,
    package_hex: Zeroizing<String>,
    transport_key_id: String,
    transport_signature: String,
}
```

`authenticated_package` hex-encodes `package.serialize()` into `package_hex`,
digests it into `package_digest`, and signs a canonical preimage of every field
except `package_hex` and the signature itself with the sender's transport
`Keypair`, an Ed25519 signing key registered per participant as
`FrostCeremonyParticipant::transport_public_key`. The round-2 branch passes
`Some(recipient)` and nothing else changes. The struct derives `Serialize` and
`Deserialize`; `Debug` redacts the package.

So the round-2 signing share is plaintext inside a signed, serializable value.
No in-tree code serializes that value onto a wire or into a store (pass 8, U8,
confirmed against the six companion checkouts on this host), which is why this
is a type-design finding today and becomes a confidentiality break the first
time a transport or persistence path does the obvious thing with a type that
offers `Serialize`.

## What is not a design

"Encrypt to the recipient's transport key" is not one. The transport key is an
Ed25519 *signing* key. Reusing it for key agreement (by mapping the Edwards
point to Montgomery form) violates key separation: the same secret would then
authorize signatures and decrypt shares, a compromise of either use exposes the
other, and the proofs for Ed25519 say nothing about the combined use. The
external review of 2026-09-26 made this correction and it stands. A sealing
design needs its own key material, a stated suite, recipient binding,
authenticated metadata, and replay handling. Those five decisions follow.

## Step 1: the immediate boundary (no new cryptography)

Land this first, separately, and before any sealing work:

1. Split the type. `FrostRound1Package` is public: it keeps `Serialize` and
   `Deserialize`. `FrostRound2Package` holds the plaintext share for the local
   process only: no `Serialize`, no `Deserialize`, `Debug` redacted, the share
   in `Zeroizing<Vec<u8>>` rather than hex text. A round-2 value that must leave
   the process is a `SealedFrostRound2Package` (step 2), and nothing else.
2. `FrostRound2Transition::packages` becomes `Vec<FrostRound2Package>` until
   step 2 lands, at which point it becomes `Vec<SealedFrostRound2Package>`.
3. A test asserts, for every serializable type in the module, that the
   serialized bytes of a round-2 transition do not contain the share bytes.
   Serialization of the plaintext form does not compile, so the test's purpose
   is to catch a future re-derivation or a leak through an enclosing type.

There is no wire compatibility cost, because nothing serializes the round-2
form today. The schema string `chio.frost.dkg-package.v1` (`DKG_PACKAGE_SCHEMA`,
`frost_ceremony.rs:12`) stays with round 1.

## Step 2: sealing

### Key material

Each participant registers a second public key for sealing, separate from the
signing key:

```rust
pub struct FrostCeremonyParticipant {
    pub participant_id: String,
    pub transport_key_id: String,
    pub transport_public_key: PublicKey,          // Ed25519, signs
    pub sealing_key_id: String,
    pub sealing_public_key: X25519PublicKey,      // X25519, receives
}
```

The sealing key is generated and stored beside the participant's other ceremony
secrets, under the same at-rest protection the ceremony secrets already use, and
appears in the participant roster that `participant_set_digest` covers. A roster
without a sealing key for every participant fails validation before round 1, so
a ceremony cannot reach round 2 with a recipient it cannot seal to.

X25519 is chosen over a post-quantum KEM for the first version because the
vendored `aws-lc-rs` exposes `agreement::X25519` today, the ceremony's
long-term threat is compromise of a participant's stored share rather than
harvest-now-decrypt-later of a one-time DKG message, and the suite identifier
below leaves room for a hybrid. The KEM module in the same crate is the path to
that hybrid when it is wanted.

### Suite

One suite in version 1, named in the sealed value so a second suite is an
additive change:

- Key agreement: X25519, ephemeral sender key against the recipient's static
  sealing key. The ephemeral private key lives in a `Zeroizing` wrapper and is
  dropped after the shared secret is derived.
- Key derivation: HKDF-SHA256. Salt: the participant-set digest bytes (the
  roster carries them hex-encoded; decode, do not hash the text). Info: the canonical bytes of the metadata below. Output: a 32-byte AEAD key
  and a 12-byte nonce. Because the ephemeral key is used once, the derived
  nonce is unique per message without a random source at seal time.
- AEAD: ChaCha20-Poly1305, the primitive already in the tree for at-rest blobs
  and the decoy registry, so no new dependency and one primitive to audit.
- Authenticity: the sender signs the sealed value with its Ed25519 transport
  key, after encryption. The recipient verifies the signature first and
  decrypts only a package whose sender is established. Encrypt-then-sign is
  chosen over sign-then-encrypt because the recipient must be able to attribute
  a rejected package to a sender without decrypting it, and because the
  signature covers the ciphertext and the metadata, which forecloses
  re-labelling a valid ciphertext under a fresh signature.

### Recipient binding and authenticated metadata

The sealed value:

```rust
pub struct SealedFrostRound2Package {
    schema: String,                    // "chio.frost.dkg-round2-sealed.v1"
    suite: SealingSuite,               // X25519HkdfSha256ChaCha20Poly1305
    ceremony_id: String,
    participant_set_digest: String,
    key_epoch: u64,
    sender_participant_id: String,
    recipient_participant_id: String,  // required, not Option
    recipient_sealing_key_id: String,
    sender_ephemeral_public_key: X25519PublicKey,
    ciphertext: Vec<u8>,
    transport_key_id: String,
    transport_signature: Signature,
}
```

Every field except `ciphertext` and `transport_signature` is metadata. The
metadata is canonicalized once (the existing canonical JSON, strict form) and
that byte string serves three roles: the HKDF info, the AEAD associated data,
and, concatenated with the ciphertext, the signing preimage. Using one byte
string for all three means a mismatch anywhere fails both the AEAD tag and the
signature, and there is no second serialization to keep in step.

Binding therefore holds as follows. A package sealed for participant B cannot
be opened by A: A lacks B's sealing private key. A package for B cannot be
re-labelled as being for C: `recipient_participant_id` and
`recipient_sealing_key_id` are in the associated data and the signature. A
package from ceremony X cannot be replayed into ceremony Y, epoch, or roster:
`ceremony_id`, `key_epoch` and `participant_set_digest` are bound the same way.
The plaintext `package_digest` of the current type is dropped from the sealed
form; a digest of the share is not needed for binding once the ciphertext is
signed, and it would otherwise be a stable identifier for a secret.

### Replay within a ceremony

Binding does not stop the same valid sealed package being delivered twice, or a
sender delivering two different valid packages to one recipient in one round.
The transcript verifier already rejects a round-1 package whose sender is not
in the roster; it must also reject, for round 2, a second package for the same
`(ceremony_id, key_epoch, sender_participant_id, recipient_participant_id)`.
Whether it does today is a fact to read from
`verify_frost_ceremony_transcript`, not to assume; the lane records which and
adds the check if it is missing. The first accepted package wins and a second
one is a ceremony failure, not a silent replacement, because a participant who
can substitute a share after the fact can choose the recipient's long-term key.

### Opening

`open` runs in this order and stops at the first failure with a distinct error
variant for each step: schema and suite recognized; sender in roster and
`transport_key_id` matches the roster; signature verifies over the canonical
metadata plus ciphertext; `recipient_participant_id` is the local participant
and `recipient_sealing_key_id` matches the local sealing key; X25519 with the
local sealing private key, HKDF, AEAD open with the canonical metadata as
associated data; plaintext decodes as a `round2::Package`. The plaintext is
`Zeroizing` from the AEAD output onward. Error variants name the step and never
carry key or plaintext material.

## Tests the lane must land

Positive: seal then open round-trips for every participant pair in a
three-of-five roster; the recorded test vectors (roster, ephemeral key, share,
sealed bytes) pin the suite so an implementation change that alters the bytes
is a deliberate schema bump.

Negative, each asserting its variant: wrong recipient sealing key; metadata
field altered after sealing (each field in turn, driven by a loop over the
canonical fields so a new field is covered automatically); recipient
re-labelled with a fresh signature from the real sender; ciphertext truncated
or extended by one byte; signature from a sender not in the roster; sender's
`transport_key_id` not matching the roster; replay of an accepted package;
second distinct package from the same sender for the same recipient and round;
schema or suite string unknown.

Leakage: serializing a round-2 transition, and every enclosing type that can
contain one, yields bytes with no share, no ephemeral private key, and no
derived key; `Debug` of every type in the module prints no such material.

Zeroization: the ephemeral private key, the shared secret, the derived key and
the opened plaintext are `Zeroizing`; a test using a drop-observing wrapper
confirms the plaintext is zeroized after the share is installed.

## Exit for the lane

Step 1 is one commit and may land as soon as it is reviewed. Step 2 is a
separate commit series: roster change with migration and validation, the
sealing primitive with vectors, the transition and verifier changes, the
negative suite. The hardening spec's H7 acceptance (no secret-bearing struct
derives `Debug` or `Serialize` on the secret field; `expose_secret()` sites are
the complete inventory) applies to every type this note introduces.
