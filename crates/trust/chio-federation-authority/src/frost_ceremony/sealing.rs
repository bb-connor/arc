//! Recipient-bound round-two transport. Only `open` constructs plaintext proof.
use super::*;
use aws_lc_rs::{agreement, hkdf};
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use chio_core_types::canonical::UntrustedJsonText;

#[path = "sealing/keys.rs"]
mod keys;
pub use keys::{FrostSealingKey, X25519PublicKey};

pub const FROST_ROUND2_SCHEMA: &str =
    chio_core_types::signed_artifact::CHIO_FROST_DKG_ROUND2_SEALED_V1_SCHEMA;
pub const FROST_ROUND2_SUITE: &str = "X25519HkdfSha256ChaCha20Poly1305";
const MAX_SEALED_WIRE_BYTES: usize = 32 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrostSealingError {
    #[error("invalid sealed package encoding or size")]
    Encoding,
    #[error("unrecognized sealed package schema")]
    Schema,
    #[error("unrecognized sealed package suite")]
    Suite,
    #[error("sealed package ceremony context mismatch")]
    Context,
    #[error("sealed package recipient mismatch")]
    Recipient,
    #[error("sealing key does not match the roster")]
    SealingKey,
    #[error("sealed package sender is not in the roster")]
    Sender,
    #[error("sealed package transport key mismatch")]
    TransportKey,
    #[error("sealed package signature does not verify")]
    Signature,
    #[error("X25519 key agreement failed")]
    Agreement,
    #[error("sealed package key derivation failed")]
    Derivation,
    #[error("sealed package authenticated decryption failed")]
    Authentication,
    #[error("round-two plaintext does not decode")]
    Plaintext,
    #[error("cryptographic random source failed")]
    Random,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    schema: String,
    suite: String,
    ceremony_id: String,
    participant_set_digest: String,
    key_epoch: u64,
    round: u8,
    sender_participant_id: String,
    recipient_participant_id: String,
    recipient_sealing_key_id: String,
    sender_ephemeral_public_key: X25519PublicKey,
    transport_key_id: String,
}

/// Untrusted public transport value. Deserialization grants no authority.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedFrostRound2Package {
    #[serde(flatten)]
    metadata: Metadata,
    ciphertext: Vec<u8>,
    transport_signature: String,
}

#[cfg(test)]
type DropObserver = Box<dyn FnOnce(&[u8]) + Send + Sync>;

/// Authenticated, recipient-local plaintext. Neither serde nor public construction
/// is available; custody and completion can only consume a successful opening.
/// ```compile_fail
/// use chio_federation_authority::FrostRound2Package;
/// fn serialize(p: &FrostRound2Package) { let _ = serde_json::to_vec(p); }
/// ```
/// ```compile_fail
/// use chio_federation_authority::FrostRound2Package;
/// fn deserialize(b: &[u8]) { let _ = serde_json::from_slice::<FrostRound2Package>(b); }
/// ```
pub struct FrostRound2Package {
    pub(super) envelope: SealedFrostRound2Package,
    pub(super) bytes: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    drop_observer: Option<DropObserver>,
}

impl Drop for FrostRound2Package {
    fn drop(&mut self) {
        // Wipe initialized plaintext before any following field destructors.
        // Zeroizing also clears the allocation capacity when the field drops.
        zeroize::Zeroize::zeroize(self.bytes.as_mut_slice());
        #[cfg(test)]
        if let Some(observer) = self.drop_observer.take() {
            observer(&self.bytes);
        }
    }
}
impl zeroize::ZeroizeOnDrop for FrostRound2Package {}

impl std::fmt::Debug for FrostRound2Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostRound2Package")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl FrostRound2Package {
    /// Borrow only for immediate encrypted custody persistence.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl SealedFrostRound2Package {
    pub fn from_wire(bytes: &[u8]) -> Result<Self, FrostCeremonyError> {
        let package: Self = UntrustedJsonText::from_wire(bytes, MAX_SEALED_WIRE_BYTES)
            .and_then(|text| text.decode_signed())
            .map_err(|_| FrostSealingError::Encoding)?;
        package.check_encoding()?;
        Ok(package)
    }

    pub fn envelope_digest(&self) -> Result<String, FrostCeremonyError> {
        canonical_digest(b"chio.frost.round2-envelope.digest.v1\0", self)
    }

    pub fn sender_participant_id(&self) -> &str {
        &self.metadata.sender_participant_id
    }
    pub fn recipient_participant_id(&self) -> &str {
        &self.metadata.recipient_participant_id
    }
    pub const fn round(&self) -> FrostDkgRound {
        FrostDkgRound::Round2
    }

    fn metadata_bytes(&self) -> Result<Vec<u8>, FrostCeremonyError> {
        canonical_json_bytes(&self.metadata)
            .map_err(|e| FrostCeremonyError::Canonical(e.to_string()))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, FrostCeremonyError> {
        let mut bytes = self.metadata_bytes()?;
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    fn check_encoding(&self) -> Result<(), FrostSealingError> {
        if self.metadata.schema != FROST_ROUND2_SCHEMA {
            return Err(FrostSealingError::Schema);
        }
        if self.metadata.suite != FROST_ROUND2_SUITE {
            return Err(FrostSealingError::Suite);
        }
        if !(17..=MAX_CIPHERTEXT_BYTES).contains(&self.ciphertext.len())
            || self.transport_signature.len() != 128
            || !self
                .transport_signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !valid_digest(&self.metadata.ceremony_id)
            || !valid_digest(&self.metadata.participant_set_digest)
            || [
                &self.metadata.sender_participant_id,
                &self.metadata.recipient_participant_id,
                &self.metadata.recipient_sealing_key_id,
                &self.metadata.transport_key_id,
            ]
            .into_iter()
            .any(|id| validate_identifier(id).is_err())
        {
            return Err(FrostSealingError::Encoding);
        }
        Ok(())
    }

    /// Verify the public transcript, including envelopes intended for other peers.
    pub fn verify(&self, config: &FrostCeremonyConfig) -> Result<(), FrostCeremonyError> {
        self.verify_context(&ValidatedCeremony::new_without_key(config)?, false)
    }

    pub(super) fn verify_context(
        &self,
        context: &ValidatedCeremony<'_>,
        local: bool,
    ) -> Result<(), FrostCeremonyError> {
        self.check_encoding()?;
        let m = &self.metadata;
        if m.ceremony_id != context.ceremony_id
            || m.key_epoch != context.config.key_epoch
            || m.participant_set_digest != context.participant_set_digest
            || m.round != 2
        {
            return Err(FrostSealingError::Context.into());
        }
        if local && m.recipient_participant_id != context.config.local_participant_id {
            return Err(FrostSealingError::Recipient.into());
        }
        let recipient = context
            .config
            .participants
            .iter()
            .find(|p| p.participant_id == m.recipient_participant_id)
            .ok_or(FrostSealingError::Recipient)?;
        if m.recipient_sealing_key_id != recipient.sealing_key_id {
            return Err(FrostSealingError::SealingKey.into());
        }
        let sender = context
            .config
            .participants
            .iter()
            .find(|p| p.participant_id == m.sender_participant_id)
            .ok_or(FrostSealingError::Sender)?;
        if sender.participant_id == recipient.participant_id {
            return Err(FrostSealingError::Recipient.into());
        }
        if sender.transport_key_id != m.transport_key_id {
            return Err(FrostSealingError::TransportKey.into());
        }
        let signature = Signature::from_hex(&self.transport_signature)
            .map_err(|_| FrostSealingError::Signature)?;
        if !sender
            .transport_public_key
            .verify(&self.signing_bytes()?, &signature)
        {
            return Err(FrostSealingError::Signature.into());
        }
        Ok(())
    }

    pub fn open(
        &self,
        config: &FrostCeremonyConfig,
        key: &FrostSealingKey,
    ) -> Result<FrostRound2Package, FrostCeremonyError> {
        let context = ValidatedCeremony::new_without_key(config)?;
        self.verify_context(&context, true)?;
        key.validate_for(config)?;
        let metadata = self.metadata_bytes()?;
        let material = derive(
            key,
            &self.metadata.sender_ephemeral_public_key,
            &self.metadata.participant_set_digest,
            &metadata,
        )?;
        let mut bytes = Zeroizing::new(self.ciphertext.clone());
        let cipher = ChaCha20Poly1305::new_from_slice(&material[..32])
            .map_err(|_| FrostSealingError::Derivation)?;
        cipher
            .decrypt_in_place(Nonce::from_slice(&material[32..]), &metadata, &mut *bytes)
            .map_err(|_| FrostSealingError::Authentication)?;
        round2::Package::deserialize(&bytes).map_err(|_| FrostSealingError::Plaintext)?;
        Ok(FrostRound2Package {
            envelope: self.clone(),
            bytes,
            #[cfg(test)]
            drop_observer: None,
        })
    }

    pub(super) fn seal<R: CryptoRng + RngCore>(
        context: &ValidatedCeremony<'_>,
        recipient_id: &str,
        bytes: Vec<u8>,
        transport: &Keypair,
        rng: &mut R,
    ) -> Result<Self, FrostCeremonyError> {
        let mut plaintext = Zeroizing::new(bytes);
        if plaintext.is_empty() || plaintext.len() > MAX_CIPHERTEXT_BYTES - 16 {
            return Err(FrostSealingError::Encoding.into());
        }
        let recipient = context
            .config
            .participants
            .iter()
            .find(|p| p.participant_id == recipient_id)
            .ok_or(FrostSealingError::Recipient)?;
        let ephemeral = FrostSealingKey::generate(rng)?;
        let mut sealed = Self {
            metadata: Metadata {
                schema: FROST_ROUND2_SCHEMA.to_string(),
                suite: FROST_ROUND2_SUITE.to_string(),
                ceremony_id: context.ceremony_id.clone(),
                participant_set_digest: context.participant_set_digest.clone(),
                key_epoch: context.config.key_epoch,
                round: 2,
                sender_participant_id: context.config.local_participant_id.clone(),
                recipient_participant_id: recipient_id.to_string(),
                recipient_sealing_key_id: recipient.sealing_key_id.clone(),
                sender_ephemeral_public_key: ephemeral.public_key()?,
                transport_key_id: context.local_participant()?.transport_key_id.clone(),
            },
            ciphertext: Vec::new(),
            transport_signature: String::new(),
        };
        let metadata = sealed.metadata_bytes()?;
        let material = derive(
            &ephemeral,
            &recipient.sealing_public_key,
            &context.participant_set_digest,
            &metadata,
        )?;
        let cipher = ChaCha20Poly1305::new_from_slice(&material[..32])
            .map_err(|_| FrostSealingError::Derivation)?;
        cipher
            .encrypt_in_place(
                Nonce::from_slice(&material[32..]),
                &metadata,
                &mut *plaintext,
            )
            .map_err(|_| FrostSealingError::Authentication)?;
        sealed.ciphertext = std::mem::take(&mut *plaintext);
        sealed.transport_signature = transport.sign(&sealed.signing_bytes()?).to_hex();
        Ok(sealed)
    }
}

struct MaterialLength;
impl hkdf::KeyType for MaterialLength {
    fn len(&self) -> usize {
        44
    }
}

fn derive(
    key: &FrostSealingKey,
    peer: &X25519PublicKey,
    roster_digest: &str,
    metadata: &[u8],
) -> Result<Zeroizing<[u8; 44]>, FrostCeremonyError> {
    let salt = hex::decode(roster_digest).map_err(|_| FrostSealingError::Context)?;
    let shared = key.agree(peer)?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&shared);
    let info = [metadata];
    let okm = prk
        .expand(&info, MaterialLength)
        .map_err(|_| FrostSealingError::Derivation)?;
    let mut material = Zeroizing::new([0; 44]);
    okm.fill(&mut *material)
        .map_err(|_| FrostSealingError::Derivation)?;
    Ok(material)
}

#[cfg(test)]
#[path = "sealing/tests.rs"]
mod tests;
