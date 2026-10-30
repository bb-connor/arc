//! C2SP signed notes (c2sp.org/signed-note) and the tlog-checkpoint body
//! (c2sp.org/tlog-checkpoint), projected from a signed [`KernelCheckpoint`].

use alloc::string::String;
use core::fmt;

use super::checkpoint::KernelCheckpoint;
use crate::crypto::{Keypair, PublicKey};
use crate::hashing::Hash;

/// Why a signed note, verifier key or checkpoint body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedNoteError {
    /// The note is not a text, a blank line and signature lines.
    MalformedNote,
    /// A key name is empty or contains a space, a plus or a control character.
    InvalidKeyName,
    /// A verifier key string is not `name+hex(key id)+base64(type || key)`.
    MalformedVerifierKey,
    /// The key is not an Ed25519 key.
    UnsupportedKeyAlgorithm,
    /// No signature line names a supplied verifier key.
    UnknownKey,
    /// A signature line from a supplied verifier key does not verify.
    InvalidSignature,
    /// The note text is not a Chio tlog-checkpoint body.
    MalformedCheckpoint,
    /// The checkpoint carries extension lines, which the Chio profile refuses.
    ExtensionLine,
    /// The kernel checkpoint is not signed by the supplied key.
    CheckpointNotSignedByKey,
}

impl fmt::Display for SignedNoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedNote => "signed note is malformed",
            Self::InvalidKeyName => "note key name is invalid",
            Self::MalformedVerifierKey => "note verifier key is malformed",
            Self::UnsupportedKeyAlgorithm => "note key is not an Ed25519 key",
            Self::UnknownKey => "no note signature names a supplied verifier key",
            Self::InvalidSignature => "note signature does not verify",
            Self::MalformedCheckpoint => "note text is not a checkpoint body",
            Self::ExtensionLine => "checkpoint note carries an extension line",
            Self::CheckpointNotSignedByKey => "kernel checkpoint is not signed by the supplied key",
        })
    }
}

impl core::error::Error for SignedNoteError {}

/// A pinned Ed25519 note verifier key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteVerifier {
    name: String,
    key_id: [u8; 4],
    key: PublicKey,
}

impl NoteVerifier {
    /// Pins `key` under the note key `name`.
    pub fn new(_name: &str, _key: &PublicKey) -> Result<Self, SignedNoteError> {
        Err(SignedNoteError::MalformedVerifierKey)
    }

    /// Parses `name+hex(key id)+base64(0x01 || public key)`.
    pub fn from_vkey(_vkey: &str) -> Result<Self, SignedNoteError> {
        Err(SignedNoteError::MalformedVerifierKey)
    }

    /// The `name+hex(key id)+base64(0x01 || public key)` form.
    #[must_use]
    pub fn to_vkey(&self) -> String {
        String::new()
    }

    /// The note key name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The four-byte key id.
    #[must_use]
    pub fn key_id(&self) -> [u8; 4] {
        self.key_id
    }

    /// The pinned key.
    #[must_use]
    pub fn key(&self) -> &PublicKey {
        &self.key
    }
}

/// Signs `text` as a note under the key name `name`.
pub fn sign_note(_text: &str, _name: &str, _signer: &Keypair) -> Result<String, SignedNoteError> {
    Err(SignedNoteError::MalformedNote)
}

/// Returns the note text once a signature from a supplied verifier verifies
/// and no signature from a supplied verifier fails. Signatures from other
/// keys are ignored.
pub fn open_note<'a>(
    _note: &'a str,
    _verifiers: &[NoteVerifier],
) -> Result<&'a str, SignedNoteError> {
    Err(SignedNoteError::MalformedNote)
}

/// The fields of a Chio tlog-checkpoint body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointNote {
    /// The log origin line.
    pub origin: String,
    /// The number of leaves in the tree.
    pub tree_size: u64,
    /// The RFC 6962 root hash.
    pub root_hash: Hash,
}

/// The tlog-checkpoint body of `checkpoint` under the log `origin`, once
/// `kernel_key` is the checkpoint's key and its signature verifies.
pub fn checkpoint_note_text(
    _checkpoint: &KernelCheckpoint,
    _origin: &str,
    _kernel_key: &PublicKey,
) -> Result<String, SignedNoteError> {
    Err(SignedNoteError::MalformedCheckpoint)
}

/// Parses a tlog-checkpoint body with no extension lines.
pub fn parse_checkpoint_text(_text: &str) -> Result<CheckpointNote, SignedNoteError> {
    Err(SignedNoteError::MalformedCheckpoint)
}

/// Signs the checkpoint body of `checkpoint` as a note under the key name
/// `name`. The kernel checkpoint must be signed by `signer`.
pub fn sign_checkpoint_note(
    _checkpoint: &KernelCheckpoint,
    _origin: &str,
    _name: &str,
    _signer: &Keypair,
) -> Result<String, SignedNoteError> {
    Err(SignedNoteError::MalformedCheckpoint)
}

/// Opens a checkpoint note under `verifiers` and parses its body.
pub fn open_checkpoint_note(
    _note: &str,
    _verifiers: &[NoteVerifier],
) -> Result<CheckpointNote, SignedNoteError> {
    Err(SignedNoteError::MalformedNote)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests;
