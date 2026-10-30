//! C2SP signed notes (c2sp.org/signed-note) and the tlog-checkpoint body
//! (c2sp.org/tlog-checkpoint), projected from a signed [`KernelCheckpoint`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::checkpoint::{KernelCheckpoint, CHECKPOINT_SCHEMA};
use crate::crypto::{Keypair, PublicKey, Signature};
use crate::hashing::{sha256, Hash};

/// Signature type byte of an Ed25519 note key.
const ED25519_KEY_TYPE: u8 = 0x01;
/// The signature line marker: an em dash and a space.
const SIGNATURE_PREFIX: &str = "\u{2014} ";
const ED25519_SIGNATURE_LEN: usize = 64;
const KEY_ID_LEN: usize = 4;

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

type Result<T> = core::result::Result<T, SignedNoteError>;

/// A pinned Ed25519 note verifier key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteVerifier {
    name: String,
    key_id: [u8; KEY_ID_LEN],
    key: PublicKey,
}

impl NoteVerifier {
    /// Pins `key` under the note key `name`.
    pub fn new(name: &str, key: &PublicKey) -> Result<Self> {
        if !valid_key_name(name) {
            return Err(SignedNoteError::InvalidKeyName);
        }
        let key_bytes = key
            .ed25519_bytes()
            .map_err(|_| SignedNoteError::UnsupportedKeyAlgorithm)?;
        Ok(Self {
            name: String::from(name),
            key_id: key_id(name, key_bytes),
            key: key.clone(),
        })
    }

    /// Parses `name+hex(key id)+base64(0x01 || public key)`.
    pub fn from_vkey(vkey: &str) -> Result<Self> {
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(id_hex), Some(blob)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(SignedNoteError::MalformedVerifierKey);
        };
        if !valid_key_name(name) {
            return Err(SignedNoteError::MalformedVerifierKey);
        }
        let mut stated_id = [0_u8; KEY_ID_LEN];
        if id_hex.bytes().any(|byte| byte.is_ascii_uppercase())
            || hex::decode_to_slice(id_hex, &mut stated_id).is_err()
        {
            return Err(SignedNoteError::MalformedVerifierKey);
        }
        let decoded = base64_decode(blob).ok_or(SignedNoteError::MalformedVerifierKey)?;
        let Some((key_type, key_bytes)) = decoded.split_first() else {
            return Err(SignedNoteError::MalformedVerifierKey);
        };
        if *key_type != ED25519_KEY_TYPE {
            return Err(SignedNoteError::UnsupportedKeyAlgorithm);
        }
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| SignedNoteError::MalformedVerifierKey)?;
        if key_id(name, &key_bytes) != stated_id {
            return Err(SignedNoteError::MalformedVerifierKey);
        }
        let key =
            PublicKey::from_bytes(&key_bytes).map_err(|_| SignedNoteError::MalformedVerifierKey)?;
        Ok(Self {
            name: String::from(name),
            key_id: stated_id,
            key,
        })
    }

    /// The `name+hex(key id)+base64(0x01 || public key)` form.
    #[must_use]
    pub fn to_vkey(&self) -> String {
        let mut blob = Vec::with_capacity(33);
        blob.push(ED25519_KEY_TYPE);
        if let Ok(key_bytes) = self.key.ed25519_bytes() {
            blob.extend_from_slice(key_bytes);
        }
        format!(
            "{}+{}+{}",
            self.name,
            hex::encode(self.key_id),
            base64_encode(&blob)
        )
    }

    /// The note key name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The four-byte key id.
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        self.key_id
    }

    /// The pinned key.
    #[must_use]
    pub fn key(&self) -> &PublicKey {
        &self.key
    }
}

/// Signs `text` as a note under the key name `name`.
pub fn sign_note(text: &str, name: &str, signer: &Keypair) -> Result<String> {
    if !valid_key_name(name) {
        return Err(SignedNoteError::InvalidKeyName);
    }
    if !valid_text(text) {
        return Err(SignedNoteError::MalformedNote);
    }
    let public = signer.public_key();
    let key_bytes = public
        .ed25519_bytes()
        .map_err(|_| SignedNoteError::UnsupportedKeyAlgorithm)?;
    let mut blob = Vec::with_capacity(KEY_ID_LEN + ED25519_SIGNATURE_LEN);
    blob.extend_from_slice(&key_id(name, key_bytes));
    blob.extend_from_slice(&signer.sign(text.as_bytes()).to_bytes());
    Ok(format!(
        "{text}\n{SIGNATURE_PREFIX}{name} {}\n",
        base64_encode(&blob)
    ))
}

/// Returns the note text once a signature from a supplied verifier verifies
/// and no signature from a supplied verifier fails. Signatures from other
/// keys are ignored.
pub fn open_note<'a>(note: &'a str, verifiers: &[NoteVerifier]) -> Result<&'a str> {
    let separator = note.rfind("\n\n").ok_or(SignedNoteError::MalformedNote)?;
    let text = note
        .get(..=separator)
        .ok_or(SignedNoteError::MalformedNote)?;
    let signatures = note
        .get(separator + 2..)
        .and_then(|rest| rest.strip_suffix('\n'))
        .ok_or(SignedNoteError::MalformedNote)?;
    if !valid_text(text) || signatures.is_empty() {
        return Err(SignedNoteError::MalformedNote);
    }
    let mut verified = false;
    for line in signatures.split('\n') {
        let (name, blob) = line
            .strip_prefix(SIGNATURE_PREFIX)
            .and_then(|rest| rest.split_once(' '))
            .ok_or(SignedNoteError::MalformedNote)?;
        if !valid_key_name(name) {
            return Err(SignedNoteError::MalformedNote);
        }
        let blob = base64_decode(blob).ok_or(SignedNoteError::MalformedNote)?;
        let (id, signature) = blob
            .split_first_chunk::<KEY_ID_LEN>()
            .ok_or(SignedNoteError::MalformedNote)?;
        for verifier in verifiers {
            if verifier.name != name || verifier.key_id != *id {
                continue;
            }
            let signature: &[u8; ED25519_SIGNATURE_LEN] = signature
                .try_into()
                .map_err(|_| SignedNoteError::InvalidSignature)?;
            if !verifier
                .key
                .verify(text.as_bytes(), &Signature::from_bytes(signature))
            {
                return Err(SignedNoteError::InvalidSignature);
            }
            verified = true;
        }
    }
    if verified {
        Ok(text)
    } else {
        Err(SignedNoteError::UnknownKey)
    }
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
    checkpoint: &KernelCheckpoint,
    origin: &str,
    kernel_key: &PublicKey,
) -> Result<String> {
    let body = &checkpoint.body;
    if body.schema != CHECKPOINT_SCHEMA
        || body.kernel_key != *kernel_key
        || !kernel_key
            .verify_canonical(body, &checkpoint.signature)
            .unwrap_or(false)
    {
        return Err(SignedNoteError::CheckpointNotSignedByKey);
    }
    if !valid_origin(origin) {
        return Err(SignedNoteError::MalformedCheckpoint);
    }
    let tree_size =
        u64::try_from(body.tree_size).map_err(|_| SignedNoteError::MalformedCheckpoint)?;
    Ok(format!(
        "{origin}\n{tree_size}\n{}\n",
        base64_encode(body.merkle_root.as_bytes())
    ))
}

/// Parses a tlog-checkpoint body with no extension lines.
pub fn parse_checkpoint_text(text: &str) -> Result<CheckpointNote> {
    let lines = text
        .strip_suffix('\n')
        .ok_or(SignedNoteError::MalformedCheckpoint)?;
    let mut lines = lines.split('\n');
    let (Some(origin), Some(size), Some(root)) = (lines.next(), lines.next(), lines.next()) else {
        return Err(SignedNoteError::MalformedCheckpoint);
    };
    if !valid_origin(origin) {
        return Err(SignedNoteError::MalformedCheckpoint);
    }
    let tree_size = parse_tree_size(size)?;
    let root_bytes: [u8; 32] = base64_decode(root)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SignedNoteError::MalformedCheckpoint)?;
    let mut extensions = lines.peekable();
    if extensions.peek().is_some() {
        return Err(if extensions.any(str::is_empty) {
            SignedNoteError::MalformedCheckpoint
        } else {
            SignedNoteError::ExtensionLine
        });
    }
    Ok(CheckpointNote {
        origin: String::from(origin),
        tree_size,
        root_hash: Hash::from_bytes(root_bytes),
    })
}

/// Signs the checkpoint body of `checkpoint` as a note under the key name
/// `name`. The kernel checkpoint must be signed by `signer`.
pub fn sign_checkpoint_note(
    checkpoint: &KernelCheckpoint,
    origin: &str,
    name: &str,
    signer: &Keypair,
) -> Result<String> {
    let text = checkpoint_note_text(checkpoint, origin, &signer.public_key())?;
    sign_note(&text, name, signer)
}

/// Opens a checkpoint note under `verifiers` and parses its body.
pub fn open_checkpoint_note(note: &str, verifiers: &[NoteVerifier]) -> Result<CheckpointNote> {
    parse_checkpoint_text(open_note(note, verifiers)?)
}

fn parse_tree_size(text: &str) -> Result<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return Err(SignedNoteError::MalformedCheckpoint);
    }
    text.parse()
        .map_err(|_| SignedNoteError::MalformedCheckpoint)
}

fn valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(|character| {
            character == '+' || character.is_whitespace() || character.is_control()
        })
}

fn valid_origin(origin: &str) -> bool {
    !origin.is_empty() && !origin.chars().any(char::is_control)
}

fn valid_text(text: &str) -> bool {
    text.ends_with('\n')
        && !text
            .chars()
            .any(|character| character.is_control() && character != '\n')
}

fn key_id(name: &str, key: &[u8; 32]) -> [u8; KEY_ID_LEN] {
    let mut preimage = Vec::with_capacity(name.len() + 2 + key.len());
    preimage.extend_from_slice(name.as_bytes());
    preimage.push(b'\n');
    preimage.push(ED25519_KEY_TYPE);
    preimage.extend_from_slice(key);
    let [first, second, third, fourth, ..] = *sha256(&preimage).as_bytes();
    [first, second, third, fourth]
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_char(index: u32) -> char {
    usize::try_from(index & 0x3f)
        .ok()
        .and_then(|index| BASE64_ALPHABET.get(index))
        .map_or('A', |byte| char::from(*byte))
}

fn base64_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = 0_u32;
        for slot in 0..3 {
            group = (group << 8) | chunk.get(slot).map_or(0, |byte| u32::from(*byte));
        }
        text.push(base64_char(group >> 18));
        text.push(base64_char(group >> 12));
        text.push(if chunk.len() > 1 {
            base64_char(group >> 6)
        } else {
            '='
        });
        text.push(if chunk.len() > 2 {
            base64_char(group)
        } else {
            '='
        });
    }
    text
}

fn sextet(character: u8) -> Option<u32> {
    match character {
        b'A'..=b'Z' => Some(u32::from(character - b'A')),
        b'a'..=b'z' => Some(u32::from(character - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(character - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes padded standard base64 in its canonical form only: the padding is
/// exact and the unused trailing bits are zero.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let data = bytes.get(..bytes.len() - padding)?;
    let mut decoded = Vec::with_capacity(data.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut width = 0_u32;
    for character in data {
        accumulator = (accumulator << 6) | sextet(*character)?;
        width += 6;
        if width >= 8 {
            width -= 8;
            decoded.push(u8::try_from((accumulator >> width) & 0xff).ok()?);
            accumulator &= (1 << width) - 1;
        }
    }
    (accumulator == 0).then_some(decoded)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests;
