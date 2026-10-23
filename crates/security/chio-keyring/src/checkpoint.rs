use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chio_core_types::{canonical_json_bytes, sha256, Hash, PublicKey, Signature, SigningBackend};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::signing::{sign_wrapped_value, verify_wrapped_value};
use crate::{derive_key_id, KeyId, KeyringError, LogId, Result, WitnessId};

pub const KEY_LOG_CHECKPOINT_SCHEMA: &str = "chio.key-log.checkpoint.v1";
pub const KEY_ACTIVATION_COMMIT_SCHEMA: &str = "chio.key-log.activation-commit.v1";
const CHECKPOINT_HASH_DOMAIN: &[u8] = b"chio.key-log.checkpoint-envelope.v1\0";
const CHECKPOINT_BODY_HASH_DOMAIN: &[u8] = b"chio.key-log.checkpoint-body.v1\0";
pub const KEY_LOG_WITNESS_STATEMENT_SCHEMA: &str = "chio.key-log.witness-statement.v1";
const WITNESS_SET_HASH_DOMAIN: &[u8] = b"chio.key-log.witness-set.v1\0";
pub const MAX_WITNESS_SIGNATURES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogCheckpointBody {
    pub schema: String,
    pub log_id: LogId,
    pub checkpoint_sequence: u64,
    pub tree_size: u64,
    pub root_hash: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_hash: Option<Hash>,
    pub issued_at: u64,
}

impl KeyLogCheckpointBody {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        crate::from_bounded_json(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSignature {
    pub witness_id: WitnessId,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedKeyLogCheckpoint {
    pub body: KeyLogCheckpointBody,
    pub operator_key_id: KeyId,
    pub operator_signature: Signature,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_signatures: Vec<WitnessSignature>,
}

pub struct KeyLogCheckpointExpectation<'a> {
    pub log_id: &'a LogId,
    pub sequence: u64,
    pub tree_size: u64,
    pub root: &'a Hash,
    pub previous_checkpoint_hash: Option<&'a Hash>,
    pub last_issued_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedKeyLogCheckpointWire {
    body: KeyLogCheckpointBody,
    operator_key_id: KeyId,
    operator_signature: Signature,
    #[serde(default, deserialize_with = "deserialize_witness_signatures")]
    witness_signatures: Vec<WitnessSignature>,
}

impl<'de> Deserialize<'de> for SignedKeyLogCheckpoint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SignedKeyLogCheckpointWire::deserialize(deserializer)?;
        if wire
            .witness_signatures
            .array_windows::<2>()
            .any(|pair| pair[0].witness_id >= pair[1].witness_id)
        {
            return Err(serde::de::Error::custom(
                "witness signatures must be unique and sorted by witness identifier",
            ));
        }
        Ok(Self {
            body: wire.body,
            operator_key_id: wire.operator_key_id,
            operator_signature: wire.operator_signature,
            witness_signatures: wire.witness_signatures,
        })
    }
}

fn deserialize_witness_signatures<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<WitnessSignature>, D::Error>
where
    D: Deserializer<'de>,
{
    struct WitnessVisitor;

    impl<'de> Visitor<'de> for WitnessVisitor {
        type Value = Vec<WitnessSignature>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 64 sorted witness signatures")
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_WITNESS_SIGNATURES)
            {
                return Err(serde::de::Error::custom(
                    "witness signature count exceeds 64",
                ));
            }
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_WITNESS_SIGNATURES);
            let mut signatures = Vec::with_capacity(capacity);
            while let Some(signature) = sequence.next_element()? {
                if signatures.len() == MAX_WITNESS_SIGNATURES {
                    return Err(serde::de::Error::custom(
                        "witness signature count exceeds 64",
                    ));
                }
                signatures.push(signature);
            }
            Ok(signatures)
        }
    }

    deserializer.deserialize_seq(WitnessVisitor)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointCommitment<'a> {
    body: &'a KeyLogCheckpointBody,
    operator_key_id: KeyId,
    operator_signature: &'a Signature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WitnessStatement {
    schema: &'static str,
    checkpoint_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyActivationCommitBody {
    pub schema: String,
    pub log_id: LogId,
    pub event_id: crate::EventId,
    pub checkpoint_hash: Hash,
    pub checkpoint_body_hash: Hash,
    pub checkpoint_sequence: u64,
    pub tree_size: u64,
    pub root_hash: Hash,
    pub event_leaf_hash: Hash,
    pub witness_set_hash: Hash,
    #[serde(deserialize_with = "deserialize_witness_signatures")]
    pub witness_signatures: Vec<WitnessSignature>,
    pub committed_at: u64,
    pub signing_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedKeyActivationCommit {
    pub body: KeyActivationCommitBody,
    pub operator_key_id: KeyId,
    pub operator_signature: Signature,
}

impl SignedKeyLogCheckpoint {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        crate::from_bounded_json(bytes)
    }

    pub fn sign(body: KeyLogCheckpointBody, operator: &dyn SigningBackend) -> Result<Self> {
        let outcome = sign_wrapped_value(operator, KEY_LOG_CHECKPOINT_SCHEMA, &body)?;
        let operator_key_id = derive_key_id(outcome.public_key.algorithm(), &outcome.public_key)?;
        Ok(Self {
            body,
            operator_key_id,
            operator_signature: outcome.signature,
            witness_signatures: Vec::new(),
        })
    }

    pub fn canonical_body_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_json_bytes(&self.body)?)
    }

    pub fn checkpoint_hash(&self) -> Result<Hash> {
        let canonical = canonical_json_bytes(&CheckpointCommitment {
            body: &self.body,
            operator_key_id: self.operator_key_id,
            operator_signature: &self.operator_signature,
        })?;
        domain_hash(CHECKPOINT_HASH_DOMAIN, &canonical)
    }

    pub fn checkpoint_body_hash(&self) -> Result<Hash> {
        let canonical = canonical_json_bytes(&self.body)?;
        domain_hash(CHECKPOINT_BODY_HASH_DOMAIN, &canonical)
    }

    pub fn witness_set_hash(&self) -> Result<Hash> {
        let canonical = canonical_json_bytes(&self.witness_signatures)?;
        domain_hash(WITNESS_SET_HASH_DOMAIN, &canonical)
    }

    pub fn verify_operator(&self, operator_key: &PublicKey) -> Result<()> {
        if derive_key_id(operator_key.algorithm(), operator_key)? != self.operator_key_id {
            return Err(KeyringError::AlgorithmMismatch);
        }
        verify_wrapped_value(
            operator_key,
            KEY_LOG_CHECKPOINT_SCHEMA,
            &self.body,
            &self.operator_signature,
        )
    }

    pub fn verify_witnesses(
        &self,
        witness_keys: &BTreeMap<WitnessId, PublicKey>,
    ) -> Result<BTreeSet<WitnessId>> {
        let verified = self.verify_witness_signatures(witness_keys)?;
        let threshold = witness_keys
            .len()
            .checked_div(2)
            .and_then(|half| half.checked_add(1))
            .ok_or(KeyringError::NumericRange)?;
        if verified.len() < threshold {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        Ok(verified)
    }

    pub fn verify_witness_signatures(
        &self,
        witness_keys: &BTreeMap<WitnessId, PublicKey>,
    ) -> Result<BTreeSet<WitnessId>> {
        if witness_keys.is_empty()
            || witness_keys.len() > MAX_WITNESS_SIGNATURES
            || self.witness_signatures.len() > witness_keys.len()
            || self.witness_signatures.len() > MAX_WITNESS_SIGNATURES
        {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        let statement = witness_statement(self)?;
        let mut verified = BTreeSet::new();
        for witness in &self.witness_signatures {
            if !verified.insert(witness.witness_id.clone()) {
                return Err(KeyringError::DuplicateIdentifier);
            }
            let key = witness_keys
                .get(&witness.witness_id)
                .ok_or(KeyringError::InvalidSignature)?;
            verify_wrapped_value(
                key,
                KEY_LOG_WITNESS_STATEMENT_SCHEMA,
                &statement,
                &witness.signature,
            )
            .map_err(|_| KeyringError::InvalidSignature)?;
        }
        Ok(verified)
    }

    pub fn validate(&self, expected: KeyLogCheckpointExpectation<'_>) -> Result<()> {
        if self.body.schema != KEY_LOG_CHECKPOINT_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.body.schema.clone()));
        }
        if &self.body.log_id != expected.log_id {
            return Err(KeyringError::IdentityMismatch);
        }
        if self.body.checkpoint_sequence != expected.sequence {
            return Err(KeyringError::InvalidCheckpoint(
                "checkpoint sequence mismatch",
            ));
        }
        if self.body.tree_size == 0 || self.body.tree_size != expected.tree_size {
            return Err(KeyringError::InvalidCheckpoint("tree size mismatch"));
        }
        if &self.body.root_hash != expected.root {
            return Err(KeyringError::InvalidCheckpoint("root hash mismatch"));
        }
        if self.body.previous_checkpoint_hash.as_ref() != expected.previous_checkpoint_hash {
            return Err(KeyringError::InvalidCheckpoint(
                "checkpoint predecessor mismatch",
            ));
        }
        if expected
            .last_issued_at
            .is_some_and(|last| self.body.issued_at < last)
        {
            return Err(KeyringError::InvalidTimeOrdering);
        }
        Ok(())
    }
}

impl SignedKeyActivationCommit {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        crate::from_bounded_json(bytes)
    }

    pub fn sign(body: KeyActivationCommitBody, operator: &dyn SigningBackend) -> Result<Self> {
        let outcome = sign_wrapped_value(operator, KEY_ACTIVATION_COMMIT_SCHEMA, &body)?;
        let operator_key_id = derive_key_id(outcome.public_key.algorithm(), &outcome.public_key)?;
        Ok(Self {
            body,
            operator_key_id,
            operator_signature: outcome.signature,
        })
    }

    pub fn verify_operator(&self, operator_key: &PublicKey) -> Result<()> {
        if self.body.schema != KEY_ACTIVATION_COMMIT_SCHEMA
            || derive_key_id(operator_key.algorithm(), operator_key)? != self.operator_key_id
            || verify_wrapped_value(
                operator_key,
                KEY_ACTIVATION_COMMIT_SCHEMA,
                &self.body,
                &self.operator_signature,
            )
            .is_err()
        {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_json_bytes(self)?)
    }
}

impl WitnessSignature {
    pub fn sign(
        checkpoint: &SignedKeyLogCheckpoint,
        witness_id: WitnessId,
        witness: &dyn SigningBackend,
    ) -> Result<Self> {
        let outcome = sign_wrapped_value(
            witness,
            KEY_LOG_WITNESS_STATEMENT_SCHEMA,
            &witness_statement(checkpoint)?,
        )?;
        Ok(Self {
            witness_id,
            signature: outcome.signature,
        })
    }

    pub fn verify(
        &self,
        checkpoint: &SignedKeyLogCheckpoint,
        witness_key: &PublicKey,
    ) -> Result<()> {
        verify_wrapped_value(
            witness_key,
            KEY_LOG_WITNESS_STATEMENT_SCHEMA,
            &witness_statement(checkpoint)?,
            &self.signature,
        )
        .map_err(|_| KeyringError::InvalidSignature)
    }
}

fn witness_statement(checkpoint: &SignedKeyLogCheckpoint) -> Result<WitnessStatement> {
    Ok(WitnessStatement {
        schema: KEY_LOG_WITNESS_STATEMENT_SCHEMA,
        checkpoint_hash: checkpoint.checkpoint_hash()?,
    })
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Result<Hash> {
    let capacity = domain
        .len()
        .checked_add(bytes.len())
        .ok_or(KeyringError::NumericRange)?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    Ok(sha256(&input))
}
