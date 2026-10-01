use chio_core_types::{
    canonical_json_bytes, sha256, Hash, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use serde::{Deserialize, Serialize};

use crate::{
    derive_key_id, EventId, KeyId, KeyLogPolicy, KeyringError, LogId, RecoveryAuthorizerId, Result,
    SignedKeyActivationCommit, SignedKeyLogCheckpoint, SignedKeyLogEvent, WitnessRosterId,
    WitnessSignature, MAX_CANONICAL_RECORD_BYTES, MAX_WITNESS_SIGNATURES,
};

pub const KEY_ENTERPRISE_RECEIPT_SCHEMA: &str = "chio.key-log.enterprise-receipt.v1";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"chio.key-log.enterprise-receipt-signature.v1\0";
const TRANSACTION_ID_DOMAIN: &[u8] = b"chio.key-log.enterprise-transaction-id.v1\0";
const RECEIPT_ID_DOMAIN: &[u8] = b"chio.key-log.enterprise-receipt-id.v1\0";
const ACTIVATION_HASH_DOMAIN: &[u8] = b"chio.key-log.activation-envelope.v1\0";
const MAX_RECEIPT_IDENTIFIER_BYTES: usize = 128;
const MAX_SOURCE_RECEIPT_IDS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEnterpriseReceiptStage {
    Pending,
    Active,
}

impl KeyEnterpriseReceiptStage {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEnterpriseReceiptOutcome {
    PendingCommitted,
    Activated,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyEventSignerId {
    Bootstrap { key_id: KeyId },
    OldKey { key_id: KeyId },
    NewKey { key_id: KeyId },
    Recovery { authorizer_id: RecoveryAuthorizerId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEnterpriseReceiptBody {
    pub schema: String,
    pub receipt_id: String,
    pub transaction_id: String,
    pub issued_at: u64,
    pub log_id: LogId,
    pub event_id: EventId,
    pub event_sequence: u64,
    pub event_envelope_hash: Hash,
    pub event_signers: Vec<KeyEventSignerId>,
    pub stage: KeyEnterpriseReceiptStage,
    pub tree_size: u64,
    pub root_hash: Hash,
    pub checkpoint_hash: Hash,
    pub checkpoint_sequence: u64,
    pub operator_key_id: KeyId,
    pub witness_roster_id: WitnessRosterId,
    pub witness_signatures: Vec<WitnessSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_commit_hash: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_receipt_ids: Vec<String>,
    pub outcome: KeyEnterpriseReceiptOutcome,
}

impl KeyEnterpriseReceiptBody {
    pub fn validate(&self) -> Result<()> {
        if self.schema != KEY_ENTERPRISE_RECEIPT_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.schema.clone()));
        }
        validate_receipt_identifier(&self.receipt_id, "key receipt identifier")?;
        validate_receipt_identifier(&self.transaction_id, "key transaction identifier")?;
        if self.issued_at == 0
            || self.tree_size == 0
            || self.tree_size
                != self
                    .event_sequence
                    .checked_add(1)
                    .ok_or(KeyringError::NumericRange)?
            || self.checkpoint_sequence != self.event_sequence
            || self.event_signers.is_empty()
            || self.event_signers.windows(2).any(|pair| pair[0] >= pair[1])
            || self.witness_signatures.len() > MAX_WITNESS_SIGNATURES
            || self
                .witness_signatures
                .windows(2)
                .any(|pair| pair[0].witness_id >= pair[1].witness_id)
        {
            return Err(KeyringError::StateInvariant(
                "key enterprise receipt body is not canonical",
            ));
        }
        validate_source_receipt_ids(&self.source_receipt_ids)?;
        match (self.stage, self.outcome) {
            (KeyEnterpriseReceiptStage::Pending, KeyEnterpriseReceiptOutcome::PendingCommitted) => {
                if !self.witness_signatures.is_empty()
                    || self.activation_commit_hash.is_some()
                    || self.signing_epoch.is_some()
                    || (self.event_sequence == 0) != self.source_receipt_ids.is_empty()
                {
                    return Err(KeyringError::StateInvariant(
                        "pending key receipt carries invalid activation or lineage fields",
                    ));
                }
            }
            (KeyEnterpriseReceiptStage::Active, KeyEnterpriseReceiptOutcome::Activated) => {
                if self.witness_signatures.is_empty()
                    || self.activation_commit_hash.is_none()
                    || self.signing_epoch.is_none_or(|epoch| epoch == 0)
                    || self.source_receipt_ids.len() != 1
                {
                    return Err(KeyringError::StateInvariant(
                        "active key receipt omits witnessed activation evidence",
                    ));
                }
            }
            _ => {
                return Err(KeyringError::StateInvariant(
                    "key receipt stage and outcome disagree",
                ))
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedKeyEnterpriseReceipt {
    pub body: KeyEnterpriseReceiptBody,
    pub operator_key_id: KeyId,
    pub operator_algorithm: SigningAlgorithm,
    pub operator_signature: Signature,
}

impl SignedKeyEnterpriseReceipt {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_RECORD_BYTES {
            return Err(KeyringError::Canonical(
                "key enterprise receipt has invalid canonical byte length".to_string(),
            ));
        }
        let receipt: Self = serde_json::from_slice(bytes)?;
        receipt.body.validate()?;
        if receipt.canonical_bytes()? != bytes {
            return Err(KeyringError::Canonical(
                "key enterprise receipt is not canonical JSON".to_string(),
            ));
        }
        Ok(receipt)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_json_bytes(self)?)
    }

    pub fn verify_operator(&self, operator_key: &PublicKey) -> Result<()> {
        self.body.validate()?;
        if self.operator_key_id != self.body.operator_key_id
            || operator_key.algorithm() != self.operator_algorithm
            || self.operator_signature.algorithm() != self.operator_algorithm
            || derive_key_id(operator_key.algorithm(), operator_key)? != self.operator_key_id
            || !operator_key.verify(
                &domain_canonical_bytes(RECEIPT_SIGNATURE_DOMAIN, &self.body)?,
                &self.operator_signature,
            )
        {
            return Err(KeyringError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_against(
        &self,
        event: &SignedKeyLogEvent,
        checkpoint: &SignedKeyLogCheckpoint,
        policy: &KeyLogPolicy,
        activation: Option<&SignedKeyActivationCommit>,
    ) -> Result<()> {
        self.verify_operator(&policy.operator_key)?;
        checkpoint.verify_operator(&policy.operator_key)?;
        let checkpoint_hash = checkpoint.checkpoint_hash()?;
        let event_signers = event_signers(event);
        if self.body.log_id != event.body.log_id
            || self.body.log_id != checkpoint.body.log_id
            || self.body.log_id != policy.log_id
            || self.body.event_id != event.body.event_id
            || self.body.event_sequence != event.body.sequence
            || self.body.event_envelope_hash != event.envelope_hash()?
            || self.body.event_signers != event_signers
            || self.body.tree_size != checkpoint.body.tree_size
            || self.body.root_hash != checkpoint.body.root_hash
            || self.body.checkpoint_hash != checkpoint_hash
            || self.body.checkpoint_sequence != checkpoint.body.checkpoint_sequence
            || self.body.operator_key_id != checkpoint.operator_key_id
            || self.body.witness_roster_id != policy.witness_roster_id
            || self.body.transaction_id != transaction_id(event)?
            || self.body.receipt_id
                != receipt_id(&self.body.transaction_id, self.body.stage, &checkpoint_hash)?
        {
            return Err(KeyringError::StateInvariant(
                "key enterprise receipt does not bind its event or checkpoint",
            ));
        }
        match (self.body.stage, activation) {
            (KeyEnterpriseReceiptStage::Pending, None) => {
                if self.body.issued_at != checkpoint.body.issued_at
                    || !self.body.witness_signatures.is_empty()
                {
                    return Err(KeyringError::StateInvariant(
                        "pending key receipt does not match checkpoint publication",
                    ));
                }
            }
            (KeyEnterpriseReceiptStage::Active, Some(activation)) => {
                activation.verify_operator(&policy.operator_key)?;
                checkpoint.verify_witnesses(&policy.witness_keys)?;
                if activation.body.event_id != event.body.event_id
                    || activation.body.checkpoint_hash != checkpoint_hash
                    || activation.body.checkpoint_sequence != checkpoint.body.checkpoint_sequence
                    || activation.body.tree_size != checkpoint.body.tree_size
                    || activation.body.root_hash != checkpoint.body.root_hash
                    || activation.body.witness_signatures != checkpoint.witness_signatures
                    || self.body.issued_at != activation.body.committed_at
                    || self.body.witness_signatures != activation.body.witness_signatures
                    || self.body.activation_commit_hash != Some(activation_hash(activation)?)
                    || self.body.signing_epoch != Some(activation.body.signing_epoch)
                {
                    return Err(KeyringError::StateInvariant(
                        "active key receipt does not match witnessed activation",
                    ));
                }
            }
            _ => {
                return Err(KeyringError::StateInvariant(
                    "key receipt stage lacks its required activation artifact",
                ))
            }
        }
        Ok(())
    }

    pub(crate) fn pending(
        event: &SignedKeyLogEvent,
        checkpoint: &SignedKeyLogCheckpoint,
        policy: &KeyLogPolicy,
        source_receipt_ids: Vec<String>,
        operator: &dyn SigningBackend,
    ) -> Result<Self> {
        let transaction_id = transaction_id(event)?;
        let checkpoint_hash = checkpoint.checkpoint_hash()?;
        let body = KeyEnterpriseReceiptBody {
            schema: KEY_ENTERPRISE_RECEIPT_SCHEMA.to_string(),
            receipt_id: receipt_id(
                &transaction_id,
                KeyEnterpriseReceiptStage::Pending,
                &checkpoint_hash,
            )?,
            transaction_id,
            issued_at: checkpoint.body.issued_at,
            log_id: event.body.log_id.clone(),
            event_id: event.body.event_id.clone(),
            event_sequence: event.body.sequence,
            event_envelope_hash: event.envelope_hash()?,
            event_signers: event_signers(event),
            stage: KeyEnterpriseReceiptStage::Pending,
            tree_size: checkpoint.body.tree_size,
            root_hash: checkpoint.body.root_hash,
            checkpoint_hash,
            checkpoint_sequence: checkpoint.body.checkpoint_sequence,
            operator_key_id: checkpoint.operator_key_id,
            witness_roster_id: policy.witness_roster_id.clone(),
            witness_signatures: Vec::new(),
            activation_commit_hash: None,
            signing_epoch: None,
            source_receipt_ids,
            outcome: KeyEnterpriseReceiptOutcome::PendingCommitted,
        };
        let receipt = Self::sign(body, operator)?;
        receipt.verify_against(event, checkpoint, policy, None)?;
        Ok(receipt)
    }

    pub(crate) fn active(
        event: &SignedKeyLogEvent,
        checkpoint: &SignedKeyLogCheckpoint,
        activation: &SignedKeyActivationCommit,
        policy: &KeyLogPolicy,
        source_receipt_ids: Vec<String>,
        operator: &dyn SigningBackend,
    ) -> Result<Self> {
        let transaction_id = transaction_id(event)?;
        let checkpoint_hash = checkpoint.checkpoint_hash()?;
        let body = KeyEnterpriseReceiptBody {
            schema: KEY_ENTERPRISE_RECEIPT_SCHEMA.to_string(),
            receipt_id: receipt_id(
                &transaction_id,
                KeyEnterpriseReceiptStage::Active,
                &checkpoint_hash,
            )?,
            transaction_id,
            issued_at: activation.body.committed_at,
            log_id: event.body.log_id.clone(),
            event_id: event.body.event_id.clone(),
            event_sequence: event.body.sequence,
            event_envelope_hash: event.envelope_hash()?,
            event_signers: event_signers(event),
            stage: KeyEnterpriseReceiptStage::Active,
            tree_size: checkpoint.body.tree_size,
            root_hash: checkpoint.body.root_hash,
            checkpoint_hash,
            checkpoint_sequence: checkpoint.body.checkpoint_sequence,
            operator_key_id: checkpoint.operator_key_id,
            witness_roster_id: policy.witness_roster_id.clone(),
            witness_signatures: checkpoint.witness_signatures.clone(),
            activation_commit_hash: Some(activation_hash(activation)?),
            signing_epoch: Some(activation.body.signing_epoch),
            source_receipt_ids,
            outcome: KeyEnterpriseReceiptOutcome::Activated,
        };
        let receipt = Self::sign(body, operator)?;
        receipt.verify_against(event, checkpoint, policy, Some(activation))?;
        Ok(receipt)
    }

    fn sign(body: KeyEnterpriseReceiptBody, operator: &dyn SigningBackend) -> Result<Self> {
        body.validate()?;
        let outcome = operator
            .sign_bytes_with_identity(&domain_canonical_bytes(RECEIPT_SIGNATURE_DOMAIN, &body)?)?;
        let operator_algorithm = outcome.algorithm;
        let operator_key_id = derive_key_id(operator_algorithm, &outcome.public_key)?;
        if operator_key_id != body.operator_key_id {
            return Err(KeyringError::AlgorithmMismatch);
        }
        let operator_signature = outcome.signature;
        if operator_signature.algorithm() != operator_algorithm {
            return Err(KeyringError::AlgorithmMismatch);
        }
        Ok(Self {
            body,
            operator_key_id,
            operator_algorithm,
            operator_signature,
        })
    }
}

fn event_signers(event: &SignedKeyLogEvent) -> Vec<KeyEventSignerId> {
    let mut signers = Vec::new();
    if let Some(authorization) = &event.authorizations.bootstrap {
        signers.push(KeyEventSignerId::Bootstrap {
            key_id: authorization.key_id,
        });
    }
    if let Some(authorization) = &event.authorizations.old_key {
        signers.push(KeyEventSignerId::OldKey {
            key_id: authorization.key_id,
        });
    }
    if let Some(authorization) = &event.authorizations.new_key {
        signers.push(KeyEventSignerId::NewKey {
            key_id: authorization.key_id,
        });
    }
    signers.extend(event.authorizations.recovery.iter().map(|authorization| {
        KeyEventSignerId::Recovery {
            authorizer_id: authorization.authorizer_id.clone(),
        }
    }));
    signers.sort();
    signers
}

fn transaction_id(event: &SignedKeyLogEvent) -> Result<String> {
    let hash = domain_hash(TRANSACTION_ID_DOMAIN, &event.canonical_envelope_bytes()?)?;
    Ok(format!("key-tx:{}", hash.to_hex()))
}

fn receipt_id(
    transaction_id: &str,
    stage: KeyEnterpriseReceiptStage,
    checkpoint_hash: &Hash,
) -> Result<String> {
    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct ReceiptIdInput<'a> {
        transaction_id: &'a str,
        stage: KeyEnterpriseReceiptStage,
        checkpoint_hash: &'a Hash,
    }
    let canonical = canonical_json_bytes(&ReceiptIdInput {
        transaction_id,
        stage,
        checkpoint_hash,
    })?;
    Ok(format!(
        "key-receipt:{}",
        domain_hash(RECEIPT_ID_DOMAIN, &canonical)?.to_hex()
    ))
}

fn activation_hash(activation: &SignedKeyActivationCommit) -> Result<Hash> {
    domain_hash(ACTIVATION_HASH_DOMAIN, &activation.canonical_bytes()?)
}

fn validate_receipt_identifier(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_RECEIPT_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(KeyringError::InvalidIdentifier {
            kind,
            reason: "value is empty, oversized, or contains an unsupported character",
        });
    }
    Ok(())
}

fn validate_source_receipt_ids(ids: &[String]) -> Result<()> {
    if ids.len() > MAX_SOURCE_RECEIPT_IDS
        || ids
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(KeyringError::StateInvariant(
            "key receipt source lineage is oversized or noncanonical",
        ));
    }
    for id in ids {
        validate_receipt_identifier(id, "source key receipt identifier")?;
    }
    Ok(())
}

fn domain_canonical_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(value)?;
    let capacity = domain
        .len()
        .checked_add(canonical.len())
        .ok_or(KeyringError::NumericRange)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
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
