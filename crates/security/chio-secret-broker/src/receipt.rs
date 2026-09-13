use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_core_types::{
    canonical_json_bytes, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budget::{canonicalize_quotas, ExecutionQuota};
use crate::protocol::{
    BrokerDestination, BrokerExecuteResponse, BrokerExecutionEvidence, CredentialRef,
    MAX_HEADER_COUNT, MAX_RESPONSE_BYTES,
};
use crate::sqlite::DurableBrokerDatabaseFile;
use crate::{validate_identifier, BrokerError, Result};

pub const BROKER_RECEIPT_SCHEMA: &str = "chio.broker-execution-receipt.v1";
pub const BROKER_FAILURE_RECEIPT_SCHEMA: &str = "chio.broker-execution-failure-receipt.v1";
const RECEIPT_DOMAIN: &str = "chio.broker-execution-receipt-signature.v1\0";
const FAILURE_RECEIPT_DOMAIN: &str = "chio.broker-execution-failure-receipt-signature.v1\0";
const CREDENTIAL_REFERENCE_DOMAIN: &[u8] = b"chio.broker-credential-reference.v1\0";
const MAX_SOURCE_RECEIPT_IDS: usize = 64;
const MAX_DURABLE_COMPLETED_RESPONSE_BYTES: usize = 16 * 1_048_576;

type StoredCompletedResponseRow = (Vec<u8>, Option<String>, Option<Vec<u8>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerExecutionOutcome {
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerFailureStage {
    Admission,
    Hold,
    Capture,
    Dispatch,
    Response,
    ReceiptPersistence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerFailureOutcome {
    Denied,
    Reversed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerDispatchKnowledge {
    NotStarted,
    NotCommitted,
    Committed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerFailureReceiptBody {
    pub schema: String,
    pub receipt_id: String,
    pub issued_at_unix_seconds: u64,
    pub stage: BrokerFailureStage,
    pub outcome: BrokerFailureOutcome,
    pub diagnostic_code: String,
    pub request_digest: String,
    pub capability_digest: Option<String>,
    pub attempt_id: Option<String>,
    pub invocation_id: Option<String>,
    pub hold_id: Option<String>,
    pub parent_capability_id: Option<String>,
    pub broker_capability_id: Option<String>,
    pub dispatch_knowledge: BrokerDispatchKnowledge,
}

impl BrokerFailureReceiptBody {
    pub fn validate(&self) -> Result<()> {
        if self.schema != BROKER_FAILURE_RECEIPT_SCHEMA || self.issued_at_unix_seconds == 0 {
            return Err(BrokerError::InvalidRequest(
                "broker failure receipt schema or issue time is invalid".to_string(),
            ));
        }
        validate_identifier(&self.receipt_id, "failure receipt id", 512)?;
        if self.diagnostic_code.len() > 128
            || !self.diagnostic_code.starts_with("chio.")
            || !self.diagnostic_code.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(BrokerError::InvalidRequest(
                "broker failure receipt diagnostic code is invalid".to_string(),
            ));
        }
        crate::validate_digest(&self.request_digest, "failure receipt request digest")?;
        if let Some(digest) = &self.capability_digest {
            crate::validate_digest(digest, "failure receipt capability digest")?;
        }
        let binding = [
            self.attempt_id.as_deref(),
            self.invocation_id.as_deref(),
            self.hold_id.as_deref(),
            self.parent_capability_id.as_deref(),
            self.broker_capability_id.as_deref(),
        ];
        let present = binding.iter().filter(|value| value.is_some()).count();
        if present != 0 && present != binding.len() {
            return Err(BrokerError::InvalidRequest(
                "broker failure receipt attempt binding is incomplete".to_string(),
            ));
        }
        for value in binding.into_iter().flatten() {
            validate_identifier(value, "failure receipt attempt binding", 512)?;
        }
        if present == 0 && self.dispatch_knowledge != BrokerDispatchKnowledge::NotStarted {
            return Err(BrokerError::InvalidRequest(
                "broker failure receipt without an attempt must deny before dispatch".to_string(),
            ));
        }
        let stage_is_truthful = match self.stage {
            BrokerFailureStage::Admission => {
                self.dispatch_knowledge == BrokerDispatchKnowledge::NotStarted
            }
            BrokerFailureStage::Hold => matches!(
                self.dispatch_knowledge,
                BrokerDispatchKnowledge::NotStarted | BrokerDispatchKnowledge::NotCommitted
            ),
            BrokerFailureStage::Capture => matches!(
                self.dispatch_knowledge,
                BrokerDispatchKnowledge::NotCommitted | BrokerDispatchKnowledge::Unknown
            ),
            BrokerFailureStage::Dispatch
            | BrokerFailureStage::Response
            | BrokerFailureStage::ReceiptPersistence => matches!(
                self.dispatch_knowledge,
                BrokerDispatchKnowledge::Committed | BrokerDispatchKnowledge::Unknown
            ),
        };
        let outcome_is_truthful = match self.outcome {
            BrokerFailureOutcome::Denied => matches!(
                self.dispatch_knowledge,
                BrokerDispatchKnowledge::NotStarted | BrokerDispatchKnowledge::NotCommitted
            ),
            BrokerFailureOutcome::Reversed => {
                self.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
            }
            BrokerFailureOutcome::Failed => {
                self.dispatch_knowledge != BrokerDispatchKnowledge::Unknown
            }
            BrokerFailureOutcome::Unknown => {
                self.dispatch_knowledge == BrokerDispatchKnowledge::Unknown
            }
        };
        if !stage_is_truthful || !outcome_is_truthful {
            return Err(BrokerError::InvalidRequest(
                "broker failure receipt stage, outcome, or dispatch state is inconsistent"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerReceiptBody {
    pub schema: String,
    pub receipt_id: String,
    pub issued_at_unix_seconds: u64,
    pub evidence: BrokerExecutionEvidence,
    pub operation_id: String,
    pub authorize_event_id: String,
    pub capture_event_id: String,
    pub parent_capability_id: String,
    pub broker_capability_id: String,
    pub subject: PublicKey,
    pub credential_reference_hash: String,
    pub credential_version: u64,
    pub normalized_destination: BrokerDestination,
    pub request_body_sha256: String,
    pub caller_headers_sha256: String,
    pub caller_options_sha256: String,
    pub quotas: Vec<ExecutionQuota>,
    pub broker_quota_key_id: String,
    pub provider_adapter_id: String,
    pub provider_adapter_version: u32,
    pub request_body_bytes: u64,
    pub response_body_bytes: u64,
    pub source_receipt_ids: Vec<String>,
    pub outcome: BrokerExecutionOutcome,
}

impl BrokerReceiptBody {
    pub fn validate(&self) -> Result<()> {
        if self.schema != BROKER_RECEIPT_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "unsupported broker receipt schema".to_string(),
            ));
        }
        for (value, label) in [
            (&self.receipt_id, "receipt id"),
            (&self.operation_id, "receipt operation id"),
            (&self.authorize_event_id, "receipt authorize event id"),
            (&self.capture_event_id, "receipt capture event id"),
            (&self.parent_capability_id, "receipt parent capability id"),
            (&self.broker_capability_id, "receipt broker capability id"),
            (&self.broker_quota_key_id, "receipt broker quota key id"),
            (&self.provider_adapter_id, "receipt provider adapter id"),
        ] {
            validate_identifier(value, label, 512)?;
        }
        if self.issued_at_unix_seconds == 0
            || self.credential_version == 0
            || self.provider_adapter_version == 0
            || self.outcome != BrokerExecutionOutcome::Completed
        {
            return Err(BrokerError::InvalidRequest(
                "broker receipt time, version, or outcome is invalid".to_string(),
            ));
        }
        for (digest, label) in [
            (
                &self.credential_reference_hash,
                "receipt credential reference hash",
            ),
            (&self.request_body_sha256, "receipt request body digest"),
            (&self.caller_headers_sha256, "receipt caller header digest"),
            (&self.caller_options_sha256, "receipt caller option digest"),
        ] {
            crate::validate_digest(digest, label)?;
        }
        self.normalized_destination.validate(true)?;
        if canonicalize_quotas(self.quotas.clone())? != self.quotas
            || !self
                .quotas
                .iter()
                .any(|quota| quota.key_id == self.broker_quota_key_id)
        {
            return Err(BrokerError::InvalidRequest(
                "broker receipt quota set is not canonical or omits the broker quota".to_string(),
            ));
        }
        validate_source_receipt_ids(&self.source_receipt_ids)?;
        self.evidence.validate()?;
        if self.evidence.revocation_set_digest.is_empty()
            || self.evidence.response_body_sha256.is_empty()
        {
            return Err(BrokerError::InvalidRequest(
                "broker receipt omits capture or response evidence".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn credential_reference_hash(credential: &CredentialRef) -> Result<String> {
    credential.validate()?;
    let canonical = canonical_json_bytes(credential).map_err(|error| {
        BrokerError::Invariant(format!("credential reference encoding failed: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_REFERENCE_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn validate_source_receipt_ids(ids: &[String]) -> Result<()> {
    if ids.len() > MAX_SOURCE_RECEIPT_IDS
        || ids
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(BrokerError::InvalidRequest(
            "source receipt lineage must be bounded, sorted, and unique".to_string(),
        ));
    }
    for id in ids {
        validate_identifier(id, "source receipt id", 512)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedBrokerReceipt {
    pub body: BrokerReceiptBody,
    pub signer: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedBrokerFailureReceipt {
    pub body: BrokerFailureReceiptBody,
    pub signer: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptSigningInput<'a> {
    domain: &'static str,
    body: &'a BrokerReceiptBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FailureReceiptSigningInput<'a> {
    domain: &'static str,
    body: &'a BrokerFailureReceiptBody,
}

pub fn sign_execution_receipt(
    body: BrokerReceiptBody,
    signer: &dyn SigningBackend,
) -> Result<SignedBrokerReceipt> {
    body.validate()?;
    let input = ReceiptSigningInput {
        domain: RECEIPT_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::Invariant(format!("receipt signing input encoding failed: {error}"))
    })?;
    let signed = signer
        .sign_bytes_with_identity(&canonical)
        .map_err(|error| BrokerError::Invariant(format!("receipt signing failed: {error}")))?;
    if signed.public_key.algorithm() != signed.algorithm
        || signed.signature.algorithm() != signed.algorithm
        || !signed.public_key.verify(&canonical, &signed.signature)
    {
        return Err(BrokerError::Invariant(
            "receipt signing backend returned a mismatched identity or signature".to_string(),
        ));
    }
    Ok(SignedBrokerReceipt {
        body,
        signer: signed.public_key,
        algorithm: signed.algorithm,
        signature: signed.signature,
    })
}

pub fn verify_execution_receipt(
    receipt: &SignedBrokerReceipt,
    trusted_signer: &PublicKey,
) -> Result<()> {
    if receipt.body.schema != BROKER_RECEIPT_SCHEMA
        || &receipt.signer != trusted_signer
        || receipt.signer.algorithm() != receipt.algorithm
        || receipt.signature.algorithm() != receipt.algorithm
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker receipt schema, signer, or algorithm is invalid".to_string(),
        ));
    }
    receipt.body.validate().map_err(|error| {
        BrokerError::AuthorizationDenied(format!("broker receipt body is invalid: {error}"))
    })?;
    let input = ReceiptSigningInput {
        domain: RECEIPT_DOMAIN,
        body: &receipt.body,
    };
    if !receipt
        .signer
        .verify_canonical(&input, &receipt.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!("receipt verification failed: {error}"))
        })?
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker receipt signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub fn sign_failure_receipt(
    body: BrokerFailureReceiptBody,
    signer: &dyn SigningBackend,
) -> Result<SignedBrokerFailureReceipt> {
    body.validate()?;
    let input = FailureReceiptSigningInput {
        domain: FAILURE_RECEIPT_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::Invariant(format!(
            "failure receipt signing input encoding failed: {error}"
        ))
    })?;
    let signed = signer
        .sign_bytes_with_identity(&canonical)
        .map_err(|error| {
            BrokerError::Invariant(format!("failure receipt signing failed: {error}"))
        })?;
    if signed.public_key.algorithm() != signed.algorithm
        || signed.signature.algorithm() != signed.algorithm
        || !signed.public_key.verify(&canonical, &signed.signature)
    {
        return Err(BrokerError::Invariant(
            "failure receipt signing backend returned a mismatched identity or signature"
                .to_string(),
        ));
    }
    Ok(SignedBrokerFailureReceipt {
        body,
        signer: signed.public_key,
        algorithm: signed.algorithm,
        signature: signed.signature,
    })
}

pub fn verify_failure_receipt(
    receipt: &SignedBrokerFailureReceipt,
    trusted_signer: &PublicKey,
) -> Result<()> {
    if receipt.body.schema != BROKER_FAILURE_RECEIPT_SCHEMA
        || &receipt.signer != trusted_signer
        || receipt.signer.algorithm() != receipt.algorithm
        || receipt.signature.algorithm() != receipt.algorithm
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker failure receipt schema, signer, or algorithm is invalid".to_string(),
        ));
    }
    receipt.body.validate().map_err(|error| {
        BrokerError::AuthorizationDenied(format!("broker failure receipt body is invalid: {error}"))
    })?;
    let input = FailureReceiptSigningInput {
        domain: FAILURE_RECEIPT_DOMAIN,
        body: &receipt.body,
    };
    if !receipt
        .signer
        .verify_canonical(&input, &receipt.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "failure receipt verification failed: {error}"
            ))
        })?
    {
        return Err(BrokerError::AuthorizationDenied(
            "broker failure receipt signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub fn receipt_digest(receipt: &SignedBrokerReceipt) -> Result<String> {
    let canonical = canonical_json_bytes(receipt)
        .map_err(|error| BrokerError::Invariant(format!("receipt digest failed: {error}")))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

pub fn failure_receipt_digest(receipt: &SignedBrokerFailureReceipt) -> Result<String> {
    let canonical = canonical_json_bytes(receipt).map_err(|error| {
        BrokerError::Invariant(format!("failure receipt digest failed: {error}"))
    })?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

pub trait BrokerReceiptSink: Send + Sync {
    fn persist(&self, receipt: &SignedBrokerReceipt) -> Result<String>;

    fn persist_completed(&self, _response: &BrokerExecuteResponse) -> Result<String> {
        Err(BrokerError::AuthorityUnavailable(
            "broker receipt sink does not support durable completed responses".to_string(),
        ))
    }

    fn load_completed(&self, _attempt_id: &str) -> Result<Option<BrokerExecuteResponse>> {
        Err(BrokerError::AuthorityUnavailable(
            "broker receipt sink does not support durable completed-response replay".to_string(),
        ))
    }

    fn persist_failure(&self, _receipt: &SignedBrokerFailureReceipt) -> Result<String> {
        Err(BrokerError::AuthorityUnavailable(
            "broker receipt sink does not support failure receipts".to_string(),
        ))
    }

    fn load_failure(&self, _receipt_id: &str) -> Result<Option<SignedBrokerFailureReceipt>> {
        Err(BrokerError::AuthorityUnavailable(
            "broker receipt sink does not support durable failure-receipt replay".to_string(),
        ))
    }

    fn supports_failure_receipts(&self) -> bool {
        false
    }

    fn supports_completed_replay(&self) -> bool {
        false
    }
}

pub struct SqliteBrokerReceiptSink {
    connection: Mutex<Connection>,
    trusted_signer: PublicKey,
    durable_file: DurableBrokerDatabaseFile,
}

impl SqliteBrokerReceiptSink {
    pub fn open(path: impl AsRef<Path>, trusted_signer: PublicKey) -> Result<Self> {
        let path = path.as_ref();
        let durable_file = DurableBrokerDatabaseFile::open(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(receipt_storage)?;
        durable_file.validate()?;
        let sink = Self {
            connection: Mutex::new(connection),
            trusted_signer,
            durable_file,
        };
        sink.migrate()?;
        sink.durable_file.validate()?;
        Ok(sink)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        let connection = self.connection.lock().map_err(|_| {
            BrokerError::Storage("broker receipt store lock is poisoned".to_string())
        })?;
        self.durable_file.validate()?;
        Ok(connection)
    }

    fn migrate(&self) -> Result<()> {
        let connection = self.connection()?;
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                PRAGMA foreign_keys = ON;
                PRAGMA trusted_schema = OFF;

                CREATE TABLE IF NOT EXISTS broker_execution_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    receipt_reference TEXT NOT NULL UNIQUE,
                    attempt_id TEXT NOT NULL UNIQUE,
                    issued_at INTEGER NOT NULL CHECK(issued_at > 0),
                    canonical_receipt BLOB NOT NULL
                ) STRICT;

                CREATE TRIGGER IF NOT EXISTS broker_execution_receipts_no_update
                BEFORE UPDATE ON broker_execution_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'broker execution receipts are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_execution_receipts_no_delete
                BEFORE DELETE ON broker_execution_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'broker execution receipts are append-only');
                END;

                CREATE TABLE IF NOT EXISTS broker_failure_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    receipt_reference TEXT NOT NULL UNIQUE,
                    attempt_id TEXT,
                    issued_at INTEGER NOT NULL CHECK(issued_at > 0),
                    canonical_receipt BLOB NOT NULL
                ) STRICT;

                DROP INDEX IF EXISTS broker_failure_receipts_attempt;

                DROP INDEX IF EXISTS broker_failure_receipts_attempt_events;

                CREATE UNIQUE INDEX IF NOT EXISTS broker_failure_receipts_attempt_terminal
                    ON broker_failure_receipts(attempt_id)
                    WHERE attempt_id IS NOT NULL;

                CREATE TABLE IF NOT EXISTS broker_completed_responses (
                    attempt_id TEXT PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE,
                    canonical_response BLOB NOT NULL
                        CHECK(length(canonical_response) > 0
                            AND length(canonical_response) <= 16777216),
                    FOREIGN KEY (receipt_id) REFERENCES broker_execution_receipts(receipt_id)
                        ON DELETE RESTRICT
                ) STRICT;

                CREATE TRIGGER IF NOT EXISTS broker_execution_receipts_no_failure_terminal
                BEFORE INSERT ON broker_execution_receipts
                WHEN EXISTS (
                    SELECT 1 FROM broker_failure_receipts
                    WHERE attempt_id = NEW.attempt_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'broker attempt already has a failure terminal');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_failure_receipts_no_success_terminal
                BEFORE INSERT ON broker_failure_receipts
                WHEN NEW.attempt_id IS NOT NULL AND EXISTS (
                    SELECT 1 FROM broker_execution_receipts
                    WHERE attempt_id = NEW.attempt_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'broker attempt already has a success terminal');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_failure_receipts_no_update
                BEFORE UPDATE ON broker_failure_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'broker failure receipts are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_failure_receipts_no_delete
                BEFORE DELETE ON broker_failure_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'broker failure receipts are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_completed_responses_no_update
                BEFORE UPDATE ON broker_completed_responses
                BEGIN
                    SELECT RAISE(ABORT, 'broker completed responses are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_completed_responses_no_delete
                BEFORE DELETE ON broker_completed_responses
                BEGIN
                    SELECT RAISE(ABORT, 'broker completed responses are append-only');
                END;
                "#,
            )
            .map_err(receipt_storage)?;
        let conflicting_terminals: i64 = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM broker_execution_receipts AS success
                INNER JOIN broker_failure_receipts AS failure
                    ON failure.attempt_id = success.attempt_id
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(receipt_storage)?;
        if conflicting_terminals != 0 {
            return Err(BrokerError::Storage(
                "broker receipt store contains conflicting success and failure terminals"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn load(&self, receipt_id: &str) -> Result<Option<SignedBrokerReceipt>> {
        validate_identifier(receipt_id, "receipt id", 512)?;
        let canonical: Option<Vec<u8>> = self
            .connection()?
            .query_row(
                "SELECT canonical_receipt FROM broker_execution_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(receipt_storage)?;
        canonical
            .map(|bytes| self.decode_stored_receipt(&bytes))
            .transpose()
    }

    fn decode_stored_receipt(&self, canonical: &[u8]) -> Result<SignedBrokerReceipt> {
        let receipt: SignedBrokerReceipt = serde_json::from_slice(canonical).map_err(|error| {
            BrokerError::Storage(format!("persisted broker receipt decoding failed: {error}"))
        })?;
        let reencoded = canonical_json_bytes(&receipt).map_err(|error| {
            BrokerError::Storage(format!("persisted broker receipt encoding failed: {error}"))
        })?;
        if reencoded != canonical {
            return Err(BrokerError::Storage(
                "persisted broker receipt is not canonical JSON".to_string(),
            ));
        }
        verify_execution_receipt(&receipt, &self.trusted_signer)?;
        Ok(receipt)
    }

    pub fn load_failure(&self, receipt_id: &str) -> Result<Option<SignedBrokerFailureReceipt>> {
        validate_identifier(receipt_id, "failure receipt id", 512)?;
        let canonical: Option<Vec<u8>> = self
            .connection()?
            .query_row(
                "SELECT canonical_receipt FROM broker_failure_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(receipt_storage)?;
        canonical
            .map(|bytes| self.decode_stored_failure_receipt(&bytes))
            .transpose()
    }

    fn decode_stored_failure_receipt(
        &self,
        canonical: &[u8],
    ) -> Result<SignedBrokerFailureReceipt> {
        let receipt: SignedBrokerFailureReceipt =
            serde_json::from_slice(canonical).map_err(|error| {
                BrokerError::Storage(format!(
                    "persisted broker failure receipt decoding failed: {error}"
                ))
            })?;
        let reencoded = canonical_json_bytes(&receipt).map_err(|error| {
            BrokerError::Storage(format!(
                "persisted broker failure receipt encoding failed: {error}"
            ))
        })?;
        if reencoded != canonical {
            return Err(BrokerError::Storage(
                "persisted broker failure receipt is not canonical JSON".to_string(),
            ));
        }
        verify_failure_receipt(&receipt, &self.trusted_signer)?;
        Ok(receipt)
    }
}

impl BrokerReceiptSink for SqliteBrokerReceiptSink {
    fn persist(&self, receipt: &SignedBrokerReceipt) -> Result<String> {
        verify_execution_receipt(receipt, &self.trusted_signer)?;
        let canonical = canonical_json_bytes(receipt).map_err(|error| {
            BrokerError::Invariant(format!(
                "broker receipt persistence encoding failed: {error}"
            ))
        })?;
        let digest = receipt_digest(receipt)?;
        let reference = format!("broker-receipt-sha256-{digest}");
        validate_identifier(&reference, "receipt reference", 512)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(receipt_storage)?;
        let existing: Option<(String, String, Vec<u8>)> = transaction
            .query_row(
                r#"
                SELECT receipt_digest, receipt_reference, canonical_receipt
                FROM broker_execution_receipts
                WHERE receipt_id = ?1
                "#,
                params![receipt.body.receipt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(receipt_storage)?;
        if let Some((stored_digest, stored_reference, stored_canonical)) = existing {
            if stored_digest != digest
                || stored_reference != reference
                || stored_canonical != canonical
            {
                return Err(BrokerError::Conflict(
                    "broker receipt ID was reused with different canonical content".to_string(),
                ));
            }
            transaction.commit().map_err(receipt_storage)?;
            return Ok(reference);
        }
        transaction
            .execute(
                r#"
                INSERT INTO broker_execution_receipts (
                    receipt_id, receipt_digest, receipt_reference, attempt_id,
                    issued_at, canonical_receipt
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    receipt.body.receipt_id,
                    digest,
                    reference,
                    receipt.body.evidence.attempt_id,
                    sqlite_u64(receipt.body.issued_at_unix_seconds, "receipt issue time")?,
                    canonical,
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(failure, _)
                    if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    BrokerError::Conflict(
                        "broker receipt conflicts with an existing append-only record".to_string(),
                    )
                }
                other => receipt_storage(other),
            })?;
        transaction.commit().map_err(receipt_storage)?;
        Ok(reference)
    }

    fn persist_completed(&self, response: &BrokerExecuteResponse) -> Result<String> {
        validate_durable_completed_response(response, &self.trusted_signer)?;
        let canonical_response = canonical_json_bytes(response).map_err(|error| {
            BrokerError::Invariant(format!(
                "completed broker response persistence encoding failed: {error}"
            ))
        })?;
        if canonical_response.is_empty()
            || canonical_response.len() > MAX_DURABLE_COMPLETED_RESPONSE_BYTES
        {
            return Err(BrokerError::ResponseRejected(
                "completed broker response exceeds the durable replay bound".to_string(),
            ));
        }
        let receipt = &response.receipt;
        let canonical_receipt = canonical_json_bytes(receipt).map_err(|error| {
            BrokerError::Invariant(format!(
                "broker receipt persistence encoding failed: {error}"
            ))
        })?;
        let digest = receipt_digest(receipt)?;
        let reference = format!("broker-receipt-sha256-{digest}");
        if response.receipt_reference != reference {
            return Err(BrokerError::Invariant(
                "completed broker response has an unbound receipt reference".to_string(),
            ));
        }
        let attempt_id = &response.evidence.attempt_id;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(receipt_storage)?;
        let existing_receipt: Option<(String, String, String, Vec<u8>)> = transaction
            .query_row(
                r#"
                SELECT receipt_digest, receipt_reference, attempt_id, canonical_receipt
                FROM broker_execution_receipts
                WHERE receipt_id = ?1
                "#,
                params![receipt.body.receipt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(receipt_storage)?;
        if let Some((stored_digest, stored_reference, stored_attempt_id, stored_canonical)) =
            existing_receipt
        {
            if stored_digest != digest
                || stored_reference != reference
                || stored_attempt_id != *attempt_id
                || stored_canonical != canonical_receipt
            {
                return Err(BrokerError::Conflict(
                    "broker receipt ID was reused with different canonical content".to_string(),
                ));
            }
        } else {
            transaction
                .execute(
                    r#"
                    INSERT INTO broker_execution_receipts (
                        receipt_id, receipt_digest, receipt_reference, attempt_id,
                        issued_at, canonical_receipt
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                    params![
                        receipt.body.receipt_id,
                        digest,
                        reference,
                        attempt_id,
                        sqlite_u64(receipt.body.issued_at_unix_seconds, "receipt issue time")?,
                        canonical_receipt,
                    ],
                )
                .map_err(terminal_constraint_or_storage)?;
        }
        let existing_response: Option<(String, Vec<u8>)> = transaction
            .query_row(
                r#"
                SELECT receipt_id, canonical_response
                FROM broker_completed_responses
                WHERE attempt_id = ?1
                "#,
                params![attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(receipt_storage)?;
        if let Some((stored_receipt_id, stored_canonical)) = existing_response {
            if stored_receipt_id != receipt.body.receipt_id
                || stored_canonical != canonical_response
            {
                return Err(BrokerError::Conflict(
                    "broker attempt already has a different completed response".to_string(),
                ));
            }
        } else {
            transaction
                .execute(
                    r#"
                    INSERT INTO broker_completed_responses (
                        attempt_id, receipt_id, canonical_response
                    ) VALUES (?1, ?2, ?3)
                    "#,
                    params![attempt_id, receipt.body.receipt_id, canonical_response],
                )
                .map_err(terminal_constraint_or_storage)?;
        }
        transaction.commit().map_err(receipt_storage)?;
        Ok(reference)
    }

    fn load_completed(&self, attempt_id: &str) -> Result<Option<BrokerExecuteResponse>> {
        validate_identifier(attempt_id, "completed response attempt id", 512)?;
        let stored: Option<StoredCompletedResponseRow> = self
            .connection()?
            .query_row(
                r#"
                SELECT success.canonical_receipt,
                       completed.receipt_id,
                       completed.canonical_response
                FROM broker_execution_receipts AS success
                LEFT JOIN broker_completed_responses AS completed
                    ON completed.attempt_id = success.attempt_id
                WHERE success.attempt_id = ?1
                "#,
                params![attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(receipt_storage)?;
        let Some((canonical_receipt, stored_receipt_id, canonical_response)) = stored else {
            return Ok(None);
        };
        let stored_receipt_id = stored_receipt_id.ok_or_else(|| {
            BrokerError::Storage(
                "completed broker receipt lacks its durable replay response".to_string(),
            )
        })?;
        let canonical_response = canonical_response.ok_or_else(|| {
            BrokerError::Storage(
                "completed broker receipt lacks its durable replay bytes".to_string(),
            )
        })?;
        if canonical_response.is_empty()
            || canonical_response.len() > MAX_DURABLE_COMPLETED_RESPONSE_BYTES
        {
            return Err(BrokerError::Storage(
                "durable completed broker response is empty or oversized".to_string(),
            ));
        }
        let receipt = self.decode_stored_receipt(&canonical_receipt)?;
        let response: BrokerExecuteResponse =
            serde_json::from_slice(&canonical_response).map_err(|error| {
                BrokerError::Storage(format!(
                    "durable completed broker response decoding failed: {error}"
                ))
            })?;
        let recanonical = canonical_json_bytes(&response).map_err(|error| {
            BrokerError::Storage(format!(
                "durable completed broker response encoding failed: {error}"
            ))
        })?;
        if recanonical != canonical_response
            || response.receipt != receipt
            || response.receipt.body.receipt_id != stored_receipt_id
            || response.evidence.attempt_id != attempt_id
        {
            return Err(BrokerError::Storage(
                "durable completed broker response is noncanonical or misbound".to_string(),
            ));
        }
        validate_durable_completed_response(&response, &self.trusted_signer)?;
        Ok(Some(response))
    }

    fn persist_failure(&self, receipt: &SignedBrokerFailureReceipt) -> Result<String> {
        verify_failure_receipt(receipt, &self.trusted_signer)?;
        let canonical = canonical_json_bytes(receipt).map_err(|error| {
            BrokerError::Invariant(format!(
                "broker failure receipt persistence encoding failed: {error}"
            ))
        })?;
        let digest = failure_receipt_digest(receipt)?;
        let reference = format!("broker-failure-receipt-sha256-{digest}");
        validate_identifier(&reference, "failure receipt reference", 512)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(receipt_storage)?;
        let existing: Option<(String, String, Vec<u8>)> = transaction
            .query_row(
                r#"
                SELECT receipt_digest, receipt_reference, canonical_receipt
                FROM broker_failure_receipts
                WHERE receipt_id = ?1
                "#,
                params![receipt.body.receipt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(receipt_storage)?;
        if let Some((stored_digest, stored_reference, stored_canonical)) = existing {
            if stored_digest != digest
                || stored_reference != reference
                || stored_canonical != canonical
            {
                return Err(BrokerError::Conflict(
                    "broker failure receipt ID was reused with different canonical content"
                        .to_string(),
                ));
            }
            transaction.commit().map_err(receipt_storage)?;
            return Ok(reference);
        }
        transaction
            .execute(
                r#"
                INSERT INTO broker_failure_receipts (
                    receipt_id, receipt_digest, receipt_reference, attempt_id,
                    issued_at, canonical_receipt
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    receipt.body.receipt_id,
                    digest,
                    reference,
                    receipt.body.attempt_id,
                    sqlite_u64(
                        receipt.body.issued_at_unix_seconds,
                        "failure receipt issue time"
                    )?,
                    canonical,
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(failure, _)
                    if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    BrokerError::Conflict(
                        "broker failure receipt conflicts with an existing append-only record"
                            .to_string(),
                    )
                }
                other => receipt_storage(other),
            })?;
        transaction.commit().map_err(receipt_storage)?;
        Ok(reference)
    }

    fn load_failure(&self, receipt_id: &str) -> Result<Option<SignedBrokerFailureReceipt>> {
        SqliteBrokerReceiptSink::load_failure(self, receipt_id)
    }

    fn supports_failure_receipts(&self) -> bool {
        true
    }

    fn supports_completed_replay(&self) -> bool {
        true
    }
}

pub(crate) fn validate_durable_completed_response(
    response: &BrokerExecuteResponse,
    trusted_signer: &PublicKey,
) -> Result<()> {
    response.evidence.validate()?;
    verify_execution_receipt(&response.receipt, trusted_signer)?;
    let expected_reference = format!(
        "broker-receipt-sha256-{}",
        receipt_digest(&response.receipt)?
    );
    let response_body_bytes = u64::try_from(response.body.len()).map_err(|_| {
        BrokerError::ResponseRejected("completed broker response length overflowed".to_string())
    })?;
    if response.status != response.evidence.upstream_status
        || response.receipt_reference != expected_reference
        || response.receipt.body.evidence != response.evidence
        || response.receipt.body.response_body_bytes != response_body_bytes
        || response.evidence.response_body_sha256
            != crate::generic_https::response_digest(&response.body)
        || response.body.len() > MAX_RESPONSE_BYTES
        || response.headers.len() > MAX_HEADER_COUNT
    {
        return Err(BrokerError::ResponseRejected(
            "completed broker response is malformed or misbound".to_string(),
        ));
    }
    let mut previous: Option<&str> = None;
    for header in &response.headers {
        if crate::protocol::HeaderField::normalized(&header.name, &header.value)? != *header
            || previous.is_some_and(|name| name >= header.name.as_str())
        {
            return Err(BrokerError::ResponseRejected(
                "completed broker response headers are not normalized and unique".to_string(),
            ));
        }
        previous = Some(&header.name);
    }
    Ok(())
}

fn sqlite_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| BrokerError::Storage(format!("{label} exceeds SQLite INTEGER")))
}

fn receipt_storage(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("broker receipt store failed: {error}"))
}

fn terminal_constraint_or_storage(error: rusqlite::Error) -> BrokerError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            BrokerError::Conflict(
                "broker attempt already has different append-only terminal evidence".to_string(),
            )
        }
        other => receipt_storage(other),
    }
}

#[cfg(test)]
mod tests {
    use chio_core_types::{
        Ed25519Backend, Error, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
        SigningOutcome,
    };
    use chio_test_support::prelude::*;

    use super::*;

    fn failure_body(
        receipt_id: &str,
        diagnostic_code: &str,
        issued_at: u64,
    ) -> BrokerFailureReceiptBody {
        BrokerFailureReceiptBody {
            schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
            receipt_id: receipt_id.to_string(),
            issued_at_unix_seconds: issued_at,
            stage: BrokerFailureStage::Hold,
            outcome: BrokerFailureOutcome::Failed,
            diagnostic_code: diagnostic_code.to_string(),
            request_digest: "aa".repeat(32),
            capability_digest: Some("bb".repeat(32)),
            attempt_id: Some("broker-attempt-retry".to_string()),
            invocation_id: Some("broker-invocation-retry".to_string()),
            hold_id: Some("broker-hold-retry".to_string()),
            parent_capability_id: Some("parent-capability-retry".to_string()),
            broker_capability_id: Some("broker-capability-retry".to_string()),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        }
    }

    struct AtomicOnlyBackend {
        keypair: Keypair,
    }

    impl SigningBackend for AtomicOnlyBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            self.keypair.public_key().algorithm()
        }

        fn public_key(&self) -> PublicKey {
            self.keypair.public_key()
        }

        fn sign_bytes(&self, _message: &[u8]) -> chio_core_types::Result<Signature> {
            Err(Error::InvalidSignature(
                "legacy split signing is disabled".to_string(),
            ))
        }

        fn sign_bytes_with_identity(
            &self,
            message: &[u8],
        ) -> chio_core_types::Result<SigningOutcome> {
            Ok(SigningOutcome {
                public_key: self.keypair.public_key(),
                algorithm: self.keypair.public_key().algorithm(),
                signature: self.keypair.sign(message),
            })
        }
    }

    #[test]
    fn failure_receipt_uses_one_atomic_signing_outcome() {
        let signer = Keypair::from_seed(&[210; 32]);
        let backend = AtomicOnlyBackend {
            keypair: signer.clone(),
        };

        let receipt = sign_failure_receipt(
            failure_body(
                "broker-failure-event-cccccccccccccccc",
                "chio.broker.authority_unavailable",
                10,
            ),
            &backend,
        )
        .test_expect("failure receipt");

        verify_failure_receipt(&receipt, &signer.public_key()).test_expect("verify receipt");
    }

    #[test]
    fn append_only_failure_log_rejects_a_second_terminal_for_one_attempt() {
        let directory = crate::private_tempdir().test_expect("tempdir");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let signer = Keypair::from_seed(&[211; 32]);
        let backend = Ed25519Backend::new(signer.clone());
        let sink = SqliteBrokerReceiptSink::open(
            trusted_directory.join("failure-events.sqlite3"),
            signer.public_key(),
        )
        .test_expect("receipt sink");
        let first = sign_failure_receipt(
            failure_body(
                "broker-failure-event-aaaaaaaaaaaaaaaa",
                "chio.broker.authority_unavailable",
                10,
            ),
            &backend,
        )
        .test_expect("first failure receipt");
        let second = sign_failure_receipt(
            failure_body(
                "broker-failure-event-bbbbbbbbbbbbbbbb",
                "chio.broker.authorization_denied",
                11,
            ),
            &backend,
        )
        .test_expect("second failure receipt");

        sink.persist_failure(&first)
            .test_expect("persist first event");
        assert!(matches!(
            sink.persist_failure(&second),
            Err(BrokerError::Conflict(_))
        ));
        assert_eq!(
            sink.load_failure(&first.body.receipt_id)
                .test_expect("load first")
                .test_expect("first exists"),
            first
        );
        assert!(sink
            .load_failure(&second.body.receipt_id)
            .test_expect("load rejected second")
            .is_none());
    }
}
