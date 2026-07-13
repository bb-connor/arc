use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_core_types::{canonical_json_bytes, Keypair, PublicKey, Signature, SigningAlgorithm};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::BrokerExecutionEvidence;
use crate::{validate_identifier, BrokerError, Result};

pub const BROKER_RECEIPT_SCHEMA: &str = "chio.broker-execution-receipt.v1";
const RECEIPT_DOMAIN: &str = "chio.broker-execution-receipt-signature.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerReceiptBody {
    pub schema: String,
    pub receipt_id: String,
    pub issued_at_unix_seconds: u64,
    pub evidence: BrokerExecutionEvidence,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedBrokerReceipt {
    pub body: BrokerReceiptBody,
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

pub fn sign_execution_receipt(
    body: BrokerReceiptBody,
    signer: &Keypair,
) -> Result<SignedBrokerReceipt> {
    if body.schema != BROKER_RECEIPT_SCHEMA {
        return Err(BrokerError::InvalidRequest(
            "unsupported broker receipt schema".to_string(),
        ));
    }
    validate_identifier(&body.receipt_id, "receipt id", 512)?;
    if body.issued_at_unix_seconds == 0 || body.outcome != "completed" {
        return Err(BrokerError::InvalidRequest(
            "broker receipt time or outcome is invalid".to_string(),
        ));
    }
    body.evidence.validate()?;
    let input = ReceiptSigningInput {
        domain: RECEIPT_DOMAIN,
        body: &body,
    };
    let (signature, _) = signer
        .sign_canonical(&input)
        .map_err(|error| BrokerError::Invariant(format!("receipt signing failed: {error}")))?;
    Ok(SignedBrokerReceipt {
        body,
        signer: signer.public_key(),
        algorithm: signer.public_key().algorithm(),
        signature,
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
    validate_identifier(&receipt.body.receipt_id, "receipt id", 512)?;
    if receipt.body.issued_at_unix_seconds == 0 || receipt.body.outcome != "completed" {
        return Err(BrokerError::AuthorizationDenied(
            "broker receipt time or outcome is invalid".to_string(),
        ));
    }
    receipt.body.evidence.validate()?;
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

pub fn receipt_digest(receipt: &SignedBrokerReceipt) -> Result<String> {
    let canonical = canonical_json_bytes(receipt)
        .map_err(|error| BrokerError::Invariant(format!("receipt digest failed: {error}")))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

pub trait BrokerReceiptSink: Send + Sync {
    fn persist(&self, receipt: &SignedBrokerReceipt) -> Result<String>;
}

pub struct SqliteBrokerReceiptSink {
    connection: Mutex<Connection>,
    trusted_signer: PublicKey,
}

impl SqliteBrokerReceiptSink {
    pub fn open(path: impl AsRef<Path>, trusted_signer: PublicKey) -> Result<Self> {
        let path = path.as_ref();
        prepare_private_database(path)?;
        let connection = Connection::open(path).map_err(receipt_storage)?;
        let sink = Self {
            connection: Mutex::new(connection),
            trusted_signer,
        };
        sink.migrate()?;
        Ok(sink)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| BrokerError::Storage("broker receipt store lock is poisoned".to_string()))
    }

    fn migrate(&self) -> Result<()> {
        self.connection()?
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
                "#,
            )
            .map_err(receipt_storage)
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
}

fn prepare_private_database(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                BrokerError::Storage(format!("receipt directory creation failed: {error}"))
            })?;
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(BrokerError::Storage(
                "receipt database path is not a regular file".to_string(),
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(|error| {
        BrokerError::Storage(format!("receipt database creation failed: {error}"))
    })?;
    #[cfg(unix)]
    {
        let mode = file
            .metadata()
            .map_err(|error| {
                BrokerError::Storage(format!("receipt database metadata failed: {error}"))
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    BrokerError::Storage(format!("receipt permissions failed: {error}"))
                })?;
        }
    }
    drop(file);
    Ok(())
}

fn sqlite_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| BrokerError::Storage(format!("{label} exceeds SQLite INTEGER")))
}

fn receipt_storage(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("broker receipt store failed: {error}"))
}
