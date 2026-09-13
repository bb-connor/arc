use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
use chio_core_types::{
    canonical_json_bytes, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::CredentialRef;
use crate::sqlite::DurableBrokerDatabaseFile;
use crate::{validate_digest, BrokerError, Result};

pub const GOVERNED_ADMIN_AUTHORIZATION_SCHEMA: &str = "chio.broker-admin-authorization.v1";
pub const ADMIN_MUTATION_RECEIPT_SCHEMA: &str = "chio.broker-admin-mutation-receipt.v1";
pub const ADMIN_CONTROL_RECEIPT_SCHEMA: &str = "chio.broker-admin-control-receipt.v1";
const GOVERNED_ADMIN_INTENT_SCHEMA: &str = "chio.broker-admin-intent.v1";
const GOVERNED_ADMIN_INTENT_DOMAIN: &[u8] = b"chio.broker-admin-intent.v1\0";
const GOVERNED_ADMIN_AUTHORIZATION_DOMAIN: &[u8] = b"chio.broker-admin-authorization.v1\0";
const GOVERNED_ADMIN_OPERATION_DOMAIN: &[u8] = b"chio.broker-admin-operation.v1\0";
const ADMIN_MUTATION_RECEIPT_DOMAIN: &str = "chio.broker-admin-mutation-receipt-signature.v1\0";
const ADMIN_CONTROL_RECEIPT_DOMAIN: &str = "chio.broker-admin-control-receipt-signature.v1\0";
const MAX_GOVERNED_ADMIN_APPROVALS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminOperation {
    Provision,
    Rotate,
    Disable,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminMutationOutcome {
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminMutationReceiptBody {
    pub schema: String,
    pub operation_id: String,
    pub request_id: String,
    pub intent_digest: String,
    pub authorization_digest: String,
    pub operation: AdminOperation,
    pub tenant_scope: String,
    pub credential: CredentialRef,
    pub completed_at_unix_seconds: u64,
    pub outcome: AdminMutationOutcome,
}

impl AdminMutationReceiptBody {
    pub fn validate(&self) -> Result<()> {
        if self.schema != ADMIN_MUTATION_RECEIPT_SCHEMA
            || self.completed_at_unix_seconds == 0
            || self.outcome != AdminMutationOutcome::Applied
        {
            return Err(BrokerError::InvalidRequest(
                "admin mutation receipt schema, time, or outcome is invalid".to_string(),
            ));
        }
        for (digest, label) in [
            (&self.operation_id, "admin mutation operation id"),
            (&self.intent_digest, "admin mutation intent digest"),
            (
                &self.authorization_digest,
                "admin mutation authorization digest",
            ),
        ] {
            validate_digest(digest, label)?;
        }
        crate::validate_identifier(&self.request_id, "admin mutation request id", 512)?;
        crate::validate_identifier(&self.tenant_scope, "admin mutation tenant scope", 512)?;
        self.credential.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAdminMutationReceipt {
    pub body: AdminMutationReceiptBody,
    pub signer: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdminMutationReceiptSigningInput<'a> {
    domain: &'static str,
    body: &'a AdminMutationReceiptBody,
}

pub fn sign_admin_mutation_receipt(
    body: AdminMutationReceiptBody,
    signer: &dyn SigningBackend,
) -> Result<SignedAdminMutationReceipt> {
    body.validate()?;
    let input = AdminMutationReceiptSigningInput {
        domain: ADMIN_MUTATION_RECEIPT_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::Invariant(format!("admin mutation receipt encoding failed: {error}"))
    })?;
    let signed = signer
        .sign_bytes_with_identity(&canonical)
        .map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "admin mutation receipt signing failed: {error}"
            ))
        })?;
    Ok(SignedAdminMutationReceipt {
        body,
        signer: signed.public_key,
        algorithm: signed.algorithm,
        signature: signed.signature,
    })
}

pub fn verify_admin_mutation_receipt(receipt: &SignedAdminMutationReceipt) -> Result<()> {
    receipt.body.validate()?;
    if receipt.signer.algorithm() != receipt.algorithm
        || receipt.signature.algorithm() != receipt.algorithm
    {
        return Err(BrokerError::AuthorizationDenied(
            "admin mutation receipt signer or algorithm is invalid".to_string(),
        ));
    }
    let input = AdminMutationReceiptSigningInput {
        domain: ADMIN_MUTATION_RECEIPT_DOMAIN,
        body: &receipt.body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::AuthorizationDenied(format!(
            "admin mutation receipt verification encoding failed: {error}"
        ))
    })?;
    if !receipt.signer.verify(&canonical, &receipt.signature) {
        return Err(BrokerError::AuthorizationDenied(
            "admin mutation receipt signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub fn admin_mutation_receipt_digest(receipt: &SignedAdminMutationReceipt) -> Result<String> {
    verify_admin_mutation_receipt(receipt)?;
    let canonical = canonical_json_bytes(receipt).map_err(|error| {
        BrokerError::Invariant(format!("admin mutation receipt digest failed: {error}"))
    })?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminControlReceiptBody {
    pub schema: String,
    pub operation_id: String,
    pub request_id: String,
    pub intent_digest: String,
    pub authorization_digest: String,
    pub operation: String,
    pub tenant_scope: String,
    pub response_digest: String,
    pub completed_at_unix_seconds: u64,
    pub outcome: AdminMutationOutcome,
}

impl AdminControlReceiptBody {
    pub fn validate(&self) -> Result<()> {
        if self.schema != ADMIN_CONTROL_RECEIPT_SCHEMA
            || self.completed_at_unix_seconds == 0
            || self.outcome != AdminMutationOutcome::Applied
            || !matches!(self.operation.as_str(), "issue" | "revoke" | "status")
        {
            return Err(BrokerError::InvalidRequest(
                "admin control receipt schema, operation, time, or outcome is invalid".to_string(),
            ));
        }
        for (digest, label) in [
            (&self.operation_id, "admin control operation id"),
            (&self.intent_digest, "admin control intent digest"),
            (
                &self.authorization_digest,
                "admin control authorization digest",
            ),
            (&self.response_digest, "admin control response digest"),
        ] {
            validate_digest(digest, label)?;
        }
        crate::validate_identifier(&self.request_id, "admin control request id", 512)?;
        crate::validate_identifier(&self.operation, "admin control operation", 64)?;
        crate::validate_identifier(&self.tenant_scope, "admin control tenant scope", 512)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAdminControlReceipt {
    pub body: AdminControlReceiptBody,
    pub signer: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdminControlReceiptSigningInput<'a> {
    domain: &'static str,
    body: &'a AdminControlReceiptBody,
}

pub fn sign_admin_control_receipt(
    body: AdminControlReceiptBody,
    signer: &dyn SigningBackend,
) -> Result<SignedAdminControlReceipt> {
    body.validate()?;
    let input = AdminControlReceiptSigningInput {
        domain: ADMIN_CONTROL_RECEIPT_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::Invariant(format!("admin control receipt encoding failed: {error}"))
    })?;
    let signed = signer
        .sign_bytes_with_identity(&canonical)
        .map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "admin control receipt signing failed: {error}"
            ))
        })?;
    Ok(SignedAdminControlReceipt {
        body,
        signer: signed.public_key,
        algorithm: signed.algorithm,
        signature: signed.signature,
    })
}

pub fn verify_admin_control_receipt(receipt: &SignedAdminControlReceipt) -> Result<()> {
    receipt.body.validate()?;
    if receipt.signer.algorithm() != receipt.algorithm
        || receipt.signature.algorithm() != receipt.algorithm
    {
        return Err(BrokerError::AuthorizationDenied(
            "admin control receipt signer or algorithm is invalid".to_string(),
        ));
    }
    let input = AdminControlReceiptSigningInput {
        domain: ADMIN_CONTROL_RECEIPT_DOMAIN,
        body: &receipt.body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::AuthorizationDenied(format!(
            "admin control receipt verification encoding failed: {error}"
        ))
    })?;
    if !receipt.signer.verify(&canonical, &receipt.signature) {
        return Err(BrokerError::AuthorizationDenied(
            "admin control receipt signature is invalid".to_string(),
        ));
    }
    Ok(())
}

fn admin_control_receipt_digest(receipt: &SignedAdminControlReceipt) -> Result<String> {
    verify_admin_control_receipt(receipt)?;
    let canonical = canonical_json_bytes(receipt).map_err(|error| {
        BrokerError::Invariant(format!("admin control receipt digest failed: {error}"))
    })?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedAdminControl {
    receipt: SignedAdminControlReceipt,
    response: Vec<u8>,
}

impl CompletedAdminControl {
    #[must_use]
    pub fn receipt(&self) -> &SignedAdminControlReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }
}

pub struct AdminAuthorization {
    opaque_capability: Zeroizing<Vec<u8>>,
}

impl AdminAuthorization {
    pub fn new(mut opaque_capability: Vec<u8>) -> Result<Self> {
        if opaque_capability.is_empty() || opaque_capability.len() > 65_536 {
            opaque_capability.zeroize();
            return Err(BrokerError::InvalidRequest(
                "admin authorization is empty or oversized".to_string(),
            ));
        }
        Ok(Self {
            opaque_capability: Zeroizing::new(opaque_capability),
        })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.opaque_capability.as_slice()
    }
}

impl zeroize::ZeroizeOnDrop for AdminAuthorization {}

pub trait AdminAuthorizer: Send + Sync {
    fn authorize(
        &self,
        authorization: &AdminAuthorization,
        operation: AdminOperation,
        tenant_scope: &str,
        credential: &CredentialRef,
    ) -> Result<String>;
}

pub trait AdminClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64>;
}

#[derive(Debug, Default)]
pub struct SystemAdminClock;

impl AdminClock for SystemAdminClock {
    fn now_unix_seconds(&self) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!("admin clock failed: {error}"))
            })
            .map(|duration| duration.as_secs())
    }
}

#[derive(Debug, Clone)]
pub struct GovernedAdminPolicy {
    pub trusted_approvers: Vec<PublicKey>,
    pub subject: PublicKey,
    pub threshold: usize,
    pub maximum_token_lifetime_seconds: u64,
}

impl GovernedAdminPolicy {
    pub fn validate_for_runtime(&self) -> Result<()> {
        self.validate().map(|_| ())
    }

    fn validate(&self) -> Result<BTreeSet<String>> {
        if self.threshold == 0
            || self.threshold > self.trusted_approvers.len()
            || self.trusted_approvers.len() > MAX_GOVERNED_ADMIN_APPROVALS
            || self.maximum_token_lifetime_seconds == 0
            || self.maximum_token_lifetime_seconds > 3_600
        {
            return Err(BrokerError::InvalidRequest(
                "governed admin threshold or token lifetime policy is invalid".to_string(),
            ));
        }
        let trusted = self
            .trusted_approvers
            .iter()
            .map(PublicKey::to_hex)
            .collect::<BTreeSet<_>>();
        if trusted.len() != self.trusted_approvers.len() {
            return Err(BrokerError::InvalidRequest(
                "governed admin approver policy contains a duplicate key".to_string(),
            ));
        }
        Ok(trusted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedAdminAuthorizationEnvelope {
    pub schema: String,
    pub approvals: Vec<GovernedApprovalToken>,
}

impl GovernedAdminAuthorizationEnvelope {
    pub fn new(mut approvals: Vec<GovernedApprovalToken>) -> Result<Self> {
        if approvals.is_empty() || approvals.len() > MAX_GOVERNED_ADMIN_APPROVALS {
            return Err(BrokerError::InvalidRequest(
                "governed admin approval set is empty or oversized".to_string(),
            ));
        }
        approvals.sort_unstable_by(|left, right| {
            left.approver
                .to_hex()
                .cmp(&right.approver.to_hex())
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(Self {
            schema: GOVERNED_ADMIN_AUTHORIZATION_SCHEMA.to_string(),
            approvals,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        canonical_json_bytes(self).map_err(|error| {
            BrokerError::InvalidRequest(format!(
                "governed admin authorization canonicalization failed: {error}"
            ))
        })
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema != GOVERNED_ADMIN_AUTHORIZATION_SCHEMA
            || self.approvals.is_empty()
            || self.approvals.len() > MAX_GOVERNED_ADMIN_APPROVALS
            || self.approvals.windows(2).any(|pair| {
                let left = (pair[0].approver.to_hex(), pair[0].id.as_str());
                let right = (pair[1].approver.to_hex(), pair[1].id.as_str());
                left >= right
            })
        {
            return Err(BrokerError::InvalidRequest(
                "governed admin authorization schema or ordering is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GovernedAdminIntent<'a> {
    schema: &'static str,
    operation: AdminOperation,
    tenant_scope: &'a str,
    credential: &'a CredentialRef,
}

pub fn governed_admin_intent_digest(
    operation: AdminOperation,
    tenant_scope: &str,
    credential: &CredentialRef,
) -> Result<String> {
    crate::validate_identifier(tenant_scope, "admin tenant scope", 512)?;
    credential.validate()?;
    let canonical = canonical_json_bytes(&GovernedAdminIntent {
        schema: GOVERNED_ADMIN_INTENT_SCHEMA,
        operation,
        tenant_scope,
        credential,
    })
    .map_err(|error| BrokerError::Invariant(format!("admin intent encoding failed: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(GOVERNED_ADMIN_INTENT_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub struct GovernedAdminAuthorizer {
    connection: Mutex<Connection>,
    durable_file: DurableBrokerDatabaseFile,
    policy: GovernedAdminPolicy,
    trusted_approvers: BTreeSet<String>,
    trusted_mutation_receipt_signer: PublicKey,
    clock: Arc<dyn AdminClock>,
}

impl GovernedAdminAuthorizer {
    pub fn open(
        path: impl AsRef<Path>,
        policy: GovernedAdminPolicy,
        trusted_mutation_receipt_signer: PublicKey,
        clock: Arc<dyn AdminClock>,
    ) -> Result<Self> {
        let trusted_approvers = policy.validate()?;
        let path = path.as_ref();
        let durable_file = DurableBrokerDatabaseFile::open(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(admin_storage)?;
        durable_file.validate()?;
        let authorizer = Self {
            connection: Mutex::new(connection),
            durable_file,
            policy,
            trusted_approvers,
            trusted_mutation_receipt_signer,
            clock,
        };
        authorizer.migrate()?;
        authorizer.durable_file.validate()?;
        Ok(authorizer)
    }

    #[must_use]
    pub fn trusted_mutation_receipt_signer(&self) -> &PublicKey {
        &self.trusted_mutation_receipt_signer
    }

    #[must_use]
    pub fn policy(&self) -> &GovernedAdminPolicy {
        &self.policy
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        let connection = self.connection.lock().map_err(|_| {
            BrokerError::Storage("governed admin replay lock is poisoned".to_string())
        })?;
        self.durable_file.validate()?;
        Ok(connection)
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

                CREATE TABLE IF NOT EXISTS governed_admin_consumptions (
                    token_digest TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL UNIQUE,
                    request_id TEXT NOT NULL,
                    intent_digest TEXT NOT NULL,
                    authorization_digest TEXT NOT NULL,
                    consumed_at INTEGER NOT NULL CHECK(consumed_at >= 0)
                ) STRICT;

                CREATE INDEX IF NOT EXISTS idx_governed_admin_request
                    ON governed_admin_consumptions(request_id, intent_digest);

                CREATE TABLE IF NOT EXISTS governed_admin_operations (
                    operation_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    intent_digest TEXT NOT NULL,
                    authorization_digest TEXT NOT NULL UNIQUE,
                    started_at INTEGER NOT NULL CHECK(started_at >= 0)
                ) STRICT;

                CREATE INDEX IF NOT EXISTS idx_governed_admin_operation_request
                    ON governed_admin_operations(request_id, intent_digest);

                CREATE TABLE IF NOT EXISTS governed_admin_operation_completions (
                    operation_id TEXT PRIMARY KEY,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    completed_at INTEGER NOT NULL CHECK(completed_at > 0),
                    canonical_receipt BLOB NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES governed_admin_operations(operation_id)
                        ON DELETE RESTRICT
                ) STRICT;

                CREATE TABLE IF NOT EXISTS governed_admin_control_completions (
                    operation_id TEXT PRIMARY KEY,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    completed_at INTEGER NOT NULL CHECK(completed_at > 0),
                    canonical_receipt BLOB NOT NULL,
                    response BLOB NOT NULL CHECK(length(response) > 0),
                    FOREIGN KEY(operation_id) REFERENCES governed_admin_operations(operation_id)
                        ON DELETE RESTRICT
                ) STRICT;

                CREATE TRIGGER IF NOT EXISTS governed_admin_consumptions_no_update
                BEFORE UPDATE ON governed_admin_consumptions
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin consumptions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS governed_admin_consumptions_no_delete
                BEFORE DELETE ON governed_admin_consumptions
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin consumptions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS governed_admin_operations_no_update
                BEFORE UPDATE ON governed_admin_operations
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin operations are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS governed_admin_operations_no_delete
                BEFORE DELETE ON governed_admin_operations
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin operations are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS governed_admin_completions_no_update
                BEFORE UPDATE ON governed_admin_operation_completions
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin completions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS governed_admin_completions_no_delete
                BEFORE DELETE ON governed_admin_operation_completions
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin completions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS governed_admin_control_completions_no_update
                BEFORE UPDATE ON governed_admin_control_completions
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin control completions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS governed_admin_control_completions_no_delete
                BEFORE DELETE ON governed_admin_control_completions
                BEGIN
                    SELECT RAISE(ABORT, 'governed admin control completions are append-only');
                END;
                "#,
            )
            .map_err(admin_storage)
    }

    fn verify_envelope(
        &self,
        authorization: &AdminAuthorization,
        intent_digest: &str,
        now: u64,
    ) -> Result<VerifiedGovernedAdminAuthorization> {
        verify_governed_admin_authorization_inner(
            authorization,
            intent_digest,
            &self.policy,
            &self.trusted_approvers,
            now,
        )
    }

    fn consume(&self, verified: &VerifiedGovernedAdminAuthorization, now: u64) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(admin_storage)?;
        for (approval_id, token_digest) in verified.approval_ids.iter().zip(&verified.token_digests)
        {
            let inserted = transaction
                .execute(
                    r#"
                INSERT INTO governed_admin_consumptions (
                    token_digest, approval_id, request_id, intent_digest,
                    authorization_digest, consumed_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT DO NOTHING
                "#,
                    params![
                        token_digest,
                        approval_id,
                        verified.request_id,
                        verified.intent_digest,
                        verified.authorization_digest,
                        sqlite_u64(now, "admin consumption time")?,
                    ],
                )
                .map_err(admin_storage)?;
            if inserted != 1 {
                return Err(BrokerError::AuthorizationDenied(
                    "governed admin approval was already consumed".to_string(),
                ));
            }
        }
        transaction.commit().map_err(admin_storage)
    }

    /// Authorize and durably consume a threshold approval for an intent digest
    /// computed by a closed, domain-separated operation schema.
    pub fn authorize_intent_digest(
        &self,
        authorization: &AdminAuthorization,
        intent_digest: &str,
    ) -> Result<String> {
        let now = self.clock.now_unix_seconds()?;
        let verified = self.verify_envelope(authorization, intent_digest, now)?;
        self.consume(&verified, now)?;
        Ok(verified.authorization_digest)
    }

    /// Durably begin an exact admin operation. An exact retry returns the
    /// existing pending or completed operation, including after the original
    /// approval tokens expire. Any authorization or intent rebinding fails.
    pub fn begin_intent_digest(
        &self,
        authorization: &AdminAuthorization,
        intent_digest: &str,
    ) -> Result<AuthorizedAdminOperation> {
        validate_digest(intent_digest, "governed admin intent digest")?;
        let authorization_digest = authorization_digest_for_lookup(authorization)?;
        let existing = {
            let connection = self.connection()?;
            load_admin_operation_by_authorization(
                &connection,
                &authorization_digest,
                &self.trusted_mutation_receipt_signer,
            )?
        };
        if let Some(existing) = existing {
            if existing.intent_digest != intent_digest {
                return Err(BrokerError::Conflict(
                    "admin authorization was rebound to a different intent".to_string(),
                ));
            }
            return Ok(existing);
        }

        let now = self.clock.now_unix_seconds()?;
        let verified = self.verify_envelope(authorization, intent_digest, now)?;
        if verified.authorization_digest != authorization_digest {
            return Err(BrokerError::Invariant(
                "admin authorization digest changed during verification".to_string(),
            ));
        }
        self.consume_and_begin(&verified, now)
    }

    fn consume_and_begin(
        &self,
        verified: &VerifiedGovernedAdminAuthorization,
        now: u64,
    ) -> Result<AuthorizedAdminOperation> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(admin_storage)?;
        if let Some(existing) = load_admin_operation_by_authorization(
            &transaction,
            &verified.authorization_digest,
            &self.trusted_mutation_receipt_signer,
        )? {
            if existing.intent_digest != verified.intent_digest
                || existing.request_id != verified.request_id
            {
                return Err(BrokerError::Conflict(
                    "admin authorization conflicts with a durable operation".to_string(),
                ));
            }
            transaction.commit().map_err(admin_storage)?;
            return Ok(existing);
        }

        for (approval_id, token_digest) in verified.approval_ids.iter().zip(&verified.token_digests)
        {
            let inserted = transaction
                .execute(
                    r#"
                    INSERT INTO governed_admin_consumptions (
                        token_digest, approval_id, request_id, intent_digest,
                        authorization_digest, consumed_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    ON CONFLICT DO NOTHING
                    "#,
                    params![
                        token_digest,
                        approval_id,
                        verified.request_id,
                        verified.intent_digest,
                        verified.authorization_digest,
                        sqlite_u64(now, "admin consumption time")?,
                    ],
                )
                .map_err(admin_storage)?;
            if inserted != 1 {
                return Err(BrokerError::AuthorizationDenied(
                    "governed admin approval was already consumed by another operation".to_string(),
                ));
            }
        }
        let operation_id =
            governed_admin_operation_id(&verified.authorization_digest, &verified.intent_digest);
        transaction
            .execute(
                r#"
                INSERT INTO governed_admin_operations (
                    operation_id, request_id, intent_digest,
                    authorization_digest, started_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    operation_id,
                    verified.request_id,
                    verified.intent_digest,
                    verified.authorization_digest,
                    sqlite_u64(now, "admin operation start time")?,
                ],
            )
            .map_err(admin_storage)?;
        transaction.commit().map_err(admin_storage)?;
        Ok(AuthorizedAdminOperation {
            operation_id,
            request_id: verified.request_id.clone(),
            intent_digest: verified.intent_digest.clone(),
            authorization_digest: verified.authorization_digest.clone(),
            completed_receipt: None,
        })
    }

    /// Query a durable admin operation by its deterministic operation id.
    pub fn query_operation(&self, operation_id: &str) -> Result<Option<AuthorizedAdminOperation>> {
        validate_digest(operation_id, "admin operation id")?;
        let connection = self.connection()?;
        load_admin_operation_by_id(
            &connection,
            operation_id,
            &self.trusted_mutation_receipt_signer,
        )
    }

    /// Append the signed terminal receipt for a pending operation. Exact
    /// retries return the original receipt; conflicting completion content is
    /// rejected without mutating the journal.
    pub fn complete_operation(
        &self,
        operation: &AuthorizedAdminOperation,
        receipt: &SignedAdminMutationReceipt,
    ) -> Result<SignedAdminMutationReceipt> {
        validate_admin_operation_completion(
            operation,
            receipt,
            &self.trusted_mutation_receipt_signer,
        )?;
        let canonical = canonical_json_bytes(receipt).map_err(|error| {
            BrokerError::Invariant(format!(
                "admin mutation receipt persistence encoding failed: {error}"
            ))
        })?;
        let digest = admin_mutation_receipt_digest(receipt)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(admin_storage)?;
        let durable = load_admin_operation_by_id(
            &transaction,
            &operation.operation_id,
            &self.trusted_mutation_receipt_signer,
        )?
        .ok_or_else(|| {
            BrokerError::Conflict("admin operation is not durably admitted".to_string())
        })?;
        if durable.request_id != operation.request_id
            || durable.intent_digest != operation.intent_digest
            || durable.authorization_digest != operation.authorization_digest
        {
            return Err(BrokerError::Conflict(
                "admin operation binding changed before completion".to_string(),
            ));
        }
        if load_admin_control_completion(&transaction, &operation.operation_id)?.is_some() {
            return Err(BrokerError::Conflict(
                "admin operation cannot be both a remote control and mutation".to_string(),
            ));
        }
        if let Some(existing) = durable.completed_receipt {
            if existing.body.operation != receipt.body.operation
                || existing.body.tenant_scope != receipt.body.tenant_scope
                || existing.body.credential != receipt.body.credential
                || existing.body.outcome != receipt.body.outcome
            {
                return Err(BrokerError::Conflict(
                    "admin operation already has a different terminal receipt".to_string(),
                ));
            }
            transaction.commit().map_err(admin_storage)?;
            return Ok(existing);
        }
        transaction
            .execute(
                r#"
                INSERT INTO governed_admin_operation_completions (
                    operation_id, receipt_digest, completed_at, canonical_receipt
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    operation.operation_id,
                    digest,
                    sqlite_u64(
                        receipt.body.completed_at_unix_seconds,
                        "admin operation completion time"
                    )?,
                    canonical,
                ],
            )
            .map_err(admin_storage)?;
        transaction.commit().map_err(admin_storage)?;
        Ok(receipt.clone())
    }

    /// Query the signed completion and exact bounded response for a remote
    /// admin control operation.
    pub fn query_control_completion(
        &self,
        operation_id: &str,
    ) -> Result<Option<CompletedAdminControl>> {
        validate_digest(operation_id, "admin control operation id")?;
        let connection = self.connection()?;
        load_admin_control_completion(&connection, operation_id)
    }

    /// Append a signed terminal receipt and the exact validated response for
    /// a remote admin control operation. Exact concurrent retries converge on
    /// the first durable completion.
    pub fn complete_control_operation(
        &self,
        operation: &AuthorizedAdminOperation,
        receipt: &SignedAdminControlReceipt,
        response: &[u8],
    ) -> Result<CompletedAdminControl> {
        verify_admin_control_receipt(receipt)?;
        if response.is_empty() || response.len() > crate::protocol::MAX_WIRE_BYTES {
            return Err(BrokerError::InvalidRequest(
                "admin control response is empty or oversized".to_string(),
            ));
        }
        let response_digest = hex::encode(Sha256::digest(response));
        if receipt.body.operation_id != operation.operation_id
            || receipt.body.request_id != operation.request_id
            || receipt.body.intent_digest != operation.intent_digest
            || receipt.body.authorization_digest != operation.authorization_digest
            || receipt.body.response_digest != response_digest
        {
            return Err(BrokerError::Conflict(
                "admin control receipt does not match the durable operation or response"
                    .to_string(),
            ));
        }
        let canonical = canonical_json_bytes(receipt).map_err(|error| {
            BrokerError::Invariant(format!(
                "admin control receipt persistence encoding failed: {error}"
            ))
        })?;
        let digest = admin_control_receipt_digest(receipt)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(admin_storage)?;
        let durable = load_admin_operation_by_id(
            &transaction,
            &operation.operation_id,
            &self.trusted_mutation_receipt_signer,
        )?
        .ok_or_else(|| {
            BrokerError::Conflict("admin control operation is not durably admitted".to_string())
        })?;
        if durable.request_id != operation.request_id
            || durable.intent_digest != operation.intent_digest
            || durable.authorization_digest != operation.authorization_digest
        {
            return Err(BrokerError::Conflict(
                "admin control operation binding changed before completion".to_string(),
            ));
        }
        if durable.completed_receipt.is_some() {
            return Err(BrokerError::Conflict(
                "admin operation cannot be both a mutation and remote control".to_string(),
            ));
        }
        if let Some(existing) =
            load_admin_control_completion(&transaction, &operation.operation_id)?
        {
            if existing.receipt.body.operation != receipt.body.operation
                || existing.receipt.body.tenant_scope != receipt.body.tenant_scope
                || existing.receipt.body.response_digest != receipt.body.response_digest
                || existing.response != response
            {
                return Err(BrokerError::Conflict(
                    "admin control operation already has a different terminal result".to_string(),
                ));
            }
            transaction.commit().map_err(admin_storage)?;
            return Ok(existing);
        }
        transaction
            .execute(
                r#"
                INSERT INTO governed_admin_control_completions (
                    operation_id, receipt_digest, completed_at,
                    canonical_receipt, response
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    operation.operation_id,
                    digest,
                    sqlite_u64(
                        receipt.body.completed_at_unix_seconds,
                        "admin control completion time"
                    )?,
                    canonical,
                    response,
                ],
            )
            .map_err(admin_storage)?;
        transaction.commit().map_err(admin_storage)?;
        Ok(CompletedAdminControl {
            receipt: receipt.clone(),
            response: response.to_vec(),
        })
    }
}

impl AdminAuthorizer for GovernedAdminAuthorizer {
    fn authorize(
        &self,
        authorization: &AdminAuthorization,
        operation: AdminOperation,
        tenant_scope: &str,
        credential: &CredentialRef,
    ) -> Result<String> {
        let intent_digest = governed_admin_intent_digest(operation, tenant_scope, credential)?;
        self.authorize_intent_digest(authorization, &intent_digest)
    }
}

/// Verify a canonical governed admin approval envelope without consuming its
/// one-shot tokens. This is the post-hoc evidence verifier used for signed
/// broker audit comparisons. Runtime authorization still uses the durable
/// consuming path on [`GovernedAdminAuthorizer`].
pub fn verify_governed_admin_authorization_evidence(
    authorization: &AdminAuthorization,
    intent_digest: &str,
    policy: &GovernedAdminPolicy,
    verified_at_unix_seconds: u64,
) -> Result<String> {
    let trusted_approvers = policy.validate()?;
    verify_governed_admin_authorization_inner(
        authorization,
        intent_digest,
        policy,
        &trusted_approvers,
        verified_at_unix_seconds,
    )
    .map(|verified| verified.authorization_digest)
}

fn verify_governed_admin_authorization_inner(
    authorization: &AdminAuthorization,
    intent_digest: &str,
    policy: &GovernedAdminPolicy,
    trusted_approvers: &BTreeSet<String>,
    now: u64,
) -> Result<VerifiedGovernedAdminAuthorization> {
    validate_digest(intent_digest, "governed admin intent digest")?;
    let envelope: GovernedAdminAuthorizationEnvelope =
        serde_json::from_slice(authorization.as_bytes()).map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "governed admin authorization decoding failed: {error}"
            ))
        })?;
    envelope.validate_shape()?;
    let canonical = envelope.canonical_bytes()?;
    if canonical != authorization.as_bytes() {
        return Err(BrokerError::AuthorizationDenied(
            "governed admin authorization is not canonical JSON".to_string(),
        ));
    }
    if envelope.approvals.len() != policy.threshold {
        return Err(BrokerError::AuthorizationDenied(
            "governed admin authorization does not satisfy the exact threshold".to_string(),
        ));
    }
    let mut request_id: Option<&str> = None;
    let mut proposal_digest: Option<&str> = None;
    let mut approvers = BTreeSet::new();
    let mut approval_ids = BTreeSet::new();
    let mut token_digests = Vec::with_capacity(envelope.approvals.len());
    for approval in &envelope.approvals {
        crate::validate_identifier(&approval.id, "admin approval id", 512)?;
        crate::validate_identifier(&approval.request_id, "admin request id", 512)?;
        validate_digest(
            &approval.governed_intent_hash,
            "admin governed intent digest",
        )?;
        let proposal = approval.threshold_proposal_hash.as_deref().ok_or_else(|| {
            BrokerError::AuthorizationDenied(
                "governed admin approval omits its threshold proposal".to_string(),
            )
        })?;
        validate_digest(proposal, "admin threshold proposal digest")?;
        if approval.subject != policy.subject
            || approval.governed_intent_hash != intent_digest
            || approval.decision != GovernedApprovalDecision::Approved
            || !trusted_approvers.contains(&approval.approver.to_hex())
        {
            return Err(BrokerError::AuthorizationDenied(
                "governed admin approval subject, intent, decision, or approver is invalid"
                    .to_string(),
            ));
        }
        if approval.expires_at <= approval.issued_at
            || approval.expires_at.saturating_sub(approval.issued_at)
                > policy.maximum_token_lifetime_seconds
        {
            return Err(BrokerError::AuthorizationDenied(
                "governed admin approval lifetime exceeds policy".to_string(),
            ));
        }
        if !approval.verify_signature_at(now).map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "governed admin approval verification failed: {error}"
            ))
        })? {
            return Err(BrokerError::AuthorizationDenied(
                "governed admin approval signature is invalid".to_string(),
            ));
        }
        if request_id.is_some_and(|value| value != approval.request_id)
            || proposal_digest.is_some_and(|value| value != proposal)
        {
            return Err(BrokerError::AuthorizationDenied(
                "governed admin approvals do not share one request and proposal".to_string(),
            ));
        }
        request_id = Some(&approval.request_id);
        proposal_digest = Some(proposal);
        if !approvers.insert(approval.approver.to_hex())
            || !approval_ids.insert(approval.id.clone())
        {
            return Err(BrokerError::AuthorizationDenied(
                "governed admin approval set contains a duplicate member".to_string(),
            ));
        }
        token_digests.push(approval.artifact_digest().map_err(|error| {
            BrokerError::AuthorizationDenied(format!("governed admin token digest failed: {error}"))
        })?);
    }
    let mut hasher = Sha256::new();
    hasher.update(GOVERNED_ADMIN_AUTHORIZATION_DOMAIN);
    hasher.update(&canonical);
    let authorization_digest = hex::encode(hasher.finalize());
    Ok(VerifiedGovernedAdminAuthorization {
        request_id: request_id
            .ok_or_else(|| BrokerError::Invariant("missing admin request id".to_string()))?
            .to_string(),
        intent_digest: intent_digest.to_string(),
        authorization_digest,
        approval_ids: envelope
            .approvals
            .iter()
            .map(|approval| approval.id.clone())
            .collect(),
        token_digests,
    })
}

struct VerifiedGovernedAdminAuthorization {
    request_id: String,
    intent_digest: String,
    authorization_digest: String,
    approval_ids: Vec<String>,
    token_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAdminOperation {
    operation_id: String,
    request_id: String,
    intent_digest: String,
    authorization_digest: String,
    completed_receipt: Option<SignedAdminMutationReceipt>,
}

impl AuthorizedAdminOperation {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }

    #[must_use]
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    #[must_use]
    pub fn completed_receipt(&self) -> Option<&SignedAdminMutationReceipt> {
        self.completed_receipt.as_ref()
    }
}

fn authorization_digest_for_lookup(authorization: &AdminAuthorization) -> Result<String> {
    let envelope: GovernedAdminAuthorizationEnvelope =
        serde_json::from_slice(authorization.as_bytes()).map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "governed admin authorization decoding failed: {error}"
            ))
        })?;
    envelope.validate_shape()?;
    let canonical = envelope.canonical_bytes()?;
    if canonical != authorization.as_bytes() {
        return Err(BrokerError::AuthorizationDenied(
            "governed admin authorization is not canonical JSON".to_string(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(GOVERNED_ADMIN_AUTHORIZATION_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn governed_admin_operation_id(authorization_digest: &str, intent_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(GOVERNED_ADMIN_OPERATION_DOMAIN);
    hasher.update(authorization_digest.as_bytes());
    hasher.update([0]);
    hasher.update(intent_digest.as_bytes());
    hex::encode(hasher.finalize())
}

fn load_admin_operation_by_authorization(
    connection: &Connection,
    authorization_digest: &str,
    trusted_mutation_receipt_signer: &PublicKey,
) -> Result<Option<AuthorizedAdminOperation>> {
    load_admin_operation(
        connection,
        r#"
        SELECT operation.operation_id, operation.request_id,
               operation.intent_digest, operation.authorization_digest,
               completion.canonical_receipt
        FROM governed_admin_operations AS operation
        LEFT JOIN governed_admin_operation_completions AS completion
          ON completion.operation_id = operation.operation_id
        WHERE operation.authorization_digest = ?1
        "#,
        authorization_digest,
        trusted_mutation_receipt_signer,
    )
}

fn load_admin_operation_by_id(
    connection: &Connection,
    operation_id: &str,
    trusted_mutation_receipt_signer: &PublicKey,
) -> Result<Option<AuthorizedAdminOperation>> {
    load_admin_operation(
        connection,
        r#"
        SELECT operation.operation_id, operation.request_id,
               operation.intent_digest, operation.authorization_digest,
               completion.canonical_receipt
        FROM governed_admin_operations AS operation
        LEFT JOIN governed_admin_operation_completions AS completion
          ON completion.operation_id = operation.operation_id
        WHERE operation.operation_id = ?1
        "#,
        operation_id,
        trusted_mutation_receipt_signer,
    )
}

type StoredAdminOperationRow = (String, String, String, String, Option<Vec<u8>>);

fn load_admin_operation(
    connection: &Connection,
    query: &str,
    binding: &str,
    trusted_mutation_receipt_signer: &PublicKey,
) -> Result<Option<AuthorizedAdminOperation>> {
    let row: Option<StoredAdminOperationRow> = connection
        .query_row(query, params![binding], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .optional()
        .map_err(admin_storage)?;
    let Some((operation_id, request_id, intent_digest, authorization_digest, receipt)) = row else {
        return Ok(None);
    };
    let completed_receipt = receipt
        .map(|canonical| decode_admin_mutation_receipt(canonical, trusted_mutation_receipt_signer))
        .transpose()?;
    let operation = AuthorizedAdminOperation {
        operation_id,
        request_id,
        intent_digest,
        authorization_digest,
        completed_receipt,
    };
    if let Some(receipt) = operation.completed_receipt() {
        validate_admin_operation_completion(&operation, receipt, trusted_mutation_receipt_signer)?;
    }
    Ok(Some(operation))
}

fn decode_admin_mutation_receipt(
    canonical: Vec<u8>,
    trusted_mutation_receipt_signer: &PublicKey,
) -> Result<SignedAdminMutationReceipt> {
    let receipt: SignedAdminMutationReceipt =
        serde_json::from_slice(&canonical).map_err(|error| {
            BrokerError::Storage(format!(
                "persisted admin mutation receipt decoding failed: {error}"
            ))
        })?;
    let reencoded = canonical_json_bytes(&receipt).map_err(|error| {
        BrokerError::Storage(format!(
            "persisted admin mutation receipt encoding failed: {error}"
        ))
    })?;
    if reencoded != canonical {
        return Err(BrokerError::Storage(
            "persisted admin mutation receipt is not canonical JSON".to_string(),
        ));
    }
    verify_trusted_admin_mutation_receipt(&receipt, trusted_mutation_receipt_signer)?;
    Ok(receipt)
}

fn verify_trusted_admin_mutation_receipt(
    receipt: &SignedAdminMutationReceipt,
    trusted_mutation_receipt_signer: &PublicKey,
) -> Result<()> {
    verify_admin_mutation_receipt(receipt)?;
    if &receipt.signer != trusted_mutation_receipt_signer {
        return Err(BrokerError::AuthorizationDenied(
            "admin mutation receipt signer is not trusted".to_string(),
        ));
    }
    Ok(())
}

fn validate_admin_operation_completion(
    operation: &AuthorizedAdminOperation,
    receipt: &SignedAdminMutationReceipt,
    trusted_mutation_receipt_signer: &PublicKey,
) -> Result<()> {
    verify_trusted_admin_mutation_receipt(receipt, trusted_mutation_receipt_signer)?;
    if receipt.body.operation_id != operation.operation_id
        || receipt.body.request_id != operation.request_id
        || receipt.body.intent_digest != operation.intent_digest
        || receipt.body.authorization_digest != operation.authorization_digest
    {
        return Err(BrokerError::Conflict(
            "admin mutation receipt does not match the durable operation".to_string(),
        ));
    }
    Ok(())
}

fn load_admin_control_completion(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<CompletedAdminControl>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            r#"
            SELECT canonical_receipt, response
            FROM governed_admin_control_completions
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(admin_storage)?;
    let Some((canonical, response)) = row else {
        return Ok(None);
    };
    if response.is_empty() || response.len() > crate::protocol::MAX_WIRE_BYTES {
        return Err(BrokerError::Storage(
            "persisted admin control response is empty or oversized".to_string(),
        ));
    }
    let receipt: SignedAdminControlReceipt =
        serde_json::from_slice(&canonical).map_err(|error| {
            BrokerError::Storage(format!(
                "persisted admin control receipt decoding failed: {error}"
            ))
        })?;
    let reencoded = canonical_json_bytes(&receipt).map_err(|error| {
        BrokerError::Storage(format!(
            "persisted admin control receipt encoding failed: {error}"
        ))
    })?;
    if reencoded != canonical {
        return Err(BrokerError::Storage(
            "persisted admin control receipt is not canonical JSON".to_string(),
        ));
    }
    verify_admin_control_receipt(&receipt)?;
    if receipt.body.operation_id != operation_id
        || receipt.body.response_digest != hex::encode(Sha256::digest(&response))
    {
        return Err(BrokerError::Storage(
            "persisted admin control receipt is not bound to its operation or response".to_string(),
        ));
    }
    Ok(Some(CompletedAdminControl { receipt, response }))
}

fn sqlite_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| BrokerError::Storage(format!("{label} exceeds SQLite INTEGER")))
}

fn admin_storage(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("governed admin replay store failed: {error}"))
}
