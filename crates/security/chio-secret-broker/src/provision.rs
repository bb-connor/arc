use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
use chio_core_types::{canonical_json_bytes, PublicKey};
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encrypted_blob_backend::EncryptedBlobSecretBackend;
use crate::protocol::CredentialRef;
use crate::{validate_digest, BrokerError, Result};

pub const GOVERNED_ADMIN_AUTHORIZATION_SCHEMA: &str = "chio.broker-admin-authorization.v1";
const GOVERNED_ADMIN_INTENT_SCHEMA: &str = "chio.broker-admin-intent.v1";
const GOVERNED_ADMIN_INTENT_DOMAIN: &[u8] = b"chio.broker-admin-intent.v1\0";
const GOVERNED_ADMIN_AUTHORIZATION_DOMAIN: &[u8] = b"chio.broker-admin-authorization.v1\0";
const MAX_GOVERNED_ADMIN_APPROVALS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminOperation {
    Provision,
    Rotate,
    Disable,
    Delete,
}

pub struct AdminAuthorization {
    opaque_capability: Zeroizing<Vec<u8>>,
}

impl AdminAuthorization {
    pub fn new(opaque_capability: Vec<u8>) -> Result<Self> {
        if opaque_capability.is_empty() || opaque_capability.len() > 65_536 {
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

impl fmt::Debug for AdminAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminAuthorization(<opaque>)")
    }
}

pub struct ProvisionSecret {
    bytes: Zeroizing<Vec<u8>>,
}

impl ProvisionSecret {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(BrokerError::InvalidRequest(
                "provisioned credential is empty or oversized".to_string(),
            ));
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for ProvisionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisionSecret(<redacted>)")
    }
}

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
    policy: GovernedAdminPolicy,
    trusted_approvers: BTreeSet<String>,
    clock: Arc<dyn AdminClock>,
}

impl GovernedAdminAuthorizer {
    pub fn open(
        path: impl AsRef<Path>,
        policy: GovernedAdminPolicy,
        clock: Arc<dyn AdminClock>,
    ) -> Result<Self> {
        let trusted_approvers = policy.validate()?;
        let path = path.as_ref();
        prepare_private_database(path, "admin replay")?;
        let connection = Connection::open(path).map_err(admin_storage)?;
        let authorizer = Self {
            connection: Mutex::new(connection),
            policy,
            trusted_approvers,
            clock,
        };
        authorizer.migrate()?;
        Ok(authorizer)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| BrokerError::Storage("governed admin replay lock is poisoned".to_string()))
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
        if envelope.approvals.len() != self.policy.threshold {
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
            if approval.subject != self.policy.subject
                || approval.governed_intent_hash != intent_digest
                || approval.decision != GovernedApprovalDecision::Approved
                || !self.trusted_approvers.contains(&approval.approver.to_hex())
            {
                return Err(BrokerError::AuthorizationDenied(
                    "governed admin approval subject, intent, decision, or approver is invalid"
                        .to_string(),
                ));
            }
            if approval.expires_at <= approval.issued_at
                || approval.expires_at.saturating_sub(approval.issued_at)
                    > self.policy.maximum_token_lifetime_seconds
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
            token_digests.push(approval.token_digest().map_err(|error| {
                BrokerError::AuthorizationDenied(format!(
                    "governed admin token digest failed: {error}"
                ))
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

struct VerifiedGovernedAdminAuthorization {
    request_id: String,
    intent_digest: String,
    authorization_digest: String,
    approval_ids: Vec<String>,
    token_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedAdminReceipt {
    pub operation: AdminOperation,
    pub tenant_scope: String,
    pub credential: CredentialRef,
    pub authorization_digest: String,
    pub outcome: String,
}

pub struct AdminProvisioner {
    backend: Arc<EncryptedBlobSecretBackend>,
    authorizer: Arc<dyn AdminAuthorizer>,
}

impl AdminProvisioner {
    #[must_use]
    pub fn new(
        backend: Arc<EncryptedBlobSecretBackend>,
        authorizer: Arc<dyn AdminAuthorizer>,
    ) -> Self {
        Self {
            backend,
            authorizer,
        }
    }

    pub fn provision(
        &self,
        authorization: &AdminAuthorization,
        credential: &CredentialRef,
        secret: ProvisionSecret,
    ) -> Result<RedactedAdminReceipt> {
        self.mutate(
            authorization,
            AdminOperation::Provision,
            credential,
            Some(secret),
        )
    }

    pub fn rotate(
        &self,
        authorization: &AdminAuthorization,
        credential: &CredentialRef,
        secret: ProvisionSecret,
    ) -> Result<RedactedAdminReceipt> {
        self.mutate(
            authorization,
            AdminOperation::Rotate,
            credential,
            Some(secret),
        )
    }

    pub fn disable(
        &self,
        authorization: &AdminAuthorization,
        credential: &CredentialRef,
    ) -> Result<RedactedAdminReceipt> {
        self.mutate(authorization, AdminOperation::Disable, credential, None)
    }

    pub fn delete(
        &self,
        authorization: &AdminAuthorization,
        credential: &CredentialRef,
    ) -> Result<RedactedAdminReceipt> {
        self.mutate(authorization, AdminOperation::Delete, credential, None)
    }

    fn mutate(
        &self,
        authorization: &AdminAuthorization,
        operation: AdminOperation,
        credential: &CredentialRef,
        secret: Option<ProvisionSecret>,
    ) -> Result<RedactedAdminReceipt> {
        credential.validate()?;
        let authorization_digest = self.authorizer.authorize(
            authorization,
            operation,
            self.backend.tenant_scope(),
            credential,
        )?;
        validate_digest(&authorization_digest, "admin authorization digest")?;
        match operation {
            AdminOperation::Provision | AdminOperation::Rotate => {
                let secret = secret.ok_or_else(|| {
                    BrokerError::Invariant("credential material is missing".to_string())
                })?;
                self.backend.provision(credential, secret.as_bytes())?;
            }
            AdminOperation::Disable => self.backend.disable(credential)?,
            AdminOperation::Delete => self.backend.delete(credential)?,
        }
        Ok(RedactedAdminReceipt {
            operation,
            tenant_scope: self.backend.tenant_scope().to_string(),
            credential: credential.clone(),
            authorization_digest,
            outcome: "applied".to_string(),
        })
    }
}

pub fn admin_receipt_digest(receipt: &RedactedAdminReceipt) -> Result<String> {
    let canonical = canonical_json_bytes(receipt)
        .map_err(|error| BrokerError::Invariant(format!("admin receipt failed: {error}")))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn prepare_private_database(path: &Path, label: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                BrokerError::Storage(format!("{label} directory creation failed: {error}"))
            })?;
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(BrokerError::Storage(format!(
                "{label} database path is not a regular file"
            )));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(|error| {
        BrokerError::Storage(format!("{label} database creation failed: {error}"))
    })?;
    #[cfg(unix)]
    {
        let mode = file
            .metadata()
            .map_err(|error| {
                BrokerError::Storage(format!("{label} database metadata failed: {error}"))
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    BrokerError::Storage(format!("{label} database permissions failed: {error}"))
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

fn admin_storage(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("governed admin replay store failed: {error}"))
}

#[cfg(test)]
mod tests {
    use crate::backend::SecretBackend;

    use super::*;

    struct AllowAdmin;

    struct DenyAdmin;

    impl AdminAuthorizer for AllowAdmin {
        fn authorize(
            &self,
            _authorization: &AdminAuthorization,
            _operation: AdminOperation,
            _tenant_scope: &str,
            _credential: &CredentialRef,
        ) -> Result<String> {
            Ok("a".repeat(64))
        }
    }

    impl AdminAuthorizer for DenyAdmin {
        fn authorize(
            &self,
            _authorization: &AdminAuthorization,
            _operation: AdminOperation,
            _tenant_scope: &str,
            _credential: &CredentialRef,
        ) -> Result<String> {
            Err(BrokerError::AuthorizationDenied(
                "operator capability rejected".to_string(),
            ))
        }
    }

    #[test]
    fn provisioning_receipt_and_debug_are_redacted() {
        let backend = Arc::new(
            EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-a", [9; 32])
                .expect("backend"),
        );
        let provisioner = AdminProvisioner::new(backend, Arc::new(AllowAdmin));
        let credential = CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-a".to_string(),
            version: 1,
        };
        let canary = "unique-provision-canary";
        let secret = ProvisionSecret::new(canary.as_bytes().to_vec()).expect("secret");
        assert!(!format!("{secret:?}").contains(canary));
        let receipt = provisioner
            .provision(
                &AdminAuthorization::new(vec![1]).expect("authorization"),
                &credential,
                secret,
            )
            .expect("provision");
        let encoded = serde_json::to_string(&receipt).expect("receipt");
        assert!(!encoded.contains(canary));
    }

    #[test]
    fn unauthorized_provisioning_leaves_no_usable_reference() {
        let backend = Arc::new(
            EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-a", [9; 32])
                .expect("backend"),
        );
        let provisioner = AdminProvisioner::new(Arc::clone(&backend), Arc::new(DenyAdmin));
        let credential = CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-a".to_string(),
            version: 1,
        };
        assert!(provisioner
            .provision(
                &AdminAuthorization::new(vec![1]).expect("authorization"),
                &credential,
                ProvisionSecret::new(b"unique-denied-canary".to_vec()).expect("secret"),
            )
            .is_err());
        assert!(backend.materialize(&credential).is_err());
    }
}
