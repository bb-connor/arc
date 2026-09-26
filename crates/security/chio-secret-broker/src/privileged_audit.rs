//! Privileged, audit-only Unix transport for broker migration comparisons.
//!
//! This protocol is deliberately separate from normal tool IPC. A connection
//! has exactly two request phases: the runner precommits to the legacy wire
//! reference, submits that precommitment with the live broker request and exact
//! reference bytes, then verifies the broker-signed challenge retained it. The
//! runner signs the challenge-derived authorization body and returns it with a
//! one-shot governed admin authorization. The connection closes after one
//! canonical evidence bundle or any failure.

use std::fmt;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::{Duration, Instant};

use chio_core_types::{
    canonical_json_bytes, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
#[cfg(unix)]
use rand_core::{OsRng, RngCore};
#[cfg(unix)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[cfg(unix)]
use crate::audit::BrokerAuditRunnerScope;
use crate::audit::{
    verify_broker_audit_comparison, BrokerAuditReferencePrecommitment, BrokerAuditReferenceRequest,
    BrokerAuditRunnerAuthorizationBody, CompletedBrokerAuditComparison,
    SignedBrokerAuditComparison, SignedBrokerAuditRunnerAuthorization,
};
use crate::authority_ipc::{
    verify_authority_exchange, SignedAuthorityRequest, SignedAuthorityResponse,
    VerifiedAuthorityExchange,
};
use crate::protocol::{BrokerExecuteRequest, MAX_BODY_BYTES, MAX_WIRE_BYTES};
use crate::provision::AdminAuthorization;
use crate::{validate_digest, validate_identifier, BrokerError, Result};

pub const BROKER_PRIVILEGED_AUDIT_OPEN_SCHEMA: &str = "chio.broker-privileged-audit-open.v1";
pub const BROKER_PRIVILEGED_AUDIT_CHALLENGE_SCHEMA: &str =
    "chio.broker-privileged-audit-challenge.v1";
pub const BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA: &str = "chio.broker-privileged-audit-commit.v1";
pub const BROKER_PRIVILEGED_AUDIT_EVIDENCE_SCHEMA: &str =
    "chio.broker-privileged-audit-evidence.v1";

const CHALLENGE_SIGNATURE_DOMAIN: &str = "chio.broker-privileged-audit-challenge-signature.v1\0";
const SESSION_COMMITMENT_DOMAIN: &[u8] = b"chio.broker-privileged-audit-session-commitment.v1\0";
#[cfg(unix)]
const MAX_AUDIT_OPEN_FRAME_BYTES: usize = 16 * 1_048_576;
const MAX_AUDIT_CONTROL_FRAME_BYTES: usize = 256 * 1_024;
const MAX_AUDIT_EVIDENCE_FRAME_BYTES: usize = 2 * 1_048_576;
#[cfg(unix)]
const AUDIT_SOCKET_MODE: u32 = 0o660;
#[cfg(unix)]
const AUDIT_SOCKET_DIRECTORY_MODE: u32 = 0o710;
const MAX_SESSION_LIFETIME_SECONDS: u64 = 300;

/// First phase of one privileged audit connection.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerPrivilegedAuditOpenRequest {
    pub schema: String,
    pub audit_id: String,
    pub reference_source: String,
    pub revocation_authority_domain: String,
    pub request: BrokerExecuteRequest,
    pub reference_commitment_salt: String,
    pub reference_commitment_sha256: String,
    pub reference_request_head: Vec<u8>,
    pub reference_request_body: Vec<u8>,
}

impl BrokerPrivilegedAuditOpenRequest {
    pub fn new(
        audit_id: String,
        reference_source: String,
        revocation_authority_domain: String,
        request: BrokerExecuteRequest,
        reference_request_head: Vec<u8>,
        reference_request_body: Vec<u8>,
        reference_precommitment: &BrokerAuditReferencePrecommitment,
    ) -> Result<Self> {
        let open = Self {
            schema: BROKER_PRIVILEGED_AUDIT_OPEN_SCHEMA.to_string(),
            audit_id,
            reference_source,
            revocation_authority_domain,
            request,
            reference_commitment_salt: reference_precommitment.commitment_salt().to_string(),
            reference_commitment_sha256: reference_precommitment.commitment_sha256().to_string(),
            reference_request_head,
            reference_request_body,
        };
        open.validate()?;
        Ok(open)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != BROKER_PRIVILEGED_AUDIT_OPEN_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "privileged audit open schema is invalid".to_string(),
            ));
        }
        for (value, label) in [
            (&self.audit_id, "privileged audit identifier"),
            (&self.reference_source, "privileged audit reference source"),
            (
                &self.revocation_authority_domain,
                "privileged audit revocation authority domain",
            ),
        ] {
            validate_identifier(value, label, 512)?;
        }
        self.request.validate_bounds()?;
        if self.reference_request_head.is_empty()
            || self.reference_request_head.len() > MAX_WIRE_BYTES
            || !self.reference_request_head.ends_with(b"\r\n\r\n")
            || self.reference_request_body.len() > MAX_BODY_BYTES
        {
            return Err(BrokerError::InvalidRequest(
                "privileged audit reference request is malformed or oversized".to_string(),
            ));
        }
        let observed_commitment = crate::audit::broker_audit_reference_commitment_sha256(
            &self.reference_commitment_salt,
            &self.reference_request_head,
            &self.reference_request_body,
        )?;
        if observed_commitment != self.reference_commitment_sha256 {
            return Err(BrokerError::AuthorizationDenied(
                "privileged audit open request does not match the runner precommitment".to_string(),
            ));
        }
        Ok(())
    }

    fn take_reference(&mut self) -> Result<BrokerAuditReferenceRequest> {
        self.validate()?;
        let expected_commitment_sha256 = self.reference_commitment_sha256.clone();
        BrokerAuditReferenceRequest::from_precommitment(
            std::mem::take(&mut self.reference_request_head),
            std::mem::take(&mut self.reference_request_body),
            std::mem::take(&mut self.reference_commitment_salt),
            &expected_commitment_sha256,
        )
    }
}

impl Drop for BrokerPrivilegedAuditOpenRequest {
    fn drop(&mut self) {
        self.reference_commitment_salt.zeroize();
        self.reference_request_head.zeroize();
        self.reference_request_body.zeroize();
    }
}

impl fmt::Debug for BrokerPrivilegedAuditOpenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerPrivilegedAuditOpenRequest")
            .field("schema", &self.schema)
            .field("audit_id", &self.audit_id)
            .field("reference_source", &self.reference_source)
            .field(
                "revocation_authority_domain",
                &self.revocation_authority_domain,
            )
            .field("request", &"<redacted>")
            .field("reference_commitment_salt", &"<redacted>")
            .field(
                "reference_commitment_sha256",
                &self.reference_commitment_sha256,
            )
            .field("reference_request_head", &"<redacted>")
            .field("reference_request_body", &"<redacted>")
            .finish()
    }
}

/// Broker-signed bridge between the secret-bearing first phase and the runner
/// and operator authorizations supplied in the second phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerPrivilegedAuditChallengeBody {
    pub schema: String,
    pub session_nonce: String,
    pub session_commitment_sha256: String,
    pub runner_authorization_body: BrokerAuditRunnerAuthorizationBody,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl BrokerPrivilegedAuditChallengeBody {
    pub fn validate(&self) -> Result<()> {
        if self.schema != BROKER_PRIVILEGED_AUDIT_CHALLENGE_SCHEMA
            || self.issued_at_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.issued_at_unix_seconds
            || self
                .expires_at_unix_seconds
                .saturating_sub(self.issued_at_unix_seconds)
                > MAX_SESSION_LIFETIME_SECONDS
            || self.runner_authorization_body.issued_at_unix_seconds != self.issued_at_unix_seconds
            || self.runner_authorization_body.expires_at_unix_seconds
                != self.expires_at_unix_seconds
        {
            return Err(BrokerError::InvalidRequest(
                "privileged audit challenge schema or lifetime is invalid".to_string(),
            ));
        }
        validate_digest(&self.session_nonce, "privileged audit session nonce")?;
        validate_digest(
            &self.session_commitment_sha256,
            "privileged audit session commitment",
        )?;
        self.runner_authorization_body.validate()?;
        if self.session_commitment_sha256
            != audit_session_commitment(&self.session_nonce, &self.runner_authorization_body)?
        {
            return Err(BrokerError::AuthorizationDenied(
                "privileged audit challenge commitment is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedBrokerPrivilegedAuditChallenge {
    pub body: BrokerPrivilegedAuditChallengeBody,
    pub signer: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

impl SignedBrokerPrivilegedAuditChallenge {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        verify_broker_privileged_audit_challenge(self, &self.signer)?;
        canonical_json_bytes(self).map_err(|error| {
            BrokerError::Invariant(format!(
                "privileged audit challenge encoding failed: {error}"
            ))
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8], trusted_broker: &PublicKey) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_AUDIT_CONTROL_FRAME_BYTES {
            return Err(BrokerError::InvalidRequest(
                "privileged audit challenge is empty or oversized".to_string(),
            ));
        }
        let challenge: Self = serde_json::from_slice(bytes).map_err(|error| {
            BrokerError::InvalidRequest(format!(
                "privileged audit challenge decoding failed: {error}"
            ))
        })?;
        verify_broker_privileged_audit_challenge(&challenge, trusted_broker)?;
        if canonical_json_bytes(&challenge).map_err(|error| {
            BrokerError::InvalidRequest(format!(
                "privileged audit challenge encoding failed: {error}"
            ))
        })? != bytes
        {
            return Err(BrokerError::InvalidRequest(
                "privileged audit challenge is not canonical JSON".to_string(),
            ));
        }
        Ok(challenge)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeSigningInput<'a> {
    domain: &'static str,
    body: &'a BrokerPrivilegedAuditChallengeBody,
}

fn sign_challenge(
    body: BrokerPrivilegedAuditChallengeBody,
    signer: &dyn SigningBackend,
) -> Result<SignedBrokerPrivilegedAuditChallenge> {
    body.validate()?;
    let input = ChallengeSigningInput {
        domain: CHALLENGE_SIGNATURE_DOMAIN,
        body: &body,
    };
    let canonical = canonical_json_bytes(&input).map_err(|error| {
        BrokerError::Invariant(format!(
            "privileged audit challenge signing input failed: {error}"
        ))
    })?;
    let signed = signer
        .sign_bytes_with_identity(&canonical)
        .map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "privileged audit challenge signing failed: {error}"
            ))
        })?;
    if signed.public_key.algorithm() != signed.algorithm
        || signed.signature.algorithm() != signed.algorithm
        || !signed.public_key.verify(&canonical, &signed.signature)
    {
        return Err(BrokerError::Invariant(
            "privileged audit challenge signer returned invalid identity metadata".to_string(),
        ));
    }
    Ok(SignedBrokerPrivilegedAuditChallenge {
        body,
        signer: signed.public_key,
        algorithm: signed.algorithm,
        signature: signed.signature,
    })
}

pub fn verify_broker_privileged_audit_challenge(
    challenge: &SignedBrokerPrivilegedAuditChallenge,
    trusted_broker: &PublicKey,
) -> Result<()> {
    challenge.body.validate()?;
    if &challenge.signer != trusted_broker
        || challenge.signer.algorithm() != challenge.algorithm
        || challenge.signature.algorithm() != challenge.algorithm
    {
        return Err(BrokerError::AuthorizationDenied(
            "privileged audit challenge signer is invalid".to_string(),
        ));
    }
    let input = ChallengeSigningInput {
        domain: CHALLENGE_SIGNATURE_DOMAIN,
        body: &challenge.body,
    };
    if !challenge
        .signer
        .verify_canonical(&input, &challenge.signature)
        .map_err(|error| {
            BrokerError::AuthorizationDenied(format!(
                "privileged audit challenge verification failed: {error}"
            ))
        })?
    {
        return Err(BrokerError::AuthorizationDenied(
            "privileged audit challenge signature is invalid".to_string(),
        ));
    }
    Ok(())
}

/// Verify that the broker challenge retained the runner's pre-connection
/// reference commitment rather than substituting a broker-selected digest.
pub fn verify_broker_privileged_audit_challenge_reference(
    challenge: &SignedBrokerPrivilegedAuditChallenge,
    trusted_broker: &PublicKey,
    reference_precommitment: &BrokerAuditReferencePrecommitment,
) -> Result<()> {
    verify_broker_privileged_audit_challenge(challenge, trusted_broker)?;
    if challenge
        .body
        .runner_authorization_body
        .reference_commitment_sha256
        != reference_precommitment.commitment_sha256()
    {
        return Err(BrokerError::AuthorizationDenied(
            "privileged audit challenge replaced the runner reference precommitment".to_string(),
        ));
    }
    Ok(())
}

/// Second and final request phase. The governed authorization bytes are
/// destroyed on all return paths.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerPrivilegedAuditCommitRequest {
    pub schema: String,
    pub session_nonce: String,
    pub session_commitment_sha256: String,
    pub runner_authorization: SignedBrokerAuditRunnerAuthorization,
    pub governed_admin_authorization: Vec<u8>,
}

impl BrokerPrivilegedAuditCommitRequest {
    pub fn validate_for(&self, challenge: &SignedBrokerPrivilegedAuditChallenge) -> Result<()> {
        if self.schema != BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA
            || self.session_nonce != challenge.body.session_nonce
            || self.session_commitment_sha256 != challenge.body.session_commitment_sha256
            || self.runner_authorization.body != challenge.body.runner_authorization_body
            || self.governed_admin_authorization.is_empty()
            || self.governed_admin_authorization.len() > 65_536
        {
            return Err(BrokerError::AuthorizationDenied(
                "privileged audit commit is missing, replayed, or rebound".to_string(),
            ));
        }
        verify_broker_privileged_audit_challenge(challenge, &challenge.signer)
    }
}

impl Drop for BrokerPrivilegedAuditCommitRequest {
    fn drop(&mut self) {
        self.governed_admin_authorization.zeroize();
    }
}

impl fmt::Debug for BrokerPrivilegedAuditCommitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerPrivilegedAuditCommitRequest")
            .field("schema", &self.schema)
            .field("session_nonce", &self.session_nonce)
            .field("session_commitment_sha256", &self.session_commitment_sha256)
            .field("runner_authorization", &self.runner_authorization)
            .field("governed_admin_authorization", &"<redacted>")
            .finish()
    }
}

/// Canonical response returned after one successful comparison. It carries all
/// authorization evidence required to reconstruct the chain independently.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerPrivilegedAuditEvidenceBundle {
    pub schema: String,
    pub challenge: SignedBrokerPrivilegedAuditChallenge,
    pub runner_authorization: SignedBrokerAuditRunnerAuthorization,
    pub governed_admin_authorization: Vec<u8>,
    pub liveness_authority_exchange: BrokerPrivilegedAuditAuthorityExchange,
    pub revocation_authority_exchange: BrokerPrivilegedAuditAuthorityExchange,
    pub comparison: SignedBrokerAuditComparison,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerPrivilegedAuditAuthorityExchange {
    pub request: SignedAuthorityRequest,
    pub response: SignedAuthorityResponse,
    pub trusted_authority: PublicKey,
    pub verified_at_unix_seconds: u64,
    pub maximum_clock_skew_seconds: u64,
    pub request_sha256: String,
    pub response_sha256: String,
}

impl BrokerPrivilegedAuditAuthorityExchange {
    fn from_verified(exchange: &VerifiedAuthorityExchange) -> Result<Self> {
        Ok(Self {
            request: exchange.request().clone(),
            response: exchange.response().clone(),
            trusted_authority: exchange.trusted_authority().clone(),
            verified_at_unix_seconds: exchange.verified_at_unix_seconds(),
            maximum_clock_skew_seconds: exchange.maximum_clock_skew_seconds(),
            request_sha256: exchange.request_sha256()?,
            response_sha256: exchange.response_sha256()?,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.verified_at_unix_seconds == 0
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > 60
            || self.response.body.authority != self.trusted_authority
        {
            return Err(BrokerError::Invariant(
                "privileged audit authority exchange metadata is invalid".to_string(),
            ));
        }
        validate_digest(
            &self.request_sha256,
            "privileged audit authority request digest",
        )?;
        validate_digest(
            &self.response_sha256,
            "privileged audit authority response digest",
        )
    }

    pub fn verify(&self) -> Result<VerifiedAuthorityExchange> {
        self.validate()?;
        let verified = verify_authority_exchange(
            self.request.clone(),
            self.response.clone(),
            &self.trusted_authority,
            self.verified_at_unix_seconds,
            self.maximum_clock_skew_seconds,
        )?;
        if verified.request_sha256()? != self.request_sha256
            || verified.response_sha256()? != self.response_sha256
        {
            return Err(BrokerError::AuthorizationDenied(
                "privileged audit authority exchange digest is invalid".to_string(),
            ));
        }
        Ok(verified)
    }
}

impl BrokerPrivilegedAuditEvidenceBundle {
    fn validate(&self) -> Result<()> {
        if self.schema != BROKER_PRIVILEGED_AUDIT_EVIDENCE_SCHEMA
            || self.runner_authorization.body != self.challenge.body.runner_authorization_body
            || self.governed_admin_authorization.is_empty()
            || self.governed_admin_authorization.len() > 65_536
        {
            return Err(BrokerError::Invariant(
                "privileged audit evidence bundle is internally inconsistent".to_string(),
            ));
        }
        let _runner_canonical = self.runner_authorization.canonical_bytes()?;
        verify_broker_audit_comparison(&self.comparison, &self.challenge.signer)?;
        let _liveness = self.liveness_authority_exchange.verify()?;
        let _revocation = self.revocation_authority_exchange.verify()?;
        if self.liveness_authority_exchange.trusted_authority
            != self.revocation_authority_exchange.trusted_authority
        {
            return Err(BrokerError::Invariant(
                "privileged audit authority exchanges use different trust roots".to_string(),
            ));
        }
        verify_broker_privileged_audit_challenge(&self.challenge, &self.challenge.signer)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_json_bytes(self).map_err(|error| {
            BrokerError::Invariant(format!(
                "privileged audit evidence encoding failed: {error}"
            ))
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8], trusted_broker: &PublicKey) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_AUDIT_EVIDENCE_FRAME_BYTES {
            return Err(BrokerError::InvalidRequest(
                "privileged audit evidence is empty or oversized".to_string(),
            ));
        }
        let bundle: Self = serde_json::from_slice(bytes).map_err(|error| {
            BrokerError::InvalidRequest(format!(
                "privileged audit evidence decoding failed: {error}"
            ))
        })?;
        bundle.validate()?;
        verify_broker_privileged_audit_challenge(&bundle.challenge, trusted_broker)?;
        verify_broker_audit_comparison(&bundle.comparison, trusted_broker)?;
        let canonical = Zeroizing::new(canonical_json_bytes(&bundle).map_err(|error| {
            BrokerError::InvalidRequest(format!(
                "privileged audit evidence encoding failed: {error}"
            ))
        })?);
        if canonical.as_slice() != bytes {
            return Err(BrokerError::InvalidRequest(
                "privileged audit evidence is not canonical JSON".to_string(),
            ));
        }
        Ok(bundle)
    }

    pub fn verified_authority_exchanges(
        &self,
    ) -> Result<(VerifiedAuthorityExchange, VerifiedAuthorityExchange)> {
        Ok((
            self.liveness_authority_exchange.verify()?,
            self.revocation_authority_exchange.verify()?,
        ))
    }

    pub fn admin_authorization(&self) -> Result<AdminAuthorization> {
        AdminAuthorization::new(self.governed_admin_authorization.clone())
    }
}

impl Drop for BrokerPrivilegedAuditEvidenceBundle {
    fn drop(&mut self) {
        self.governed_admin_authorization.zeroize();
    }
}

impl fmt::Debug for BrokerPrivilegedAuditEvidenceBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerPrivilegedAuditEvidenceBundle")
            .field("schema", &self.schema)
            .field("challenge", &self.challenge)
            .field("runner_authorization", &self.runner_authorization)
            .field("governed_admin_authorization", &"<redacted>")
            .field("comparison", &self.comparison)
            .finish()
    }
}

#[cfg(unix)]
pub(crate) trait BrokerPrivilegedAuditHandler: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64>;

    fn compare(
        &self,
        request: &BrokerExecuteRequest,
        reference: BrokerAuditReferenceRequest,
        runner_authorization: &SignedBrokerAuditRunnerAuthorization,
        admin_authorization: &AdminAuthorization,
    ) -> Result<CompletedBrokerAuditComparison>;
}

#[cfg(unix)]
#[derive(Clone)]
pub(crate) struct BrokerPrivilegedAuditEndpointConfig {
    pub socket_path: PathBuf,
    pub trusted_service_uid: u32,
    pub authorized_runner_uid: u32,
    pub authorized_runner_gid: u32,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub authorization_lifetime_seconds: u64,
    pub deployment_id: String,
    pub broker_instance_id: String,
    pub tenant_scope: String,
    pub runner_id: String,
}

#[cfg(unix)]
impl BrokerPrivilegedAuditEndpointConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_audit_socket_path(&self.socket_path)?;
        for (value, label) in [
            (
                &self.deployment_id,
                "privileged audit deployment identifier",
            ),
            (
                &self.broker_instance_id,
                "privileged audit broker instance identifier",
            ),
            (&self.tenant_scope, "privileged audit tenant scope"),
            (&self.runner_id, "privileged audit runner identifier"),
        ] {
            validate_identifier(value, label, 512)?;
        }
        validate_audit_deadlines(self.read_timeout_ms, self.write_timeout_ms)?;
        if self.trusted_service_uid == u32::MAX
            || self.authorized_runner_uid == u32::MAX
            || self.authorized_runner_gid == u32::MAX
            || self.authorization_lifetime_seconds == 0
            || self.authorization_lifetime_seconds > MAX_SESSION_LIFETIME_SECONDS
        {
            return Err(BrokerError::InvalidRequest(
                "privileged audit identity or authorization lifetime is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerPrivilegedAuditServeOutcome {
    EvidenceWritten,
    ClientFault { diagnostic_code: &'static str },
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuditSocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
pub(crate) struct BrokerPrivilegedAuditEndpoint {
    listener: UnixListener,
    config: BrokerPrivilegedAuditEndpointConfig,
    challenge_signer: Arc<dyn SigningBackend>,
    handler: Arc<dyn BrokerPrivilegedAuditHandler>,
    socket_identity: AuditSocketIdentity,
    _lifecycle_lock: File,
}

#[cfg(unix)]
impl BrokerPrivilegedAuditEndpoint {
    pub(crate) fn bind(
        config: BrokerPrivilegedAuditEndpointConfig,
        challenge_signer: Arc<dyn SigningBackend>,
        handler: Arc<dyn BrokerPrivilegedAuditHandler>,
    ) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(BrokerError::AuthorityUnavailable(
                "privileged audit peer authentication requires Linux".to_string(),
            ));
        }
        config.validate()?;
        prepare_audit_socket_parent(
            &config.socket_path,
            config.trusted_service_uid,
            config.authorized_runner_gid,
        )?;
        let lifecycle_lock =
            acquire_audit_lifecycle_lock(&config.socket_path, config.trusted_service_uid)?;
        if config.socket_path.exists() {
            return Err(BrokerError::Storage(
                "privileged audit socket path already exists".to_string(),
            ));
        }
        let listener = UnixListener::bind(&config.socket_path).map_err(|error| {
            BrokerError::Storage(format!("privileged audit socket bind failed: {error}"))
        })?;
        let cleanup = AuditSocketCleanup::new(&config.socket_path)?;
        set_audit_socket_custody(
            &config.socket_path,
            config.trusted_service_uid,
            config.authorized_runner_gid,
        )?;
        let socket_identity = validate_audit_socket_identity(
            &config.socket_path,
            config.trusted_service_uid,
            config.authorized_runner_gid,
        )?;
        if socket_identity != cleanup.identity {
            return Err(BrokerError::Custody(
                "privileged audit socket identity changed during bind".to_string(),
            ));
        }
        let endpoint = Self {
            listener,
            config,
            challenge_signer,
            handler,
            socket_identity,
            _lifecycle_lock: lifecycle_lock,
        };
        cleanup.disarm();
        Ok(endpoint)
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener.set_nonblocking(nonblocking).map_err(|error| {
            BrokerError::Storage(format!("privileged audit listener mode failed: {error}"))
        })
    }

    pub(crate) fn try_serve_one(&self) -> Result<Option<BrokerPrivilegedAuditServeOutcome>> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => {
                return Err(BrokerError::Storage(format!(
                    "privileged audit accept failed: {error}"
                )))
            }
        };
        let outcome = match self.serve_stream(stream) {
            Ok(()) => BrokerPrivilegedAuditServeOutcome::EvidenceWritten,
            Err(error)
                if matches!(
                    &error,
                    BrokerError::InvalidRequest(_)
                        | BrokerError::AuthorizationDenied(_)
                        | BrokerError::Conflict(_)
                ) =>
            {
                BrokerPrivilegedAuditServeOutcome::ClientFault {
                    diagnostic_code: error.diagnostic_code(),
                }
            }
            Err(error) => return Err(error),
        };
        Ok(Some(outcome))
    }

    fn serve_stream(&self, stream: UnixStream) -> Result<()> {
        let mut stream = AuditDeadlineIo::new(
            stream,
            self.config.read_timeout_ms,
            self.config.write_timeout_ms,
        )?;
        validate_audit_peer(
            stream.stream(),
            self.config.authorized_runner_uid,
            self.config.authorized_runner_gid,
        )?;
        let mut open: BrokerPrivilegedAuditOpenRequest =
            read_canonical_frame(&mut stream, MAX_AUDIT_OPEN_FRAME_BYTES, "open")?;
        let reference = open.take_reference()?;
        let issued_at_unix_seconds = self.handler.now_unix_seconds()?;
        let expires_at_unix_seconds = issued_at_unix_seconds
            .checked_add(self.config.authorization_lifetime_seconds)
            .ok_or_else(|| {
                BrokerError::InvalidRequest(
                    "privileged audit challenge lifetime overflow".to_string(),
                )
            })?;
        let runner_authorization_body = BrokerAuditRunnerAuthorizationBody::for_request(
            &open.request,
            &reference,
            BrokerAuditRunnerScope {
                audit_id: &open.audit_id,
                deployment_id: &self.config.deployment_id,
                broker_instance_id: &self.config.broker_instance_id,
                tenant_scope: &self.config.tenant_scope,
                runner_id: &self.config.runner_id,
                reference_source: &open.reference_source,
                revocation_authority_domain: &open.revocation_authority_domain,
            },
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        )?;
        let session_nonce = generate_session_nonce()?;
        let session_commitment_sha256 =
            audit_session_commitment(&session_nonce, &runner_authorization_body)?;
        let challenge = sign_challenge(
            BrokerPrivilegedAuditChallengeBody {
                schema: BROKER_PRIVILEGED_AUDIT_CHALLENGE_SCHEMA.to_string(),
                session_nonce,
                session_commitment_sha256,
                runner_authorization_body,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            },
            self.challenge_signer.as_ref(),
        )?;
        write_canonical_frame(
            &mut stream,
            &challenge,
            MAX_AUDIT_CONTROL_FRAME_BYTES,
            "challenge",
        )?;
        let mut commit: BrokerPrivilegedAuditCommitRequest =
            read_canonical_frame(&mut stream, MAX_AUDIT_CONTROL_FRAME_BYTES, "commit")?;
        commit.validate_for(&challenge)?;
        if self.handler.now_unix_seconds()? >= challenge.body.expires_at_unix_seconds {
            return Err(BrokerError::AuthorizationDenied(
                "privileged audit session expired before commit".to_string(),
            ));
        }
        let mut governed_admin_authorization =
            Zeroizing::new(std::mem::take(&mut commit.governed_admin_authorization));
        let admin = AdminAuthorization::new(governed_admin_authorization.as_slice().to_vec())?;
        let completed = self.handler.compare(
            &open.request,
            reference,
            &commit.runner_authorization,
            &admin,
        )?;
        let liveness_authority_exchange = BrokerPrivilegedAuditAuthorityExchange::from_verified(
            &completed.liveness_authority_exchange,
        )?;
        let revocation_authority_exchange = BrokerPrivilegedAuditAuthorityExchange::from_verified(
            &completed.revocation_authority_exchange,
        )?;
        let bundle = BrokerPrivilegedAuditEvidenceBundle {
            schema: BROKER_PRIVILEGED_AUDIT_EVIDENCE_SCHEMA.to_string(),
            challenge,
            runner_authorization: commit.runner_authorization.clone(),
            governed_admin_authorization: std::mem::take(&mut *governed_admin_authorization),
            liveness_authority_exchange,
            revocation_authority_exchange,
            comparison: completed.comparison,
        };
        bundle.validate()?;
        write_canonical_frame(
            &mut stream,
            &bundle,
            MAX_AUDIT_EVIDENCE_FRAME_BYTES,
            "evidence",
        )
    }
}

#[cfg(unix)]
impl Drop for BrokerPrivilegedAuditEndpoint {
    fn drop(&mut self) {
        if validate_audit_socket_identity(
            &self.config.socket_path,
            self.config.trusted_service_uid,
            self.config.authorized_runner_gid,
        )
        .is_ok_and(|identity| identity == self.socket_identity)
        {
            let _remove_result = std::fs::remove_file(&self.config.socket_path);
        }
    }
}

#[cfg(unix)]
struct AuditDeadlineIo {
    stream: UnixStream,
    read_deadline: Instant,
    write_deadline: Instant,
    read_deadline_setup_failed: bool,
    write_deadline_setup_failed: bool,
}

#[cfg(unix)]
impl AuditDeadlineIo {
    fn new(stream: UnixStream, read_timeout_ms: u64, write_timeout_ms: u64) -> Result<Self> {
        validate_audit_deadlines(read_timeout_ms, write_timeout_ms)?;
        let now = Instant::now();
        let read_timeout = Duration::from_millis(read_timeout_ms);
        let write_timeout = Duration::from_millis(write_timeout_ms);
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|error| {
                BrokerError::Storage(format!(
                    "privileged audit read deadline setup failed: {error}"
                ))
            })?;
        stream
            .set_write_timeout(Some(write_timeout))
            .map_err(|error| {
                BrokerError::Storage(format!(
                    "privileged audit write deadline setup failed: {error}"
                ))
            })?;
        Ok(Self {
            stream,
            read_deadline: now.checked_add(read_timeout).ok_or_else(|| {
                BrokerError::InvalidRequest("privileged audit read deadline overflow".to_string())
            })?,
            write_deadline: now.checked_add(write_timeout).ok_or_else(|| {
                BrokerError::InvalidRequest("privileged audit write deadline overflow".to_string())
            })?,
            read_deadline_setup_failed: false,
            write_deadline_setup_failed: false,
        })
    }

    fn stream(&self) -> &UnixStream {
        &self.stream
    }

    fn remaining(deadline: Instant, label: &'static str) -> std::io::Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, label))
    }
}

#[cfg(unix)]
impl Read for AuditDeadlineIo {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = Self::remaining(
            self.read_deadline,
            "privileged audit absolute read deadline elapsed",
        )?;
        if let Err(error) = self.stream.set_read_timeout(Some(remaining)) {
            self.read_deadline_setup_failed = true;
            return Err(error);
        }
        self.stream.read(buffer)
    }
}

#[cfg(unix)]
impl Write for AuditDeadlineIo {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = Self::remaining(
            self.write_deadline,
            "privileged audit absolute write deadline elapsed",
        )?;
        if let Err(error) = self.stream.set_write_timeout(Some(remaining)) {
            self.write_deadline_setup_failed = true;
            return Err(error);
        }
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let remaining = Self::remaining(
            self.write_deadline,
            "privileged audit absolute write deadline elapsed",
        )?;
        if let Err(error) = self.stream.set_write_timeout(Some(remaining)) {
            self.write_deadline_setup_failed = true;
            return Err(error);
        }
        self.stream.flush()
    }
}

#[cfg(unix)]
fn read_canonical_frame<T: DeserializeOwned + Serialize>(
    reader: &mut AuditDeadlineIo,
    maximum: usize,
    phase: &str,
) -> Result<T> {
    let bytes = Zeroizing::new(read_frame(reader, maximum).map_err(|error| {
        if reader.read_deadline_setup_failed {
            BrokerError::Storage(format!(
                "privileged audit read deadline maintenance failed: {error}"
            ))
        } else {
            error
        }
    })?);
    let decoded: T = serde_json::from_slice(bytes.as_slice()).map_err(|error| {
        BrokerError::InvalidRequest(format!("privileged audit {phase} decoding failed: {error}"))
    })?;
    let canonical = Zeroizing::new(canonical_json_bytes(&decoded).map_err(|error| {
        BrokerError::InvalidRequest(format!("privileged audit {phase} encoding failed: {error}"))
    })?);
    if canonical.as_slice() != bytes.as_slice() {
        return Err(BrokerError::InvalidRequest(format!(
            "privileged audit {phase} is not canonical JSON"
        )));
    }
    Ok(decoded)
}

#[cfg(unix)]
fn write_canonical_frame<T: Serialize>(
    writer: &mut AuditDeadlineIo,
    value: &T,
    maximum: usize,
    phase: &str,
) -> Result<()> {
    let encoded = Zeroizing::new(canonical_json_bytes(value).map_err(|error| {
        BrokerError::Invariant(format!("privileged audit {phase} encoding failed: {error}"))
    })?);
    write_frame(writer, encoded.as_slice(), maximum).map_err(|error| {
        if writer.write_deadline_setup_failed {
            BrokerError::Storage(format!(
                "privileged audit write deadline maintenance failed: {error}"
            ))
        } else {
            error
        }
    })
}

#[cfg(unix)]
fn read_frame(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(|error| {
        BrokerError::InvalidRequest(format!("privileged audit frame prefix failed: {error}"))
    })?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| {
        BrokerError::InvalidRequest("privileged audit frame length overflow".to_string())
    })?;
    if length == 0 || length > maximum {
        return Err(BrokerError::InvalidRequest(
            "privileged audit frame is empty or oversized".to_string(),
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes).map_err(|error| {
        BrokerError::InvalidRequest(format!("privileged audit frame body failed: {error}"))
    })?;
    Ok(bytes)
}

#[cfg(unix)]
fn write_frame(writer: &mut impl Write, bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(BrokerError::Invariant(
            "privileged audit response frame is empty or oversized".to_string(),
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| {
        BrokerError::Invariant("privileged audit response length overflow".to_string())
    })?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(bytes))
        .and_then(|()| writer.flush())
        .map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
            ) {
                BrokerError::InvalidRequest(format!(
                    "privileged audit runner stopped receiving: {error}"
                ))
            } else {
                BrokerError::Storage(format!("privileged audit response write failed: {error}"))
            }
        })
}

#[cfg(unix)]
pub fn write_privileged_audit_open_frame(
    writer: &mut impl Write,
    open: &BrokerPrivilegedAuditOpenRequest,
) -> Result<()> {
    open.validate()?;
    let encoded = Zeroizing::new(canonical_json_bytes(open).map_err(|error| {
        BrokerError::InvalidRequest(format!("privileged audit open encoding failed: {error}"))
    })?);
    write_frame(writer, encoded.as_slice(), MAX_AUDIT_OPEN_FRAME_BYTES)
}

#[cfg(unix)]
pub fn read_privileged_audit_challenge_frame(
    reader: &mut impl Read,
    trusted_broker: &PublicKey,
    reference_precommitment: &BrokerAuditReferencePrecommitment,
) -> Result<SignedBrokerPrivilegedAuditChallenge> {
    let encoded = Zeroizing::new(read_frame(reader, MAX_AUDIT_CONTROL_FRAME_BYTES)?);
    let challenge = SignedBrokerPrivilegedAuditChallenge::from_canonical_bytes(
        encoded.as_slice(),
        trusted_broker,
    )?;
    verify_broker_privileged_audit_challenge_reference(
        &challenge,
        trusted_broker,
        reference_precommitment,
    )?;
    Ok(challenge)
}

#[cfg(unix)]
pub fn write_privileged_audit_commit_frame(
    writer: &mut impl Write,
    commit: &BrokerPrivilegedAuditCommitRequest,
    challenge: &SignedBrokerPrivilegedAuditChallenge,
) -> Result<()> {
    commit.validate_for(challenge)?;
    let encoded = Zeroizing::new(canonical_json_bytes(commit).map_err(|error| {
        BrokerError::InvalidRequest(format!("privileged audit commit encoding failed: {error}"))
    })?);
    write_frame(writer, encoded.as_slice(), MAX_AUDIT_CONTROL_FRAME_BYTES)
}

#[cfg(unix)]
pub fn read_privileged_audit_evidence_frame(
    reader: &mut impl Read,
    trusted_broker: &PublicKey,
) -> Result<BrokerPrivilegedAuditEvidenceBundle> {
    let encoded = Zeroizing::new(read_frame(reader, MAX_AUDIT_EVIDENCE_FRAME_BYTES)?);
    BrokerPrivilegedAuditEvidenceBundle::from_canonical_bytes(encoded.as_slice(), trusted_broker)
}

fn audit_session_commitment(
    session_nonce: &str,
    body: &BrokerAuditRunnerAuthorizationBody,
) -> Result<String> {
    validate_digest(session_nonce, "privileged audit session nonce")?;
    body.validate()?;
    let canonical = canonical_json_bytes(body).map_err(|error| {
        BrokerError::Invariant(format!(
            "privileged audit session commitment encoding failed: {error}"
        ))
    })?;
    let nonce_length = u64::try_from(session_nonce.len()).map_err(|_| {
        BrokerError::Invariant("privileged audit nonce length overflow".to_string())
    })?;
    let body_length = u64::try_from(canonical.len())
        .map_err(|_| BrokerError::Invariant("privileged audit body length overflow".to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(SESSION_COMMITMENT_DOMAIN);
    hasher.update(nonce_length.to_be_bytes());
    hasher.update(session_nonce.as_bytes());
    hasher.update(body_length.to_be_bytes());
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(unix)]
fn generate_session_nonce() -> Result<String> {
    let mut nonce = Zeroizing::new([0_u8; 32]);
    OsRng.try_fill_bytes(&mut nonce[..]).map_err(|_| {
        BrokerError::AuthorityUnavailable(
            "privileged audit session randomness is unavailable".to_string(),
        )
    })?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(BrokerError::AuthorityUnavailable(
            "privileged audit session randomness is invalid".to_string(),
        ));
    }
    Ok(hex::encode(nonce.as_slice()))
}

#[cfg(unix)]
fn validate_audit_deadlines(read_timeout_ms: u64, write_timeout_ms: u64) -> Result<()> {
    if read_timeout_ms == 0
        || read_timeout_ms > 30_000
        || write_timeout_ms == 0
        || write_timeout_ms > 30_000
    {
        return Err(BrokerError::InvalidRequest(
            "privileged audit deadlines must be between 1 and 30000 milliseconds".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_audit_socket_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > 100
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(BrokerError::InvalidRequest(
            "privileged audit socket path is not a normalized absolute Unix path".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_audit_peer(stream: &UnixStream, expected_uid: u32, expected_gid: u32) -> Result<()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(|error| {
        BrokerError::Storage(format!(
            "privileged audit peer credential lookup failed: {error}"
        ))
    })?;
    if credentials.uid.as_raw() != expected_uid || credentials.gid.as_raw() != expected_gid {
        return Err(BrokerError::AuthorizationDenied(
            "privileged audit peer UID or GID is not authorized".to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_audit_peer(_stream: &UnixStream, _expected_uid: u32, _expected_gid: u32) -> Result<()> {
    Err(BrokerError::AuthorityUnavailable(
        "privileged audit peer credentials require Linux".to_string(),
    ))
}

#[cfg(unix)]
fn prepare_audit_socket_parent(path: &Path, service_uid: u32, runner_gid: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        BrokerError::Storage("privileged audit socket has no parent directory".to_string())
    })?;
    match std::fs::symlink_metadata(parent) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let grandparent = parent.parent().ok_or_else(|| {
                BrokerError::Storage(
                    "privileged audit socket parent has no trusted ancestor".to_string(),
                )
            })?;
            let ancestor = std::fs::symlink_metadata(grandparent).map_err(|metadata_error| {
                BrokerError::Storage(format!(
                    "privileged audit ancestor metadata failed: {metadata_error}"
                ))
            })?;
            if !ancestor.file_type().is_dir()
                || ancestor.uid() != service_uid
                || ancestor.permissions().mode() & 0o022 != 0
            {
                return Err(BrokerError::Custody(
                    "privileged audit ancestor is not controlled by the service UID".to_string(),
                ));
            }
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(AUDIT_SOCKET_DIRECTORY_MODE);
            builder.create(parent).map_err(|create_error| {
                BrokerError::Storage(format!(
                    "privileged audit socket directory creation failed: {create_error}"
                ))
            })?;
        }
        Err(error) => {
            return Err(BrokerError::Storage(format!(
                "privileged audit socket directory metadata failed: {error}"
            )))
        }
    }
    let metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        BrokerError::Storage(format!(
            "privileged audit socket directory metadata failed: {error}"
        ))
    })?;
    if !metadata.file_type().is_dir() || metadata.uid() != service_uid {
        return Err(BrokerError::Custody(
            "privileged audit socket directory owner or type is invalid".to_string(),
        ));
    }
    if metadata.gid() != runner_gid {
        rustix::fs::chown(
            parent,
            Some(rustix::process::Uid::from_raw(service_uid)),
            Some(rustix::process::Gid::from_raw(runner_gid)),
        )
        .map_err(|error| {
            BrokerError::Custody(format!(
                "privileged audit socket directory group setup failed: {error}"
            ))
        })?;
    }
    std::fs::set_permissions(
        parent,
        std::fs::Permissions::from_mode(AUDIT_SOCKET_DIRECTORY_MODE),
    )
    .map_err(|error| {
        BrokerError::Storage(format!(
            "privileged audit socket directory permissions failed: {error}"
        ))
    })?;
    let retained = std::fs::symlink_metadata(parent).map_err(|error| {
        BrokerError::Storage(format!(
            "privileged audit socket directory revalidation failed: {error}"
        ))
    })?;
    if !retained.file_type().is_dir()
        || retained.uid() != service_uid
        || retained.gid() != runner_gid
        || retained.permissions().mode() & 0o777 != AUDIT_SOCKET_DIRECTORY_MODE
        || std::fs::canonicalize(parent).map_err(|error| {
            BrokerError::Storage(format!(
                "privileged audit socket directory canonicalization failed: {error}"
            ))
        })? != parent
    {
        return Err(BrokerError::Custody(
            "privileged audit socket directory custody is invalid".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_audit_socket_custody(path: &Path, service_uid: u32, runner_gid: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        BrokerError::Storage(format!("privileged audit socket metadata failed: {error}"))
    })?;
    if metadata.gid() != runner_gid {
        rustix::fs::chown(
            path,
            Some(rustix::process::Uid::from_raw(service_uid)),
            Some(rustix::process::Gid::from_raw(runner_gid)),
        )
        .map_err(|error| {
            BrokerError::Custody(format!(
                "privileged audit socket group setup failed: {error}"
            ))
        })?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(AUDIT_SOCKET_MODE)).map_err(
        |error| {
            BrokerError::Storage(format!(
                "privileged audit socket permissions failed: {error}"
            ))
        },
    )
}

#[cfg(unix)]
fn validate_audit_socket_identity(
    path: &Path,
    service_uid: u32,
    runner_gid: u32,
) -> Result<AuditSocketIdentity> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        BrokerError::Storage(format!("privileged audit socket metadata failed: {error}"))
    })?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != service_uid
        || metadata.gid() != runner_gid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != AUDIT_SOCKET_MODE
    {
        return Err(BrokerError::Custody(
            "privileged audit socket ownership or permissions are invalid".to_string(),
        ));
    }
    Ok(AuditSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn acquire_audit_lifecycle_lock(path: &Path, service_uid: u32) -> Result<File> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lifecycle.lock");
    let lock_path = PathBuf::from(lock_path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    options.custom_flags(i32::try_from(flags.bits()).map_err(|_| {
        BrokerError::Storage("privileged audit lifecycle lock flags are invalid".to_string())
    })?);
    let lock = options.open(&lock_path).map_err(|error| {
        BrokerError::Storage(format!(
            "privileged audit lifecycle lock open failed: {error}"
        ))
    })?;
    let path_metadata = std::fs::symlink_metadata(&lock_path).map_err(|error| {
        BrokerError::Storage(format!(
            "privileged audit lifecycle lock metadata failed: {error}"
        ))
    })?;
    let descriptor_metadata = lock.metadata().map_err(|error| {
        BrokerError::Storage(format!(
            "privileged audit lifecycle lock descriptor failed: {error}"
        ))
    })?;
    if !path_metadata.file_type().is_file()
        || path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
        || descriptor_metadata.uid() != service_uid
        || descriptor_metadata.nlink() != 1
        || descriptor_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerError::Custody(
            "privileged audit lifecycle lock identity is invalid".to_string(),
        ));
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |error| {
            BrokerError::AuthorityUnavailable(format!(
                "privileged audit socket is owned by another daemon: {error}"
            ))
        },
    )?;
    Ok(lock)
}

#[cfg(unix)]
struct AuditSocketCleanup {
    path: PathBuf,
    identity: AuditSocketIdentity,
    armed: std::cell::Cell<bool>,
}

#[cfg(unix)]
impl AuditSocketCleanup {
    fn new(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            BrokerError::Storage(format!(
                "provisional privileged audit socket metadata failed: {error}"
            ))
        })?;
        if !metadata.file_type().is_socket() {
            return Err(BrokerError::Custody(
                "provisional privileged audit path is not a socket".to_string(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            identity: AuditSocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            armed: std::cell::Cell::new(true),
        })
    }

    fn disarm(&self) {
        self.armed.set(false);
    }
}

#[cfg(unix)]
impl Drop for AuditSocketCleanup {
    fn drop(&mut self) {
        if !self.armed.get() {
            return;
        }
        let is_exact_socket = std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.identity.device
                && metadata.ino() == self.identity.inode
        });
        if is_exact_socket {
            let _remove_result = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::{Ed25519Backend, Keypair};
    use chio_test_support::prelude::*;

    #[test]
    fn signed_challenge_rejects_nonce_and_commitment_rebinding() {
        let signer = Keypair::from_seed(&[201; 32]);
        let runner_body = BrokerAuditRunnerAuthorizationBody {
            schema: crate::audit::BROKER_AUDIT_RUNNER_AUTHORIZATION_SCHEMA.to_string(),
            audit_id: "audit-production-1".to_string(),
            deployment_id: "deployment-production".to_string(),
            broker_instance_id: "broker-production-1".to_string(),
            tenant_scope: "tenant-production".to_string(),
            runner_id: "runner-production-1".to_string(),
            reference_source: "legacy-production".to_string(),
            reference_commitment_sha256: "1".repeat(64),
            capability_sha256: "2".repeat(64),
            proof_sha256: "3".repeat(64),
            canonical_request_sha256: "4".repeat(64),
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            credential_provider: "generic-https".to_string(),
            revocation_authority_domain: "authority-production".to_string(),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 130,
        };
        let session_nonce = "5".repeat(64);
        let challenge = sign_challenge(
            BrokerPrivilegedAuditChallengeBody {
                schema: BROKER_PRIVILEGED_AUDIT_CHALLENGE_SCHEMA.to_string(),
                session_commitment_sha256: audit_session_commitment(&session_nonce, &runner_body)
                    .test_expect("session commitment"),
                session_nonce,
                runner_authorization_body: runner_body,
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: 130,
            },
            &Ed25519Backend::new(signer.clone()),
        )
        .test_expect("signed challenge");
        verify_broker_privileged_audit_challenge(&challenge, &signer.public_key())
            .test_expect("valid challenge");

        let runner = Ed25519Backend::new(Keypair::from_seed(&[202; 32]));
        let runner_authorization = SignedBrokerAuditRunnerAuthorization::sign(
            challenge.body.runner_authorization_body.clone(),
            &runner,
        )
        .test_expect("runner authorization");
        let valid_commit = BrokerPrivilegedAuditCommitRequest {
            schema: BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA.to_string(),
            session_nonce: challenge.body.session_nonce.clone(),
            session_commitment_sha256: challenge.body.session_commitment_sha256.clone(),
            runner_authorization: runner_authorization.clone(),
            governed_admin_authorization: b"opaque-governed-authorization".to_vec(),
        };
        valid_commit
            .validate_for(&challenge)
            .test_expect("exact commit");
        let replayed_commit = BrokerPrivilegedAuditCommitRequest {
            schema: BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA.to_string(),
            session_nonce: "8".repeat(64),
            session_commitment_sha256: challenge.body.session_commitment_sha256.clone(),
            runner_authorization,
            governed_admin_authorization: b"opaque-governed-authorization".to_vec(),
        };
        replayed_commit
            .validate_for(&challenge)
            .test_expect_err("session replay must fail");

        let mut rebound = challenge.clone();
        rebound.body.session_nonce = "6".repeat(64);
        assert!(verify_broker_privileged_audit_challenge(&rebound, &signer.public_key()).is_err());

        let mut forged_commitment = challenge;
        forged_commitment.body.session_commitment_sha256 = "7".repeat(64);
        assert!(
            verify_broker_privileged_audit_challenge(&forged_commitment, &signer.public_key())
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn audit_peer_authentication_pins_uid_and_gid() {
        let (client, server) = UnixStream::pair().test_expect("Unix pair");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        validate_audit_peer(&server, uid, gid).test_expect("matching peer");
        assert!(validate_audit_peer(&client, uid.wrapping_add(1), gid).is_err());
        assert!(validate_audit_peer(&client, uid, gid.wrapping_add(1)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn generated_session_nonce_is_a_nonzero_digest() {
        let nonce = generate_session_nonce().test_expect("nonce");
        validate_digest(&nonce, "session nonce").test_expect("digest-shaped nonce");
        assert_ne!(nonce, "0".repeat(64));
    }
}
