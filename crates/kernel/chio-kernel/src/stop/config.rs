//! Signed stop-operator deployment configuration (`chio.stop-operator-config.v1`).
//!
//! One document per admission authority names the kernel-scope operator
//! roster, its quorum threshold, the resume policy and the pinned
//! time-attestation key. A configuration root, pinned in each host's boot
//! configuration, signs it. Verification is offline: signatures and structure
//! only, with no store reads and no clock. A document that replaces an
//! installed one also needs approvals from a quorum of the installed roster.

use std::collections::BTreeSet;

use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::crypto::{verify_wrapped_bytes, Keypair, PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};

use super::StopScope;

pub const STOP_OPERATOR_CONFIG_SCHEMA: &str = "chio.stop-operator-config.v1";
pub const STOP_OPERATOR_CONFIG_APPROVAL_SCHEMA: &str = "chio.stop-operator-config-approval.v1";
/// Upper bound on the encoded document.
pub const MAX_STOP_OPERATOR_CONFIG_BYTES: usize = 64 * 1024;
/// Upper bound on the principals of one roster.
pub const MAX_STOP_ROSTER_PRINCIPALS: usize = 256;
pub const DEFAULT_STOP_QUORUM_MAX: u16 = 8;
/// Hard ceiling on the configured `stop_quorum_max`.
pub const STOP_QUORUM_MAX_LIMIT: u16 = 64;
pub const MIN_SAME_PRINCIPAL_COOLDOWN_MS: u64 = 300_000;

const PRINCIPAL_DOMAIN: &[u8] = b"chio.stop-principal.v1\0";

/// A roster principal: SHA-256 over a domain tag and the subject key's hex
/// encoding, as 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    #[must_use]
    pub fn from_subject_key(key: &PublicKey) -> Self {
        let mut material = PRINCIPAL_DOMAIN.to_vec();
        material.extend_from_slice(key.to_hex().as_bytes());
        Self(chio_core_types::sha256_hex(&material))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopPermissions {
    pub stop: bool,
    pub resume: bool,
    pub restrict: bool,
    pub relax: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterPrincipalV1 {
    pub principal: PrincipalId,
    pub subject_key: PublicKey,
    pub permissions: StopPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopRosterV1 {
    pub scope: StopScope,
    /// Strictly ascending by principal.
    pub principals: Vec<RosterPrincipalV1>,
    /// Distinct principals a quorum needs, `1..=stop_quorum_max`.
    pub quorum_k: u16,
}

impl StopRosterV1 {
    pub fn digest(&self) -> Result<String, StopConfigError> {
        canonical_digest(self)
    }

    #[must_use]
    pub fn principal(&self, principal: &PrincipalId) -> Option<&RosterPrincipalV1> {
        self.principals
            .binary_search_by(|entry| entry.principal.cmp(principal))
            .ok()
            .and_then(|index| self.principals.get(index))
    }
}

/// Who may resume a stopped scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumePolicyV1 {
    /// A principal outside the incident's stopper set.
    OperatorPair,
    /// `quorum_k` distinct principals.
    Quorum,
    /// A stopper may resume once the configured cooldown has passed.
    SamePrincipalAfter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopOperatorConfigBodyV1 {
    pub schema: String,
    /// The admission store the document governs.
    pub authority_id: String,
    /// Strictly increasing per authority.
    pub deployment_generation: u64,
    /// Digest of the document this one replaces; absent for the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_digest: Option<String>,
    /// One roster per scope. Only the kernel scope exists.
    pub rosters: Vec<StopRosterV1>,
    pub stop_quorum_max: u16,
    pub resume_policy: ResumePolicyV1,
    /// Required by, and only valid with, `SamePrincipalAfter`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_principal_cooldown_ms: Option<u64>,
    /// The pinned time source for break-glass resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_attestation_key: Option<PublicKey>,
    /// The configuration root that signs this document.
    pub config_authority_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopOperatorConfigV1 {
    pub body: StopOperatorConfigBodyV1,
    /// The configuration root's signature over the canonical body.
    pub signature: Signature,
}

/// One installed-roster principal's approval of a replacement document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopConfigApprovalV1 {
    pub schema: String,
    pub principal: PrincipalId,
    /// Digest of the approved replacement document.
    pub config_digest: String,
    pub signature: Signature,
}

/// The approval object without its signature: the canonical body the
/// wrapper binds to `chio.stop-operator-config-approval.v1`.
#[derive(Serialize)]
struct StopConfigApprovalBody<'a> {
    schema: &'a str,
    principal: &'a PrincipalId,
    config_digest: &'a str,
}

impl StopConfigApprovalV1 {
    pub fn sign(principal: &Keypair, config_digest: &str) -> Result<Self, StopConfigError> {
        let principal_id = PrincipalId::from_subject_key(&principal.public_key());
        let signature = principal
            .sign_wrapped(
                STOP_OPERATOR_CONFIG_APPROVAL_SCHEMA,
                &approval_body(&principal_id, config_digest)?,
            )
            .map_err(|error| StopConfigError::Canonical(error.to_string()))?;
        Ok(Self {
            schema: STOP_OPERATOR_CONFIG_APPROVAL_SCHEMA.to_owned(),
            principal: principal_id,
            config_digest: config_digest.to_owned(),
            signature,
        })
    }
}

/// Values pinned outside the document.
#[derive(Debug, Clone)]
pub struct StopConfigPins {
    pub config_root: PublicKey,
    pub authority_id: String,
    pub receipt_signer: PublicKey,
}

/// The document this one replaces, and the approvals of its roster.
#[derive(Debug, Clone, Copy)]
pub struct StopConfigSuccession<'a> {
    pub installed: &'a VerifiedStopOperatorConfig,
    pub approvals: &'a [StopConfigApprovalV1],
}

/// A document that passed every load-time check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStopOperatorConfig {
    config: StopOperatorConfigV1,
    digest: String,
    kernel_roster: StopRosterV1,
    kernel_roster_digest: String,
}

impl VerifiedStopOperatorConfig {
    #[must_use]
    pub fn config(&self) -> &StopOperatorConfigV1 {
        &self.config
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn deployment_generation(&self) -> u64 {
        self.config.body.deployment_generation
    }

    #[must_use]
    pub fn kernel_roster_digest(&self) -> &str {
        &self.kernel_roster_digest
    }

    #[must_use]
    pub fn kernel_roster(&self) -> &StopRosterV1 {
        &self.kernel_roster
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StopConfigError {
    #[error("stop operator configuration does not decode: {0}")]
    Decode(String),
    #[error("stop operator configuration is not canonical: {0}")]
    Canonical(String),
    #[error("stop operator configuration schema is not chio.stop-operator-config.v1")]
    Schema,
    #[error("stop operator configuration is not signed by the pinned configuration root")]
    RootMismatch,
    #[error("stop operator configuration signature is invalid")]
    Signature,
    #[error("stop operator configuration governs another authority")]
    AuthorityMismatch,
    #[error("a first stop operator configuration names a predecessor")]
    UnexpectedPredecessor,
    #[error("stop operator configuration generation must start at 1")]
    GenerationZero,
    #[error("stop operator configuration generation {generation} is not above the installed {installed}")]
    GenerationNotAbove { generation: u64, installed: u64 },
    #[error("stop operator configuration does not name the installed document as its predecessor")]
    PredecessorMismatch,
    #[error("stop operator configuration has no kernel roster")]
    MissingKernelRoster,
    #[error("stop operator configuration repeats a scope")]
    DuplicateScope,
    #[error("stop roster is empty")]
    EmptyRoster,
    #[error("stop roster exceeds {MAX_STOP_ROSTER_PRINCIPALS} principals")]
    RosterTooLarge,
    #[error("stop roster principals are not strictly ascending")]
    PrincipalsUnordered,
    #[error("stop roster principal does not derive from its subject key")]
    PrincipalMismatch,
    #[error("stop configuration key is not a strong Ed25519 key")]
    WeakKey,
    #[error("the kernel receipt signer is on the stop roster")]
    ReceiptSignerOnRoster,
    #[error("stop_quorum_max must be between 1 and {STOP_QUORUM_MAX_LIMIT}")]
    QuorumMaxOutOfRange,
    #[error("stop roster quorum_k must be between 1 and stop_quorum_max")]
    QuorumOutOfRange,
    #[error(
        "stop roster has fewer principals with resume permission than its resume policy needs"
    )]
    ResumeQuorumUnreachable,
    #[error(
        "same-principal resume needs a cooldown of at least {MIN_SAME_PRINCIPAL_COOLDOWN_MS} ms"
    )]
    CooldownRequired,
    #[error("a cooldown is set without the same-principal resume policy")]
    UnexpectedCooldown,
    #[error("stop configuration approvals exceed twice stop_quorum_max")]
    TooManyApprovals,
    #[error("stop configuration approval is malformed or names another document")]
    ApprovalInvalid,
    #[error("stop configuration approval is not from an installed roster principal")]
    ApprovalUnknownPrincipal,
    #[error("stop configuration approval repeats a principal")]
    ApprovalDuplicate,
    #[error("stop configuration approval signature is invalid")]
    ApprovalSignature,
    #[error(
        "stop configuration has {approved} installed-roster approvals; {required} are required"
    )]
    ApprovalQuorumShort { approved: usize, required: usize },
}

impl StopOperatorConfigV1 {
    /// Sign `body` with the configuration root.
    pub fn sign(body: StopOperatorConfigBodyV1, root: &Keypair) -> Result<Self, StopConfigError> {
        let canonical = CanonicalBytes::from_serializable(&body)
            .map_err(|error| StopConfigError::Canonical(error.to_string()))?;
        let signature = root
            .sign_wrapped(STOP_OPERATOR_CONFIG_SCHEMA, &canonical)
            .map_err(|error| StopConfigError::Canonical(error.to_string()))?;
        Ok(Self { signature, body })
    }

    /// Decode one bounded, canonical document.
    pub fn decode(bytes: &[u8]) -> Result<Self, StopConfigError> {
        chio_core::canonical::UntrustedJsonText::from_wire(bytes, MAX_STOP_OPERATOR_CONFIG_BYTES)
            .and_then(|text| text.decode_canonical())
            .map_err(|error| StopConfigError::Decode(error.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StopConfigError> {
        chio_core_types::canonical_json_bytes(self)
            .map_err(|error| StopConfigError::Canonical(error.to_string()))
    }

    pub fn digest(&self) -> Result<String, StopConfigError> {
        canonical_digest(self)
    }

    /// Run every load-time check. A first document passes `None`; a
    /// replacement passes the installed document and its roster's approvals.
    pub fn verify(
        self,
        pins: &StopConfigPins,
        succession: Option<StopConfigSuccession<'_>>,
    ) -> Result<VerifiedStopOperatorConfig, StopConfigError> {
        let body = &self.body;
        if body.schema != STOP_OPERATOR_CONFIG_SCHEMA {
            return Err(StopConfigError::Schema);
        }
        if body.config_authority_key != pins.config_root {
            return Err(StopConfigError::RootMismatch);
        }
        let canonical = CanonicalBytes::from_serializable(body)
            .map_err(|error| StopConfigError::Canonical(error.to_string()))?;
        if verify_wrapped_bytes(
            &pins.config_root,
            STOP_OPERATOR_CONFIG_SCHEMA,
            &canonical,
            &self.signature,
        )
        .is_err()
        {
            return Err(StopConfigError::Signature);
        }
        if body.authority_id != pins.authority_id {
            return Err(StopConfigError::AuthorityMismatch);
        }
        if body.deployment_generation == 0 {
            return Err(StopConfigError::GenerationZero);
        }
        if !(1..=STOP_QUORUM_MAX_LIMIT).contains(&body.stop_quorum_max) {
            return Err(StopConfigError::QuorumMaxOutOfRange);
        }
        if let Some(key) = &body.time_attestation_key {
            require_strong(key)?;
        }
        match (body.resume_policy, body.same_principal_cooldown_ms) {
            (ResumePolicyV1::SamePrincipalAfter, Some(cooldown))
                if cooldown >= MIN_SAME_PRINCIPAL_COOLDOWN_MS => {}
            (ResumePolicyV1::SamePrincipalAfter, _) => {
                return Err(StopConfigError::CooldownRequired)
            }
            (_, Some(_)) => return Err(StopConfigError::UnexpectedCooldown),
            (_, None) => {}
        }
        let roster = match body.rosters.as_slice() {
            [] => return Err(StopConfigError::MissingKernelRoster),
            [roster] if roster.scope == StopScope::Kernel => roster,
            [_] => return Err(StopConfigError::MissingKernelRoster),
            _ => return Err(StopConfigError::DuplicateScope),
        };
        verify_roster(roster, body, pins)?;
        let digest = self.digest()?;
        match succession {
            None if body.predecessor_digest.is_some() => {
                return Err(StopConfigError::UnexpectedPredecessor)
            }
            None => {}
            Some(succession) => verify_succession(body, &digest, succession)?,
        }
        let kernel_roster = roster.clone();
        let kernel_roster_digest = kernel_roster.digest()?;
        Ok(VerifiedStopOperatorConfig {
            config: self,
            digest,
            kernel_roster,
            kernel_roster_digest,
        })
    }
}

fn verify_roster(
    roster: &StopRosterV1,
    body: &StopOperatorConfigBodyV1,
    pins: &StopConfigPins,
) -> Result<(), StopConfigError> {
    if roster.principals.is_empty() {
        return Err(StopConfigError::EmptyRoster);
    }
    if roster.principals.len() > MAX_STOP_ROSTER_PRINCIPALS {
        return Err(StopConfigError::RosterTooLarge);
    }
    if roster
        .principals
        .windows(2)
        .any(|pair| matches!(pair, [left, right] if left.principal >= right.principal))
    {
        return Err(StopConfigError::PrincipalsUnordered);
    }
    for entry in &roster.principals {
        require_strong(&entry.subject_key)?;
        if PrincipalId::from_subject_key(&entry.subject_key) != entry.principal {
            return Err(StopConfigError::PrincipalMismatch);
        }
        if entry.subject_key == pins.receipt_signer {
            return Err(StopConfigError::ReceiptSignerOnRoster);
        }
    }
    if roster.quorum_k == 0
        || roster.quorum_k > body.stop_quorum_max
        || usize::from(roster.quorum_k) > roster.principals.len()
    {
        return Err(StopConfigError::QuorumOutOfRange);
    }
    let resumers = roster
        .principals
        .iter()
        .filter(|entry| entry.permissions.resume)
        .count();
    let needed = match body.resume_policy {
        ResumePolicyV1::OperatorPair => 2,
        ResumePolicyV1::Quorum => usize::from(roster.quorum_k),
        ResumePolicyV1::SamePrincipalAfter => 1,
    };
    if resumers < needed {
        return Err(StopConfigError::ResumeQuorumUnreachable);
    }
    Ok(())
}

fn verify_succession(
    body: &StopOperatorConfigBodyV1,
    digest: &str,
    succession: StopConfigSuccession<'_>,
) -> Result<(), StopConfigError> {
    let installed = succession.installed;
    if body.deployment_generation <= installed.deployment_generation() {
        return Err(StopConfigError::GenerationNotAbove {
            generation: body.deployment_generation,
            installed: installed.deployment_generation(),
        });
    }
    if body.predecessor_digest.as_deref() != Some(installed.digest()) {
        return Err(StopConfigError::PredecessorMismatch);
    }
    let roster = installed.kernel_roster();
    let bound = usize::from(installed.config.body.stop_quorum_max) * 2;
    if succession.approvals.len() > bound {
        return Err(StopConfigError::TooManyApprovals);
    }
    let mut approved = BTreeSet::new();
    for approval in succession.approvals {
        if approval.schema != STOP_OPERATOR_CONFIG_APPROVAL_SCHEMA
            || approval.config_digest != digest
        {
            return Err(StopConfigError::ApprovalInvalid);
        }
        let entry = roster
            .principal(&approval.principal)
            .ok_or(StopConfigError::ApprovalUnknownPrincipal)?;
        if !approved.insert(&approval.principal) {
            return Err(StopConfigError::ApprovalDuplicate);
        }
        if verify_wrapped_bytes(
            &entry.subject_key,
            STOP_OPERATOR_CONFIG_APPROVAL_SCHEMA,
            &approval_body(&approval.principal, &approval.config_digest)?,
            &approval.signature,
        )
        .is_err()
        {
            return Err(StopConfigError::ApprovalSignature);
        }
    }
    let required = usize::from(roster.quorum_k);
    if approved.len() < required {
        return Err(StopConfigError::ApprovalQuorumShort {
            approved: approved.len(),
            required,
        });
    }
    Ok(())
}

fn approval_body(
    principal: &PrincipalId,
    config_digest: &str,
) -> Result<CanonicalBytes, StopConfigError> {
    CanonicalBytes::from_serializable(&StopConfigApprovalBody {
        schema: STOP_OPERATOR_CONFIG_APPROVAL_SCHEMA,
        principal,
        config_digest,
    })
    .map_err(|error| StopConfigError::Canonical(error.to_string()))
}

fn require_strong(key: &PublicKey) -> Result<(), StopConfigError> {
    if key.algorithm() != SigningAlgorithm::Ed25519 || key.is_weak_ed25519() {
        return Err(StopConfigError::WeakKey);
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, StopConfigError> {
    chio_core_types::canonical_json_bytes(value)
        .map(|bytes| chio_core_types::sha256_hex(&bytes))
        .map_err(|error| StopConfigError::Canonical(error.to_string()))
}

#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;
