use alloc::string::String;
use alloc::sync::Arc;
use core::fmt;

use crate::ports::{Digest32, PortResult, RecordId};
use serde::{Deserialize, Serialize};

pub const ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION: u8 = 1;
pub const ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN: &str =
    "chio.enterprise-migration-transition.v1";
pub const MAX_ENTERPRISE_MIGRATION_SIGNER_BYTES: usize = 8_192;
pub const MAX_ENTERPRISE_MIGRATION_SIGNATURE_BYTES: usize = 16_384;
pub const CAGE_MIGRATION_POSTURE_SCHEMA: &str = "chio.cage-migration-posture.v1";

/// Digests of every authority-bearing component of a native cage policy.
///
/// The migration posture commits to these component digests instead of the
/// complete policy envelope because the envelope contains the ledger head
/// that commits to the posture. Keeping the component boundary explicit avoids
/// that cycle while still making any change to the signed manifest, policy
/// signer, permissions, retained artifacts, limits, receipt authority, broker
/// binding, or durable ledger configuration require a new ledger registration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CageLaunchContractDigests {
    pub policy_schema_digest: Digest32,
    pub policy_signer_digest: Digest32,
    pub signed_manifest_digest: Digest32,
    pub registered_public_key_digest: Digest32,
    pub operator_ceilings_digest: Digest32,
    pub runtime_digest: Digest32,
    pub limits_digest: Digest32,
    pub receipt_digest: Digest32,
    pub broker_binding_digest: Digest32,
    pub migration_ledger_digest: Digest32,
}

impl CageLaunchContractDigests {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.policy_schema_digest.is_zero()
            && !self.policy_signer_digest.is_zero()
            && !self.signed_manifest_digest.is_zero()
            && !self.registered_public_key_digest.is_zero()
            && !self.operator_ceilings_digest.is_zero()
            && !self.runtime_digest.is_zero()
            && !self.limits_digest.is_zero()
            && !self.receipt_digest.is_zero()
            && !self.broker_binding_digest.is_zero()
            && !self.migration_ledger_digest.is_zero()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CageMigrationPostureDigestError {
    InvalidContract,
    Encoding,
}

impl fmt::Display for CageMigrationPostureDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContract => "cage launch contract contains a zero digest",
            Self::Encoding => "cage migration posture encoding failed",
        })
    }
}

impl core::error::Error for CageMigrationPostureDigestError {}

/// Compute the canonical posture digest for one exact native cage contract.
#[cfg(feature = "std")]
pub fn cage_migration_posture_digest(
    deployment_id: &RecordId,
    tool_server_id: &RecordId,
    contract: &CageLaunchContractDigests,
) -> Result<Digest32, CageMigrationPostureDigestError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CageMigrationPosture<'a> {
        schema: &'static str,
        deployment_id: &'a RecordId,
        tool_server_id: &'a RecordId,
        control: EnterpriseMigrationControl,
        contract: &'a CageLaunchContractDigests,
    }

    if !contract.is_valid() {
        return Err(CageMigrationPostureDigestError::InvalidContract);
    }
    let bytes = serde_json::to_vec(&CageMigrationPosture {
        schema: CAGE_MIGRATION_POSTURE_SCHEMA,
        deployment_id,
        tool_server_id,
        control: EnterpriseMigrationControl::CageEnforcement,
        contract,
    })
    .map_err(|_| CageMigrationPostureDigestError::Encoding)?;
    use sha2::{Digest as _, Sha256};
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Ok(Digest32::new(digest))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseMigrationControl {
    KeyLogVerification,
    BrokerCredentialCustody,
    BrokerQuotaEnforcement,
    CageEnforcement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseMigrationScopeKind {
    Deployment,
    Provider,
    ToolServer,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationKey {
    pub deployment_id: RecordId,
    pub scope_kind: EnterpriseMigrationScopeKind,
    pub scope_id: RecordId,
    pub control: EnterpriseMigrationControl,
}

impl EnterpriseMigrationKey {
    #[must_use]
    pub const fn control_scope_is_valid(&self) -> bool {
        match self.control {
            EnterpriseMigrationControl::KeyLogVerification => {
                matches!(self.scope_kind, EnterpriseMigrationScopeKind::Deployment)
            }
            EnterpriseMigrationControl::BrokerCredentialCustody
            | EnterpriseMigrationControl::BrokerQuotaEnforcement => {
                matches!(self.scope_kind, EnterpriseMigrationScopeKind::Provider)
            }
            EnterpriseMigrationControl::CageEnforcement => {
                matches!(self.scope_kind, EnterpriseMigrationScopeKind::ToolServer)
            }
        }
    }
}

/// Canonical, domain-separated body that enrolls one control as enforced.
///
/// A ledger holds exactly one registration per key. The registration pins
/// the posture of the enforced contract; changing that contract requires a
/// new ledger whose registration digest the operator pins again.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationTransitionBody {
    pub signature_domain: String,
    pub schema_version: u8,
    pub key: EnterpriseMigrationKey,
    pub posture_digest: Digest32,
    pub evidence_digest: Digest32,
    pub authorization_digest: Digest32,
    pub intent_digest: Digest32,
    pub trusted_at_unix_ms: u64,
    pub signer_public_key: String,
}

impl EnterpriseMigrationTransitionBody {
    pub fn enforced(
        key: EnterpriseMigrationKey,
        posture_digest: Digest32,
        evidence_digest: Digest32,
        authorization_digest: Digest32,
        intent_digest: Digest32,
        trusted_at_unix_ms: u64,
        signer_public_key: String,
    ) -> Result<Self, EnterpriseMigrationTransitionValidationError> {
        let body = Self {
            signature_domain: String::from(ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN),
            schema_version: ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION,
            key,
            posture_digest,
            evidence_digest,
            authorization_digest,
            intent_digest,
            trusted_at_unix_ms,
            signer_public_key,
        };
        body.validate_shape()?;
        Ok(body)
    }

    pub fn validate_shape(&self) -> Result<(), EnterpriseMigrationTransitionValidationError> {
        if self.signature_domain != ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN {
            return Err(EnterpriseMigrationTransitionValidationError::SignatureDomain);
        }
        if self.schema_version != ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION {
            return Err(EnterpriseMigrationTransitionValidationError::SchemaVersion);
        }
        if !self.key.control_scope_is_valid() {
            return Err(EnterpriseMigrationTransitionValidationError::ControlScope);
        }
        if self.posture_digest.is_zero()
            || self.evidence_digest.is_zero()
            || self.authorization_digest.is_zero()
            || self.intent_digest.is_zero()
        {
            return Err(EnterpriseMigrationTransitionValidationError::ZeroDigest);
        }
        if self.trusted_at_unix_ms == 0 {
            return Err(EnterpriseMigrationTransitionValidationError::UntrustedTime);
        }
        if self.signer_public_key.is_empty()
            || self.signer_public_key.len() > MAX_ENTERPRISE_MIGRATION_SIGNER_BYTES
        {
            return Err(EnterpriseMigrationTransitionValidationError::SignerEncoding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationTransition {
    pub body: EnterpriseMigrationTransitionBody,
    pub signature: String,
}

impl EnterpriseMigrationTransition {
    pub fn validate_shape(&self) -> Result<(), EnterpriseMigrationTransitionValidationError> {
        self.body.validate_shape()?;
        if self.signature.is_empty()
            || self.signature.len() > MAX_ENTERPRISE_MIGRATION_SIGNATURE_BYTES
        {
            return Err(EnterpriseMigrationTransitionValidationError::SignatureEncoding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseMigrationTransitionValidationError {
    SignatureDomain,
    SchemaVersion,
    ControlScope,
    ZeroDigest,
    UntrustedTime,
    SignerEncoding,
    SignatureEncoding,
}

impl fmt::Display for EnterpriseMigrationTransitionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SignatureDomain => "invalid migration transition signature domain",
            Self::SchemaVersion => "invalid migration transition schema version",
            Self::ControlScope => "invalid migration control scope",
            Self::ZeroDigest => "migration transition contains a zero digest",
            Self::UntrustedTime => "migration transition has no trusted time",
            Self::SignerEncoding => "invalid migration transition signer encoding",
            Self::SignatureEncoding => "invalid migration transition signature encoding",
        })
    }
}

impl core::error::Error for EnterpriseMigrationTransitionValidationError {}

/// The single durable enforced registration for one migration key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationState {
    pub schema_version: u8,
    pub key: EnterpriseMigrationKey,
    pub transition_digest: Digest32,
    pub posture_digest: Digest32,
    pub evidence_digest: Digest32,
    pub authorization_digest: Digest32,
    pub intent_digest: Digest32,
    pub registered_at_unix_ms: u64,
    pub signer_public_key: String,
}

impl EnterpriseMigrationState {
    #[must_use]
    pub fn head(&self) -> EnterpriseMigrationHead {
        EnterpriseMigrationHead {
            key: self.key.clone(),
            transition_digest: self.transition_digest,
        }
    }
}

/// The registration digest asserted by storage outside the ledger database.
///
/// Supplying this value to the durable store rejects any ledger whose
/// registration for the key is not this exact digest, so a replaced or
/// restored database cannot rebind the control to another contract.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationHead {
    pub key: EnterpriseMigrationKey,
    pub transition_digest: Digest32,
}

impl EnterpriseMigrationHead {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.key.control_scope_is_valid() && !self.transition_digest.is_zero()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnterpriseMigrationRegisterOutcome {
    Registered(EnterpriseMigrationState),
    Existing(EnterpriseMigrationState),
    Conflict(EnterpriseMigrationState),
}

pub trait EnterpriseMigrationStateStore: Send + Sync {
    fn register(
        &self,
        transition: &EnterpriseMigrationTransition,
    ) -> PortResult<EnterpriseMigrationRegisterOutcome>;

    fn load(&self, key: &EnterpriseMigrationKey) -> PortResult<Option<EnterpriseMigrationState>>;
}

/// Exact durable state retained by a production process.
///
/// Construction binds the configured posture to one store record. Every
/// protected operation re-reads that record so a posture change, file
/// replacement, or storage failure invalidates the process until it is
/// rebuilt from the new externally anchored head.
#[derive(Clone)]
pub struct EnterpriseMigrationRuntimeBinding {
    store: Arc<dyn EnterpriseMigrationStateStore>,
    key: EnterpriseMigrationKey,
    state: EnterpriseMigrationState,
}

impl EnterpriseMigrationRuntimeBinding {
    pub fn load(
        store: &Arc<dyn EnterpriseMigrationStateStore>,
        key: &EnterpriseMigrationKey,
        configured_posture_digest: Digest32,
    ) -> Result<Self, EnterpriseMigrationRuntimeError> {
        let state = store
            .load(key)
            .map_err(EnterpriseMigrationRuntimeError::Store)?
            .ok_or(EnterpriseMigrationRuntimeError::Unregistered)?;
        if state.posture_digest != configured_posture_digest {
            return Err(EnterpriseMigrationRuntimeError::PostureMismatch);
        }
        Ok(Self {
            store: Arc::clone(store),
            key: key.clone(),
            state,
        })
    }

    #[must_use]
    pub const fn state(&self) -> &EnterpriseMigrationState {
        &self.state
    }

    pub fn revalidate(&self) -> Result<(), EnterpriseMigrationRuntimeError> {
        let current = self
            .store
            .load(&self.key)
            .map_err(EnterpriseMigrationRuntimeError::Store)?
            .ok_or(EnterpriseMigrationRuntimeError::Unregistered)?;
        if current != self.state {
            return Err(EnterpriseMigrationRuntimeError::StateChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnterpriseMigrationRuntimeError {
    Store(crate::ports::PortError),
    Unregistered,
    PostureMismatch,
    StateChanged,
}

impl fmt::Display for EnterpriseMigrationRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(
                formatter,
                "enterprise migration state store failed: {error}"
            ),
            Self::Unregistered => {
                formatter.write_str("enterprise migration control is not durably registered")
            }
            Self::PostureMismatch => formatter
                .write_str("enterprise migration posture differs from the registered posture"),
            Self::StateChanged => {
                formatter.write_str("enterprise migration state changed after runtime binding")
            }
        }
    }
}

impl core::error::Error for EnterpriseMigrationRuntimeError {}
