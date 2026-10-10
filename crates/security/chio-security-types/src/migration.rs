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
pub const CAGE_MIGRATION_POSTURE_SCHEMA: &str = "chio.cage-migration-posture.v2";

/// Digests of every authority-bearing component of a native cage policy.
///
/// The migration posture commits to these component digests instead of the
/// complete policy envelope because the envelope contains the migration head
/// that commits to the posture. Keeping the component boundary explicit avoids
/// that cycle while still making any change to the signed manifest, policy
/// signer, permissions, retained artifacts, limits, receipt authority, broker
/// binding, or durable ledger configuration require a new migration transition.
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

/// Compute the canonical v2 posture for one exact native cage contract.
#[cfg(feature = "std")]
pub fn cage_migration_posture_digest(
    deployment_id: &RecordId,
    tool_server_id: &RecordId,
    stage: EnterpriseMigrationStage,
    contract: &CageLaunchContractDigests,
) -> Result<Digest32, CageMigrationPostureDigestError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CageMigrationPosture<'a> {
        schema: &'static str,
        deployment_id: &'a RecordId,
        tool_server_id: &'a RecordId,
        control: EnterpriseMigrationControl,
        stage: EnterpriseMigrationStage,
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
        stage,
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
    LegacyConfiguration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseMigrationScopeKind {
    Deployment,
    Provider,
    ToolServer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseMigrationStage {
    Disabled,
    Shadow,
    Enforced,
    LegacyRemoved,
}

impl EnterpriseMigrationStage {
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Disabled => Some(Self::Shadow),
            Self::Shadow => Some(Self::Enforced),
            Self::Enforced => Some(Self::LegacyRemoved),
            Self::LegacyRemoved => None,
        }
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        match self {
            Self::Disabled => 0,
            Self::Shadow => 1,
            Self::Enforced => 2,
            Self::LegacyRemoved => 3,
        }
    }

    #[must_use]
    pub const fn legacy_fallback_permitted(self) -> bool {
        matches!(self, Self::Disabled | Self::Shadow)
    }

    #[must_use]
    pub const fn operational_failure_must_deny(self) -> bool {
        !self.legacy_fallback_permitted()
    }
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
            EnterpriseMigrationControl::LegacyConfiguration => true,
        }
    }
}

/// Canonical, domain-separated body authorized for one migration transition.
///
/// Genesis has no prior digest or prior stage. Every later body names the
/// exact prior transition digest and advances exactly one stage. The store
/// verifies these invariants again before accepting an envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationTransitionBody {
    pub signature_domain: String,
    pub schema_version: u8,
    pub key: EnterpriseMigrationKey,
    pub generation: u64,
    pub from_stage: Option<EnterpriseMigrationStage>,
    pub to_stage: EnterpriseMigrationStage,
    pub prior_head_digest: Option<Digest32>,
    pub posture_digest: Digest32,
    pub evidence_digest: Digest32,
    pub authorization_digest: Digest32,
    pub intent_digest: Digest32,
    pub trusted_at_unix_ms: u64,
    pub signer_public_key: String,
}

impl EnterpriseMigrationTransitionBody {
    pub fn genesis(
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
            generation: 0,
            from_stage: None,
            to_stage: EnterpriseMigrationStage::Disabled,
            prior_head_digest: None,
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

    pub fn promotion(
        prior: &EnterpriseMigrationState,
        posture_digest: Digest32,
        evidence_digest: Digest32,
        authorization_digest: Digest32,
        intent_digest: Digest32,
        trusted_at_unix_ms: u64,
        signer_public_key: String,
    ) -> Result<Self, EnterpriseMigrationTransitionValidationError> {
        let to_stage = prior
            .stage
            .next()
            .ok_or(EnterpriseMigrationTransitionValidationError::TerminalStage)?;
        let body = Self {
            signature_domain: String::from(ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN),
            schema_version: ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION,
            key: prior.key.clone(),
            generation: to_stage.generation(),
            from_stage: Some(prior.stage),
            to_stage,
            prior_head_digest: Some(prior.transition_digest),
            posture_digest,
            evidence_digest,
            authorization_digest,
            intent_digest,
            trusted_at_unix_ms,
            signer_public_key,
        };
        body.validate_shape()?;
        if trusted_at_unix_ms < prior.updated_at_unix_ms {
            return Err(EnterpriseMigrationTransitionValidationError::TimeRegression);
        }
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
        if self.generation != self.to_stage.generation() {
            return Err(EnterpriseMigrationTransitionValidationError::GenerationStage);
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
        if self.generation == 0 {
            if self.from_stage.is_some()
                || self.prior_head_digest.is_some()
                || self.to_stage != EnterpriseMigrationStage::Disabled
            {
                return Err(EnterpriseMigrationTransitionValidationError::GenesisShape);
            }
        } else {
            let from_stage = self
                .from_stage
                .ok_or(EnterpriseMigrationTransitionValidationError::PromotionShape)?;
            let prior_head_digest = self
                .prior_head_digest
                .ok_or(EnterpriseMigrationTransitionValidationError::PromotionShape)?;
            if prior_head_digest.is_zero()
                || from_stage.next() != Some(self.to_stage)
                || from_stage.generation().checked_add(1) != Some(self.generation)
            {
                return Err(EnterpriseMigrationTransitionValidationError::PromotionShape);
            }
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
    GenerationStage,
    GenesisShape,
    PromotionShape,
    TerminalStage,
    ZeroDigest,
    UntrustedTime,
    TimeRegression,
    SignerEncoding,
    SignatureEncoding,
}

impl fmt::Display for EnterpriseMigrationTransitionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SignatureDomain => "invalid migration transition signature domain",
            Self::SchemaVersion => "invalid migration transition schema version",
            Self::ControlScope => "invalid migration control scope",
            Self::GenerationStage => "migration generation does not equal its stage",
            Self::GenesisShape => "invalid migration genesis shape",
            Self::PromotionShape => "invalid migration promotion shape",
            Self::TerminalStage => "terminal migration stage cannot advance",
            Self::ZeroDigest => "migration transition contains a zero digest",
            Self::UntrustedTime => "migration transition has no trusted time",
            Self::TimeRegression => "migration transition trusted time regressed",
            Self::SignerEncoding => "invalid migration transition signer encoding",
            Self::SignatureEncoding => "invalid migration transition signature encoding",
        })
    }
}

impl core::error::Error for EnterpriseMigrationTransitionValidationError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationState {
    pub schema_version: u8,
    pub key: EnterpriseMigrationKey,
    pub stage: EnterpriseMigrationStage,
    pub generation: u64,
    pub transition_digest: Digest32,
    pub prior_head_digest: Option<Digest32>,
    pub posture_digest: Digest32,
    pub evidence_digest: Digest32,
    pub authorization_digest: Digest32,
    pub intent_digest: Digest32,
    pub updated_at_unix_ms: u64,
    pub signer_public_key: String,
}

impl EnterpriseMigrationState {
    #[must_use]
    pub fn minimum_head(&self) -> EnterpriseMigrationMinimumHead {
        EnterpriseMigrationMinimumHead {
            key: self.key.clone(),
            minimum_generation: self.generation,
            transition_digest: self.transition_digest,
        }
    }

    pub fn runtime_binding(
        &self,
        configured_stage: EnterpriseMigrationStage,
        configured_posture_digest: Digest32,
    ) -> Result<(), EnterpriseRuntimeBindingError> {
        if configured_stage < self.stage {
            return Err(EnterpriseRuntimeBindingError::DowngradeAttempt);
        }
        if configured_stage > self.stage {
            return Err(EnterpriseRuntimeBindingError::UncommittedAdvance);
        }
        if configured_posture_digest != self.posture_digest {
            return Err(EnterpriseRuntimeBindingError::ConfigurationMismatch);
        }
        Ok(())
    }
}

/// A head asserted by storage outside the SQLite database being opened.
///
/// Supplying this value to the durable store rejects a restored, otherwise
/// valid prefix whose chain does not contain this exact generation and digest.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationMinimumHead {
    pub key: EnterpriseMigrationKey,
    pub minimum_generation: u64,
    pub transition_digest: Digest32,
}

impl EnterpriseMigrationMinimumHead {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.key.control_scope_is_valid()
            && self.minimum_generation <= EnterpriseMigrationStage::LegacyRemoved.generation()
            && !self.transition_digest.is_zero()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseRuntimeBindingError {
    DowngradeAttempt,
    UncommittedAdvance,
    ConfigurationMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnterpriseMigrationRegisterOutcome {
    Registered(EnterpriseMigrationState),
    Existing(EnterpriseMigrationState),
    Conflict(EnterpriseMigrationState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnterpriseMigrationCasOutcome {
    Promoted(EnterpriseMigrationState),
    Conflict(EnterpriseMigrationState),
}

pub trait EnterpriseMigrationStateStore: Send + Sync {
    fn register(
        &self,
        transition: &EnterpriseMigrationTransition,
    ) -> PortResult<EnterpriseMigrationRegisterOutcome>;

    fn load(&self, key: &EnterpriseMigrationKey) -> PortResult<Option<EnterpriseMigrationState>>;

    fn compare_and_promote(
        &self,
        transition: &EnterpriseMigrationTransition,
    ) -> PortResult<EnterpriseMigrationCasOutcome>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseOperationalFailureDisposition {
    LegacyFallbackAllowed,
    Deny,
}

/// Exact durable state retained by a production process.
///
/// Construction binds the configured stage and posture to one store record.
/// Every protected operation re-reads that record so a promotion, rollback,
/// posture change, file replacement, or storage failure invalidates the
/// process until it is rebuilt from the new externally anchored head.
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
        configured_stage: EnterpriseMigrationStage,
        configured_posture_digest: Digest32,
    ) -> Result<Self, EnterpriseMigrationRuntimeError> {
        let state = store
            .load(key)
            .map_err(EnterpriseMigrationRuntimeError::Store)?
            .ok_or(EnterpriseMigrationRuntimeError::Unregistered)?;
        state
            .runtime_binding(configured_stage, configured_posture_digest)
            .map_err(EnterpriseMigrationRuntimeError::Binding)?;
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
        current
            .runtime_binding(self.state.stage, self.state.posture_digest)
            .map_err(EnterpriseMigrationRuntimeError::Binding)
    }

    pub fn require_enforced(&self) -> Result<(), EnterpriseMigrationRuntimeError> {
        self.revalidate()?;
        if self.state.stage.legacy_fallback_permitted() {
            return Err(EnterpriseMigrationRuntimeError::LegacyFallbackPermitted);
        }
        Ok(())
    }

    pub fn require_legacy_fallback_permitted(&self) -> Result<(), EnterpriseMigrationRuntimeError> {
        self.revalidate()?;
        if !self.state.stage.legacy_fallback_permitted() {
            return Err(EnterpriseMigrationRuntimeError::LegacyFallbackDenied);
        }
        Ok(())
    }

    #[must_use]
    pub fn operational_failure_disposition(&self) -> EnterpriseOperationalFailureDisposition {
        match self.revalidate() {
            Ok(()) if self.state.stage.legacy_fallback_permitted() => {
                EnterpriseOperationalFailureDisposition::LegacyFallbackAllowed
            }
            Ok(()) | Err(_) => EnterpriseOperationalFailureDisposition::Deny,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnterpriseMigrationRuntimeError {
    Store(crate::ports::PortError),
    Unregistered,
    Binding(EnterpriseRuntimeBindingError),
    StateChanged,
    LegacyFallbackPermitted,
    LegacyFallbackDenied,
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
            Self::Binding(error) => {
                write!(
                    formatter,
                    "enterprise migration runtime binding failed: {error:?}"
                )
            }
            Self::StateChanged => {
                formatter.write_str("enterprise migration state changed after runtime binding")
            }
            Self::LegacyFallbackPermitted => {
                formatter.write_str("enterprise migration state still permits a legacy fallback")
            }
            Self::LegacyFallbackDenied => {
                formatter.write_str("enterprise migration state denies a legacy fallback")
            }
        }
    }
}

impl core::error::Error for EnterpriseMigrationRuntimeError {}
