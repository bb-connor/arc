use chio_core_types::{
    canonical_json_bytes, sha256, Hash, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationScopeKind, EnterpriseMigrationStage,
    EnterpriseMigrationState,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ENTERPRISE_MIGRATION_CANARY_EVIDENCE_SCHEMA: &str =
    "chio.enterprise-migration-canary-evidence.v1";
pub const ENTERPRISE_MIGRATION_CUTOVER_ATTESTATION_SCHEMA: &str =
    "chio.enterprise-migration-cutover-attestation.v1";

const CANARY_SIGNATURE_DOMAIN: &[u8] = b"chio.enterprise-migration-canary-evidence-signature.v1\0";
const CUTOVER_SIGNATURE_DOMAIN: &[u8] =
    b"chio.enterprise-migration-cutover-attestation-signature.v1\0";
const SIGNER_KEY_ID_DOMAIN: &[u8] = b"chio.enterprise-migration-evidence-signer-key-id.v1\0";
const BINDING_DIGEST_DOMAIN: &[u8] = b"chio.enterprise-migration-evidence-binding.v1\0";
const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_MIGRATION_STATES: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseEvidenceRunnerIdentity {
    pub runner_name: String,
    pub runner_os: String,
    pub runner_arch: String,
    pub required_labels_digest: Hash,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationGateResultDigests {
    pub runner_contract: Hash,
    pub key_log_transparency: Hash,
    pub broker_boundary: Hash,
    pub cage_enforcement: Hash,
    pub committed_adversarial_evidence: Hash,
    pub linux_adversarial_controls: Hash,
    pub migration_state_store: Hash,
}

impl EnterpriseMigrationGateResultDigests {
    fn validate(&self) -> Result<(), EnterpriseMigrationEvidenceError> {
        for digest in [
            self.runner_contract,
            self.key_log_transparency,
            self.broker_boundary,
            self.cage_enforcement,
            self.committed_adversarial_evidence,
            self.linux_adversarial_controls,
            self.migration_state_store,
        ] {
            validate_nonzero_hash(digest, "gate result digest")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseMigrationCanaryVerificationPolicy {
    pub source_commit: String,
    pub runner: EnterpriseEvidenceRunnerIdentity,
    pub configuration_digest: Hash,
    pub inventory_digest: Hash,
    pub gate_result_digests: EnterpriseMigrationGateResultDigests,
    pub binding_digest: Hash,
    pub generated_at_not_before_unix_ms: u64,
    pub generated_at_not_after_unix_ms: u64,
}

impl EnterpriseMigrationCanaryVerificationPolicy {
    pub fn validate(&self) -> Result<(), EnterpriseMigrationEvidenceError> {
        validate_source_commit(&self.source_commit)?;
        validate_identifier(&self.runner.runner_name, "expected runner name")?;
        validate_identifier(&self.runner.runner_os, "expected runner operating system")?;
        validate_identifier(&self.runner.runner_arch, "expected runner architecture")?;
        validate_nonzero_hash(
            self.runner.required_labels_digest,
            "expected runner labels digest",
        )?;
        validate_nonzero_hash(self.configuration_digest, "expected configuration digest")?;
        validate_nonzero_hash(self.inventory_digest, "expected inventory digest")?;
        self.gate_result_digests.validate()?;
        validate_nonzero_hash(self.binding_digest, "expected binding digest")?;
        if self.generated_at_not_before_unix_ms == 0
            || self.generated_at_not_after_unix_ms == 0
            || self.generated_at_not_before_unix_ms > self.generated_at_not_after_unix_ms
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "canary generation window is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableEnterpriseMigrationStateBinding {
    pub deployment_id: String,
    pub scope_kind: EnterpriseMigrationScopeKind,
    pub scope_id: String,
    pub control: EnterpriseMigrationControl,
    pub stage: EnterpriseMigrationStage,
    pub generation: u64,
    pub config_digest: Hash,
    pub evidence_digest: Hash,
    pub updated_at_unix_ms: u64,
}

impl DurableEnterpriseMigrationStateBinding {
    #[must_use]
    pub fn from_state(state: &EnterpriseMigrationState) -> Self {
        Self {
            deployment_id: state.key.deployment_id.as_str().to_owned(),
            scope_kind: state.key.scope_kind,
            scope_id: state.key.scope_id.as_str().to_owned(),
            control: state.key.control,
            stage: state.stage,
            generation: state.generation,
            config_digest: Hash::from_bytes(*state.posture_digest.as_bytes()),
            evidence_digest: Hash::from_bytes(*state.evidence_digest.as_bytes()),
            updated_at_unix_ms: state.updated_at_unix_ms,
        }
    }

    fn sort_key(
        &self,
    ) -> (
        &str,
        EnterpriseMigrationScopeKind,
        &str,
        EnterpriseMigrationControl,
    ) {
        (
            self.deployment_id.as_str(),
            self.scope_kind,
            self.scope_id.as_str(),
            self.control,
        )
    }

    fn validate(
        &self,
        expected_config_digest: Hash,
    ) -> Result<(), EnterpriseMigrationEvidenceError> {
        validate_identifier(&self.deployment_id, "migration deployment identifier")?;
        validate_identifier(&self.scope_id, "migration scope identifier")?;
        if !control_scope_is_valid(self.scope_kind, self.control) {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "migration control is bound to the wrong scope kind",
            ));
        }
        if self.generation != stage_generation(self.stage) {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "migration generation does not match its forward-only stage",
            ));
        }
        if self.config_digest != expected_config_digest {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "durable migration state is rebound to a different configuration",
            ));
        }
        validate_nonzero_hash(self.config_digest, "durable state configuration digest")?;
        validate_nonzero_hash(self.evidence_digest, "durable state evidence digest")?;
        if self.updated_at_unix_ms == 0 {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "durable migration state has no update time",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationEvidenceBinding {
    pub source_commit: String,
    pub runner: EnterpriseEvidenceRunnerIdentity,
    pub configuration_digest: Hash,
    pub inventory_digest: Hash,
    pub durable_migration_states: Vec<DurableEnterpriseMigrationStateBinding>,
    pub gate_result_digests: EnterpriseMigrationGateResultDigests,
}

impl EnterpriseMigrationEvidenceBinding {
    pub fn validate(&self) -> Result<(), EnterpriseMigrationEvidenceError> {
        validate_source_commit(&self.source_commit)?;
        validate_identifier(&self.runner.runner_name, "runner name")?;
        validate_identifier(&self.runner.runner_os, "runner operating system")?;
        validate_identifier(&self.runner.runner_arch, "runner architecture")?;
        validate_nonzero_hash(
            self.runner.required_labels_digest,
            "required runner labels digest",
        )?;
        validate_nonzero_hash(self.configuration_digest, "configuration digest")?;
        validate_nonzero_hash(self.inventory_digest, "inventory digest")?;
        self.gate_result_digests.validate()?;
        if self.durable_migration_states.is_empty()
            || self.durable_migration_states.len() > MAX_MIGRATION_STATES
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "durable migration state count is outside the supported range",
            ));
        }
        for state in &self.durable_migration_states {
            state.validate(self.configuration_digest)?;
        }
        if self
            .durable_migration_states
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "durable migration states are not sorted and unique",
            ));
        }
        Ok(())
    }

    pub fn binding_digest(&self) -> Result<Hash, EnterpriseMigrationEvidenceError> {
        self.validate()?;
        Ok(sha256(&domain_canonical_bytes(
            BINDING_DIGEST_DOMAIN,
            self,
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationCanaryEvidenceBody {
    pub schema: String,
    pub evidence_kind: String,
    pub generated_at_unix_ms: u64,
    pub binding: EnterpriseMigrationEvidenceBinding,
    pub repository_mechanics_only: bool,
    pub production_traffic_attested: bool,
    pub production_cutover_attested: bool,
    pub operator_attestation_required: bool,
}

impl EnterpriseMigrationCanaryEvidenceBody {
    pub fn validate(&self) -> Result<(), EnterpriseMigrationEvidenceError> {
        if self.schema != ENTERPRISE_MIGRATION_CANARY_EVIDENCE_SCHEMA
            || self.evidence_kind != "designated_runner_repository_canary"
            || self.generated_at_unix_ms == 0
            || !self.repository_mechanics_only
            || self.production_traffic_attested
            || self.production_cutover_attested
            || !self.operator_attestation_required
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "canary scope assertions are invalid",
            ));
        }
        self.binding.validate()?;
        if self
            .binding
            .durable_migration_states
            .iter()
            .any(|state| state.stage != EnterpriseMigrationStage::Shadow)
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "pre-promotion canary contains a state outside shadow",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnterpriseMigrationCanaryEvidence {
    pub body: EnterpriseMigrationCanaryEvidenceBody,
    pub signer_key_id: Hash,
    pub signer: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

impl SignedEnterpriseMigrationCanaryEvidence {
    pub fn sign(
        body: EnterpriseMigrationCanaryEvidenceBody,
        signer: &dyn SigningBackend,
        trusted_runner_key: &PublicKey,
    ) -> Result<Self, EnterpriseMigrationEvidenceError> {
        body.validate()?;
        let signing_bytes = domain_canonical_bytes(CANARY_SIGNATURE_DOMAIN, &body)?;
        let outcome = signer.sign_bytes_for_identity(trusted_runner_key, &signing_bytes)?;
        Ok(Self {
            body,
            signer_key_id: signer_key_id(&outcome.public_key),
            signer: outcome.public_key,
            algorithm: outcome.algorithm,
            signature: outcome.signature,
        })
    }

    pub fn verify(
        &self,
        trusted_runner_key: &PublicKey,
    ) -> Result<(), EnterpriseMigrationEvidenceError> {
        self.body.validate()?;
        if &self.signer != trusted_runner_key
            || self.signer_key_id != signer_key_id(trusted_runner_key)
            || self.algorithm != self.signer.algorithm()
            || self.algorithm != self.signature.algorithm()
            || !self.signer.verify(
                &domain_canonical_bytes(CANARY_SIGNATURE_DOMAIN, &self.body)?,
                &self.signature,
            )
        {
            return Err(EnterpriseMigrationEvidenceError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_against_policy(
        &self,
        trusted_runner_key: &PublicKey,
        policy: &EnterpriseMigrationCanaryVerificationPolicy,
    ) -> Result<(), EnterpriseMigrationEvidenceError> {
        self.verify(trusted_runner_key)?;
        policy.validate()?;
        if self.body.generated_at_unix_ms < policy.generated_at_not_before_unix_ms
            || self.body.generated_at_unix_ms > policy.generated_at_not_after_unix_ms
        {
            return Err(EnterpriseMigrationEvidenceError::Stale);
        }
        if self.body.binding.source_commit != policy.source_commit {
            return Err(EnterpriseMigrationEvidenceError::ExternalBindingMismatch(
                "source commit",
            ));
        }
        if self.body.binding.runner != policy.runner {
            return Err(EnterpriseMigrationEvidenceError::ExternalBindingMismatch(
                "runner identity",
            ));
        }
        if self.body.binding.configuration_digest != policy.configuration_digest {
            return Err(EnterpriseMigrationEvidenceError::ExternalBindingMismatch(
                "configuration digest",
            ));
        }
        if self.body.binding.inventory_digest != policy.inventory_digest {
            return Err(EnterpriseMigrationEvidenceError::ExternalBindingMismatch(
                "inventory digest",
            ));
        }
        if self.body.binding.gate_result_digests != policy.gate_result_digests {
            return Err(EnterpriseMigrationEvidenceError::ExternalBindingMismatch(
                "gate result digests",
            ));
        }
        if self.body.binding.binding_digest()? != policy.binding_digest {
            return Err(EnterpriseMigrationEvidenceError::ExternalBindingMismatch(
                "complete canary binding digest",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(
        &self,
        trusted_runner_key: &PublicKey,
    ) -> Result<Vec<u8>, EnterpriseMigrationEvidenceError> {
        self.verify(trusted_runner_key)?;
        Ok(canonical_json_bytes(self)?)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        trusted_runner_key: &PublicKey,
    ) -> Result<Self, EnterpriseMigrationEvidenceError> {
        validate_wire_size(bytes, "canary evidence")?;
        let artifact: Self = serde_json::from_slice(bytes)?;
        artifact.verify(trusted_runner_key)?;
        if canonical_json_bytes(&artifact)? != bytes {
            return Err(EnterpriseMigrationEvidenceError::NonCanonical);
        }
        Ok(artifact)
    }

    pub fn from_canonical_bytes_against_policy(
        bytes: &[u8],
        trusted_runner_key: &PublicKey,
        policy: &EnterpriseMigrationCanaryVerificationPolicy,
    ) -> Result<Self, EnterpriseMigrationEvidenceError> {
        let artifact = Self::from_canonical_bytes(bytes, trusted_runner_key)?;
        artifact.verify_against_policy(trusted_runner_key, policy)?;
        Ok(artifact)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMigrationCutoverAttestationBody {
    pub schema: String,
    pub evidence_kind: String,
    pub attested_at_unix_ms: u64,
    pub operator_id: String,
    pub cohort_digest: Hash,
    pub provider_set_digest: Hash,
    pub tool_server_set_digest: Hash,
    pub pre_promotion_canary_binding_digest: Hash,
    pub pre_promotion_binding: EnterpriseMigrationEvidenceBinding,
    pub post_cutover_durable_migration_states: Vec<DurableEnterpriseMigrationStateBinding>,
    pub shadow_to_enforced_governance_authorization_digest: Hash,
    pub production_traffic_attested: bool,
    pub production_cutover_attested: bool,
    pub operational_failure_fail_closed: bool,
    pub authorizes_shadow_to_enforced: bool,
    pub legacy_removal_authorized: bool,
}

impl EnterpriseMigrationCutoverAttestationBody {
    pub fn validate(&self) -> Result<(), EnterpriseMigrationEvidenceError> {
        if self.schema != ENTERPRISE_MIGRATION_CUTOVER_ATTESTATION_SCHEMA
            || self.evidence_kind != "operator_production_cutover_attestation"
            || self.attested_at_unix_ms == 0
            || !self.production_traffic_attested
            || !self.production_cutover_attested
            || !self.operational_failure_fail_closed
            || self.authorizes_shadow_to_enforced
            || !self.legacy_removal_authorized
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "operator cutover assertions are invalid",
            ));
        }
        validate_identifier(&self.operator_id, "operator identifier")?;
        validate_nonzero_hash(self.cohort_digest, "cohort digest")?;
        validate_nonzero_hash(self.provider_set_digest, "provider set digest")?;
        validate_nonzero_hash(self.tool_server_set_digest, "tool-server set digest")?;
        validate_nonzero_hash(
            self.shadow_to_enforced_governance_authorization_digest,
            "shadow-to-enforced governance authorization digest",
        )?;
        self.pre_promotion_binding.validate()?;
        if self.pre_promotion_canary_binding_digest
            != self.pre_promotion_binding.binding_digest()?
        {
            return Err(EnterpriseMigrationEvidenceError::BindingMismatch);
        }
        if self
            .pre_promotion_binding
            .durable_migration_states
            .iter()
            .any(|state| state.stage != EnterpriseMigrationStage::Shadow)
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "operator attestation pre-promotion binding is not shadow state",
            ));
        }
        if self.post_cutover_durable_migration_states.is_empty()
            || self.post_cutover_durable_migration_states.len() > MAX_MIGRATION_STATES
            || self.post_cutover_durable_migration_states.len()
                != self.pre_promotion_binding.durable_migration_states.len()
        {
            return Err(EnterpriseMigrationEvidenceError::Invalid(
                "post-cutover durable migration state count is invalid",
            ));
        }
        for (pre_promotion, post_cutover) in self
            .pre_promotion_binding
            .durable_migration_states
            .iter()
            .zip(&self.post_cutover_durable_migration_states)
        {
            post_cutover.validate(self.pre_promotion_binding.configuration_digest)?;
            if pre_promotion.sort_key() != post_cutover.sort_key()
                || post_cutover.stage != EnterpriseMigrationStage::Enforced
                || post_cutover.generation
                    != pre_promotion.generation.checked_add(1).ok_or(
                        EnterpriseMigrationEvidenceError::Invalid(
                            "post-cutover migration generation overflowed",
                        ),
                    )?
                || post_cutover.updated_at_unix_ms <= pre_promotion.updated_at_unix_ms
            {
                return Err(EnterpriseMigrationEvidenceError::Invalid(
                    "post-cutover state is not the exact shadow-to-enforced successor",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnterpriseMigrationCutoverAttestation {
    pub body: EnterpriseMigrationCutoverAttestationBody,
    pub operator_key_id: Hash,
    pub operator_algorithm: SigningAlgorithm,
    pub operator_signature: Signature,
}

impl SignedEnterpriseMigrationCutoverAttestation {
    pub fn sign(
        body: EnterpriseMigrationCutoverAttestationBody,
        signer: &dyn SigningBackend,
    ) -> Result<Self, EnterpriseMigrationEvidenceError> {
        body.validate()?;
        let signing_bytes = domain_canonical_bytes(CUTOVER_SIGNATURE_DOMAIN, &body)?;
        let outcome = signer.sign_bytes_with_identity(&signing_bytes)?;
        Ok(Self {
            body,
            operator_key_id: signer_key_id(&outcome.public_key),
            operator_algorithm: outcome.algorithm,
            operator_signature: outcome.signature,
        })
    }

    pub fn verify_operator(
        &self,
        operator_key: &PublicKey,
    ) -> Result<(), EnterpriseMigrationEvidenceError> {
        self.body.validate()?;
        if self.operator_key_id != signer_key_id(operator_key)
            || self.operator_algorithm != operator_key.algorithm()
            || self.operator_algorithm != self.operator_signature.algorithm()
            || !operator_key.verify(
                &domain_canonical_bytes(CUTOVER_SIGNATURE_DOMAIN, &self.body)?,
                &self.operator_signature,
            )
        {
            return Err(EnterpriseMigrationEvidenceError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_against_canary(
        &self,
        operator_key: &PublicKey,
        canary: &SignedEnterpriseMigrationCanaryEvidence,
        trusted_runner_key: &PublicKey,
    ) -> Result<(), EnterpriseMigrationEvidenceError> {
        canary.verify(trusted_runner_key)?;
        self.verify_operator(operator_key)?;
        if self.body.pre_promotion_binding != canary.body.binding
            || self.body.pre_promotion_canary_binding_digest
                != canary.body.binding.binding_digest()?
        {
            return Err(EnterpriseMigrationEvidenceError::BindingMismatch);
        }
        Ok(())
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        operator_key: &PublicKey,
        canary: &SignedEnterpriseMigrationCanaryEvidence,
        trusted_runner_key: &PublicKey,
    ) -> Result<Self, EnterpriseMigrationEvidenceError> {
        validate_wire_size(bytes, "operator cutover attestation")?;
        let artifact: Self = serde_json::from_slice(bytes)?;
        artifact.verify_against_canary(operator_key, canary, trusted_runner_key)?;
        if canonical_json_bytes(&artifact)? != bytes {
            return Err(EnterpriseMigrationEvidenceError::NonCanonical);
        }
        Ok(artifact)
    }
}

#[derive(Debug, Error)]
pub enum EnterpriseMigrationEvidenceError {
    #[error("invalid enterprise migration evidence: {0}")]
    Invalid(&'static str),
    #[error("enterprise migration evidence signature is invalid")]
    InvalidSignature,
    #[error("operator attestation and designated-runner canary bindings differ")]
    BindingMismatch,
    #[error("enterprise migration canary does not match the external {0}")]
    ExternalBindingMismatch(&'static str),
    #[error("enterprise migration canary is outside the trusted generation window")]
    Stale,
    #[error("enterprise migration evidence is not canonical JSON")]
    NonCanonical,
    #[error("enterprise migration evidence cryptography failed: {0}")]
    Crypto(#[from] chio_core_types::Error),
    #[error("enterprise migration evidence JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

fn validate_source_commit(source_commit: &str) -> Result<(), EnterpriseMigrationEvidenceError> {
    if source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EnterpriseMigrationEvidenceError::Invalid(
            "source commit is not an exact lowercase SHA-1 object identifier",
        ));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), EnterpriseMigrationEvidenceError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(EnterpriseMigrationEvidenceError::Invalid(field));
    }
    Ok(())
}

fn validate_nonzero_hash(
    digest: Hash,
    field: &'static str,
) -> Result<(), EnterpriseMigrationEvidenceError> {
    if digest == Hash::zero() {
        return Err(EnterpriseMigrationEvidenceError::Invalid(field));
    }
    Ok(())
}

const fn stage_generation(stage: EnterpriseMigrationStage) -> u64 {
    match stage {
        EnterpriseMigrationStage::Disabled => 0,
        EnterpriseMigrationStage::Shadow => 1,
        EnterpriseMigrationStage::Enforced => 2,
        EnterpriseMigrationStage::LegacyRemoved => 3,
    }
}

const fn control_scope_is_valid(
    scope_kind: EnterpriseMigrationScopeKind,
    control: EnterpriseMigrationControl,
) -> bool {
    match control {
        EnterpriseMigrationControl::KeyLogVerification => {
            matches!(scope_kind, EnterpriseMigrationScopeKind::Deployment)
        }
        EnterpriseMigrationControl::BrokerCredentialCustody
        | EnterpriseMigrationControl::BrokerQuotaEnforcement => {
            matches!(scope_kind, EnterpriseMigrationScopeKind::Provider)
        }
        EnterpriseMigrationControl::CageEnforcement => {
            matches!(scope_kind, EnterpriseMigrationScopeKind::ToolServer)
        }
        EnterpriseMigrationControl::LegacyConfiguration => true,
    }
}

fn domain_canonical_bytes<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Vec<u8>, EnterpriseMigrationEvidenceError> {
    let canonical = canonical_json_bytes(value)?;
    let capacity = domain.len().checked_add(canonical.len()).ok_or(
        EnterpriseMigrationEvidenceError::Invalid(
            "signed enterprise evidence exceeds the byte range",
        ),
    )?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn signer_key_id(public_key: &PublicKey) -> Hash {
    let encoded = public_key.to_hex();
    let mut bytes = Vec::with_capacity(SIGNER_KEY_ID_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(SIGNER_KEY_ID_DOMAIN);
    bytes.extend_from_slice(encoded.as_bytes());
    sha256(&bytes)
}

fn validate_wire_size(
    bytes: &[u8],
    artifact: &'static str,
) -> Result<(), EnterpriseMigrationEvidenceError> {
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(EnterpriseMigrationEvidenceError::Invalid(artifact));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core_types::{Ed25519Backend, Keypair};

    fn digest(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn states(
        config_digest: Hash,
        stage: EnterpriseMigrationStage,
    ) -> Vec<DurableEnterpriseMigrationStateBinding> {
        let generation = stage_generation(stage);
        vec![
            DurableEnterpriseMigrationStateBinding {
                deployment_id: "deployment-1".to_owned(),
                scope_kind: EnterpriseMigrationScopeKind::Deployment,
                scope_id: "deployment-1".to_owned(),
                control: EnterpriseMigrationControl::KeyLogVerification,
                stage,
                generation,
                config_digest,
                evidence_digest: digest(31),
                updated_at_unix_ms: 1_000,
            },
            DurableEnterpriseMigrationStateBinding {
                deployment_id: "deployment-1".to_owned(),
                scope_kind: EnterpriseMigrationScopeKind::Provider,
                scope_id: "provider-1".to_owned(),
                control: EnterpriseMigrationControl::BrokerCredentialCustody,
                stage,
                generation,
                config_digest,
                evidence_digest: digest(32),
                updated_at_unix_ms: 1_001,
            },
            DurableEnterpriseMigrationStateBinding {
                deployment_id: "deployment-1".to_owned(),
                scope_kind: EnterpriseMigrationScopeKind::ToolServer,
                scope_id: "server-1".to_owned(),
                control: EnterpriseMigrationControl::CageEnforcement,
                stage,
                generation,
                config_digest,
                evidence_digest: digest(33),
                updated_at_unix_ms: 1_002,
            },
        ]
    }

    fn binding(stage: EnterpriseMigrationStage) -> EnterpriseMigrationEvidenceBinding {
        let configuration_digest = digest(2);
        EnterpriseMigrationEvidenceBinding {
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            runner: EnterpriseEvidenceRunnerIdentity {
                runner_name: "enterprise-runner-1".to_owned(),
                runner_os: "Linux".to_owned(),
                runner_arch: "X64".to_owned(),
                required_labels_digest: digest(1),
            },
            configuration_digest,
            inventory_digest: digest(3),
            durable_migration_states: states(configuration_digest, stage),
            gate_result_digests: EnterpriseMigrationGateResultDigests {
                runner_contract: digest(10),
                key_log_transparency: digest(11),
                broker_boundary: digest(12),
                cage_enforcement: digest(13),
                committed_adversarial_evidence: digest(14),
                linux_adversarial_controls: digest(15),
                migration_state_store: digest(16),
            },
        }
    }

    fn runner() -> Ed25519Backend {
        Ed25519Backend::new(Keypair::from_seed(&[41; 32]))
    }

    fn canary() -> SignedEnterpriseMigrationCanaryEvidence {
        let runner = runner();
        SignedEnterpriseMigrationCanaryEvidence::sign(
            EnterpriseMigrationCanaryEvidenceBody {
                schema: ENTERPRISE_MIGRATION_CANARY_EVIDENCE_SCHEMA.to_owned(),
                evidence_kind: "designated_runner_repository_canary".to_owned(),
                generated_at_unix_ms: 2_000,
                binding: binding(EnterpriseMigrationStage::Shadow),
                repository_mechanics_only: true,
                production_traffic_attested: false,
                production_cutover_attested: false,
                operator_attestation_required: true,
            },
            &runner,
            &runner.public_key(),
        )
        .expect("sign canary")
    }

    fn verification_policy(
        canary: &SignedEnterpriseMigrationCanaryEvidence,
    ) -> EnterpriseMigrationCanaryVerificationPolicy {
        EnterpriseMigrationCanaryVerificationPolicy {
            source_commit: canary.body.binding.source_commit.clone(),
            runner: canary.body.binding.runner.clone(),
            configuration_digest: canary.body.binding.configuration_digest,
            inventory_digest: canary.body.binding.inventory_digest,
            gate_result_digests: canary.body.binding.gate_result_digests.clone(),
            binding_digest: canary
                .body
                .binding
                .binding_digest()
                .expect("binding digest"),
            generated_at_not_before_unix_ms: 1_900,
            generated_at_not_after_unix_ms: 2_100,
        }
    }

    fn post_cutover_states(
        canary: &SignedEnterpriseMigrationCanaryEvidence,
    ) -> Vec<DurableEnterpriseMigrationStateBinding> {
        canary
            .body
            .binding
            .durable_migration_states
            .iter()
            .cloned()
            .map(|mut state| {
                state.stage = EnterpriseMigrationStage::Enforced;
                state.generation = 2;
                state.updated_at_unix_ms += 100;
                state
            })
            .collect()
    }

    fn operator_attestation(
        canary: &SignedEnterpriseMigrationCanaryEvidence,
        operator: &Ed25519Backend,
    ) -> SignedEnterpriseMigrationCutoverAttestation {
        SignedEnterpriseMigrationCutoverAttestation::sign(
            EnterpriseMigrationCutoverAttestationBody {
                schema: ENTERPRISE_MIGRATION_CUTOVER_ATTESTATION_SCHEMA.to_owned(),
                evidence_kind: "operator_production_cutover_attestation".to_owned(),
                attested_at_unix_ms: 3_000,
                operator_id: "operator-1".to_owned(),
                cohort_digest: digest(21),
                provider_set_digest: digest(22),
                tool_server_set_digest: digest(23),
                pre_promotion_canary_binding_digest: canary
                    .body
                    .binding
                    .binding_digest()
                    .expect("binding digest"),
                pre_promotion_binding: canary.body.binding.clone(),
                post_cutover_durable_migration_states: post_cutover_states(canary),
                shadow_to_enforced_governance_authorization_digest: digest(24),
                production_traffic_attested: true,
                production_cutover_attested: true,
                operational_failure_fail_closed: true,
                authorizes_shadow_to_enforced: false,
                legacy_removal_authorized: true,
            },
            operator,
        )
        .expect("sign operator attestation")
    }

    #[test]
    fn canary_is_canonical_signed_and_excludes_production_claims() {
        let runner = runner();
        let canary = canary();
        canary.verify(&runner.public_key()).expect("verify canary");
        let canonical = canary
            .canonical_bytes(&runner.public_key())
            .expect("canonical canary");
        let decoded = SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes(
            &canonical,
            &runner.public_key(),
        )
        .expect("decode canonical canary");
        assert_eq!(decoded, canary);

        let value: serde_json::Value = serde_json::from_slice(&canonical).expect("parse JSON");
        let body = value.get("body").expect("body");
        assert_eq!(
            body.get("repository_mechanics_only"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            body.get("production_traffic_attested"),
            Some(&serde_json::Value::Bool(false))
        );
        assert_eq!(
            body.get("production_cutover_attested"),
            Some(&serde_json::Value::Bool(false))
        );
        assert_eq!(
            body.get("operator_attestation_required"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_no_secret_or_raw_output_fields(&value);
    }

    #[test]
    fn canary_rejects_every_security_binding_mutation() {
        let runner = runner();
        let original = canary();
        let mut mutants = Vec::new();

        let mut source = original.clone();
        source.body.binding.source_commit = "1123456789abcdef0123456789abcdef01234567".to_owned();
        mutants.push(source);
        let mut runner_mutant = original.clone();
        runner_mutant.body.binding.runner.runner_name.push('x');
        mutants.push(runner_mutant);
        let mut config = original.clone();
        config.body.binding.configuration_digest = digest(55);
        mutants.push(config);
        let mut inventory = original.clone();
        inventory.body.binding.inventory_digest = digest(56);
        mutants.push(inventory);
        let mut generation = original.clone();
        generation.body.binding.durable_migration_states[0].generation = 3;
        mutants.push(generation);
        let mut gate = original.clone();
        gate.body.binding.gate_result_digests.cage_enforcement = digest(57);
        mutants.push(gate);
        let mut scope = original.clone();
        scope.body.production_cutover_attested = true;
        mutants.push(scope);

        for mutant in mutants {
            assert!(mutant.verify(&runner.public_key()).is_err());
        }
    }

    #[test]
    fn canary_requires_the_independently_pinned_runner_key() {
        let canary = canary();
        let wrong_runner = Keypair::from_seed(&[99; 32]).public_key();
        assert!(canary.verify(&wrong_runner).is_err());
        assert!(
            SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes(
                &canonical_json_bytes(&canary).expect("canonical JSON"),
                &wrong_runner,
            )
            .is_err()
        );
    }

    #[test]
    fn canary_requires_every_external_linux_evidence_binding() {
        let runner = runner();
        let canary = canary();
        let policy = verification_policy(&canary);
        let canonical = canary
            .canonical_bytes(&runner.public_key())
            .expect("canonical canary");
        SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes_against_policy(
            &canonical,
            &runner.public_key(),
            &policy,
        )
        .expect("externally bound canary");

        let mut mutants = Vec::new();
        let mut source = policy.clone();
        source.source_commit = "1123456789abcdef0123456789abcdef01234567".to_owned();
        mutants.push(source);
        let mut runner_name = policy.clone();
        runner_name.runner.runner_name.push('x');
        mutants.push(runner_name);
        let mut runner_os = policy.clone();
        runner_os.runner.runner_os = "linux".to_owned();
        mutants.push(runner_os);
        let mut runner_arch = policy.clone();
        runner_arch.runner.runner_arch = "x86_64".to_owned();
        mutants.push(runner_arch);
        let mut labels = policy.clone();
        labels.runner.required_labels_digest = digest(40);
        mutants.push(labels);
        let mut configuration = policy.clone();
        configuration.configuration_digest = digest(41);
        mutants.push(configuration);
        let mut inventory = policy.clone();
        inventory.inventory_digest = digest(42);
        mutants.push(inventory);
        let mut binding_digest = policy.clone();
        binding_digest.binding_digest = digest(43);
        mutants.push(binding_digest);

        let mutate_gates: [fn(&mut EnterpriseMigrationGateResultDigests); 7] = [
            |gates| gates.runner_contract = digest(50),
            |gates| gates.key_log_transparency = digest(51),
            |gates| gates.broker_boundary = digest(52),
            |gates| gates.cage_enforcement = digest(53),
            |gates| gates.committed_adversarial_evidence = digest(54),
            |gates| gates.linux_adversarial_controls = digest(55),
            |gates| gates.migration_state_store = digest(56),
        ];
        for mutate in mutate_gates {
            let mut gate_policy = policy.clone();
            mutate(&mut gate_policy.gate_result_digests);
            mutants.push(gate_policy);
        }

        for mutant in mutants {
            assert!(canary
                .verify_against_policy(&runner.public_key(), &mutant)
                .is_err());
        }
    }

    #[test]
    fn canary_rejects_stale_noncanonical_corrupt_and_substituted_evidence() {
        let runner = runner();
        let canary = canary();
        let policy = verification_policy(&canary);
        let canonical = canary
            .canonical_bytes(&runner.public_key())
            .expect("canonical canary");

        let mut stale = policy.clone();
        stale.generated_at_not_before_unix_ms = 2_001;
        stale.generated_at_not_after_unix_ms = 2_100;
        assert!(matches!(
            canary.verify_against_policy(&runner.public_key(), &stale),
            Err(EnterpriseMigrationEvidenceError::Stale)
        ));

        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        assert!(matches!(
            SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes_against_policy(
                &noncanonical,
                &runner.public_key(),
                &policy,
            ),
            Err(EnterpriseMigrationEvidenceError::NonCanonical)
        ));

        let mut corrupt: serde_json::Value =
            serde_json::from_slice(&canonical).expect("parse canonical canary");
        corrupt["signature"] = serde_json::Value::String("00".repeat(64));
        let corrupt = canonical_json_bytes(&corrupt).expect("canonical corrupt canary");
        assert!(
            SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes_against_policy(
                &corrupt,
                &runner.public_key(),
                &policy,
            )
            .is_err()
        );

        let substituted_key = Keypair::from_seed(&[99; 32]).public_key();
        assert!(
            SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes_against_policy(
                &canonical,
                &substituted_key,
                &policy,
            )
            .is_err()
        );
    }

    #[test]
    fn operator_attestation_requires_pinned_key_and_exact_canary_binding() {
        let runner = runner();
        let canary = canary();
        let operator = Ed25519Backend::new(Keypair::from_seed(&[42; 32]));
        let attestation = operator_attestation(&canary, &operator);
        attestation
            .verify_against_canary(&operator.public_key(), &canary, &runner.public_key())
            .expect("verify operator attestation");

        let wrong_operator = Keypair::from_seed(&[43; 32]).public_key();
        assert!(attestation
            .verify_against_canary(&wrong_operator, &canary, &runner.public_key())
            .is_err());

        let mut other_body = canary.body.clone();
        other_body.binding.inventory_digest = digest(77);
        let other_canary = SignedEnterpriseMigrationCanaryEvidence::sign(
            other_body,
            &runner,
            &runner.public_key(),
        )
        .expect("sign other canary");
        assert!(attestation
            .verify_against_canary(&operator.public_key(), &other_canary, &runner.public_key(),)
            .is_err());

        let mut rebound = attestation.clone();
        rebound.body.pre_promotion_binding.inventory_digest = digest(44);
        assert!(rebound
            .verify_against_canary(&operator.public_key(), &canary, &runner.public_key())
            .is_err());
    }

    #[test]
    fn canary_and_operator_signature_domains_are_not_interchangeable() {
        let canary = canary();
        let operator = Ed25519Backend::new(Keypair::from_seed(&[42; 32]));
        let mut attestation = operator_attestation(&canary, &operator);
        attestation.operator_signature = canary.signature.clone();
        assert!(attestation.verify_operator(&operator.public_key()).is_err());
    }

    #[test]
    fn operator_attestation_is_post_cutover_and_cannot_authorize_shadow_to_enforced() {
        let canary = canary();
        let operator = Ed25519Backend::new(Keypair::from_seed(&[42; 32]));
        let body = EnterpriseMigrationCutoverAttestationBody {
            schema: ENTERPRISE_MIGRATION_CUTOVER_ATTESTATION_SCHEMA.to_owned(),
            evidence_kind: "operator_production_cutover_attestation".to_owned(),
            attested_at_unix_ms: 3_000,
            operator_id: "operator-1".to_owned(),
            cohort_digest: digest(21),
            provider_set_digest: digest(22),
            tool_server_set_digest: digest(23),
            pre_promotion_canary_binding_digest: canary
                .body
                .binding
                .binding_digest()
                .expect("binding digest"),
            pre_promotion_binding: canary.body.binding.clone(),
            post_cutover_durable_migration_states: canary
                .body
                .binding
                .durable_migration_states
                .clone(),
            shadow_to_enforced_governance_authorization_digest: digest(24),
            production_traffic_attested: true,
            production_cutover_attested: true,
            operational_failure_fail_closed: true,
            authorizes_shadow_to_enforced: true,
            legacy_removal_authorized: true,
        };
        assert!(SignedEnterpriseMigrationCutoverAttestation::sign(body, &operator).is_err());
    }

    #[test]
    fn strict_deserialization_rejects_unknown_and_secret_fields() {
        let runner = runner();
        let canonical = canary()
            .canonical_bytes(&runner.public_key())
            .expect("canonical canary");
        let mut value: serde_json::Value = serde_json::from_slice(&canonical).expect("parse JSON");
        value.as_object_mut().expect("envelope object").insert(
            "raw_output".to_owned(),
            serde_json::Value::String("x".to_owned()),
        );
        let encoded = serde_json::to_vec(&value).expect("encode mutant");
        assert!(
            serde_json::from_slice::<SignedEnterpriseMigrationCanaryEvidence>(&encoded).is_err()
        );
    }

    #[test]
    fn evidence_capacity_supports_more_than_sixty_four_controls() {
        let mut binding = binding(EnterpriseMigrationStage::Shadow);
        let template = binding.durable_migration_states[0].clone();
        binding.durable_migration_states = (0..65)
            .map(|index| {
                let mut state = template.clone();
                state.deployment_id = format!("deployment-{index:03}");
                state.scope_id = state.deployment_id.clone();
                state
            })
            .collect();
        binding
            .validate()
            .expect("65 migration controls are supported");
    }

    fn assert_no_secret_or_raw_output_fields(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, nested) in object {
                    let lowered = key.to_ascii_lowercase();
                    assert!(!lowered.contains("secret"));
                    assert!(!lowered.contains("credential"));
                    assert!(!lowered.contains("raw_output"));
                    assert!(!lowered.contains("request_body"));
                    assert!(!lowered.contains("response_body"));
                    assert_no_secret_or_raw_output_fields(nested);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    assert_no_secret_or_raw_output_fields(item);
                }
            }
            _ => {}
        }
    }
}
