use serde::{Deserialize, Serialize};

use chio_core::crypto::{PublicKey, SigningBackend};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::signing::ReceiptSigningHandle;

use crate::{
    CageEnforcementRecord, CageEnforcementState, CompiledCage, EnforcementEvidenceError,
    EnforcementPrepared, FileIdentity, FullyEnforcedEvidence, ResourceKind,
};

pub const CAGE_RECEIPT_BODY_SCHEMA: &str = "chio.cage.receipt-body.v1";
pub const CAGE_RECEIPT_METADATA_SCHEMA: &str = "chio.cage.receipt-metadata.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CageReceiptStage {
    Rejection,
    Bootstrap,
    Enforcement,
    TerminalExit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageReceiptBindings {
    pub manifest_digest: String,
    pub profile_digest: String,
    pub plan_digest: String,
    pub fd_table_digest: String,
    pub helper_binding_digest: String,
    pub target_binding_digest: String,
    pub target_identity: FileIdentity,
}

impl CageReceiptBindings {
    #[must_use]
    pub fn from_compiled(compiled: &CompiledCage) -> Self {
        Self {
            manifest_digest: compiled.plan().manifest_digest.clone(),
            profile_digest: compiled.profile_digest().to_string(),
            plan_digest: compiled.plan_digest().to_string(),
            fd_table_digest: compiled.profile().fd_table_digest.clone(),
            helper_binding_digest: compiled.profile().helper_binding_digest.clone(),
            target_binding_digest: compiled.profile().target_binding_digest.clone(),
            target_identity: compiled.runtime().target().resource().identity(),
        }
    }

    #[must_use]
    pub fn from_prepared(prepared: &EnforcementPrepared) -> Self {
        Self {
            manifest_digest: prepared.manifest_digest.clone(),
            profile_digest: prepared.profile_digest.clone(),
            plan_digest: prepared.plan_digest.clone(),
            fd_table_digest: prepared.fd_table_digest.clone(),
            helper_binding_digest: prepared.helper_binding_digest.clone(),
            target_binding_digest: prepared.target_binding_digest.clone(),
            target_identity: prepared.target_identity,
        }
    }

    pub fn validate(&self) -> Result<(), CageReceiptError> {
        for digest in [
            &self.manifest_digest,
            &self.profile_digest,
            &self.plan_digest,
            &self.fd_table_digest,
            &self.helper_binding_digest,
            &self.target_binding_digest,
        ] {
            validate_digest(digest)?;
        }
        if self.target_identity.kind() != ResourceKind::RegularFile
            || self.target_identity.inode() == 0
            || self.target_identity.mount_id() == 0
            || self.target_identity.mode() & 0o111 == 0
        {
            return Err(CageReceiptError::InvalidTargetIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageReceiptBody {
    pub schema: String,
    pub attempt_id: String,
    pub stage: CageReceiptStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bindings: Option<CageReceiptBindings>,
    pub enforcement_record: CageEnforcementRecord,
    pub started_at_unix_ms: u64,
    pub recorded_at_unix_ms: u64,
}

impl CageReceiptBody {
    pub fn new(
        attempt_id: impl Into<String>,
        bindings: Option<CageReceiptBindings>,
        enforcement_record: CageEnforcementRecord,
        started_at_unix_ms: u64,
        recorded_at_unix_ms: u64,
    ) -> Result<Self, CageReceiptError> {
        let stage = stage_for_state(enforcement_record.state);
        let derived_bindings = evidence_bindings(&enforcement_record);
        let bindings = match (bindings, derived_bindings) {
            (Some(claimed), Some(observed)) if claimed != observed => {
                return Err(CageReceiptError::BindingMismatch);
            }
            (Some(claimed), _) => Some(claimed),
            (None, Some(observed)) => Some(observed),
            (None, None) => None,
        };
        let body = Self {
            schema: CAGE_RECEIPT_BODY_SCHEMA.to_string(),
            attempt_id: attempt_id.into(),
            stage,
            bindings,
            enforcement_record,
            started_at_unix_ms,
            recorded_at_unix_ms,
        };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), CageReceiptError> {
        if self.schema != CAGE_RECEIPT_BODY_SCHEMA {
            return Err(CageReceiptError::InvalidSchema);
        }
        validate_identifier(&self.attempt_id)?;
        self.enforcement_record.validate()?;
        if self.stage != stage_for_state(self.enforcement_record.state) {
            return Err(CageReceiptError::InvalidStage);
        }
        if self.started_at_unix_ms == 0
            || self.recorded_at_unix_ms < 1_000
            || self.recorded_at_unix_ms < self.started_at_unix_ms
        {
            return Err(CageReceiptError::InvalidTime);
        }
        if let Some(bindings) = &self.bindings {
            bindings.validate()?;
        }

        match self.enforcement_record.state {
            CageEnforcementState::Unsupported | CageEnforcementState::Rejected => {}
            CageEnforcementState::BootstrapFailed => {
                if self.bindings.is_none() {
                    return Err(CageReceiptError::MissingBindings);
                }
            }
            CageEnforcementState::FullyEnforced | CageEnforcementState::Exited => {
                let evidence = self
                    .enforcement_record
                    .fully_enforced
                    .as_ref()
                    .ok_or(CageReceiptError::InvalidStage)?;
                validate_enforcement_time(evidence, self.started_at_unix_ms)?;
                if self.recorded_at_unix_ms < evidence.exec_transition.observed_at_unix_ms {
                    return Err(CageReceiptError::InvalidTime);
                }
                let observed = CageReceiptBindings::from_prepared(&evidence.prepared);
                if self.bindings.as_ref() != Some(&observed) {
                    return Err(CageReceiptError::BindingMismatch);
                }
                if let Some(exit) = &self.enforcement_record.exit {
                    if exit.exited_at_unix_ms < evidence.exec_transition.observed_at_unix_ms
                        || self.recorded_at_unix_ms < exit.exited_at_unix_ms
                    {
                        return Err(CageReceiptError::InvalidTime);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CageReceiptSigningContext {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    policy_hash: String,
    tenant_id: Option<String>,
}

impl CageReceiptSigningContext {
    pub fn new(
        capability_id: impl Into<String>,
        tool_server: impl Into<String>,
        tool_name: impl Into<String>,
        policy_hash: impl Into<String>,
        tenant_id: Option<String>,
    ) -> Result<Self, CageReceiptError> {
        let context = Self {
            capability_id: capability_id.into(),
            tool_server: tool_server.into(),
            tool_name: tool_name.into(),
            policy_hash: policy_hash.into(),
            tenant_id,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> Result<(), CageReceiptError> {
        validate_identifier(&self.capability_id)?;
        validate_identifier(&self.tool_server)?;
        validate_identifier(&self.tool_name)?;
        validate_digest(&self.policy_hash)?;
        if let Some(tenant_id) = &self.tenant_id {
            validate_identifier(tenant_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CageReceiptMetadata {
    schema: String,
    cage_receipt: CageReceiptBody,
}

#[derive(Debug)]
pub struct PreparedCageReceipt {
    body: ChioReceiptBody,
    handle: ReceiptSigningHandle,
}

impl PreparedCageReceipt {
    pub fn sign(self, backend: &dyn SigningBackend) -> Result<ChioReceipt, CageReceiptError> {
        let receipt = ChioReceipt::sign_with_backend_using_handle(self.body, backend, self.handle)?;
        verify_signed_cage_receipt(&receipt)?;
        Ok(receipt)
    }

    #[must_use]
    pub fn into_signing_parts(self) -> (ChioReceiptBody, ReceiptSigningHandle) {
        (self.body, self.handle)
    }
}

pub fn prepare_cage_receipt(
    cage_receipt: CageReceiptBody,
    context: &CageReceiptSigningContext,
    kernel_key: PublicKey,
) -> Result<PreparedCageReceipt, CageReceiptError> {
    cage_receipt.validate()?;
    context.validate()?;
    if cage_receipt
        .bindings
        .as_ref()
        .is_some_and(|bindings| bindings.profile_digest != context.policy_hash)
    {
        return Err(CageReceiptError::BindingMismatch);
    }
    let handle = ReceiptSigningHandle::from_content(&cage_receipt)?;
    let content_hash = handle.content_hash().to_string();
    let parameters = serde_json::json!({
        "attempt_id": cage_receipt.attempt_id,
        "stage": cage_receipt.stage,
        "state": cage_receipt.enforcement_record.state,
    });
    let (decision, receipt_kind, boundary_class, observation_outcome, trust_level) =
        generic_semantics(&cage_receipt);
    let metadata = CageReceiptMetadata {
        schema: CAGE_RECEIPT_METADATA_SCHEMA.to_string(),
        cage_receipt,
    };
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: metadata.cage_receipt.recorded_at_unix_ms / 1_000,
        capability_id: context.capability_id.clone(),
        tool_server: context.tool_server.clone(),
        tool_name: context.tool_name.clone(),
        action: ToolCallAction::from_parameters(parameters)?,
        decision,
        receipt_kind,
        boundary_class,
        observation_outcome,
        tool_origin: ToolOrigin::ChioInternal,
        redaction_mode: RedactionMode::Summary,
        actor_chain: Vec::new(),
        content_hash,
        policy_hash: context.policy_hash.clone(),
        evidence: Vec::new(),
        metadata: Some(serde_json::to_value(metadata)?),
        trust_level,
        tenant_id: context.tenant_id.clone(),
        kernel_key,
        bbs_projection_version: None,
    };
    Ok(PreparedCageReceipt { body, handle })
}

pub fn sign_cage_receipt(
    cage_receipt: CageReceiptBody,
    context: &CageReceiptSigningContext,
    backend: &dyn SigningBackend,
) -> Result<ChioReceipt, CageReceiptError> {
    prepare_cage_receipt(cage_receipt, context, backend.public_key())?.sign(backend)
}

pub fn verify_signed_cage_receipt(
    receipt: &ChioReceipt,
) -> Result<CageReceiptBody, CageReceiptError> {
    if !receipt.verify_signature()? || !receipt.action.verify_hash()? {
        return Err(CageReceiptError::InvalidSignature);
    }
    validate_identifier(&receipt.capability_id)?;
    validate_identifier(&receipt.tool_server)?;
    validate_identifier(&receipt.tool_name)?;
    validate_digest(&receipt.policy_hash)?;
    if receipt
        .tenant_id
        .as_ref()
        .is_some_and(|tenant_id| validate_identifier(tenant_id).is_err())
    {
        return Err(CageReceiptError::InvalidIdentifier);
    }
    let metadata: CageReceiptMetadata = serde_json::from_value(
        receipt
            .metadata
            .clone()
            .ok_or(CageReceiptError::MissingMetadata)?,
    )?;
    if metadata.schema != CAGE_RECEIPT_METADATA_SCHEMA {
        return Err(CageReceiptError::InvalidSchema);
    }
    metadata.cage_receipt.validate()?;
    let canonical = chio_core::canonical_json_bytes(&metadata.cage_receipt)?;
    if receipt.content_hash != chio_core::sha256_hex(&canonical)
        || receipt.timestamp != metadata.cage_receipt.recorded_at_unix_ms / 1_000
        || metadata
            .cage_receipt
            .bindings
            .as_ref()
            .is_some_and(|bindings| bindings.profile_digest != receipt.policy_hash)
    {
        return Err(CageReceiptError::ContentMismatch);
    }
    let expected_parameters = serde_json::json!({
        "attempt_id": metadata.cage_receipt.attempt_id,
        "stage": metadata.cage_receipt.stage,
        "state": metadata.cage_receipt.enforcement_record.state,
    });
    if receipt.action.parameters != expected_parameters {
        return Err(CageReceiptError::ContentMismatch);
    }
    let (decision, receipt_kind, boundary_class, observation_outcome, trust_level) =
        generic_semantics(&metadata.cage_receipt);
    if receipt.decision != decision
        || receipt.receipt_kind != receipt_kind
        || receipt.boundary_class != boundary_class
        || receipt.observation_outcome != observation_outcome
        || receipt.trust_level != trust_level
        || receipt.tool_origin != ToolOrigin::ChioInternal
        || receipt.redaction_mode != RedactionMode::Summary
        || !receipt.actor_chain.is_empty()
        || !receipt.evidence.is_empty()
        || receipt.bbs_projection_version.is_some()
        || receipt.bbs_signature.is_some()
    {
        return Err(CageReceiptError::SemanticMismatch);
    }
    Ok(metadata.cage_receipt)
}

pub fn verify_signed_cage_receipt_with_trusted_key(
    receipt: &ChioReceipt,
    trusted_kernel_key: &PublicKey,
) -> Result<CageReceiptBody, CageReceiptError> {
    if &receipt.kernel_key != trusted_kernel_key {
        return Err(CageReceiptError::UntrustedSigner);
    }
    verify_signed_cage_receipt(receipt)
}

#[derive(Debug)]
pub enum CageReceiptPersistenceError<E> {
    Invalid(CageReceiptError),
    Sink(E),
}

pub fn persist_signed_cage_receipt<E>(
    receipt: &ChioReceipt,
    append_chio_receipt: impl FnOnce(&ChioReceipt) -> Result<(), E>,
) -> Result<(), CageReceiptPersistenceError<E>> {
    verify_signed_cage_receipt(receipt).map_err(CageReceiptPersistenceError::Invalid)?;
    append_chio_receipt(receipt).map_err(CageReceiptPersistenceError::Sink)
}

pub fn persist_signed_cage_receipt_with_trusted_key<E>(
    receipt: &ChioReceipt,
    trusted_kernel_key: &PublicKey,
    append_chio_receipt: impl FnOnce(&ChioReceipt) -> Result<(), E>,
) -> Result<(), CageReceiptPersistenceError<E>> {
    verify_signed_cage_receipt_with_trusted_key(receipt, trusted_kernel_key)
        .map_err(CageReceiptPersistenceError::Invalid)?;
    append_chio_receipt(receipt).map_err(CageReceiptPersistenceError::Sink)
}

fn stage_for_state(state: CageEnforcementState) -> CageReceiptStage {
    match state {
        CageEnforcementState::Unsupported | CageEnforcementState::Rejected => {
            CageReceiptStage::Rejection
        }
        CageEnforcementState::BootstrapFailed => CageReceiptStage::Bootstrap,
        CageEnforcementState::FullyEnforced => CageReceiptStage::Enforcement,
        CageEnforcementState::Exited => CageReceiptStage::TerminalExit,
    }
}

fn evidence_bindings(record: &CageEnforcementRecord) -> Option<CageReceiptBindings> {
    record
        .fully_enforced
        .as_ref()
        .map(|evidence| CageReceiptBindings::from_prepared(&evidence.prepared))
}

fn validate_enforcement_time(
    evidence: &FullyEnforcedEvidence,
    started_at_unix_ms: u64,
) -> Result<(), CageReceiptError> {
    if evidence.prepared.prepared_at_unix_ms < started_at_unix_ms
        || evidence.exec_transition.observed_at_unix_ms < evidence.prepared.prepared_at_unix_ms
    {
        return Err(CageReceiptError::InvalidTime);
    }
    Ok(())
}

fn generic_semantics(
    cage_receipt: &CageReceiptBody,
) -> (
    Option<Decision>,
    ReceiptKind,
    BoundaryClass,
    Option<ObservationOutcome>,
    TrustLevel,
) {
    match cage_receipt.enforcement_record.state {
        CageEnforcementState::Unsupported
        | CageEnforcementState::Rejected
        | CageEnforcementState::BootstrapFailed => (
            Some(Decision::Deny {
                reason: "native cage launch did not reach full enforcement".to_string(),
                guard: "chio-cage".to_string(),
            }),
            ReceiptKind::MediatedDecision,
            BoundaryClass::Prevent,
            None,
            TrustLevel::Mediated,
        ),
        CageEnforcementState::FullyEnforced => (
            Some(Decision::Allow),
            ReceiptKind::MediatedDecision,
            BoundaryClass::Prevent,
            None,
            TrustLevel::Mediated,
        ),
        CageEnforcementState::Exited => (
            None,
            ReceiptKind::TraceObservation,
            BoundaryClass::DetectOnly,
            Some(ObservationOutcome::Observed),
            TrustLevel::Verified,
        ),
    }
}

fn validate_identifier(value: &str) -> Result<(), CageReceiptError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CageReceiptError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), CageReceiptError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CageReceiptError::InvalidDigest);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CageReceiptError {
    #[error("cage receipt schema is invalid")]
    InvalidSchema,
    #[error("cage receipt identifier is invalid")]
    InvalidIdentifier,
    #[error("cage receipt digest is invalid")]
    InvalidDigest,
    #[error("cage receipt target identity is invalid")]
    InvalidTargetIdentity,
    #[error("cage receipt stage does not match its enforcement state")]
    InvalidStage,
    #[error("cage receipt timestamps are invalid")]
    InvalidTime,
    #[error("bootstrap cage receipt is missing compiled bindings")]
    MissingBindings,
    #[error("cage receipt bindings do not match observed enforcement")]
    BindingMismatch,
    #[error("signed cage receipt has no cage metadata")]
    MissingMetadata,
    #[error("signed cage receipt signature is invalid")]
    InvalidSignature,
    #[error("signed cage receipt signer is not a configured trust root")]
    UntrustedSigner,
    #[error("signed cage receipt content does not match its cage body")]
    ContentMismatch,
    #[error("signed cage receipt semantics do not match its cage outcome")]
    SemanticMismatch,
    #[error("enforcement evidence is invalid: {0}")]
    Enforcement(#[from] EnforcementEvidenceError),
    #[error("Chio receipt operation failed: {0}")]
    Chio(#[from] chio_core::error::Error),
    #[error("cage receipt metadata failed: {0}")]
    Json(#[from] serde_json::Error),
}
