//! Independently verifiable simulation evidence, distinct from live receipts.

use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::ToolCallAction;
use chio_core::receipt::kinds::*;
use chio_core::{canonical_json_bytes, sha256, Hash, PublicKey};
use chio_core_types::receipt::metadata::{
    metadata_salt_ref, MetadataCommitment, MetadataOpenings, MetadataProjector, ProjectionError,
};
use chio_core_types::rng::Rng;
use chio_core_types::tenant_index::{IndexDomain, KeyedIndexValue, TenantIndexKeySet};
use chio_security_types::ports::*;
use chio_security_types::response_simulation::*;
use chio_security_types::{ResponseApprovalRequirement, ResponseExecutionMode, ResponsePlan};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSimulationReport {
    pub schema: String,
    pub configuration_digest: Digest32,
    pub plan: ResponsePlan,
    pub authorization_capability_hash: String,
    pub governed_intent_hash: String,
    pub policy_decision_hash: String,
    pub approval_set_hash: Option<String>,
    pub authorized_at_unix_ms: u64,
    pub snapshot: ResponseSimulationSnapshot,
    pub evaluation: ResponseSimulationEvaluation,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SimulationMetadata {
    response_simulation_evidence_id: OpaqueReceiptRef,
    response_simulation_report: ResponseSimulationReport,
}

pub fn response_simulation_evidence_id(
    plan: &ResponsePlan,
    configuration_digest: Digest32,
) -> PortResult<OpaqueReceiptRef> {
    let commitment = (
        RESPONSE_SIMULATION_SCHEMA,
        &plan.tenant_id,
        &plan.action_id,
        plan.plan_hash,
        configuration_digest,
    );
    let hash = domain_hash(b"chio.response-simulation.identity.v1\0", &commitment)?;
    OpaqueReceiptRef::new(format!(
        "response_simulation_{}",
        Hash::from_bytes(*hash.as_bytes()).to_hex()
    ))
    .map_err(PortError::from)
}

impl ResponseSimulationReport {
    pub fn validate(&self) -> PortResult<()> {
        if self.schema != RESPONSE_SIMULATION_SCHEMA
            || self.configuration_digest.is_zero()
            || self.plan.execution.mode() != ResponseExecutionMode::DryRun
            || self.authorized_at_unix_ms < self.plan.created_at_unix_ms
            || self.authorized_at_unix_ms >= self.plan.expires_at_unix_ms
            || self.snapshot.captured_at_unix_ms < self.authorized_at_unix_ms
            || self.authorization_capability_hash
                != Hash::from_bytes(*self.plan.operator_capability.capability_digest.as_bytes())
                    .to_hex()
            || matches!(
                (&self.plan.approval_requirement, &self.approval_set_hash),
                (ResponseApprovalRequirement::Automatic, Some(_))
                    | (ResponseApprovalRequirement::Governed { .. }, None)
            )
        {
            return Err(PortError::integrity_failure());
        }
        for value in [
            &self.authorization_capability_hash,
            &self.governed_intent_hash,
            &self.policy_decision_hash,
        ]
        .into_iter()
        .chain(self.approval_set_hash.iter())
        {
            if Hash::from_hex(value)
                .map_err(|_| PortError::invalid_data())?
                .to_hex()
                != *value
            {
                return Err(PortError::invalid_data());
            }
        }
        if chio_response_model::simulation::evaluate_response_simulation(
            &self.plan,
            &self.snapshot,
        )? != self.evaluation
        {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    pub fn evidence_id(&self) -> PortResult<OpaqueReceiptRef> {
        response_simulation_evidence_id(&self.plan, self.configuration_digest)
    }

    pub fn body_hash(&self) -> PortResult<Digest32> {
        domain_hash(b"chio.response-simulation.report.v1\0", self)
    }

    pub fn receipt_body(&self, signer: PublicKey) -> PortResult<ChioReceiptBody> {
        self.validate()?;
        let evidence_id = self.evidence_id()?;
        Ok(ChioReceiptBody {
            id: String::new(),
            timestamp: self.snapshot.captured_at_unix_ms / 1_000,
            capability_id: self
                .plan
                .operator_capability
                .capability_id
                .as_str()
                .to_owned(),
            tool_server: "chio.kernel".to_owned(),
            tool_name: RESPONSE_SIMULATION_SCHEMA.to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "simulation_evidence_id": evidence_id,
                "execution_mode": "dry_run"
            }))
            .map_err(|_| PortError::invalid_data())?,
            decision: None,
            receipt_kind: ReceiptKind::AdvisoryEvaluation,
            boundary_class: BoundaryClass::AdvisoryOnly,
            observation_outcome: Some(ObservationOutcome::Evaluated),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
            content_hash: Hash::from_bytes(*self.body_hash()?.as_bytes()).to_hex(),
            policy_hash: Hash::from_bytes(*self.plan.policy_hash.as_bytes()).to_hex(),
            evidence: Vec::new(),
            metadata: Some(
                serde_json::to_value(SimulationMetadata {
                    response_simulation_evidence_id: self.evidence_id()?,
                    response_simulation_report: self.clone(),
                })
                .map_err(|_| PortError::invalid_data())?,
            ),
            trust_level: TrustLevel::Advisory,
            tenant_id: Some(self.plan.tenant_id.as_str().to_owned()),
            kernel_key: signer,
            bbs_projection_version: None,
        })
    }
}

/// The trust anchor comes from the verifier, never from the embedded receipt.
pub fn verify_response_simulation_receipt(
    receipt: &ChioReceipt,
    expected_id: &OpaqueReceiptRef,
    trusted_signer: &PublicKey,
    configuration_digest: Digest32,
) -> PortResult<ResponseSimulationReport> {
    if &receipt.kernel_key != trusted_signer
        || !receipt
            .verify_integrity_embedded_key()
            .map_err(|_| PortError::integrity_failure())?
    {
        return Err(PortError::integrity_failure());
    }
    let report = validate_response_simulation_receipt_binding(receipt, expected_id)?;
    if report.configuration_digest != configuration_digest {
        return Err(PortError::integrity_failure());
    }
    Ok(report)
}

/// Structural validation used by the receipt store after signature verification.
pub fn validate_response_simulation_receipt_binding(
    receipt: &ChioReceipt,
    expected_id: &OpaqueReceiptRef,
) -> PortResult<ResponseSimulationReport> {
    let metadata: SimulationMetadata = serde_json::from_value(
        receipt
            .metadata
            .clone()
            .ok_or_else(PortError::invalid_data)?,
    )
    .map_err(|_| PortError::invalid_data())?;
    let report = metadata.response_simulation_report;
    if &metadata.response_simulation_evidence_id != expected_id
        || report.evidence_id()? != *expected_id
    {
        return Err(PortError::integrity_failure());
    }
    let mut expected = report.receipt_body(receipt.kernel_key.clone())?;
    expected.id = receipt.id.clone();
    if canonical_json_bytes(&expected).map_err(|_| PortError::invalid_data())?
        != canonical_json_bytes(&receipt.body()).map_err(|_| PortError::invalid_data())?
    {
        return Err(PortError::integrity_failure());
    }
    Ok(report)
}

fn domain_hash(domain: &[u8], value: &impl Serialize) -> PortResult<Digest32> {
    let mut bytes = domain.to_vec();
    bytes.extend(canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?);
    Ok(Digest32::new(*sha256(&bytes).as_bytes()))
}

/// Signed metadata block `response_simulation`: the report without its plan, snapshot or
/// evaluation. The plan, policy, configuration and authorization digests are committed
/// (`metadata.response_simulation.<field>`); the affected-set hash, the governed intent hash,
/// the snapshot and evaluation digests and the evidence id are keyed under the active-defense
/// purpose subkey. The full report stays the receipt's content preimage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSimulationProjection {
    pub schema: String,
    pub configuration_digest: MetadataCommitment,
    pub plan_hash: MetadataCommitment,
    pub policy_version: RecordId,
    pub policy_hash: MetadataCommitment,
    pub affected_set_hash: KeyedIndexValue,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub authorization_capability_hash: MetadataCommitment,
    pub governed_intent_hash: KeyedIndexValue,
    pub policy_decision_hash: MetadataCommitment,
    pub approval_set_hash: Option<MetadataCommitment>,
    pub authorized_at_unix_ms: u64,
    pub snapshot_digest: KeyedIndexValue,
    pub captured_at_unix_ms: u64,
    pub evaluation_digest: KeyedIndexValue,
    pub response_simulation_evidence_id: KeyedIndexValue,
}

impl ResponseSimulationReport {
    /// Draws one salt per committed field from `rng` and derives each keyed value under the
    /// active generation of `keys`; returns the projection and its openings.
    pub fn project(
        &self,
        keys: &TenantIndexKeySet,
        rng: &dyn Rng,
    ) -> Result<(ResponseSimulationProjection, MetadataOpenings), SimulationProjectionError> {
        let mut projector = MetadataProjector::project(keys, rng);
        let projection = self.build_projection(&mut projector)?;
        Ok((projection, projector.into_openings()))
    }

    /// True when every commitment in `projection` opens to this report with `openings`,
    /// every opening is used, and every keyed value derives from it under the generation the
    /// projection names; false on any mismatch, missing or unused opening or unknown
    /// generation.
    #[must_use]
    pub fn matches_projection(
        &self,
        projection: &ResponseSimulationProjection,
        openings: &MetadataOpenings,
        keys: &TenantIndexKeySet,
    ) -> bool {
        MetadataProjector::verify(
            keys,
            &projection.response_simulation_evidence_id.key_id,
            openings,
        )
        .map_err(SimulationProjectionError::from)
        .and_then(|mut projector| {
            let rebuilt = self.build_projection(&mut projector)?;
            projector.finish()?;
            Ok(rebuilt)
        })
        .is_ok_and(|rebuilt| rebuilt == *projection)
    }

    fn build_projection(
        &self,
        projector: &mut MetadataProjector<'_>,
    ) -> Result<ResponseSimulationProjection, SimulationProjectionError> {
        let salt_ref = |field: &str| {
            metadata_salt_ref("response_simulation", field)
                .map_err(|error| SimulationProjectionError::from(ProjectionError::from(error)))
        };
        let keyed = |projector: &MetadataProjector<'_>, preimage: &[u8]| {
            projector.keyed(IndexDomain::ActiveDefenseKeyedDigest, preimage)
        };
        let canonical = |value: Result<Vec<u8>, chio_core::Error>| {
            value.map_err(|_| SimulationProjectionError::Canonical)
        };
        let evidence_id = self
            .evidence_id()
            .map_err(|_| SimulationProjectionError::Canonical)?;
        let approval_set_hash = match &self.approval_set_hash {
            Some(hash) => Some(projector.commit(salt_ref("approval_set_hash")?, hash)?),
            None => None,
        };
        Ok(ResponseSimulationProjection {
            schema: self.schema.clone(),
            configuration_digest: projector.commit(
                salt_ref("configuration_digest")?,
                &self.configuration_digest,
            )?,
            plan_hash: projector.commit(salt_ref("plan_hash")?, &self.plan.plan_hash)?,
            policy_version: self.plan.policy_version.clone(),
            policy_hash: projector.commit(salt_ref("policy_hash")?, &self.plan.policy_hash)?,
            affected_set_hash: keyed(projector, self.plan.affected_set_hash.as_bytes())?,
            created_at_unix_ms: self.plan.created_at_unix_ms,
            expires_at_unix_ms: self.plan.expires_at_unix_ms,
            authorization_capability_hash: projector.commit(
                salt_ref("authorization_capability_hash")?,
                &self.authorization_capability_hash,
            )?,
            governed_intent_hash: keyed(projector, self.governed_intent_hash.as_bytes())?,
            policy_decision_hash: projector.commit(
                salt_ref("policy_decision_hash")?,
                &self.policy_decision_hash,
            )?,
            approval_set_hash,
            authorized_at_unix_ms: self.authorized_at_unix_ms,
            snapshot_digest: keyed(projector, &canonical(canonical_json_bytes(&self.snapshot))?)?,
            captured_at_unix_ms: self.snapshot.captured_at_unix_ms,
            evaluation_digest: keyed(
                projector,
                &canonical(canonical_json_bytes(&self.evaluation))?,
            )?,
            response_simulation_evidence_id: keyed(projector, evidence_id.as_str().as_bytes())?,
        })
    }
}

/// Why a response simulation projection cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationProjectionError {
    Projection(ProjectionError),
    /// The report has no canonical form or evidence id.
    Canonical,
}

impl From<ProjectionError> for SimulationProjectionError {
    fn from(error: ProjectionError) -> Self {
        Self::Projection(error)
    }
}

impl std::fmt::Display for SimulationProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Projection(error) => error.fmt(formatter),
            Self::Canonical => formatter.write_str("response simulation report is not canonical"),
        }
    }
}

impl std::error::Error for SimulationProjectionError {}
