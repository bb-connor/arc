//! Independently verifiable simulation evidence, distinct from live receipts.

use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::ToolCallAction;
use chio_core::receipt::kinds::*;
use chio_core::{canonical_json_bytes, sha256, Hash, PublicKey};
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
        if chio_quarantine::simulation::evaluate_response_simulation(&self.plan, &self.snapshot)?
            != self.evaluation
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
            .verify_signature()
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
