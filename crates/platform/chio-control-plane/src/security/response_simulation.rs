use chio_core::{receipt::body::ChioReceipt, SigningBackend};
use chio_kernel::response_simulation_report::{
    response_simulation_evidence_id, verify_response_simulation_receipt, ResponseSimulationReport,
};
use chio_kernel::{ActiveResponseSimulationRequest, ChioKernel, IndexedSecurityEvidenceStore};
use chio_security_types::ports::*;
use chio_security_types::response_simulation::*;
use chio_security_types::{ResponseEffectKind, ResponseExecutionMode, ResponsePlan};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use std::sync::Arc;

const RECEIPT_STORE_UNAVAILABLE: &str = "urn:chio:error:attest:receipt-store-unavailable";
const RECEIPT_VERIFICATION_FAILED: &str = "urn:chio:error:attest:receipt-verification-failed";

/// Both native failures from an append whose committed result cannot be read back.
/// Neither public formatting path discloses retained source text.
#[derive(Debug)]
pub struct ResponseSimulationReconciliationError {
    append_error: PortError,
    readback_error: PortError,
}
impl ResponseSimulationReconciliationError {
    #[must_use]
    pub const fn append_error(&self) -> &PortError {
        &self.append_error
    }
    #[must_use]
    pub const fn readback_error(&self) -> &PortError {
        &self.readback_error
    }
}
impl std::fmt::Display for ResponseSimulationReconciliationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("response simulation receipt reconciliation failed")
    }
}
impl std::error::Error for ResponseSimulationReconciliationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.readback_error)
    }
}

fn port_rule(kind: PortErrorKind) -> &'static str {
    match kind {
        PortErrorKind::Unavailable => RECEIPT_STORE_UNAVAILABLE,
        PortErrorKind::Conflict | PortErrorKind::IntegrityFailure => RECEIPT_VERIFICATION_FAILED,
        PortErrorKind::InvalidData => "urn:chio:error:transport:invalid-request-shape",
    }
}
fn registered_port_error(error: PortError) -> PortError {
    if chio_errors::_generated::error_codes::lookup_error_code(error.code().as_str()).is_some() {
        return error;
    }
    PortError::with_source(error.kind(), port_rule(error.kind()), error)
}
fn signing_error(error: chio_core::Error) -> PortError {
    PortError::with_source(
        PortErrorKind::Unavailable,
        "urn:chio:error:attest:receipt-signing-failed",
        error,
    )
}

fn receipt_store_error(error: chio_kernel::ReceiptStoreError) -> PortError {
    use chio_kernel::ReceiptStoreError;
    let (kind, code) = match &error {
        ReceiptStoreError::Clock(error) => (PortErrorKind::Unavailable, error.code()),
        ReceiptStoreError::UntrustedInput(error) => (PortErrorKind::IntegrityFailure, error.code()),
        ReceiptStoreError::Conflict(_)
        | ReceiptStoreError::Canonical(_)
        | ReceiptStoreError::CryptoDecode(_)
        | ReceiptStoreError::Json(_)
        | ReceiptStoreError::RetentionArchiveIncomplete { .. }
        | ReceiptStoreError::ArchivedRangeProjection { .. } => {
            (PortErrorKind::IntegrityFailure, RECEIPT_VERIFICATION_FAILED)
        }
        ReceiptStoreError::ReadBoundary(_) | ReceiptStoreError::Fenced => {
            (PortErrorKind::Unavailable, RECEIPT_STORE_UNAVAILABLE)
        }
        ReceiptStoreError::InvalidOutcome(_)
        | ReceiptStoreError::ReadAuthorization(_)
        | ReceiptStoreError::RetentionTenantScopeUnsupported => (
            PortErrorKind::InvalidData,
            "urn:chio:error:transport:invalid-request-shape",
        ),
        ReceiptStoreError::Sqlite(rusqlite::Error::SqliteFailure(native, _))
            if matches!(
                native.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            (PortErrorKind::IntegrityFailure, RECEIPT_VERIFICATION_FAILED)
        }
        _ => (PortErrorKind::Unavailable, RECEIPT_STORE_UNAVAILABLE),
    };
    PortError::with_source(kind, code, error)
}

// Emit closed cause classes, not arbitrary parser/provider messages. The complete
// native errors remain inspectable through Error::source and reconciliation accessors.
fn record_simulation_failure(operation: &'static str, error: &PortError) {
    let mut causes = Vec::new();
    let mut source = std::error::Error::source(error);
    for _ in 0..4 {
        let Some(cause) = source else {
            break;
        };
        let entry = if let Some(error) = cause.downcast_ref::<PortError>() {
            let code =
                chio_errors::_generated::error_codes::lookup_error_code(error.code().as_str())
                    .map_or_else(|| port_rule(error.kind()), |spec| spec.urn);
            serde_json::json!({ "class": "port", "kind": error.kind(), "code": code })
        } else if let Some(error) = cause.downcast_ref::<chio_kernel::ReceiptStoreError>() {
            use chio_kernel::ReceiptStoreError;
            let class = match error {
                ReceiptStoreError::Clock(_) => "authority_clock",
                ReceiptStoreError::Sqlite(_) => "sqlite",
                ReceiptStoreError::Io(_) => "io",
                ReceiptStoreError::Conflict(_) => "conflict",
                ReceiptStoreError::Fenced => "fenced",
                ReceiptStoreError::OutcomeUnknown(_) => "outcome_unknown",
                ReceiptStoreError::Unsupported(_) => "unsupported",
                ReceiptStoreError::Json(_) => "json",
                ReceiptStoreError::ReadBoundary(_) => "read_boundary",
                ReceiptStoreError::UntrustedInput(_) => "original_json",
                _ => "receipt_store",
            };
            serde_json::json!({ "class": class })
        } else if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            serde_json::json!({ "class": "io", "kind": format!("{:?}", error.kind()) })
        } else if let Some(error) = cause.downcast_ref::<serde_json::Error>() {
            serde_json::json!({ "class": "json_parser", "category": format!("{:?}", error.classify()), "line": error.line(), "column": error.column() })
        } else if let Some(error) = cause.downcast_ref::<chio_security_types::clock::ClockError>() {
            serde_json::json!({ "class": "authority_clock", "code": error.code() })
        } else if cause.is::<chio_core::Error>() {
            serde_json::json!({ "class": "core_validation" })
        } else {
            serde_json::json!({ "class": "native_error" })
        };
        causes.push(entry);
        source = cause.source();
    }
    tracing::warn!(operation, code = %error.code().as_str(), kind = ?error.kind(), causes = %serde_json::json!({ "chain": causes, "truncated": source.is_some() }), "response simulation boundary refused");
}

pub struct SqliteResponseSimulationSource {
    state: Arc<SqliteSecurityStateStore>,
    scope: Arc<dyn BlastRadiusPort>,
}

impl SqliteResponseSimulationSource {
    pub fn new(state: Arc<SqliteSecurityStateStore>, scope: Arc<dyn BlastRadiusPort>) -> Self {
        Self { state, scope }
    }
}

impl ResponseSimulationSnapshotSource for SqliteResponseSimulationSource {
    fn capture(&self, plan: &ResponsePlan) -> PortResult<ResponseSimulationSnapshot> {
        let mut snapshot = self.state.capture_response_simulation(plan)?;
        let mut scopes = Vec::new();
        for effect in plan.effects.as_slice() {
            if effect.kind == ResponseEffectKind::FreezeIssuance {
                let spec: IssuanceFreezeSpec = chio_core::canonical::UntrustedJsonText::from_wire(
                    effect.canonical_contribution.as_bytes(),
                    64 * 1024 * 1024,
                )
                .and_then(|input| input.decode_signed())
                .map_err(|error| {
                    PortError::with_source(
                        chio_security_types::ports::PortErrorKind::InvalidData,
                        error.code(),
                        error,
                    )
                })?;
                // This read is separately versioned; never acquire or renew a
                // live fence while modelling issuance.
                let result = self.scope.resolve(&spec.acquisition.request)?;
                scopes.push(ResponseSimulationScope {
                    effect_id: effect.effect_id.clone(),
                    result,
                });
            }
        }
        snapshot.scopes = BoundedVec::new(scopes).map_err(|_| PortError::invalid_data())?;
        Ok(snapshot)
    }
}

/// Production simulation service. Its only write capability is the signed
/// receipt store. It owns neither an effect port nor an alert delivery port.
pub struct ProductionResponseSimulator {
    snapshots: Arc<dyn ResponseSimulationSnapshotSource>,
    receipts: Arc<dyn IndexedSecurityEvidenceStore>,
    signer: Arc<dyn SigningBackend>,
    configuration_digest: Digest32,
}

impl ProductionResponseSimulator {
    pub const fn configuration_digest(&self) -> Digest32 {
        self.configuration_digest
    }

    pub fn signing_identity(&self) -> chio_core::PublicKey {
        self.signer.public_key()
    }

    pub fn new(
        snapshots: Arc<dyn ResponseSimulationSnapshotSource>,
        receipts: Arc<dyn IndexedSecurityEvidenceStore>,
        signer: Arc<dyn SigningBackend>,
        configuration_digest: Digest32,
    ) -> PortResult<Self> {
        if configuration_digest.is_zero() {
            return Err(registered_port_error(PortError::invalid_data()));
        }
        let service = Self {
            snapshots,
            receipts,
            signer,
            configuration_digest,
        };
        service.ensure_ready()?;
        Ok(service)
    }

    pub fn ensure_ready(&self) -> PortResult<()> {
        self.receipts
            .ensure_indexed_security_evidence_ready()
            .map_err(|error| {
                let error = receipt_store_error(error);
                record_simulation_failure("store_readiness", &error);
                error
            })?;
        self.signer
            .sign_bytes(b"chio.response-simulation.readiness.v1\0")
            .map_err(|error| {
                let error = signing_error(error);
                record_simulation_failure("signer_readiness", &error);
                error
            })?;
        Ok(())
    }

    /// Exact immutable readback remains valid after plan expiry or restart.
    /// It returns historical evidence and never reissues authorization.
    pub fn load(
        &self,
        plan: &ResponsePlan,
    ) -> PortResult<Option<(ResponseSimulationReport, ChioReceipt)>> {
        if plan.execution.mode() != ResponseExecutionMode::DryRun {
            return Err(registered_port_error(PortError::invalid_data()));
        }
        let id = response_simulation_evidence_id(plan, self.configuration_digest)
            .map_err(registered_port_error)?;
        let Some(receipt) = self
            .receipts
            .load_indexed_security_evidence(&id)
            .map_err(|error| {
                let error = receipt_store_error(error);
                record_simulation_failure("load", &error);
                error
            })?
        else {
            return Ok(None);
        };
        let report = verify_response_simulation_receipt(
            &receipt,
            &id,
            &self.signer.public_key(),
            self.configuration_digest,
        )
        .map_err(registered_port_error)?;
        if report.plan != *plan {
            return Err(registered_port_error(PortError::integrity_failure()));
        }
        Ok(Some((report, receipt)))
    }

    pub fn run(
        &self,
        kernel: &ChioKernel,
        request: &ActiveResponseSimulationRequest,
    ) -> PortResult<(ResponseSimulationReport, ChioReceipt)> {
        let plan = request.response_plan();
        if let Some(retained) = self.load(plan)? {
            return Ok(retained);
        }
        let authorization = kernel
            .verify_active_response_simulation(request)
            .map_err(super::event_consumer::map_active_response_kernel_error)?;
        let snapshot = self
            .snapshots
            .capture(plan)
            .map_err(registered_port_error)?;
        let evaluation = chio_quarantine::simulation::evaluate_response_simulation(plan, &snapshot)
            .map_err(registered_port_error)?;
        let report = ResponseSimulationReport {
            schema: RESPONSE_SIMULATION_SCHEMA.to_owned(),
            configuration_digest: self.configuration_digest,
            plan: plan.clone(),
            authorization_capability_hash: authorization
                .bindings()
                .authorization_capability_hash()
                .to_owned(),
            governed_intent_hash: authorization.bindings().governed_intent_hash().to_owned(),
            policy_decision_hash: authorization.policy_decision_hash().to_owned(),
            approval_set_hash: authorization.approval_set_hash().map(str::to_owned),
            authorized_at_unix_ms: authorization.authorized_at_unix_ms(),
            snapshot,
            evaluation,
        };
        let receipt = ChioReceipt::sign_with_backend(
            report
                .receipt_body(self.signer.public_key())
                .map_err(registered_port_error)?,
            self.signer.as_ref(),
        )
        .map_err(|error| {
            let error = signing_error(error);
            record_simulation_failure("sign", &error);
            error
        })?;
        // Recheck real authority after capture and signing, before recording a
        // fresh successful evaluation. This cannot reserve or consume tokens.
        kernel
            .verify_active_response_simulation(request)
            .map_err(super::event_consumer::map_active_response_kernel_error)?;
        let id = report.evidence_id().map_err(registered_port_error)?;
        let persisted = match self
            .receipts
            .append_indexed_security_evidence(&id, &receipt)
        {
            Ok(persisted) => persisted,
            Err(append_error) => {
                let append_error = receipt_store_error(append_error);
                record_simulation_failure("append", &append_error);
                return match self.load(plan) {
                    Ok(Some(retained)) => Ok(retained),
                    Ok(None) => Err(append_error),
                    Err(readback_error) => {
                        let code = chio_errors::_generated::error_codes::lookup_error_code(
                            readback_error.code().as_str(),
                        )
                        .map_or_else(|| port_rule(readback_error.kind()), |spec| spec.urn);
                        Err(PortError::with_source(
                            readback_error.kind(),
                            code,
                            ResponseSimulationReconciliationError {
                                append_error,
                                readback_error,
                            },
                        ))
                    }
                };
            }
        };
        let verified = verify_response_simulation_receipt(
            &persisted,
            &id,
            &self.signer.public_key(),
            self.configuration_digest,
        )
        .map_err(registered_port_error)?;
        if verified != report {
            return Err(registered_port_error(PortError::integrity_failure()));
        }
        Ok((verified, persisted))
    }
}

/// Selected explicitly by the deployment host; there is no inferred default.
#[derive(Clone)]
pub enum ActiveResponseExecutionProfile {
    Live,
    DryRun(Arc<ProductionResponseSimulator>),
}

/// The host's scheduler cannot execute or maintain a retained live response
/// while the deployment selects dry-run. Unexpected live work fails closed.
pub(super) struct SimulationOnlyEffects;
impl EffectPort for SimulationOnlyEffects {
    fn ensure_effects_ready(&self) -> PortResult<()> {
        Ok(())
    }
    fn execute(&self, _: &EffectRequest) -> PortResult<EffectResult> {
        Err(PortError::invalid_data())
    }
    fn load_result(&self, _: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        Err(PortError::invalid_data())
    }
}

/// Assemble exactly the effects available in the selected host profile.
pub(super) fn production_response_effects(
    mode: ResponseExecutionMode,
    security_store: Arc<SqliteSecurityStateStore>,
    alert_outbox: Arc<super::adapters::SqliteSiemOutbox>,
    blast_radius: Arc<dyn BlastRadiusPort>,
) -> PortResult<Arc<dyn EffectPort>> {
    match mode {
        ResponseExecutionMode::Live => Ok(Arc::new(
            super::adapters::effect_port::ActiveResponseEffectPort::production(
                security_store,
                alert_outbox,
                blast_radius,
            )?,
        )),
        ResponseExecutionMode::DryRun => Ok(Arc::new(SimulationOnlyEffects)),
    }
}

#[cfg(test)]
mod diagnostic_classification_tests {
    use super::*;

    #[test]
    fn simulation_diagnostic_fenced_store_retains_refusal_without_claiming_corruption() {
        let error = receipt_store_error(chio_kernel::ReceiptStoreError::Fenced);
        assert_eq!(error.kind(), PortErrorKind::Unavailable);
        assert_eq!(
            error.code().as_str(),
            "urn:chio:error:attest:receipt-store-unavailable"
        );
        assert!(matches!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<chio_kernel::ReceiptStoreError>()),
            Some(chio_kernel::ReceiptStoreError::Fenced)
        ));
    }

    #[test]
    fn simulation_diagnostic_read_capacity_retains_refusal_without_claiming_corruption() {
        let error = receipt_store_error(chio_kernel::ReceiptStoreError::ReadBoundary(
            "private-capacity-detail".into(),
        ));
        assert_eq!(error.kind(), PortErrorKind::Unavailable);
        assert_eq!(
            error.code().as_str(),
            "urn:chio:error:attest:receipt-store-unavailable"
        );
        assert!(matches!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<chio_kernel::ReceiptStoreError>()),
            Some(chio_kernel::ReceiptStoreError::ReadBoundary(_))
        ));
        assert!(!format!("{error} {error:?}").contains("private"));
    }
}

#[cfg(test)]
mod production_effects_tests;
