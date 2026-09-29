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
            return Err(PortError::invalid_data());
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
            .map_err(|_| PortError::unavailable())?;
        self.signer
            .sign_bytes(b"chio.response-simulation.readiness.v1\0")
            .map_err(|_| PortError::unavailable())?;
        Ok(())
    }

    /// Exact immutable readback remains valid after plan expiry or restart.
    /// It returns historical evidence and never reissues authorization.
    pub fn load(
        &self,
        plan: &ResponsePlan,
    ) -> PortResult<Option<(ResponseSimulationReport, ChioReceipt)>> {
        if plan.execution.mode() != ResponseExecutionMode::DryRun {
            return Err(PortError::invalid_data());
        }
        let id = response_simulation_evidence_id(plan, self.configuration_digest)?;
        let Some(receipt) = self
            .receipts
            .load_indexed_security_evidence(&id)
            .map_err(|_| PortError::unavailable())?
        else {
            return Ok(None);
        };
        let report = verify_response_simulation_receipt(
            &receipt,
            &id,
            &self.signer.public_key(),
            self.configuration_digest,
        )?;
        if report.plan != *plan {
            return Err(PortError::integrity_failure());
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
        let snapshot = self.snapshots.capture(plan)?;
        let evaluation =
            chio_quarantine::simulation::evaluate_response_simulation(plan, &snapshot)?;
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
            report.receipt_body(self.signer.public_key())?,
            self.signer.as_ref(),
        )
        .map_err(|_| PortError::unavailable())?;
        // Recheck real authority after capture and signing, before recording a
        // fresh successful evaluation. This cannot reserve or consume tokens.
        kernel
            .verify_active_response_simulation(request)
            .map_err(super::event_consumer::map_active_response_kernel_error)?;
        let id = report.evidence_id()?;
        let persisted = match self
            .receipts
            .append_indexed_security_evidence(&id, &receipt)
        {
            Ok(persisted) => persisted,
            Err(_) => return self.load(plan)?.ok_or_else(PortError::unavailable),
        };
        let verified = verify_response_simulation_receipt(
            &persisted,
            &id,
            &self.signer.public_key(),
            self.configuration_digest,
        )?;
        if verified != report {
            return Err(PortError::integrity_failure());
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
