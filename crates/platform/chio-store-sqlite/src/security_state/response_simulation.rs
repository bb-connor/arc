#[cfg(target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::{
    capability_set_suspension, empty_egress_restriction_snapshot, issuance_freeze,
    load_egress_restriction_snapshot, load_overlay_snapshot, load_session_throttle_snapshot,
    sqlite_error, EgressRestrictionSessionKey, PortError, PortResult, SessionThrottleKey,
    SqliteSecurityStateStore, TransactionBehavior,
};
use chio_security_types::response_simulation::{
    ResponseSimulationSnapshot, ResponseSimulationState,
};
use chio_security_types::{ResponseEffectKind, ResponsePlan, ResponseTarget};

impl SqliteSecurityStateStore {
    /// Capture every effect target in one SQLite read transaction. This never
    /// creates response rows, scheduler leases or effect contributions.
    pub fn capture_response_simulation(
        &self,
        plan: &ResponsePlan,
    ) -> PortResult<ResponseSimulationSnapshot> {
        plan.validate_shape()
            .map_err(|_| PortError::invalid_data())?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let mut states = Vec::<ResponseSimulationState>::new();
        for effect in plan.effects.as_slice() {
            if states
                .iter()
                .any(|state| state.matches(plan, effect) == Ok(true))
            {
                continue;
            }
            let state = match (effect.kind, &effect.target) {
                (ResponseEffectKind::EscalateAlert, ResponseTarget::Tenant { tenant_id })
                    if tenant_id == &plan.tenant_id =>
                {
                    continue;
                }
                (ResponseEffectKind::SuspendSession, ResponseTarget::Session { session_id }) => {
                    let target = chio_security_types::ports::containment_session_target(
                        &plan.tenant_id,
                        session_id,
                    )?;
                    ResponseSimulationState::Suspension(load_overlay_snapshot(
                        &transaction,
                        &target,
                    )?)
                }
                (ResponseEffectKind::ThrottleSession, ResponseTarget::Session { session_id }) => {
                    let key = SessionThrottleKey {
                        tenant_id: plan.tenant_id.clone(),
                        session_id: session_id.clone(),
                    };
                    ResponseSimulationState::Throttle(load_session_throttle_snapshot(
                        &transaction,
                        &key,
                    )?)
                }
                (ResponseEffectKind::RestrictEgress, ResponseTarget::Session { session_id }) => {
                    let key = EgressRestrictionSessionKey {
                        tenant_id: plan.tenant_id.clone(),
                        session_id: session_id.clone(),
                    };
                    ResponseSimulationState::Egress(
                        load_egress_restriction_snapshot(&transaction, &key)?
                            .unwrap_or(empty_egress_restriction_snapshot(&key)?),
                    )
                }
                (
                    ResponseEffectKind::SuspendCapabilitySet,
                    ResponseTarget::CapabilitySet { affected_set_hash },
                ) => {
                    let key = chio_security_types::ports::CapabilitySetSuspensionKey {
                        tenant_id: plan.tenant_id.clone(),
                        affected_set_hash: *affected_set_hash,
                    };
                    ResponseSimulationState::CapabilitySet(
                        capability_set_suspension::load_snapshot(&transaction, &key)?,
                    )
                }
                (ResponseEffectKind::FreezeIssuance, ResponseTarget::Lineage { lineage_id }) => {
                    let key = chio_security_types::ports::IssuanceFreezeKey {
                        tenant_id: plan.tenant_id.clone(),
                        lineage_id: lineage_id.clone(),
                    };
                    ResponseSimulationState::Issuance(issuance_freeze::load_snapshot(
                        &transaction,
                        &key,
                    )?)
                }
                _ => return Err(PortError::invalid_data()),
            };
            state.version_hash()?;
            states.push(state);
        }
        let captured_at_unix_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(ResponseSimulationSnapshot {
            tenant_id: plan.tenant_id.clone(),
            plan_hash: plan.plan_hash,
            captured_at_unix_ms,
            states: chio_security_types::ports::BoundedVec::new(states)
                .map_err(|_| PortError::invalid_data())?,
            scopes: chio_security_types::ports::BoundedVec::new(Vec::new())
                .map_err(|_| PortError::invalid_data())?,
        })
    }
}
