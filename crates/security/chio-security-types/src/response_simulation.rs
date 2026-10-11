//! Snapshot and report vocabulary for isolated response evaluation.

use crate::ports::*;
use crate::ResponsePlan;
#[cfg(feature = "std")]
use crate::{PlannedResponseEffect, ResponseEffectKind, ResponseTarget};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const RESPONSE_SIMULATION_SCHEMA: &str = "chio.response-simulation.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "snapshot",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ResponseSimulationState {
    Suspension(OverlaySnapshot),
    Throttle(SessionThrottleSnapshot),
    Egress(EgressRestrictionSnapshot),
    CapabilitySet(CapabilitySetSuspensionSnapshot),
    Issuance(IssuanceFreezeSnapshot),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSimulationScope {
    pub effect_id: EffectId,
    pub result: BlastRadiusResult,
}

/// Effect state is captured in one database read transaction. Causal scope
/// observations are separately versioned and are not a live issuance fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSimulationSnapshot {
    pub tenant_id: TenantId,
    pub plan_hash: Digest32,
    pub captured_at_unix_ms: u64,
    pub states: BoundedVec<ResponseSimulationState, 64>,
    pub scopes: BoundedVec<ResponseSimulationScope, 64>,
}

/// Read-only surface: no leases, mutations, alert delivery or dispatch.
pub trait ResponseSimulationSnapshotSource: Send + Sync {
    fn capture(&self, plan: &ResponsePlan) -> PortResult<ResponseSimulationSnapshot>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseSimulationOutcome {
    WouldApply,
    WouldDeliverAlert,
    WouldRemove,
    AlertNotReversible,
    WouldExpire,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSimulationStep {
    pub effect_id: EffectId,
    pub at_unix_ms: u64,
    pub outcome: ResponseSimulationOutcome,
    pub resulting_version_hash: Option<Digest32>,
}

/// Predictions only. Issuance prediction assumes a future external fence can
/// be acquired; alert prediction makes no assertion about future delivery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSimulationEvaluation {
    pub apply: Vec<ResponseSimulationStep>,
    pub rollback: Vec<ResponseSimulationStep>,
    pub expiry: Vec<ResponseSimulationStep>,
    pub after_apply: BoundedVec<ResponseSimulationState, 64>,
    pub after_rollback: BoundedVec<ResponseSimulationState, 64>,
    pub after_expiry: BoundedVec<ResponseSimulationState, 64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSuspensionSpec {
    pub posture_rank: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionSpec {
    pub destinations: EgressDestinationSet,
}

#[cfg(feature = "std")]
impl ResponseSimulationState {
    pub fn matches(&self, plan: &ResponsePlan, effect: &PlannedResponseEffect) -> PortResult<bool> {
        Ok(match (self, effect.kind, &effect.target) {
            (
                Self::Suspension(state),
                ResponseEffectKind::SuspendSession,
                ResponseTarget::Session { session_id },
            ) => state.target == containment_session_target(&plan.tenant_id, session_id)?,
            (
                Self::Throttle(state),
                ResponseEffectKind::ThrottleSession,
                ResponseTarget::Session { session_id },
            ) => state.key.tenant_id == plan.tenant_id && &state.key.session_id == session_id,
            (
                Self::Egress(state),
                ResponseEffectKind::RestrictEgress,
                ResponseTarget::Session { session_id },
            ) => state.key.tenant_id == plan.tenant_id && &state.key.session_id == session_id,
            (
                Self::CapabilitySet(state),
                ResponseEffectKind::SuspendCapabilitySet,
                ResponseTarget::CapabilitySet { affected_set_hash },
            ) => {
                state.key.tenant_id == plan.tenant_id
                    && &state.key.affected_set_hash == affected_set_hash
            }
            (
                Self::Issuance(state),
                ResponseEffectKind::FreezeIssuance,
                ResponseTarget::Lineage { lineage_id },
            ) => state.key.tenant_id == plan.tenant_id && &state.key.lineage_id == lineage_id,
            _ => false,
        })
    }

    pub fn version_hash(&self) -> PortResult<Digest32> {
        match self {
            Self::Suspension(state) => {
                validate_containment_overlay_snapshot(state, &state.target)?;
                containment_overlay_version_hash(state)
            }
            Self::Throttle(state) => {
                validate_session_throttle_snapshot(state, &state.key)?;
                session_throttle_version_hash(state)
            }
            Self::Egress(state) => {
                validate_egress_restriction_snapshot(state, &state.key)?;
                egress_snapshot_version_hash(state)
            }
            Self::CapabilitySet(state) => {
                validate_capability_set_suspension_snapshot(state, &state.key)?;
                capability_set_suspension_version_hash(state)
            }
            Self::Issuance(state) => {
                validate_issuance_freeze_snapshot(state, &state.key)?;
                issuance_freeze_version_hash(state)
            }
        }
    }
}
