use chio_security_types::clock::{Clock, SystemClock};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chio_quarantine::decode_response_record;
use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, egress_snapshot_version_hash,
    empty_capability_set_suspension_snapshot, empty_egress_restriction_snapshot,
    empty_issuance_freeze_snapshot, empty_session_throttle_snapshot,
    issuance_freeze_installed_version_hash, issuance_freeze_version_hash,
    predict_capability_set_suspension_apply, predict_capability_set_suspension_remove,
    predict_containment_overlay_apply, predict_containment_overlay_remove, predict_egress_apply,
    predict_egress_removal, predict_issuance_freeze_apply, predict_issuance_freeze_remove,
    predict_session_throttle_apply, predict_session_throttle_remove, response_affected_set_hash,
    session_throttle_installed_version_hash, session_throttle_version_hash,
    validate_capability_set_suspension_snapshot, validate_containment_overlay_snapshot,
    validate_egress_restriction_snapshot, validate_issuance_freeze_contribution,
    validate_issuance_freeze_snapshot, validate_session_throttle_snapshot, AlertDeliveryQuery,
    AlertDeliveryStatus, BlastRadiusPort, BlastRadiusResult, CanonicalBody,
    CapabilitySetSuspensionApplyRequest, CapabilitySetSuspensionCommand,
    CapabilitySetSuspensionContribution, CapabilitySetSuspensionKey,
    CapabilitySetSuspensionRemoveRequest, CapabilitySetSuspensionSnapshot,
    CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore, ContainmentOverlayCommand,
    ContainmentOverlayStore, Digest32, EffectExecutionStatus, EffectId, EffectOperation,
    EffectPort, EffectRequest, EffectResult, EffectResultQuery, EgressDestinationSet,
    EgressRestrictionApplyRequest, EgressRestrictionCommand, EgressRestrictionContribution,
    EgressRestrictionRemoveRequest, EgressRestrictionSessionKey, EgressRestrictionSnapshot,
    EgressRestrictionStore, IssuanceFreezeApplyRequest, IssuanceFreezeCommand,
    IssuanceFreezeContribution, IssuanceFreezeFenceMaintenanceRequest, IssuanceFreezeKey,
    IssuanceFreezeOperationStatus, IssuanceFreezePendingRelease, IssuanceFreezeRemoveRequest,
    IssuanceFreezeSnapshot, IssuanceFreezeSpec, IssuanceFreezeStore, LineageFence,
    LineageFenceMaintenanceOutcome, LineageFenceMaintenanceRequest, LineageFenceRelease,
    LineageFenceRenewal, LineageFenceRequest, LineageFenceTakeover, MaintainedLineageFence,
    OverlayApplyRequest, OverlayContribution, OverlayRemoveRequest, OverlaySnapshot, PortError,
    PortResult, RecordId, ResponsePlanKey, ResponseSchedulerStore, ScheduledWork, SecurityAlert,
    SecurityAlertPort, SessionId, SessionThrottleApplyRequest, SessionThrottleCommand,
    SessionThrottleContribution, SessionThrottleKey, SessionThrottleLimits,
    SessionThrottleRemoveRequest, SessionThrottleSnapshot, SessionThrottleStore, TenantId,
    TenantScopedId, LINEAGE_FENCE_MAX_LEASE_MS,
};
use chio_security_types::{
    ResponseEffectKind, ResponseEffectProgress, ResponseSnapshot, ResponseState, ResponseTarget,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use serde::Serialize;

use super::native_evidence::SqliteSiemOutbox;

use chio_security_types::response_simulation::SessionSuspensionSpec as SessionSuspensionContribution;

use chio_security_types::response_simulation::EgressRestrictionSpec as RestrictEgressContribution;

mod dispatch;
pub use dispatch::ResponseEffectBackend;
pub use dispatch::LineageFenceMaintenanceResult;
pub use dispatch::ActiveResponseEffectPortConfigError;
pub use dispatch::ActiveResponseEffectPort;

use dispatch::validate_request_binding;

mod alert;
pub use alert::EscalateAlertStore;
pub use alert::EscalateAlertBackend;


















mod throttle;
pub use throttle::SessionThrottleBackend;



mod suspension;
pub use suspension::CapabilitySetSuspensionBackend;



mod issuance;
pub use issuance::IssuanceFreezeBackend;


mod containment;
pub use containment::SessionSuspensionOverlayBackend;
pub use containment::session_containment_target;
pub use containment::session_overlay_version_hash;








mod egress;
pub use egress::RestrictEgressOverlayBackend;
pub use egress::egress_restriction_version_hash;








mod evidence;
use evidence::EFFECT_COMMAND_ID_PREFIX;
use evidence::effect_query_from_request;
use evidence::verify_contribution_hash;
use evidence::domain_hash;

#[cfg(test)]
mod tests;
