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
pub use dispatch::*;
use dispatch::REQUIRED_EFFECT_KINDS;
use dispatch::validate_request_binding;

mod alert;
pub use alert::*;
use alert::ESCALATE_ALERT_SCHEMA_VERSION;
use alert::ESCALATE_ALERT_TYPE;
use alert::ESCALATE_ALERT_EVENT_DOMAIN;
use alert::ESCALATE_ALERT_COMMAND_DOMAIN;
use alert::ESCALATE_ALERT_FINDING_DOMAIN;
use alert::ESCALATE_ALERT_ACTION_DOMAIN;
use alert::ESCALATE_ALERT_EVIDENCE_DOMAIN;
use alert::ESCALATE_ALERT_RESULT_DOMAIN;
use alert::EscalateAlertCommitment;
use alert::validate_escalate_alert_request;
use alert::validate_escalate_alert_query;
use alert::verify_canonical_json_contribution;
use alert::build_escalate_alert;
use alert::validate_escalate_alert;
use alert::validate_alert_delivery_status;
use alert::escalate_alert_result;
use alert::escalate_alert_record_id;

mod throttle;
pub use throttle::*;
use throttle::decode_session_throttle_limits;
use throttle::valid_throttle_effect_result;

mod suspension;
pub use suspension::*;
use suspension::decode_capability_set_suspension_spec;
use suspension::valid_capability_set_suspension_result;

mod issuance;
pub use issuance::*;
use issuance::decode_issuance_freeze_spec;

mod containment;
pub use containment::*;
use containment::valid_containment_effect_result;
use containment::empty_overlay_snapshot;
use containment::decode_session_suspension;
use containment::validate_overlay_snapshot;
use containment::overlay_version_hash;
use containment::installed_result;
use containment::installed_version_hash;

mod egress;
pub use egress::*;
use egress::valid_egress_effect_result;
use egress::decode_egress_restriction;
use egress::InstalledEgressContributionCommitment;
use egress::egress_installed_result;
use egress::egress_installed_version_hash;
use egress::egress_installed_contribution_hash;
use egress::INSTALLED_EGRESS_CONTRIBUTION_DOMAIN;

mod evidence;
use evidence::*;
use evidence::EFFECT_COMMAND_ID_PREFIX;
use evidence::effect_query_from_request;
use evidence::verify_contribution_hash;
use evidence::domain_hash;

#[cfg(test)]
mod tests;
