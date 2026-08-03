use super::*;

use chio_core::capability::governance::{
    GovernedApprovalToken, GovernedResponseEffect, GovernedResponsePlanIntentBody,
    GovernedTransactionIntent, CHIO_ACTIVE_RESPONSE_SERVER_ID, CHIO_RESPONSE_PLAN_SCHEMA,
};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::ToolCallAction;
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::security::{
    active_defense_response_receipt_for_mutation, expected_response_mutation_transition_id,
    ActiveDefenseEffectCommitment, ActiveDefenseEffectOutcome,
    ActiveDefenseEffectOutcomeCommitment, ActiveDefenseEffectOutcomeCommitments,
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    ActiveDefenseResponseBinding, CorrelatedFindingReceiptBody, ResponseCompletionReceiptBody,
};
use chio_core::{canonical_json_bytes, sha256, Ed25519Backend};
use chio_security_types::ports::{
    ActionId, CanonicalBody, Digest32, EffectId, ErrorCode, OpaqueReceiptRef,
    PreparedActiveResponseDispatchBinding, RecordId, RecordIdSet, ResponseDispatchApproval,
    ResponseDispatchAuthorization, ResponseDispatchAuthorizationBody, ResponseDispatchKey,
    ResponsePlanRecord, SessionId as ResponseSessionId, TenantId,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::{
    OperatorCapabilityBinding, PlannedResponseEffect, PlannedResponseEffects,
    ResponseApprovalRequirement, ResponseEffectAppliedRecord, ResponseEffectKind,
    ResponseEffectRequestedRecord, ResponseEffectSpec, ResponseExecutionDispatchBinding,
    ResponseMutationLog, ResponseMutationRecord, ResponsePlan, ResponsePlanAuthorizationBody,
    ResponseRequestedRecord, ResponseSnapshot, ResponseState, ResponseTarget,
    ResponseTransitionCause, ResponseTransitionRecord, RESPONSE_STATE_SCHEMA_VERSION,
};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use crate::kernel::{
    ActiveResponseCommittedDispatch, ActiveResponseEffectEvidence, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionEvidenceParts, ActiveResponseExecutionOutcome,
    ActiveResponseExecutionRequest, ActiveResponseExecutorAuthority,
    ActiveResponseExecutorAuthorityIdentity, ActiveResponseExecutorError,
    ActiveResponseFailureEvidence,
};
use crate::kernel::{
    ActiveResponseFindingAuthority, ActiveResponseFindingAuthorityError,
    AuthoritativeCorrelatedFindingEvidence,
};

use crate::kernel::active_response_admission::{
    ActiveResponseAuthorizationRequest, ActiveResponseSubmissionProof,
    ActiveResponseSubmissionProofBody,
};

const RESPONSE_EFFECT_ID_DOMAIN: &[u8] = b"chio.response-effect.v1\0";
const AFFECTED_SET_HASH_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";

include!("active_response_admission/body_support.inc");
include!("active_response_admission/authorization_tests.inc");
#[path = "active_response_admission/policy.rs"]
mod policy;

#[path = "active_response_admission/coordinator.rs"]
mod coordinator;
