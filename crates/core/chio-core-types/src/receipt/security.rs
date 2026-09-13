//! Canonical Chio-native receipt bodies for active defense.
//!
//! These bodies carry identifiers, hashes, state, and causal links only.
//! Payloads, markers, credentials, and rollback material are deliberately
//! absent from the closed wire vocabulary.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use chio_security_types::ports::{
    ActionId, BoundedVec, DeclassificationUseState, Digest32, EffectId, ErrorCode, EventId,
    GrantId, LeaseOwnerId, LineageId, OpaqueReceiptRef, RecordId, RequestId, RuleId, TenantId,
    TripwireKind,
};
use chio_security_types::{
    is_legal_response_transition, response_completion_effect_shape_is_valid,
    response_snapshot_has_mutation_capacity, DetectorGroupBindingEvidence, DetectorHealthKind,
    DetectorWatermarkEvidence, FindingEventIds, FindingEvidenceDigests, FindingSourceReceiptIds,
    PlannedResponseEffect, ResponseApprovalRequirement, ResponseCompletionEffectState,
    ResponseEffectKind, ResponseEffectProgress, ResponseExecutionDispatchBinding,
    ResponseMutationLog, ResponseMutationRecord, ResponsePlan, ResponseRollbackOutcome,
    ResponseSnapshot, ResponseState, ResponseTarget, ResponseTransitionCause, SecuritySeverity,
    RESPONSE_STATE_SCHEMA_VERSION,
};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{canonical_json_bytes, sha256, Error, Result};

include!("security_parts/definitions_and_projection.inc");
include!("security_parts/lifecycle_and_validation.inc");
