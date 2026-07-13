#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod deception;
pub mod declassification;
pub mod event;
pub mod flow;
pub mod ports;
pub mod response;

pub use deception::{
    DecoyAeadNonce, DecoyArtifactLookup, DecoyErrorClass, DecoyEvidenceRef, DecoyLifecycle,
    DecoyLifecycleState, DecoyOperationAttempt, DecoyOperationKind, DecoyRecord, DecoyRecordError,
    DecoyScan, DecoyScanError, DecoySurface, DecoyVersion, EncryptedDecoyEnvelope,
    SealedDecoyCasRequest, SealedDecoyPage, SealedDecoyRecord, SealedMarkerLookup,
    SealedPublicRefLookup, WatermarkObservation, WatermarkObservationResult, WatermarkSequenceKey,
    WatermarkSequenceReservation, WatermarkSequenceReservationResult, MAX_DECOY_EXPORT_PAGE,
    MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES,
};
pub use declassification::{
    DeclassificationGrantBody, DeclassificationGrantClaims, DeclassificationGrantValidationError,
    DECLASSIFICATION_GRANT_DOMAIN_VERSION,
};
pub use event::{
    CorrelatedFinding, CorrelatedFindingInput, CorrelatedFindingValidationError,
    DetectorHealthEvidence, DetectorHealthKind, EventEvidenceReferences, FindingEventIds,
    FindingEvidenceDigests, SecurityEventBody, SecurityEventBodyInput, SecurityEventKind,
    SecurityEventValidationError, SecuritySeverity, SecuritySubject, MAX_EVENT_EVIDENCE_REFERENCES,
    MAX_FINDING_EVENTS,
};
pub use flow::{
    Compartment, InformationLabel, LabelLimits, LabelValidationError, PrincipalId,
    DEFAULT_LABEL_LIMITS,
};
pub use response::{
    is_legal_response_transition, OperatorCapabilityBinding, PlannedResponseEffect,
    PlannedResponseEffects, ResponseApprovalRequirement, ResponseEffectAppliedRecord,
    ResponseEffectFailedRecord, ResponseEffectKind, ResponseEffectProgress,
    ResponseEffectRequestedRecord, ResponseEffectSpec, ResponseFailureRecord, ResponseFinalRecord,
    ResponseMutationLog, ResponseMutationRecord, ResponsePlan, ResponsePlanInput,
    ResponseRequestedRecord, ResponseRollbackOutcome, ResponseRollbackRecord, ResponseShapeError,
    ResponseSnapshot, ResponseState, ResponseTarget, ResponseTransitionCause,
    ResponseTransitionRecord, MAX_RESPONSE_EFFECTS, MAX_RESPONSE_MUTATIONS,
    RESPONSE_STATE_SCHEMA_VERSION,
};
