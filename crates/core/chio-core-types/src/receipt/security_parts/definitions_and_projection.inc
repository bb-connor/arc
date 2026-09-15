pub const ACTIVE_DEFENSE_RECEIPT_SCHEMA_VERSION: u8 = 1;
pub const MAX_ACTIVE_DEFENSE_PRIOR_RECEIPTS: usize = 64;
pub const MAX_ACTIVE_DEFENSE_EFFECTS: usize = 64;
pub const MAX_ACTIVE_DEFENSE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

pub const FLOW_DENIAL_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:flow-denial:v1";
pub const DECLASSIFICATION_CONSUMPTION_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:declassification-consumption:v1";
pub const DECLASSIFICATION_OUTCOME_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:declassification-outcome:v1";
pub const TRIPWIRE_OBSERVATION_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:tripwire-observation:v1";
pub const CORRELATED_FINDING_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:correlated-finding:v1";
pub const RESPONSE_PLAN_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:response-plan:v1";
pub const RESPONSE_STATE_TRANSITION_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:response-state-transition:v1";
pub const EFFECT_TRANSITION_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:effect-transition:v1";
pub const RESPONSE_COMPLETION_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:response-completion:v1";
pub const LIFT_ROLLBACK_COMPLETION_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:lift-rollback-completion:v1";
pub const DETECTOR_HEALTH_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:detector-health:v1";
pub const SCHEDULER_HEALTH_RECEIPT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio:active-defense-receipt:scheduler-health:v1";
pub const ACTIVE_DEFENSE_EVIDENCE_ID_DOMAIN: &[u8] = b"chio:active-defense-evidence-id:v1";
const RESPONSE_REQUEST_ID_DOMAIN: &[u8] = b"chio.response-request.v1\0";
const RESPONSE_MUTATION_ID_DOMAIN: &[u8] = b"chio.response-transition.v1\0";
const RESPONSE_DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR: &str =
    "active_response.dispatch_committed_resume_expired";
const RESPONSE_DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR: &str =
    "active_response.dispatch_apply_lease_expired_before_effect";
const RESPONSE_APPLYING_LEASE_EXPIRED_ERROR: &str = "response.applying_lease_expired";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveDefenseReceiptKind {
    FlowDenial,
    DeclassificationConsumption,
    DeclassificationOutcome,
    TripwireObservation,
    CorrelatedFinding,
    ResponsePlan,
    ResponseStateTransition,
    EffectTransition,
    ResponseCompletion,
    LiftRollbackCompletion,
    DetectorHealth,
    SchedulerHealth,
}

impl ActiveDefenseReceiptKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FlowDenial => "flow_denial",
            Self::DeclassificationConsumption => "declassification_consumption",
            Self::DeclassificationOutcome => "declassification_outcome",
            Self::TripwireObservation => "tripwire_observation",
            Self::CorrelatedFinding => "correlated_finding",
            Self::ResponsePlan => "response_plan",
            Self::ResponseStateTransition => "response_state_transition",
            Self::EffectTransition => "effect_transition",
            Self::ResponseCompletion => "response_completion",
            Self::LiftRollbackCompletion => "lift_rollback_completion",
            Self::DetectorHealth => "detector_health",
            Self::SchedulerHealth => "scheduler_health",
        }
    }

    #[must_use]
    pub const fn body_digest_domain(self) -> &'static [u8] {
        match self {
            Self::FlowDenial => FLOW_DENIAL_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::DeclassificationConsumption => {
                DECLASSIFICATION_CONSUMPTION_RECEIPT_BODY_DIGEST_DOMAIN
            }
            Self::DeclassificationOutcome => DECLASSIFICATION_OUTCOME_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::TripwireObservation => TRIPWIRE_OBSERVATION_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::CorrelatedFinding => CORRELATED_FINDING_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::ResponsePlan => RESPONSE_PLAN_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::ResponseStateTransition => RESPONSE_STATE_TRANSITION_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::EffectTransition => EFFECT_TRANSITION_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::ResponseCompletion => RESPONSE_COMPLETION_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::LiftRollbackCompletion => LIFT_ROLLBACK_COMPLETION_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::DetectorHealth => DETECTOR_HEALTH_RECEIPT_BODY_DIGEST_DOMAIN,
            Self::SchedulerHealth => SCHEDULER_HEALTH_RECEIPT_BODY_DIGEST_DOMAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveDefenseReceiptValidationError {
    UnsupportedSchemaVersion,
    ZeroTime(&'static str),
    InvalidTimeRange(&'static str),
    InvalidJsonInteger(&'static str),
    ZeroDigest(&'static str),
    TooManyPriorReceipts,
    PriorReceiptsNotStrictlySorted,
    MissingPriorReceipt,
    InvalidPriorReceiptCount,
    MissingTriggerFindingReceipt,
    InvalidDeclassificationConsumptionState,
    InvalidDeclassificationOutcomeTransition,
    EmptyFindingEvents,
    MismatchedFindingEvidence,
    FindingPriorReceiptMismatch,
    DuplicateFindingEvent,
    EmptyEffects,
    InvalidEffectOrdinal,
    DuplicateEffectId,
    InvalidEffectTarget,
    CrossTenantTarget,
    ZeroSchedulerFencingToken,
    InvalidEffectTransition,
    ZeroResponseGeneration,
    InvalidResponseStateTransition,
    InvalidResponseDispatchBinding,
    InvalidResponseCompletion,
    InvalidLiftRollbackCompletion,
    ZeroSchedulerAttempts,
    InvalidDetectorKnowledge,
}

impl fmt::Display for ActiveDefenseReceiptValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion => {
                formatter.write_str("unsupported active-defense receipt schema version")
            }
            Self::ZeroTime(field) => write!(formatter, "{field} must be nonzero"),
            Self::InvalidTimeRange(field) => {
                write!(formatter, "{field} is outside its valid time range")
            }
            Self::InvalidJsonInteger(field) => {
                write!(formatter, "{field} exceeds the portable JSON integer range")
            }
            Self::ZeroDigest(field) => write!(formatter, "{field} must not be the zero digest"),
            Self::TooManyPriorReceipts => {
                formatter.write_str("prior receipt list exceeds the item limit")
            }
            Self::PriorReceiptsNotStrictlySorted => {
                formatter.write_str("prior receipt ids must be strictly sorted and unique")
            }
            Self::MissingPriorReceipt => {
                formatter.write_str("receipt kind requires at least one prior receipt id")
            }
            Self::InvalidPriorReceiptCount => {
                formatter.write_str("receipt kind requires exactly one prior receipt id")
            }
            Self::MissingTriggerFindingReceipt => formatter
                .write_str("response plan receipt does not cite its trigger finding receipt"),
            Self::InvalidDeclassificationConsumptionState => formatter
                .write_str("declassification consumption must enter consumed_pending_dispatch"),
            Self::InvalidDeclassificationOutcomeTransition => formatter.write_str(
                "declassification outcome must leave consumed_pending_dispatch exactly once",
            ),
            Self::EmptyFindingEvents => {
                formatter.write_str("correlated finding must contain at least one event")
            }
            Self::MismatchedFindingEvidence => formatter.write_str(
                "correlated finding event, evidence, and source receipt cardinalities must match",
            ),
            Self::FindingPriorReceiptMismatch => formatter
                .write_str("correlated finding prior receipts do not match its source receipts"),
            Self::DuplicateFindingEvent => {
                formatter.write_str("correlated finding contains a duplicate event id")
            }
            Self::EmptyEffects => {
                formatter.write_str("response receipt must contain at least one effect")
            }
            Self::InvalidEffectOrdinal => {
                formatter.write_str("response effects are not in canonical ordinal order")
            }
            Self::DuplicateEffectId => {
                formatter.write_str("response receipt contains a duplicate effect id")
            }
            Self::InvalidEffectTarget => {
                formatter.write_str("response effect kind does not accept its target")
            }
            Self::CrossTenantTarget => {
                formatter.write_str("response effect target crosses the receipt tenant")
            }
            Self::ZeroSchedulerFencingToken => {
                formatter.write_str("scheduler fencing token must be nonzero")
            }
            Self::InvalidEffectTransition => {
                formatter.write_str("effect transition outcome is invalid for the effect")
            }
            Self::ZeroResponseGeneration => {
                formatter.write_str("response state transition generation must be nonzero")
            }
            Self::InvalidResponseStateTransition => {
                formatter.write_str("response state transition is invalid")
            }
            Self::InvalidResponseDispatchBinding => {
                formatter.write_str("response dispatch proof binding is invalid")
            }
            Self::InvalidResponseCompletion => {
                formatter.write_str("response completion state contradicts its effect outcomes")
            }
            Self::InvalidLiftRollbackCompletion => {
                formatter.write_str("lift or rollback state contradicts its effect outcomes")
            }
            Self::ZeroSchedulerAttempts => {
                formatter.write_str("scheduler attempts must be nonzero")
            }
            Self::InvalidDetectorKnowledge => {
                formatter.write_str("detector watermark knowledge is internally inconsistent")
            }
        }
    }
}

impl core::error::Error for ActiveDefenseReceiptValidationError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ActiveDefensePriorReceiptIds(
    BoundedVec<OpaqueReceiptRef, MAX_ACTIVE_DEFENSE_PRIOR_RECEIPTS>,
);

impl ActiveDefensePriorReceiptIds {
    pub fn new(
        prior_receipt_ids: Vec<OpaqueReceiptRef>,
    ) -> core::result::Result<Self, ActiveDefenseReceiptValidationError> {
        if prior_receipt_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ActiveDefenseReceiptValidationError::PriorReceiptsNotStrictlySorted);
        }
        BoundedVec::new(prior_receipt_ids)
            .map(Self)
            .map_err(|_| ActiveDefenseReceiptValidationError::TooManyPriorReceipts)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[OpaqueReceiptRef] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn validate(&self) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
        if self.0.as_slice().windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ActiveDefenseReceiptValidationError::PriorReceiptsNotStrictlySorted);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ActiveDefensePriorReceiptIds {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values =
            BoundedVec::<OpaqueReceiptRef, MAX_ACTIVE_DEFENSE_PRIOR_RECEIPTS>::deserialize(
                deserializer,
            )?
            .into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseReceiptHeader {
    pub schema_version: u8,
    pub occurred_at_unix_ms: u64,
    pub tenant_id: TenantId,
    pub transition_id: RecordId,
    pub prior_receipt_ids: ActiveDefensePriorReceiptIds,
}

impl ActiveDefenseReceiptHeader {
    pub fn new(
        occurred_at_unix_ms: u64,
        tenant_id: TenantId,
        transition_id: RecordId,
        prior_receipt_ids: Vec<OpaqueReceiptRef>,
    ) -> core::result::Result<Self, ActiveDefenseReceiptValidationError> {
        let header = Self {
            schema_version: ACTIVE_DEFENSE_RECEIPT_SCHEMA_VERSION,
            occurred_at_unix_ms,
            tenant_id,
            transition_id,
            prior_receipt_ids: ActiveDefensePriorReceiptIds::new(prior_receipt_ids)?,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(&self) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
        if self.schema_version != ACTIVE_DEFENSE_RECEIPT_SCHEMA_VERSION {
            return Err(ActiveDefenseReceiptValidationError::UnsupportedSchemaVersion);
        }
        require_nonzero_time(self.occurred_at_unix_ms, "occurred_at_unix_ms")?;
        require_json_safe_time(self.occurred_at_unix_ms, "occurred_at_unix_ms")?;
        self.prior_receipt_ids.validate()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveDefenseReceiptHeaderWire {
    schema_version: u8,
    occurred_at_unix_ms: u64,
    tenant_id: TenantId,
    transition_id: RecordId,
    prior_receipt_ids: ActiveDefensePriorReceiptIds,
}

impl<'de> Deserialize<'de> for ActiveDefenseReceiptHeader {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ActiveDefenseReceiptHeaderWire::deserialize(deserializer)?;
        let header = Self {
            schema_version: wire.schema_version,
            occurred_at_unix_ms: wire.occurred_at_unix_ms,
            tenant_id: wire.tenant_id,
            transition_id: wire.transition_id,
            prior_receipt_ids: wire.prior_receipt_ids,
        };
        header.validate().map_err(de::Error::custom)?;
        Ok(header)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefensePolicyBinding {
    pub policy_version: RecordId,
    pub policy_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseResponseBinding {
    pub policy: ActiveDefensePolicyBinding,
    pub plan_hash: Digest32,
    pub action_id: ActionId,
    pub trigger_finding_id: RecordId,
    pub trigger_finding_hash: Digest32,
    pub trigger_finding_receipt_id: OpaqueReceiptRef,
    pub affected_set_hash: Digest32,
    pub plan_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseEffectCommitment {
    pub effect_id: EffectId,
    pub ordinal: u16,
    pub kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub contribution_hash: Digest32,
    pub observed_base_version_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActiveDefenseEffectOutcome {
    Planned,
    Requested,
    Applied { resulting_version_hash: Digest32 },
    ApplyFailed { error_code: ErrorCode },
    RollbackRequested,
    Restored { resulting_version_hash: Digest32 },
    RollbackFailed { error_code: ErrorCode },
    NoRollbackRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseEffectOutcomeCommitment {
    pub effect: ActiveDefenseEffectCommitment,
    pub outcome: ActiveDefenseEffectOutcome,
}

pub type ActiveDefenseEffectCommitments =
    BoundedVec<ActiveDefenseEffectCommitment, MAX_ACTIVE_DEFENSE_EFFECTS>;
pub type ActiveDefenseEffectOutcomeCommitments =
    BoundedVec<ActiveDefenseEffectOutcomeCommitment, MAX_ACTIVE_DEFENSE_EFFECTS>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowDenialReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub policy: ActiveDefensePolicyBinding,
    pub request_hash: Digest32,
    pub source_label_hash: Digest32,
    pub destination_label_hash: Digest32,
    pub guard_evidence_hash: Digest32,
    pub denial_code: ErrorCode,
    pub event_id: EventId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationConsumptionReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub policy: ActiveDefensePolicyBinding,
    pub grant_id: GrantId,
    pub grant_hash: Digest32,
    pub request_hash: Digest32,
    pub event_id: EventId,
    pub state: DeclassificationUseState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationOutcomeReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub policy: ActiveDefensePolicyBinding,
    pub grant_id: GrantId,
    pub grant_hash: Digest32,
    pub request_hash: Digest32,
    pub event_id: EventId,
    pub from_state: DeclassificationUseState,
    pub to_state: DeclassificationUseState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireObservationReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub policy: ActiveDefensePolicyBinding,
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub event_id: EventId,
    pub tripwire_kind: TripwireKind,
    pub artifact_id_hash: Digest32,
    pub artifact_version_hash: Digest32,
    pub observation_hash: Digest32,
    pub severity: SecuritySeverity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelatedFindingReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub policy: ActiveDefensePolicyBinding,
    pub finding_id: RecordId,
    pub finding_hash: Digest32,
    pub rule_id: RuleId,
    pub rule_version_hash: Digest32,
    pub group_key_hash: Digest32,
    pub ordered_event_ids: FindingEventIds,
    pub ordered_evidence_digests: FindingEvidenceDigests,
    pub ordered_source_receipt_ids: FindingSourceReceiptIds,
    pub first_event_time_unix_ms: u64,
    pub last_event_time_unix_ms: u64,
    pub lineage_seed: LineageId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub response: ActiveDefenseResponseBinding,
    pub plan_created_at_unix_ms: u64,
    pub effects: ActiveDefenseEffectCommitments,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseStateTransitionReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub response: ActiveDefenseResponseBinding,
    pub generation: u64,
    pub from_state: ResponseState,
    pub to_state: ResponseState,
    pub cause: ResponseTransitionCause,
    pub applying_lease_expires_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_fencing_token: Option<u64>,
    pub error_code: Option<ErrorCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectTransitionReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub response: ActiveDefenseResponseBinding,
    pub effect: ActiveDefenseEffectCommitment,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: u64,
    pub outcome: ActiveDefenseEffectOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCompletionReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub response: ActiveDefenseResponseBinding,
    pub execution_dispatch: Option<ResponseExecutionDispatchBinding>,
    pub dispatch_authorization_hash: Option<Digest32>,
    pub response_generation: u64,
    pub response_body_hash: Digest32,
    pub final_state: ResponseState,
    pub error_code: Option<ErrorCode>,
    pub effects: ActiveDefenseEffectOutcomeCommitments,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiftRollbackCompletionReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub response: ActiveDefenseResponseBinding,
    pub execution_dispatch: Option<ResponseExecutionDispatchBinding>,
    pub dispatch_authorization_hash: Option<Digest32>,
    pub response_generation: u64,
    pub response_body_hash: Digest32,
    pub final_state: ResponseState,
    pub effects: ActiveDefenseEffectOutcomeCommitments,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorHealthReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub policy: ActiveDefensePolicyBinding,
    pub rule_id: RuleId,
    pub rule_version_hash: Digest32,
    pub group_binding: DetectorGroupBindingEvidence,
    pub event_id: EventId,
    pub health_kind: DetectorHealthKind,
    pub watermark: DetectorWatermarkEvidence,
    pub evidence_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthReceiptBody {
    pub header: ActiveDefenseReceiptHeader,
    pub response: ActiveDefenseResponseBinding,
    pub event_id: RecordId,
    pub first_failure_at_unix_ms: u64,
    pub attempts: u32,
    pub scheduler_fencing_token: u64,
    pub error_code: ErrorCode,
    pub evidence_hash: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ActiveDefenseReceiptBody {
    FlowDenial(FlowDenialReceiptBody),
    DeclassificationConsumption(DeclassificationConsumptionReceiptBody),
    DeclassificationOutcome(DeclassificationOutcomeReceiptBody),
    TripwireObservation(TripwireObservationReceiptBody),
    CorrelatedFinding(CorrelatedFindingReceiptBody),
    ResponsePlan(ResponsePlanReceiptBody),
    ResponseStateTransition(ResponseStateTransitionReceiptBody),
    EffectTransition(EffectTransitionReceiptBody),
    ResponseCompletion(ResponseCompletionReceiptBody),
    LiftRollbackCompletion(LiftRollbackCompletionReceiptBody),
    DetectorHealth(DetectorHealthReceiptBody),
    SchedulerHealth(SchedulerHealthReceiptBody),
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ActiveDefenseReceiptBodyWire {
    FlowDenial(FlowDenialReceiptBody),
    DeclassificationConsumption(DeclassificationConsumptionReceiptBody),
    DeclassificationOutcome(DeclassificationOutcomeReceiptBody),
    TripwireObservation(TripwireObservationReceiptBody),
    CorrelatedFinding(CorrelatedFindingReceiptBody),
    ResponsePlan(ResponsePlanReceiptBody),
    ResponseStateTransition(ResponseStateTransitionReceiptBody),
    EffectTransition(EffectTransitionReceiptBody),
    ResponseCompletion(ResponseCompletionReceiptBody),
    LiftRollbackCompletion(LiftRollbackCompletionReceiptBody),
    DetectorHealth(DetectorHealthReceiptBody),
    SchedulerHealth(SchedulerHealthReceiptBody),
}

impl From<ActiveDefenseReceiptBodyWire> for ActiveDefenseReceiptBody {
    fn from(wire: ActiveDefenseReceiptBodyWire) -> Self {
        match wire {
            ActiveDefenseReceiptBodyWire::FlowDenial(body) => Self::FlowDenial(body),
            ActiveDefenseReceiptBodyWire::DeclassificationConsumption(body) => {
                Self::DeclassificationConsumption(body)
            }
            ActiveDefenseReceiptBodyWire::DeclassificationOutcome(body) => {
                Self::DeclassificationOutcome(body)
            }
            ActiveDefenseReceiptBodyWire::TripwireObservation(body) => {
                Self::TripwireObservation(body)
            }
            ActiveDefenseReceiptBodyWire::CorrelatedFinding(body) => Self::CorrelatedFinding(body),
            ActiveDefenseReceiptBodyWire::ResponsePlan(body) => Self::ResponsePlan(body),
            ActiveDefenseReceiptBodyWire::ResponseStateTransition(body) => {
                Self::ResponseStateTransition(body)
            }
            ActiveDefenseReceiptBodyWire::EffectTransition(body) => Self::EffectTransition(body),
            ActiveDefenseReceiptBodyWire::ResponseCompletion(body) => {
                Self::ResponseCompletion(body)
            }
            ActiveDefenseReceiptBodyWire::LiftRollbackCompletion(body) => {
                Self::LiftRollbackCompletion(body)
            }
            ActiveDefenseReceiptBodyWire::DetectorHealth(body) => Self::DetectorHealth(body),
            ActiveDefenseReceiptBodyWire::SchedulerHealth(body) => Self::SchedulerHealth(body),
        }
    }
}

impl<'de> Deserialize<'de> for ActiveDefenseReceiptBody {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let body = Self::from(ActiveDefenseReceiptBodyWire::deserialize(deserializer)?);
        body.validate().map_err(de::Error::custom)?;
        Ok(body)
    }
}

impl ActiveDefenseReceiptBody {
    #[must_use]
    pub const fn kind(&self) -> ActiveDefenseReceiptKind {
        match self {
            Self::FlowDenial(_) => ActiveDefenseReceiptKind::FlowDenial,
            Self::DeclassificationConsumption(_) => {
                ActiveDefenseReceiptKind::DeclassificationConsumption
            }
            Self::DeclassificationOutcome(_) => ActiveDefenseReceiptKind::DeclassificationOutcome,
            Self::TripwireObservation(_) => ActiveDefenseReceiptKind::TripwireObservation,
            Self::CorrelatedFinding(_) => ActiveDefenseReceiptKind::CorrelatedFinding,
            Self::ResponsePlan(_) => ActiveDefenseReceiptKind::ResponsePlan,
            Self::ResponseStateTransition(_) => ActiveDefenseReceiptKind::ResponseStateTransition,
            Self::EffectTransition(_) => ActiveDefenseReceiptKind::EffectTransition,
            Self::ResponseCompletion(_) => ActiveDefenseReceiptKind::ResponseCompletion,
            Self::LiftRollbackCompletion(_) => ActiveDefenseReceiptKind::LiftRollbackCompletion,
            Self::DetectorHealth(_) => ActiveDefenseReceiptKind::DetectorHealth,
            Self::SchedulerHealth(_) => ActiveDefenseReceiptKind::SchedulerHealth,
        }
    }

    #[must_use]
    pub const fn header(&self) -> &ActiveDefenseReceiptHeader {
        match self {
            Self::FlowDenial(body) => &body.header,
            Self::DeclassificationConsumption(body) => &body.header,
            Self::DeclassificationOutcome(body) => &body.header,
            Self::TripwireObservation(body) => &body.header,
            Self::CorrelatedFinding(body) => &body.header,
            Self::ResponsePlan(body) => &body.header,
            Self::ResponseStateTransition(body) => &body.header,
            Self::EffectTransition(body) => &body.header,
            Self::ResponseCompletion(body) => &body.header,
            Self::LiftRollbackCompletion(body) => &body.header,
            Self::DetectorHealth(body) => &body.header,
            Self::SchedulerHealth(body) => &body.header,
        }
    }

    pub fn validate(&self) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
        self.header().validate()?;
        match self {
            Self::FlowDenial(body) => validate_flow_denial(body),
            Self::DeclassificationConsumption(body) => validate_declassification_consumption(body),
            Self::DeclassificationOutcome(body) => validate_declassification_outcome(body),
            Self::TripwireObservation(body) => validate_tripwire_observation(body),
            Self::CorrelatedFinding(body) => validate_correlated_finding(body),
            Self::ResponsePlan(body) => validate_response_plan(body),
            Self::ResponseStateTransition(body) => validate_response_state_transition(body),
            Self::EffectTransition(body) => validate_effect_transition(body),
            Self::ResponseCompletion(body) => validate_response_completion(body),
            Self::LiftRollbackCompletion(body) => validate_lift_rollback_completion(body),
            Self::DetectorHealth(body) => validate_detector_health(body),
            Self::SchedulerHealth(body) => validate_scheduler_health(body),
        }
    }

    pub fn body_digest(&self) -> Result<Digest32> {
        active_defense_body_digest(self)
    }

    pub fn evidence_id(&self) -> Result<OpaqueReceiptRef> {
        active_defense_evidence_id(self)
    }
}

pub fn active_defense_body_digest(body: &ActiveDefenseReceiptBody) -> Result<Digest32> {
    body.validate()
        .map_err(|error| Error::CanonicalJson(error.to_string()))?;
    let canonical = canonical_json_bytes(body)?;
    let domain = body.kind().body_digest_domain();
    let mut preimage = Vec::with_capacity(domain.len() + 1 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    let digest = sha256(&preimage);
    Ok(Digest32::new(*digest.as_bytes()))
}

pub fn active_defense_evidence_id(body: &ActiveDefenseReceiptBody) -> Result<OpaqueReceiptRef> {
    let body_digest = active_defense_body_digest(body)?;
    let kind = body.kind().as_str().as_bytes();
    let mut preimage =
        Vec::with_capacity(ACTIVE_DEFENSE_EVIDENCE_ID_DOMAIN.len() + 1 + kind.len() + 1 + 32);
    preimage.extend_from_slice(ACTIVE_DEFENSE_EVIDENCE_ID_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(kind);
    preimage.push(0);
    preimage.extend_from_slice(body_digest.as_bytes());
    let evidence_hash = sha256(&preimage);
    OpaqueReceiptRef::new(format!(
        "active_defense_evidence_{}",
        evidence_hash.to_hex()
    ))
    .map_err(|error| Error::CanonicalJson(format!("invalid active-defense evidence id: {error}")))
}

/// Durable transition metadata used to project a committed response effect.
pub struct ActiveDefenseEffectReceiptTransition {
    /// Stable identifier for this effect transition.
    pub transition_id: RecordId,
    /// Evidence identifier for the immediately prior response receipt.
    pub prior_receipt_id: OpaqueReceiptRef,
    /// Wall-clock time at which the transition occurred.
    pub occurred_at_unix_ms: u64,
    /// Monotonic generation of the effect state machine.
    pub generation: u64,
    /// Scheduler lease owner responsible for the transition, when present.
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    /// Scheduler fencing token that authorized the transition.
    pub scheduler_fencing_token: u64,
    /// Canonical outcome committed by this transition.
    pub outcome: ActiveDefenseEffectOutcome,
}

struct ResponseStateTransitionProjection {
    transition_id: RecordId,
    prior_receipt_id: OpaqueReceiptRef,
    occurred_at_unix_ms: u64,
    generation: u64,
    from_state: ResponseState,
    to_state: ResponseState,
    cause: ResponseTransitionCause,
    applying_lease_expires_at_unix_ms: Option<u64>,
    scheduler_lease_owner_id: Option<LeaseOwnerId>,
    scheduler_fencing_token: Option<u64>,
    error_code: Option<ErrorCode>,
}

struct ResponseCompletionProjection {
    transition_id: RecordId,
    prior_receipt_id: OpaqueReceiptRef,
    occurred_at_unix_ms: u64,
    generation: u64,
    final_state: ResponseState,
    error_code: Option<ErrorCode>,
}

/// Project one durable response mutation into its canonical native receipt.
///
/// This is the single projection used by response persistence, lifecycle
/// validation, and kernel readback. Keeping the projection here prevents a
/// verifier from accepting a lineage that the receipt writer would not emit.
pub fn active_defense_response_receipt_for_mutation(
    snapshot: &ResponseSnapshot,
    mutation_index: usize,
) -> Result<ActiveDefenseReceiptBody> {
    let mutation = snapshot
        .mutations
        .as_slice()
        .get(mutation_index)
        .ok_or_else(|| response_snapshot_error("response mutation index is out of bounds"))?;
    match mutation {
        ResponseMutationRecord::Requested(record) => {
            let body = ActiveDefenseReceiptBody::ResponsePlan(ResponsePlanReceiptBody {
                header: response_snapshot_header(
                    record.occurred_at_unix_ms,
                    &snapshot.plan,
                    record.transition_id.clone(),
                    record.prior_receipt_id.clone(),
                )?,
                response: response_snapshot_binding(&snapshot.plan),
                plan_created_at_unix_ms: snapshot.plan.created_at_unix_ms,
                effects: response_snapshot_effect_commitments(&snapshot.plan)?,
            });
            validate_response_snapshot_body(body)
        }
        ResponseMutationRecord::Transition(record) => {
            if record.to_state == ResponseState::Active {
                response_snapshot_completion(
                    snapshot,
                    mutation_index,
                    ResponseCompletionProjection {
                        transition_id: record.transition_id.clone(),
                        prior_receipt_id: record.prior_receipt_id.clone(),
                        occurred_at_unix_ms: record.occurred_at_unix_ms,
                        generation: record.generation,
                        final_state: record.to_state,
                        error_code: None,
                    },
                )
            } else {
                response_snapshot_state_transition(
                    snapshot,
                    ResponseStateTransitionProjection {
                        transition_id: record.transition_id.clone(),
                        prior_receipt_id: record.prior_receipt_id.clone(),
                        occurred_at_unix_ms: record.occurred_at_unix_ms,
                        generation: record.generation,
                        from_state: record.from_state,
                        to_state: record.to_state,
                        cause: record.cause,
                        applying_lease_expires_at_unix_ms: record
                            .applying_lease_expires_at_unix_ms,
                        scheduler_lease_owner_id: record.scheduler_lease_owner_id.clone(),
                        scheduler_fencing_token: record.scheduler_fencing_token,
                        error_code: None,
                    },
                )
            }
        }
        ResponseMutationRecord::EffectRequested(record) => response_snapshot_effect_transition(
            snapshot,
            &record.effect_id,
            ActiveDefenseEffectReceiptTransition {
                transition_id: record.transition_id.clone(),
                prior_receipt_id: record.prior_receipt_id.clone(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
                generation: record.effect_generation,
                scheduler_lease_owner_id: record.scheduler_lease_owner_id.clone(),
                scheduler_fencing_token: record.scheduler_fencing_token,
                outcome: ActiveDefenseEffectOutcome::Requested,
            },
        ),
        ResponseMutationRecord::EffectApplied(record) => response_snapshot_effect_transition(
            snapshot,
            &record.effect_id,
            ActiveDefenseEffectReceiptTransition {
                transition_id: record
                    .effect_transition_id
                    .clone()
                    .unwrap_or_else(|| record.transition_id.clone()),
                prior_receipt_id: record.prior_receipt_id.clone(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
                generation: record.effect_generation,
                scheduler_lease_owner_id: record.scheduler_lease_owner_id.clone(),
                scheduler_fencing_token: record.scheduler_fencing_token,
                outcome: ActiveDefenseEffectOutcome::Applied {
                    resulting_version_hash: record.resulting_version_hash,
                },
            },
        ),
        ResponseMutationRecord::EffectFailed(record) => response_snapshot_effect_transition(
            snapshot,
            &record.effect_id,
            ActiveDefenseEffectReceiptTransition {
                transition_id: record
                    .effect_transition_id
                    .clone()
                    .unwrap_or_else(|| record.transition_id.clone()),
                prior_receipt_id: record.prior_receipt_id.clone(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
                generation: record.effect_generation,
                scheduler_lease_owner_id: record.scheduler_lease_owner_id.clone(),
                scheduler_fencing_token: record.scheduler_fencing_token,
                outcome: ActiveDefenseEffectOutcome::ApplyFailed {
                    error_code: record.error_code.clone(),
                },
            },
        ),
        ResponseMutationRecord::Rollback(record) => {
            let outcome = match &record.outcome {
                ResponseRollbackOutcome::Requested => ActiveDefenseEffectOutcome::RollbackRequested,
                ResponseRollbackOutcome::Restored {
                    resulting_version_hash,
                } => ActiveDefenseEffectOutcome::Restored {
                    resulting_version_hash: *resulting_version_hash,
                },
                ResponseRollbackOutcome::Failed { error_code } => {
                    ActiveDefenseEffectOutcome::RollbackFailed {
                        error_code: error_code.clone(),
                    }
                }
            };
            response_snapshot_effect_transition(
                snapshot,
                &record.effect_id,
                ActiveDefenseEffectReceiptTransition {
                    transition_id: record
                        .effect_transition_id
                        .clone()
                        .unwrap_or_else(|| record.transition_id.clone()),
                    prior_receipt_id: record.prior_receipt_id.clone(),
                    occurred_at_unix_ms: record.occurred_at_unix_ms,
                    generation: record.effect_generation,
                    scheduler_lease_owner_id: record.scheduler_lease_owner_id.clone(),
                    scheduler_fencing_token: record.scheduler_fencing_token,
                    outcome,
                },
            )
        }
        ResponseMutationRecord::Failed(record) => {
            if record.to_state == ResponseState::Failed
                || (record.to_state == ResponseState::ApplyPartial
                    && response_snapshot_has_applied_effect(snapshot, mutation_index))
            {
                response_snapshot_completion(
                    snapshot,
                    mutation_index,
                    ResponseCompletionProjection {
                        transition_id: record.transition_id.clone(),
                        prior_receipt_id: record.prior_receipt_id.clone(),
                        occurred_at_unix_ms: record.occurred_at_unix_ms,
                        generation: record.generation,
                        final_state: record.to_state,
                        error_code: Some(record.error_code.clone()),
                    },
                )
            } else {
                response_snapshot_state_transition(
                    snapshot,
                    ResponseStateTransitionProjection {
                        transition_id: record.transition_id.clone(),
                        prior_receipt_id: record.prior_receipt_id.clone(),
                        occurred_at_unix_ms: record.occurred_at_unix_ms,
                        generation: record.generation,
                        from_state: record.from_state,
                        to_state: record.to_state,
                        cause: response_snapshot_failure_cause(
                            record.to_state,
                            &record.error_code,
                        ),
                        applying_lease_expires_at_unix_ms: None,
                        scheduler_lease_owner_id: record.scheduler_lease_owner_id.clone(),
                        scheduler_fencing_token: record.scheduler_fencing_token,
                        error_code: Some(record.error_code.clone()),
                    },
                )
            }
        }
        ResponseMutationRecord::Final(record) => {
            if record.final_state == ResponseState::Lifted {
                response_snapshot_lift_completion(
                    snapshot,
                    mutation_index,
                    record.transition_id.clone(),
                    record.prior_receipt_id.clone(),
                    record.occurred_at_unix_ms,
                    record.generation,
                    record.final_state,
                )
            } else {
                response_snapshot_state_transition(
                    snapshot,
                    ResponseStateTransitionProjection {
                        transition_id: record.transition_id.clone(),
                        prior_receipt_id: record.prior_receipt_id.clone(),
                        occurred_at_unix_ms: record.occurred_at_unix_ms,
                        generation: record.generation,
                        from_state: record.from_state,
                        to_state: record.final_state,
                        cause: response_snapshot_final_cause(record.final_state),
                        applying_lease_expires_at_unix_ms: None,
                        scheduler_lease_owner_id: record.scheduler_lease_owner_id.clone(),
                        scheduler_fencing_token: record.scheduler_fencing_token,
                        error_code: None,
                    },
                )
            }
        }
    }
}

pub fn active_defense_effect_receipt_for_committed_effect(
    plan: &ResponsePlan,
    effect: &PlannedResponseEffect,
    transition: ActiveDefenseEffectReceiptTransition,
) -> Result<ActiveDefenseReceiptBody> {
    let ActiveDefenseEffectReceiptTransition {
        transition_id,
        prior_receipt_id,
        occurred_at_unix_ms,
        generation,
        scheduler_lease_owner_id,
        scheduler_fencing_token,
        outcome,
    } = transition;
    validate_response_snapshot_body(ActiveDefenseReceiptBody::EffectTransition(
        EffectTransitionReceiptBody {
            header: response_snapshot_header(
                occurred_at_unix_ms,
                plan,
                transition_id,
                prior_receipt_id,
            )?,
            response: response_snapshot_binding(plan),
            effect: response_snapshot_effect_commitment(effect),
            generation,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            outcome,
        },
    ))
}

fn response_snapshot_state_transition(
    snapshot: &ResponseSnapshot,
    transition: ResponseStateTransitionProjection,
) -> Result<ActiveDefenseReceiptBody> {
    let ResponseStateTransitionProjection {
        transition_id,
        prior_receipt_id,
        occurred_at_unix_ms,
        generation,
        from_state,
        to_state,
        cause,
        applying_lease_expires_at_unix_ms,
        scheduler_lease_owner_id,
        scheduler_fencing_token,
        error_code,
    } = transition;
    validate_response_snapshot_body(ActiveDefenseReceiptBody::ResponseStateTransition(
        ResponseStateTransitionReceiptBody {
            header: response_snapshot_header(
                occurred_at_unix_ms,
                &snapshot.plan,
                transition_id,
                prior_receipt_id,
            )?,
            response: response_snapshot_binding(&snapshot.plan),
            generation,
            from_state,
            to_state,
            cause,
            applying_lease_expires_at_unix_ms,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            error_code,
        },
    ))
}

fn response_snapshot_effect_transition(
    snapshot: &ResponseSnapshot,
    effect_id: &EffectId,
    transition: ActiveDefenseEffectReceiptTransition,
) -> Result<ActiveDefenseReceiptBody> {
    let effect = snapshot
        .plan
        .effect(effect_id)
        .ok_or_else(|| response_snapshot_error("response receipt references an unknown effect"))?;
    active_defense_effect_receipt_for_committed_effect(&snapshot.plan, effect, transition)
}

fn response_snapshot_completion(
    snapshot: &ResponseSnapshot,
    mutation_index: usize,
    projection: ResponseCompletionProjection,
) -> Result<ActiveDefenseReceiptBody> {
    let ResponseCompletionProjection {
        transition_id,
        prior_receipt_id,
        occurred_at_unix_ms,
        generation,
        final_state,
        error_code,
    } = projection;
    let completion = response_snapshot_completion_prefix(
        snapshot,
        mutation_index,
        occurred_at_unix_ms,
        generation,
        final_state,
    )?;
    validate_response_snapshot_body(ActiveDefenseReceiptBody::ResponseCompletion(
        ResponseCompletionReceiptBody {
            header: response_snapshot_header(
                occurred_at_unix_ms,
                &snapshot.plan,
                transition_id,
                prior_receipt_id,
            )?,
            response: response_snapshot_binding(&snapshot.plan),
            execution_dispatch: completion.execution_dispatch.clone(),
            dispatch_authorization_hash: completion.dispatch_authorization_hash,
            response_generation: completion.generation,
            response_body_hash: response_snapshot_body_hash(&completion)?,
            final_state,
            error_code,
            effects: response_snapshot_effect_outcomes(snapshot, mutation_index, false)?,
        },
    ))
}

fn response_snapshot_lift_completion(
    snapshot: &ResponseSnapshot,
    mutation_index: usize,
    transition_id: RecordId,
    prior_receipt_id: OpaqueReceiptRef,
    occurred_at_unix_ms: u64,
    generation: u64,
    final_state: ResponseState,
) -> Result<ActiveDefenseReceiptBody> {
    let completion = response_snapshot_completion_prefix(
        snapshot,
        mutation_index,
        occurred_at_unix_ms,
        generation,
        final_state,
    )?;
    validate_response_snapshot_body(ActiveDefenseReceiptBody::LiftRollbackCompletion(
        LiftRollbackCompletionReceiptBody {
            header: response_snapshot_header(
                occurred_at_unix_ms,
                &snapshot.plan,
                transition_id,
                prior_receipt_id,
            )?,
            response: response_snapshot_binding(&snapshot.plan),
            execution_dispatch: completion.execution_dispatch.clone(),
            dispatch_authorization_hash: completion.dispatch_authorization_hash,
            response_generation: completion.generation,
            response_body_hash: response_snapshot_body_hash(&completion)?,
            final_state,
            effects: response_snapshot_effect_outcomes(snapshot, mutation_index, true)?,
        },
    ))
}

fn response_snapshot_completion_prefix(
    snapshot: &ResponseSnapshot,
    mutation_index: usize,
    occurred_at_unix_ms: u64,
    generation: u64,
    final_state: ResponseState,
) -> Result<ResponseSnapshot> {
    let mutations = snapshot
        .mutations
        .as_slice()
        .get(..=mutation_index)
        .ok_or_else(|| response_snapshot_error("response completion index is out of bounds"))?;
    let mut completion = snapshot.clone();
    completion.state = final_state;
    completion.generation = generation;
    completion.applying_lease_expires_at_unix_ms = None;
    completion.due_at_unix_ms = match final_state {
        ResponseState::Planned | ResponseState::AwaitingApproval | ResponseState::Active => {
            Some(snapshot.plan.expires_at_unix_ms)
        }
        ResponseState::Applying => {
            return Err(response_snapshot_error(
                "response completion cannot target applying",
            ));
        }
        ResponseState::ApplyPartial
        | ResponseState::Expiring
        | ResponseState::RollingBack
        | ResponseState::RollbackPartial => Some(occurred_at_unix_ms),
        ResponseState::Cancelled
        | ResponseState::Expired
        | ResponseState::Failed
        | ResponseState::Lifted => None,
    };
    completion.operator_page_required = mutations.iter().any(|mutation| {
        matches!(
            mutation,
            ResponseMutationRecord::Failed(record)
                if record.to_state == ResponseState::RollbackPartial
        )
    });
    completion.mutations = ResponseMutationLog::new(mutations.to_vec())
        .map_err(|_| response_snapshot_error("response completion prefix is invalid"))?;
    Ok(completion)
}

fn response_snapshot_effect_outcomes(
    snapshot: &ResponseSnapshot,
    mutation_index: usize,
    lift: bool,
) -> Result<ActiveDefenseEffectOutcomeCommitments> {
    let mut outcomes = snapshot
        .plan
        .effects
        .as_slice()
        .iter()
        .map(|effect| ActiveDefenseEffectOutcomeCommitment {
            effect: response_snapshot_effect_commitment(effect),
            outcome: ActiveDefenseEffectOutcome::Planned,
        })
        .collect::<Vec<_>>();
    for mutation in snapshot
        .mutations
        .as_slice()
        .iter()
        .take(mutation_index.saturating_add(1))
    {
        let (effect_id, outcome) = match mutation {
            ResponseMutationRecord::EffectRequested(record) => {
                (&record.effect_id, ActiveDefenseEffectOutcome::Requested)
            }
            ResponseMutationRecord::EffectApplied(record) => (
                &record.effect_id,
                ActiveDefenseEffectOutcome::Applied {
                    resulting_version_hash: record.resulting_version_hash,
                },
            ),
            ResponseMutationRecord::EffectFailed(record) => (
                &record.effect_id,
                ActiveDefenseEffectOutcome::ApplyFailed {
                    error_code: record.error_code.clone(),
                },
            ),
            ResponseMutationRecord::Rollback(record) => {
                let outcome = match &record.outcome {
                    ResponseRollbackOutcome::Requested => {
                        ActiveDefenseEffectOutcome::RollbackRequested
                    }
                    ResponseRollbackOutcome::Restored {
                        resulting_version_hash,
                    } => ActiveDefenseEffectOutcome::Restored {
                        resulting_version_hash: *resulting_version_hash,
                    },
                    ResponseRollbackOutcome::Failed { error_code } => {
                        ActiveDefenseEffectOutcome::RollbackFailed {
                            error_code: error_code.clone(),
                        }
                    }
                };
                (&record.effect_id, outcome)
            }
            _ => continue,
        };
        let position = snapshot
            .plan
            .effects
            .as_slice()
            .iter()
            .position(|effect| &effect.effect_id == effect_id)
            .ok_or_else(|| response_snapshot_error("response outcome references unknown effect"))?;
        outcomes[position].outcome = outcome;
    }
    if lift {
        for outcome in &mut outcomes {
            if !outcome.effect.kind.is_reversible()
                && matches!(outcome.outcome, ActiveDefenseEffectOutcome::Applied { .. })
            {
                outcome.outcome = ActiveDefenseEffectOutcome::NoRollbackRequired;
            }
        }
    }
    ActiveDefenseEffectOutcomeCommitments::new(outcomes)
        .map_err(|error| response_snapshot_error(&error.to_string()))
}

fn response_snapshot_effect_commitments(
    plan: &ResponsePlan,
) -> Result<ActiveDefenseEffectCommitments> {
    ActiveDefenseEffectCommitments::new(
        plan.effects
            .as_slice()
            .iter()
            .map(response_snapshot_effect_commitment)
            .collect(),
    )
    .map_err(|error| response_snapshot_error(&error.to_string()))
}

fn response_snapshot_effect_commitment(
    effect: &PlannedResponseEffect,
) -> ActiveDefenseEffectCommitment {
    ActiveDefenseEffectCommitment {
        effect_id: effect.effect_id.clone(),
        ordinal: effect.ordinal,
        kind: effect.kind,
        target: effect.target.clone(),
        contribution_hash: effect.contribution_hash,
        observed_base_version_hash: effect.observed_base_version_hash,
    }
}

fn response_snapshot_binding(plan: &ResponsePlan) -> ActiveDefenseResponseBinding {
    ActiveDefenseResponseBinding {
        policy: ActiveDefensePolicyBinding {
            policy_version: plan.policy_version.clone(),
            policy_hash: plan.policy_hash,
        },
        plan_hash: plan.plan_hash,
        action_id: plan.action_id.clone(),
        trigger_finding_id: plan.trigger_finding_id.clone(),
        trigger_finding_hash: plan.trigger_finding_hash,
        trigger_finding_receipt_id: plan.trigger_finding_receipt_id.clone(),
        affected_set_hash: plan.affected_set_hash,
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
    }
}

fn response_snapshot_body_hash(snapshot: &ResponseSnapshot) -> Result<Digest32> {
    let canonical = canonical_json_bytes(snapshot)?;
    Ok(Digest32::new(*sha256(&canonical).as_bytes()))
}

fn response_snapshot_header(
    occurred_at_unix_ms: u64,
    plan: &ResponsePlan,
    transition_id: RecordId,
    prior_receipt_id: OpaqueReceiptRef,
) -> Result<ActiveDefenseReceiptHeader> {
    ActiveDefenseReceiptHeader::new(
        occurred_at_unix_ms,
        plan.tenant_id.clone(),
        transition_id,
        vec![prior_receipt_id],
    )
    .map_err(|error| response_snapshot_error(&error.to_string()))
}

fn validate_response_snapshot_body(
    body: ActiveDefenseReceiptBody,
) -> Result<ActiveDefenseReceiptBody> {
    body.validate()
        .map_err(|error| response_snapshot_error(&error.to_string()))?;
    Ok(body)
}

fn response_snapshot_has_applied_effect(
    snapshot: &ResponseSnapshot,
    mutation_index: usize,
) -> bool {
    snapshot
        .mutations
        .as_slice()
        .iter()
        .take(mutation_index.saturating_add(1))
        .any(|mutation| matches!(mutation, ResponseMutationRecord::EffectApplied(_)))
}

fn response_snapshot_failure_cause(
    state: ResponseState,
    error_code: &ErrorCode,
) -> ResponseTransitionCause {
    match state {
        ResponseState::RollbackPartial => ResponseTransitionCause::RollbackFailed,
        ResponseState::ApplyPartial if error_code.as_str() == "response.applying_lease_expired" => {
            ResponseTransitionCause::ApplyingLeaseExpired
        }
        _ => ResponseTransitionCause::ValidationFailed,
    }
}

fn response_snapshot_final_cause(state: ResponseState) -> ResponseTransitionCause {
    match state {
        ResponseState::Expired => ResponseTransitionCause::PlanExpired,
        ResponseState::Cancelled => ResponseTransitionCause::OperatorCancelled,
        ResponseState::Lifted => ResponseTransitionCause::RollbackCompleted,
        _ => ResponseTransitionCause::ValidationFailed,
    }
}

fn response_snapshot_error(message: &str) -> Error {
    Error::CanonicalJson(message.to_owned())
}
