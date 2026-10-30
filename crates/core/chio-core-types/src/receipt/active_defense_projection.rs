//! Signed metadata block `active_defense`: the projection of an `ActiveDefenseReceiptBody`
//! with every raw tenant, plan, finding, grant, request and session identifier and every
//! digest not shown to be entropy-backed replaced by a `MetadataCommitment`
//! (`metadata.active_defense.<field>`), and every dictionary-testable domain hash replaced
//! by a keyed value under the active-defense purpose subkey. The full body stays the
//! receipt's content preimage; the receipt's signed tenant binding carries the tenant.

use alloc::format;
use alloc::vec::Vec;

use chio_security_types::ports::{
    DeclassificationUseState, Digest32, ErrorCode, EventId, LeaseOwnerId, LineageId, RecordId,
    ResponseDispatchApproval, TripwireKind,
};
use chio_security_types::{
    DetectorHealthKind, FindingEventIds, FindingSourceReceiptIds, ResponseEffectKind,
    ResponseExecutionDispatchBinding, ResponseState, ResponseTarget, ResponseTransitionCause,
    SecuritySeverity,
};
use serde::{Deserialize, Serialize};

use crate::receipt::metadata::{
    metadata_salt_ref, MetadataCommitment, MetadataCommitter, MetadataProjector, ProjectionError,
};
use crate::receipt::security::{
    ActiveDefenseEffectCommitment, ActiveDefenseEffectOutcome,
    ActiveDefenseEffectOutcomeCommitment, ActiveDefensePolicyBinding, ActiveDefensePriorReceiptIds,
    ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader, ActiveDefenseResponseBinding,
};
use crate::tenant_index::{IndexDomain, KeyedIndexValue, TenantIndexKeySet};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseHeaderProjection {
    pub schema_version: u8,
    pub occurred_at_unix_ms: u64,
    pub transition_id: KeyedIndexValue,
    pub prior_receipt_ids: ActiveDefensePriorReceiptIds,
}

/// `ActiveDefensePolicyBinding` with the policy hash committed: a policy document is
/// guessable, so its hash is not entropy-backed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefensePolicyProjection {
    pub policy_version: RecordId,
    pub policy_hash: MetadataCommitment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseResponseProjection {
    pub policy: ActiveDefensePolicyProjection,
    pub plan_hash: MetadataCommitment,
    pub action_id: MetadataCommitment,
    pub trigger_finding_id: MetadataCommitment,
    pub trigger_finding_hash: MetadataCommitment,
    pub trigger_finding_receipt_id: MetadataCommitment,
    pub affected_set_hash: KeyedIndexValue,
    pub plan_expires_at_unix_ms: u64,
}

/// `ResponseTarget` without the raw tenant or session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "target_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseTargetProjection {
    Tenant,
    Session { session_id: MetadataCommitment },
    Lineage { lineage_id: LineageId },
    CapabilitySet { affected_set_hash: KeyedIndexValue },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseEffectProjection {
    pub effect_id: MetadataCommitment,
    pub ordinal: u16,
    pub kind: ResponseEffectKind,
    pub target: ResponseTargetProjection,
    pub contribution_hash: MetadataCommitment,
    pub observed_base_version_hash: MetadataCommitment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActiveDefenseEffectOutcomeProjection {
    Planned,
    Requested,
    Applied {
        resulting_version_hash: MetadataCommitment,
    },
    ApplyFailed {
        error_code: ErrorCode,
    },
    RollbackRequested,
    Restored {
        resulting_version_hash: MetadataCommitment,
    },
    RollbackFailed {
        error_code: ErrorCode,
    },
    NoRollbackRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDefenseEffectOutcomeProjectionEntry {
    pub effect: ActiveDefenseEffectProjection,
    pub outcome: ActiveDefenseEffectOutcomeProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "approval_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseDispatchApprovalProjection {
    Automatic,
    Governed {
        admission_operation_id: MetadataCommitment,
        admission_operation_version: u64,
        approval_set_hash: MetadataCommitment,
    },
}

/// `ResponseExecutionDispatchBinding` without the raw tenant; the governed intent hash is
/// keyed and every other identifier and digest is committed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseExecutionDispatchProjection {
    pub schema_version: u8,
    pub dispatch_id: MetadataCommitment,
    pub action_id: MetadataCommitment,
    pub plan_hash: MetadataCommitment,
    pub executor_authority_id: MetadataCommitment,
    pub executor_authority_generation: u64,
    pub authorization_capability_hash: MetadataCommitment,
    pub governed_intent_hash: KeyedIndexValue,
    pub policy_decision_hash: MetadataCommitment,
    pub admission_artifact_fingerprint: MetadataCommitment,
    pub approval: ResponseDispatchApprovalProjection,
    pub authorized_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "binding", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetectorGroupBindingProjection {
    Unresolved,
    Resolved { group_key_hash: MetadataCommitment },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "watermark", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetectorWatermarkProjection {
    Unknown,
    Committed { unix_ms: u64 },
    Contradictory { claimed_unix_ms: MetadataCommitment },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowDenialProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub policy: ActiveDefensePolicyProjection,
    pub request_hash: MetadataCommitment,
    pub source_label_hash: MetadataCommitment,
    pub destination_label_hash: MetadataCommitment,
    pub guard_evidence_hash: MetadataCommitment,
    pub denial_code: ErrorCode,
    pub event_id: EventId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationConsumptionProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub policy: ActiveDefensePolicyProjection,
    pub grant_id: MetadataCommitment,
    pub grant_hash: MetadataCommitment,
    pub request_hash: MetadataCommitment,
    pub event_id: EventId,
    pub state: DeclassificationUseState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationOutcomeProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub policy: ActiveDefensePolicyProjection,
    pub grant_id: MetadataCommitment,
    pub grant_hash: MetadataCommitment,
    pub request_hash: MetadataCommitment,
    pub event_id: EventId,
    pub from_state: DeclassificationUseState,
    pub to_state: DeclassificationUseState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireObservationProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub policy: ActiveDefensePolicyProjection,
    pub request_id: MetadataCommitment,
    pub request_hash: MetadataCommitment,
    pub event_id: EventId,
    pub tripwire_kind: TripwireKind,
    pub artifact_id_hash: MetadataCommitment,
    pub artifact_version_hash: MetadataCommitment,
    pub observation_hash: MetadataCommitment,
    pub severity: SecuritySeverity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelatedFindingProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub policy: ActiveDefensePolicyProjection,
    pub finding_id: MetadataCommitment,
    pub finding_hash: MetadataCommitment,
    pub rule_id: MetadataCommitment,
    pub rule_version_hash: MetadataCommitment,
    pub group_key_hash: MetadataCommitment,
    pub ordered_event_ids: FindingEventIds,
    pub ordered_evidence_digests: MetadataCommitment,
    pub ordered_source_receipt_ids: FindingSourceReceiptIds,
    pub first_event_time_unix_ms: u64,
    pub last_event_time_unix_ms: u64,
    pub lineage_seed: LineageId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub response: ActiveDefenseResponseProjection,
    pub plan_created_at_unix_ms: u64,
    pub effects: Vec<ActiveDefenseEffectProjection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseStateTransitionProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub response: ActiveDefenseResponseProjection,
    pub generation: u64,
    pub from_state: ResponseState,
    pub to_state: ResponseState,
    pub cause: ResponseTransitionCause,
    pub applying_lease_expires_at_unix_ms: Option<u64>,
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: Option<u64>,
    pub error_code: Option<ErrorCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectTransitionProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub response: ActiveDefenseResponseProjection,
    pub effect: ActiveDefenseEffectProjection,
    pub generation: u64,
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: u64,
    pub outcome: ActiveDefenseEffectOutcomeProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCompletionProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub response: ActiveDefenseResponseProjection,
    pub execution_dispatch: Option<ResponseExecutionDispatchProjection>,
    pub dispatch_authorization_hash: Option<MetadataCommitment>,
    pub response_generation: u64,
    pub response_body_hash: MetadataCommitment,
    pub final_state: ResponseState,
    pub error_code: Option<ErrorCode>,
    pub effects: Vec<ActiveDefenseEffectOutcomeProjectionEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiftRollbackCompletionProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub response: ActiveDefenseResponseProjection,
    pub execution_dispatch: Option<ResponseExecutionDispatchProjection>,
    pub dispatch_authorization_hash: Option<MetadataCommitment>,
    pub response_generation: u64,
    pub response_body_hash: MetadataCommitment,
    pub final_state: ResponseState,
    pub effects: Vec<ActiveDefenseEffectOutcomeProjectionEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorHealthProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub policy: ActiveDefensePolicyProjection,
    pub rule_id: MetadataCommitment,
    pub rule_version_hash: MetadataCommitment,
    pub group_binding: DetectorGroupBindingProjection,
    pub event_id: EventId,
    pub health_kind: DetectorHealthKind,
    pub watermark: DetectorWatermarkProjection,
    pub evidence_hash: MetadataCommitment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthProjection {
    pub header: ActiveDefenseHeaderProjection,
    pub response: ActiveDefenseResponseProjection,
    pub event_id: RecordId,
    pub first_failure_at_unix_ms: u64,
    pub attempts: u32,
    pub scheduler_fencing_token: u64,
    pub error_code: ErrorCode,
    pub evidence_hash: MetadataCommitment,
}

/// Signed metadata block `active_defense`, one variant per `ActiveDefenseReceiptBody`
/// variant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ActiveDefenseReceiptProjection {
    FlowDenial(FlowDenialProjection),
    DeclassificationConsumption(DeclassificationConsumptionProjection),
    DeclassificationOutcome(DeclassificationOutcomeProjection),
    TripwireObservation(TripwireObservationProjection),
    CorrelatedFinding(CorrelatedFindingProjection),
    ResponsePlan(ResponsePlanProjection),
    ResponseStateTransition(ResponseStateTransitionProjection),
    EffectTransition(EffectTransitionProjection),
    ResponseCompletion(ResponseCompletionProjection),
    LiftRollbackCompletion(LiftRollbackCompletionProjection),
    DetectorHealth(DetectorHealthProjection),
    SchedulerHealth(SchedulerHealthProjection),
}

impl ActiveDefenseReceiptProjection {
    #[must_use]
    pub const fn header(&self) -> &ActiveDefenseHeaderProjection {
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
}

impl ActiveDefenseReceiptBody {
    /// The projection of this body, committing through `committer`, which the receipt's
    /// other blocks share, and deriving each keyed value under the active generation of
    /// `keys`.
    pub fn project_with(
        &self,
        keys: &TenantIndexKeySet,
        committer: &mut MetadataCommitter<'_>,
    ) -> Result<ActiveDefenseReceiptProjection, ProjectionError> {
        Projection(&mut MetadataProjector::active(keys, committer)).body(self)
    }

    /// True when `projection` is the projection of this body under `committer` and the
    /// generation the projection names; false on any mismatch, missing opening or unknown
    /// generation. The caller calls `finish` once per receipt.
    #[must_use]
    pub fn matches_with(
        &self,
        projection: &ActiveDefenseReceiptProjection,
        keys: &TenantIndexKeySet,
        committer: &mut MetadataCommitter<'_>,
    ) -> bool {
        let key_id = projection.header().transition_id.key_id;
        MetadataProjector::generation(keys, &key_id, committer)
            .and_then(|mut projector| Projection(&mut projector).body(self))
            .is_ok_and(|rebuilt| rebuilt == *projection)
    }
}

struct Projection<'p, 'a, 'o>(&'p mut MetadataProjector<'a, 'o>);

impl Projection<'_, '_, '_> {
    fn commit<T: Serialize>(
        &mut self,
        field: &str,
        value: &T,
    ) -> Result<MetadataCommitment, ProjectionError> {
        self.0
            .commit(metadata_salt_ref("active_defense", field)?, value)
    }

    fn keyed(&self, digest: &[u8]) -> Result<KeyedIndexValue, ProjectionError> {
        self.0.keyed(IndexDomain::ActiveDefenseKeyedDigest, digest)
    }

    fn header(
        &mut self,
        header: &ActiveDefenseReceiptHeader,
    ) -> Result<ActiveDefenseHeaderProjection, ProjectionError> {
        Ok(ActiveDefenseHeaderProjection {
            schema_version: header.schema_version,
            occurred_at_unix_ms: header.occurred_at_unix_ms,
            transition_id: self.keyed(header.transition_id.as_str().as_bytes())?,
            prior_receipt_ids: header.prior_receipt_ids.clone(),
        })
    }

    fn policy(
        &mut self,
        policy: &ActiveDefensePolicyBinding,
    ) -> Result<ActiveDefensePolicyProjection, ProjectionError> {
        Ok(ActiveDefensePolicyProjection {
            policy_version: policy.policy_version.clone(),
            policy_hash: self.commit("policy_hash", &policy.policy_hash)?,
        })
    }

    fn response(
        &mut self,
        response: &ActiveDefenseResponseBinding,
    ) -> Result<ActiveDefenseResponseProjection, ProjectionError> {
        Ok(ActiveDefenseResponseProjection {
            policy: self.policy(&response.policy)?,
            plan_hash: self.commit("plan_hash", &response.plan_hash)?,
            action_id: self.commit("action", &response.action_id)?,
            trigger_finding_id: self.commit("finding", &response.trigger_finding_id)?,
            trigger_finding_hash: self
                .commit("trigger_finding_hash", &response.trigger_finding_hash)?,
            trigger_finding_receipt_id: self
                .commit("finding_receipt", &response.trigger_finding_receipt_id)?,
            affected_set_hash: self.keyed(response.affected_set_hash.as_bytes())?,
            plan_expires_at_unix_ms: response.plan_expires_at_unix_ms,
        })
    }

    fn effect(
        &mut self,
        effect: &ActiveDefenseEffectCommitment,
    ) -> Result<ActiveDefenseEffectProjection, ProjectionError> {
        let ordinal = effect.ordinal;
        let target = match &effect.target {
            ResponseTarget::Tenant { .. } => ResponseTargetProjection::Tenant,
            ResponseTarget::Session { session_id } => ResponseTargetProjection::Session {
                session_id: self.commit(&format!("effect_{ordinal}_session"), session_id)?,
            },
            ResponseTarget::Lineage { lineage_id } => ResponseTargetProjection::Lineage {
                lineage_id: lineage_id.clone(),
            },
            ResponseTarget::CapabilitySet { affected_set_hash } => {
                ResponseTargetProjection::CapabilitySet {
                    affected_set_hash: self.keyed(affected_set_hash.as_bytes())?,
                }
            }
        };
        Ok(ActiveDefenseEffectProjection {
            effect_id: self.commit(&format!("effect_{ordinal}_id"), &effect.effect_id)?,
            ordinal,
            kind: effect.kind,
            target,
            contribution_hash: self.commit(
                &format!("effect_{ordinal}_contribution_hash"),
                &effect.contribution_hash,
            )?,
            observed_base_version_hash: self.commit(
                &format!("effect_{ordinal}_observed_base_version_hash"),
                &effect.observed_base_version_hash,
            )?,
        })
    }

    fn outcome(
        &mut self,
        ordinal: u16,
        outcome: &ActiveDefenseEffectOutcome,
    ) -> Result<ActiveDefenseEffectOutcomeProjection, ProjectionError> {
        let field = format!("effect_{ordinal}_resulting_version_hash");
        Ok(match outcome {
            ActiveDefenseEffectOutcome::Planned => ActiveDefenseEffectOutcomeProjection::Planned,
            ActiveDefenseEffectOutcome::Requested => {
                ActiveDefenseEffectOutcomeProjection::Requested
            }
            ActiveDefenseEffectOutcome::Applied {
                resulting_version_hash,
            } => ActiveDefenseEffectOutcomeProjection::Applied {
                resulting_version_hash: self.commit(&field, resulting_version_hash)?,
            },
            ActiveDefenseEffectOutcome::ApplyFailed { error_code } => {
                ActiveDefenseEffectOutcomeProjection::ApplyFailed {
                    error_code: error_code.clone(),
                }
            }
            ActiveDefenseEffectOutcome::RollbackRequested => {
                ActiveDefenseEffectOutcomeProjection::RollbackRequested
            }
            ActiveDefenseEffectOutcome::Restored {
                resulting_version_hash,
            } => ActiveDefenseEffectOutcomeProjection::Restored {
                resulting_version_hash: self.commit(&field, resulting_version_hash)?,
            },
            ActiveDefenseEffectOutcome::RollbackFailed { error_code } => {
                ActiveDefenseEffectOutcomeProjection::RollbackFailed {
                    error_code: error_code.clone(),
                }
            }
            ActiveDefenseEffectOutcome::NoRollbackRequired => {
                ActiveDefenseEffectOutcomeProjection::NoRollbackRequired
            }
        })
    }

    fn outcomes(
        &mut self,
        effects: &[ActiveDefenseEffectOutcomeCommitment],
    ) -> Result<Vec<ActiveDefenseEffectOutcomeProjectionEntry>, ProjectionError> {
        effects
            .iter()
            .map(|entry| {
                Ok(ActiveDefenseEffectOutcomeProjectionEntry {
                    effect: self.effect(&entry.effect)?,
                    outcome: self.outcome(entry.effect.ordinal, &entry.outcome)?,
                })
            })
            .collect()
    }

    fn dispatch(
        &mut self,
        dispatch: &ResponseExecutionDispatchBinding,
    ) -> Result<ResponseExecutionDispatchProjection, ProjectionError> {
        let approval = match &dispatch.approval {
            ResponseDispatchApproval::Automatic => ResponseDispatchApprovalProjection::Automatic,
            ResponseDispatchApproval::Governed {
                admission_operation_id,
                admission_operation_version,
                approval_set_hash,
            } => ResponseDispatchApprovalProjection::Governed {
                admission_operation_id: self
                    .commit("dispatch_admission_operation", admission_operation_id)?,
                admission_operation_version: *admission_operation_version,
                approval_set_hash: self.commit("dispatch_approval_set_hash", approval_set_hash)?,
            },
        };
        Ok(ResponseExecutionDispatchProjection {
            schema_version: dispatch.schema_version,
            dispatch_id: self.commit("dispatch_id", &dispatch.dispatch_id)?,
            action_id: self.commit("action", &dispatch.action_id)?,
            plan_hash: self.commit("dispatch_plan_hash", &dispatch.plan_hash)?,
            executor_authority_id: self.commit(
                "dispatch_executor_authority",
                &dispatch.executor_authority_id,
            )?,
            executor_authority_generation: dispatch.executor_authority_generation,
            authorization_capability_hash: self.commit(
                "dispatch_authorization_capability_hash",
                &dispatch.authorization_capability_hash,
            )?,
            governed_intent_hash: self.keyed(dispatch.governed_intent_hash.as_bytes())?,
            policy_decision_hash: self.commit(
                "dispatch_policy_decision_hash",
                &dispatch.policy_decision_hash,
            )?,
            admission_artifact_fingerprint: self.commit(
                "dispatch_admission_artifact_fingerprint",
                &dispatch.admission_artifact_fingerprint,
            )?,
            approval,
            authorized_at_unix_ms: dispatch.authorized_at_unix_ms,
        })
    }

    fn optional_dispatch(
        &mut self,
        dispatch: Option<&ResponseExecutionDispatchBinding>,
        authorization_hash: Option<&Digest32>,
    ) -> Result<
        (
            Option<ResponseExecutionDispatchProjection>,
            Option<MetadataCommitment>,
        ),
        ProjectionError,
    > {
        let dispatch = dispatch
            .map(|dispatch| self.dispatch(dispatch))
            .transpose()?;
        let authorization_hash = authorization_hash
            .map(|hash| self.commit("dispatch_authorization_hash", hash))
            .transpose()?;
        Ok((dispatch, authorization_hash))
    }

    fn body(
        &mut self,
        body: &ActiveDefenseReceiptBody,
    ) -> Result<ActiveDefenseReceiptProjection, ProjectionError> {
        Ok(match body {
            ActiveDefenseReceiptBody::FlowDenial(body) => {
                ActiveDefenseReceiptProjection::FlowDenial(FlowDenialProjection {
                    header: self.header(&body.header)?,
                    policy: self.policy(&body.policy)?,
                    request_hash: self.commit("request_hash", &body.request_hash)?,
                    source_label_hash: self.commit("source_label_hash", &body.source_label_hash)?,
                    destination_label_hash: self
                        .commit("destination_label_hash", &body.destination_label_hash)?,
                    guard_evidence_hash: self
                        .commit("guard_evidence_hash", &body.guard_evidence_hash)?,
                    denial_code: body.denial_code.clone(),
                    event_id: body.event_id.clone(),
                })
            }
            ActiveDefenseReceiptBody::DeclassificationConsumption(body) => {
                ActiveDefenseReceiptProjection::DeclassificationConsumption(
                    DeclassificationConsumptionProjection {
                        header: self.header(&body.header)?,
                        policy: self.policy(&body.policy)?,
                        grant_id: self.commit("grant", &body.grant_id)?,
                        grant_hash: self.commit("grant_hash", &body.grant_hash)?,
                        request_hash: self.commit("request_hash", &body.request_hash)?,
                        event_id: body.event_id.clone(),
                        state: body.state,
                    },
                )
            }
            ActiveDefenseReceiptBody::DeclassificationOutcome(body) => {
                ActiveDefenseReceiptProjection::DeclassificationOutcome(
                    DeclassificationOutcomeProjection {
                        header: self.header(&body.header)?,
                        policy: self.policy(&body.policy)?,
                        grant_id: self.commit("grant", &body.grant_id)?,
                        grant_hash: self.commit("grant_hash", &body.grant_hash)?,
                        request_hash: self.commit("request_hash", &body.request_hash)?,
                        event_id: body.event_id.clone(),
                        from_state: body.from_state,
                        to_state: body.to_state,
                    },
                )
            }
            ActiveDefenseReceiptBody::TripwireObservation(body) => {
                ActiveDefenseReceiptProjection::TripwireObservation(TripwireObservationProjection {
                    header: self.header(&body.header)?,
                    policy: self.policy(&body.policy)?,
                    request_id: self.commit("request", &body.request_id)?,
                    request_hash: self.commit("request_hash", &body.request_hash)?,
                    event_id: body.event_id.clone(),
                    tripwire_kind: body.tripwire_kind,
                    artifact_id_hash: self.commit("artifact_id_hash", &body.artifact_id_hash)?,
                    artifact_version_hash: self
                        .commit("artifact_version_hash", &body.artifact_version_hash)?,
                    observation_hash: self.commit("observation_hash", &body.observation_hash)?,
                    severity: body.severity,
                })
            }
            ActiveDefenseReceiptBody::CorrelatedFinding(body) => {
                ActiveDefenseReceiptProjection::CorrelatedFinding(CorrelatedFindingProjection {
                    header: self.header(&body.header)?,
                    policy: self.policy(&body.policy)?,
                    finding_id: self.commit("finding", &body.finding_id)?,
                    finding_hash: self.commit("finding_hash", &body.finding_hash)?,
                    rule_id: self.commit("rule_id", &body.rule_id)?,
                    rule_version_hash: self.commit("rule_version_hash", &body.rule_version_hash)?,
                    group_key_hash: self.commit("group_key_hash", &body.group_key_hash)?,
                    ordered_event_ids: body.ordered_event_ids.clone(),
                    ordered_evidence_digests: self
                        .commit("ordered_evidence_digests", &body.ordered_evidence_digests)?,
                    ordered_source_receipt_ids: body.ordered_source_receipt_ids.clone(),
                    first_event_time_unix_ms: body.first_event_time_unix_ms,
                    last_event_time_unix_ms: body.last_event_time_unix_ms,
                    lineage_seed: body.lineage_seed.clone(),
                })
            }
            ActiveDefenseReceiptBody::ResponsePlan(body) => {
                ActiveDefenseReceiptProjection::ResponsePlan(ResponsePlanProjection {
                    header: self.header(&body.header)?,
                    response: self.response(&body.response)?,
                    plan_created_at_unix_ms: body.plan_created_at_unix_ms,
                    effects: body
                        .effects
                        .as_slice()
                        .iter()
                        .map(|effect| self.effect(effect))
                        .collect::<Result<_, _>>()?,
                })
            }
            ActiveDefenseReceiptBody::ResponseStateTransition(body) => {
                ActiveDefenseReceiptProjection::ResponseStateTransition(
                    ResponseStateTransitionProjection {
                        header: self.header(&body.header)?,
                        response: self.response(&body.response)?,
                        generation: body.generation,
                        from_state: body.from_state,
                        to_state: body.to_state,
                        cause: body.cause,
                        applying_lease_expires_at_unix_ms: body.applying_lease_expires_at_unix_ms,
                        scheduler_lease_owner_id: body.scheduler_lease_owner_id.clone(),
                        scheduler_fencing_token: body.scheduler_fencing_token,
                        error_code: body.error_code.clone(),
                    },
                )
            }
            ActiveDefenseReceiptBody::EffectTransition(body) => {
                ActiveDefenseReceiptProjection::EffectTransition(EffectTransitionProjection {
                    header: self.header(&body.header)?,
                    response: self.response(&body.response)?,
                    effect: self.effect(&body.effect)?,
                    generation: body.generation,
                    scheduler_lease_owner_id: body.scheduler_lease_owner_id.clone(),
                    scheduler_fencing_token: body.scheduler_fencing_token,
                    outcome: self.outcome(body.effect.ordinal, &body.outcome)?,
                })
            }
            ActiveDefenseReceiptBody::ResponseCompletion(body) => {
                let (execution_dispatch, dispatch_authorization_hash) = self.optional_dispatch(
                    body.execution_dispatch.as_ref(),
                    body.dispatch_authorization_hash.as_ref(),
                )?;
                ActiveDefenseReceiptProjection::ResponseCompletion(ResponseCompletionProjection {
                    header: self.header(&body.header)?,
                    response: self.response(&body.response)?,
                    execution_dispatch,
                    dispatch_authorization_hash,
                    response_generation: body.response_generation,
                    response_body_hash: self
                        .commit("response_body_hash", &body.response_body_hash)?,
                    final_state: body.final_state,
                    error_code: body.error_code.clone(),
                    effects: self.outcomes(body.effects.as_slice())?,
                })
            }
            ActiveDefenseReceiptBody::LiftRollbackCompletion(body) => {
                let (execution_dispatch, dispatch_authorization_hash) = self.optional_dispatch(
                    body.execution_dispatch.as_ref(),
                    body.dispatch_authorization_hash.as_ref(),
                )?;
                ActiveDefenseReceiptProjection::LiftRollbackCompletion(
                    LiftRollbackCompletionProjection {
                        header: self.header(&body.header)?,
                        response: self.response(&body.response)?,
                        execution_dispatch,
                        dispatch_authorization_hash,
                        response_generation: body.response_generation,
                        response_body_hash: self
                            .commit("response_body_hash", &body.response_body_hash)?,
                        final_state: body.final_state,
                        effects: self.outcomes(body.effects.as_slice())?,
                    },
                )
            }
            ActiveDefenseReceiptBody::DetectorHealth(body) => {
                let group_binding = match &body.group_binding {
                    chio_security_types::DetectorGroupBindingEvidence::Unresolved => {
                        DetectorGroupBindingProjection::Unresolved
                    }
                    chio_security_types::DetectorGroupBindingEvidence::Resolved {
                        group_key_hash,
                    } => DetectorGroupBindingProjection::Resolved {
                        group_key_hash: self.commit("group_key_hash", group_key_hash)?,
                    },
                };
                let watermark = match &body.watermark {
                    chio_security_types::DetectorWatermarkEvidence::Unknown => {
                        DetectorWatermarkProjection::Unknown
                    }
                    chio_security_types::DetectorWatermarkEvidence::Committed { unix_ms } => {
                        DetectorWatermarkProjection::Committed { unix_ms: *unix_ms }
                    }
                    chio_security_types::DetectorWatermarkEvidence::Contradictory {
                        claimed_unix_ms,
                    } => DetectorWatermarkProjection::Contradictory {
                        claimed_unix_ms: self.commit("claimed_watermark", claimed_unix_ms)?,
                    },
                };
                ActiveDefenseReceiptProjection::DetectorHealth(DetectorHealthProjection {
                    header: self.header(&body.header)?,
                    policy: self.policy(&body.policy)?,
                    rule_id: self.commit("rule_id", &body.rule_id)?,
                    rule_version_hash: self.commit("rule_version_hash", &body.rule_version_hash)?,
                    group_binding,
                    event_id: body.event_id.clone(),
                    health_kind: body.health_kind,
                    watermark,
                    evidence_hash: self.commit("evidence_hash", &body.evidence_hash)?,
                })
            }
            ActiveDefenseReceiptBody::SchedulerHealth(body) => {
                ActiveDefenseReceiptProjection::SchedulerHealth(SchedulerHealthProjection {
                    header: self.header(&body.header)?,
                    response: self.response(&body.response)?,
                    event_id: body.event_id.clone(),
                    first_failure_at_unix_ms: body.first_failure_at_unix_ms,
                    attempts: body.attempts,
                    scheduler_fencing_token: body.scheduler_fencing_token,
                    error_code: body.error_code.clone(),
                    evidence_hash: self.commit("evidence_hash", &body.evidence_hash)?,
                })
            }
        })
    }
}
