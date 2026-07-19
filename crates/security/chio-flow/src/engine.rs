#[cfg(any(feature = "std", test))]
use crate::VerifiedClassification;
use crate::{authorize_egress, EgressDenial, InformationFlowLattice};
#[cfg(any(feature = "std", test))]
use crate::{
    information_label_hash, ConsumedDeclassification, DeclassificationError,
    VerifiedDeclassification,
};
#[cfg(any(feature = "std", test))]
use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(any(feature = "std", test))]
use chio_core_types::PublicKey;
#[cfg(any(feature = "std", test))]
use chio_security_types::flow::DeclassificationPurpose;
use chio_security_types::flow::ToolFlowDeclaration;
use chio_security_types::ports::{
    BoundedVec, Digest32, EgressFenceRequest, FlowJoinRequest, FlowStateSnapshot, RecordId,
    RequestId,
};
#[cfg(any(feature = "std", test))]
use chio_security_types::ports::{DeclassificationUseStore, DestinationId};
use chio_security_types::InformationLabel;
use core::fmt;

const MAX_POLICY_CLEARANCES: usize = 64;

#[derive(Debug, Eq, PartialEq)]
pub struct ResolvedFlowRequest {
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub transition_id: RecordId,
    pub state: FlowStateSnapshot,
    pub payload_label: InformationLabel,
    pub operator_input_floor: InformationLabel,
    pub runtime_egress: bool,
    #[cfg(any(feature = "std", test))]
    pub capability_id: RecordId,
    #[cfg(any(feature = "std", test))]
    pub agent_id: RecordId,
    #[cfg(any(feature = "std", test))]
    pub tool_name: RecordId,
    #[cfg(any(feature = "std", test))]
    pub destination_id: DestinationId,
    #[cfg(any(feature = "std", test))]
    pub purpose: DeclassificationPurpose,
    #[cfg(any(feature = "std", test))]
    pub effective_declassification_purposes: BTreeSet<DeclassificationPurpose>,
    #[cfg(any(feature = "std", test))]
    pub trusted_declassification_authorities: BTreeMap<RecordId, PublicKey>,
    #[cfg(any(feature = "std", test))]
    pub now_unix_ms: u64,
    #[cfg(any(feature = "std", test))]
    pub declassification: Option<VerifiedDeclassification>,
    pub policy_clearances: BoundedVec<InformationLabel, MAX_POLICY_CLEARANCES>,
    pub manifest: ToolFlowDeclaration,
    pub fence_expires_at_unix_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct FlowAdmission {
    pub request_hash: Digest32,
    pub source_label: InformationLabel,
    pub egress_source_label: InformationLabel,
    pub effective_egress: bool,
    pub taint_transition: FlowJoinRequest,
    pub egress_fence_plan: Option<EgressFencePlan>,
    #[cfg(any(feature = "std", test))]
    pub declassification: Option<ConsumedDeclassification>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedFlowAdmission {
    admission: FlowAdmission,
    #[cfg(any(feature = "std", test))]
    declassification: Option<VerifiedDeclassification>,
    #[cfg(any(feature = "std", test))]
    consumed_at_unix_ms: u64,
}

impl PreparedFlowAdmission {
    #[must_use]
    pub const fn admission(&self) -> &FlowAdmission {
        &self.admission
    }

    #[cfg(any(feature = "std", test))]
    pub fn consume_declassification(
        mut self,
        store: &dyn DeclassificationUseStore,
    ) -> Result<FlowAdmission, FlowDenial> {
        self.admission.declassification = match self.declassification {
            Some(verified) => Some(
                verified
                    .consume(store, self.consumed_at_unix_ms)
                    .map_err(map_declassification_consumption_error)?,
            ),
            None => None,
        };
        Ok(self.admission)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressFencePlan {
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[cfg(any(feature = "std", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostInvocationFlow {
    pub request_id: RequestId,
    pub payload_digest: Digest32,
    pub state: FlowStateSnapshot,
    pub classified: VerifiedClassification,
    pub operator_output_floor: InformationLabel,
    pub manifest: ToolFlowDeclaration,
    pub transition_id: RecordId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDenial {
    StateOverflow,
    StateChanged,
    InvalidManifest,
    DeclassificationBindingMismatch,
    DeclassificationPurposeDenied,
    DeclassificationNotYetValid,
    DeclassificationExpired,
    DeclassificationUntrustedAuthority,
    UnexpectedDeclassification,
    DeclassificationReplay,
    DeclassificationStoreFailure,
    ClassifierFailure,
    ClassifierBindingMismatch,
    MissingPolicyClearance,
    MissingManifestClearance,
    TopSource,
    TopClearance,
    PolicyFlowViolation,
    ManifestFlowViolation,
}

impl fmt::Display for FlowDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StateOverflow => "flow state exceeded label limits",
            Self::StateChanged => "flow state changed and requires reevaluation",
            Self::InvalidManifest => "tool flow declaration is invalid",
            Self::DeclassificationBindingMismatch => {
                "verified declassification does not match the flow request"
            }
            Self::DeclassificationPurposeDenied => {
                "declassification purpose is not effective for the flow request"
            }
            Self::DeclassificationNotYetValid => "declassification grant is not yet valid",
            Self::DeclassificationExpired => "declassification grant is expired",
            Self::DeclassificationUntrustedAuthority => {
                "declassification authority is not currently trusted"
            }
            Self::UnexpectedDeclassification => {
                "declassification cannot be applied to a non-egress request"
            }
            Self::DeclassificationReplay => "declassification grant is already consumed",
            Self::DeclassificationStoreFailure => "declassification state store failed",
            Self::ClassifierFailure => "classifier evaluation failed",
            Self::ClassifierBindingMismatch => {
                "classification result does not match the effective representation"
            }
            Self::MissingPolicyClearance => "policy clearance is missing",
            Self::MissingManifestClearance => "manifest clearance is missing",
            Self::TopSource => "top-labeled data cannot egress",
            Self::TopClearance => "top is not an operational clearance",
            Self::PolicyFlowViolation => "source exceeds policy clearance",
            Self::ManifestFlowViolation => "source exceeds manifest clearance",
        })
    }
}

impl core::error::Error for FlowDenial {}

pub fn evaluate_pre_invocation(request: ResolvedFlowRequest) -> Result<FlowAdmission, FlowDenial> {
    let prepared = prepare_pre_invocation(request)?;
    #[cfg(any(feature = "std", test))]
    if prepared.declassification.is_some() {
        return Err(FlowDenial::DeclassificationStoreFailure);
    }
    Ok(prepared.admission)
}

#[cfg(any(feature = "std", test))]
pub fn evaluate_pre_invocation_with_declassification(
    request: ResolvedFlowRequest,
    store: &dyn DeclassificationUseStore,
) -> Result<FlowAdmission, FlowDenial> {
    prepare_pre_invocation(request)?.consume_declassification(store)
}

pub fn prepare_pre_invocation(
    request: ResolvedFlowRequest,
) -> Result<PreparedFlowAdmission, FlowDenial> {
    request
        .manifest
        .validate()
        .map_err(|_| FlowDenial::InvalidManifest)?;
    let source_label = join_labels([
        &request.payload_label,
        &request.operator_input_floor,
        &request.state.principal_label,
        &request.state.lineage_label,
        &request.state.session_label,
    ])?;
    let taint_transition = FlowJoinRequest {
        key: request.state.key.clone(),
        principal_join: source_label.clone(),
        lineage_join: source_label.clone(),
        session_join: source_label.clone(),
        transition_id: request.transition_id,
    };
    let effective_egress = request.runtime_egress || request.manifest.egress;
    #[cfg(any(feature = "std", test))]
    let declassification = request.declassification;
    #[cfg(any(feature = "std", test))]
    if declassification.is_some() && !effective_egress {
        return Err(FlowDenial::UnexpectedDeclassification);
    }
    #[cfg(any(feature = "std", test))]
    let egress_source_label = if let Some(verified) = declassification.as_ref() {
        if verified.tenant_id() != &request.state.key.tenant_id
            || verified.capability_id() != &request.capability_id
            || verified.subject_id() != &request.state.key.principal_id
            || verified.agent_id() != &request.agent_id
            || verified.session_id() != &request.state.key.session_id
            || verified.request_hash() != request.request_hash
            || verified.destination_id() != &request.destination_id
            || verified.tool_name() != &request.tool_name
            || verified.purpose() != &request.purpose
            || verified.source_label_hash()
                != information_label_hash(&source_label)
                    .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?
            || verified.target_label() == &source_label
            || !verified.target_label().flows_to(&source_label)
        {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        let now_unix_seconds = request.now_unix_ms / 1_000;
        if now_unix_seconds < verified.issued_at_unix_seconds() {
            return Err(FlowDenial::DeclassificationNotYetValid);
        }
        if now_unix_seconds >= verified.expires_at_unix_seconds() {
            return Err(FlowDenial::DeclassificationExpired);
        }
        if request
            .trusted_declassification_authorities
            .get(verified.authority_key_id())
            != Some(verified.authority_key())
        {
            return Err(FlowDenial::DeclassificationUntrustedAuthority);
        }
        if !request
            .effective_declassification_purposes
            .contains(verified.purpose())
            || !request
                .manifest
                .declassification_purposes
                .contains(verified.purpose())
        {
            return Err(FlowDenial::DeclassificationPurposeDenied);
        }
        verified.target_label().clone()
    } else {
        source_label.clone()
    };
    #[cfg(not(any(feature = "std", test)))]
    let egress_source_label = source_label.clone();
    if !effective_egress {
        return Ok(PreparedFlowAdmission {
            admission: FlowAdmission {
                request_hash: request.request_hash,
                egress_source_label: source_label.clone(),
                source_label,
                effective_egress,
                taint_transition,
                egress_fence_plan: None,
                #[cfg(any(feature = "std", test))]
                declassification: None,
            },
            #[cfg(any(feature = "std", test))]
            declassification: None,
            #[cfg(any(feature = "std", test))]
            consumed_at_unix_ms: request.now_unix_ms,
        });
    }
    if request.policy_clearances.is_empty() {
        return Err(FlowDenial::MissingPolicyClearance);
    }
    for clearance in request.policy_clearances.as_slice() {
        authorize_egress(&egress_source_label, Some(clearance)).map_err(map_policy_denial)?;
    }
    let manifest_clearance = request
        .manifest
        .input_clearance
        .as_ref()
        .ok_or(FlowDenial::MissingManifestClearance)?;
    authorize_egress(&egress_source_label, Some(manifest_clearance))
        .map_err(map_manifest_denial)?;
    let egress_fence_plan = EgressFencePlan {
        request_id: request.request_id,
        request_hash: request.request_hash,
        expires_at_unix_ms: request.fence_expires_at_unix_ms,
    };
    Ok(PreparedFlowAdmission {
        admission: FlowAdmission {
            request_hash: request.request_hash,
            egress_source_label,
            source_label,
            effective_egress,
            taint_transition,
            egress_fence_plan: Some(egress_fence_plan),
            #[cfg(any(feature = "std", test))]
            declassification: None,
        },
        #[cfg(any(feature = "std", test))]
        declassification,
        #[cfg(any(feature = "std", test))]
        consumed_at_unix_ms: request.now_unix_ms,
    })
}

pub fn prepare_egress_fence(
    admission: &FlowAdmission,
    persisted: &FlowStateSnapshot,
) -> Result<Option<EgressFenceRequest>, FlowDenial> {
    let Some(plan) = admission.egress_fence_plan.as_ref() else {
        return Ok(None);
    };
    if plan.request_hash != admission.request_hash
        || persisted.key != admission.taint_transition.key
    {
        return Err(FlowDenial::StateChanged);
    }
    let persisted_label = join_labels([
        &persisted.principal_label,
        &persisted.lineage_label,
        &persisted.session_label,
    ])?;
    if persisted_label != admission.source_label {
        return Err(FlowDenial::StateChanged);
    }
    Ok(Some(EgressFenceRequest {
        key: persisted.key.clone(),
        request_id: plan.request_id.clone(),
        request_hash: plan.request_hash,
        expected_context_generation: persisted.context_generation,
        expires_at_unix_ms: plan.expires_at_unix_ms,
    }))
}

#[cfg(any(feature = "std", test))]
pub fn evaluate_post_invocation(
    request: PostInvocationFlow,
) -> Result<FlowJoinRequest, FlowDenial> {
    request
        .manifest
        .validate()
        .map_err(|_| FlowDenial::InvalidManifest)?;
    if request.classified.tenant_id() != &request.state.key.tenant_id
        || request.classified.request_id() != &request.request_id
        || request.classified.payload_digest() != request.payload_digest
    {
        return Err(FlowDenial::ClassifierBindingMismatch);
    }
    let mut joined = InformationLabel::bottom();
    for label in [
        &request.state.principal_label,
        &request.state.lineage_label,
        &request.state.session_label,
        request.classified.label(),
        &request.operator_output_floor,
    ] {
        joined = join_or_top(&joined, label);
    }
    if let Some(manifest_floor) = request.manifest.output_label.as_ref() {
        joined = join_or_top(&joined, manifest_floor);
    }
    Ok(FlowJoinRequest {
        key: request.state.key,
        principal_join: joined.clone(),
        lineage_join: joined.clone(),
        session_join: joined,
        transition_id: request.transition_id,
    })
}

fn join_labels<'a>(
    labels: impl IntoIterator<Item = &'a InformationLabel>,
) -> Result<InformationLabel, FlowDenial> {
    let mut joined = InformationLabel::bottom();
    for label in labels {
        joined = joined.join(label).map_err(|_| FlowDenial::StateOverflow)?;
    }
    Ok(joined)
}

#[cfg(any(feature = "std", test))]
fn join_or_top(left: &InformationLabel, right: &InformationLabel) -> InformationLabel {
    left.join(right).unwrap_or(InformationLabel::Top)
}

fn map_policy_denial(denial: EgressDenial) -> FlowDenial {
    match denial {
        EgressDenial::MissingClearance => FlowDenial::MissingPolicyClearance,
        EgressDenial::TopSource => FlowDenial::TopSource,
        EgressDenial::TopClearance => FlowDenial::TopClearance,
        EgressDenial::FlowViolation => FlowDenial::PolicyFlowViolation,
    }
}

fn map_manifest_denial(denial: EgressDenial) -> FlowDenial {
    match denial {
        EgressDenial::MissingClearance => FlowDenial::MissingManifestClearance,
        EgressDenial::TopSource => FlowDenial::TopSource,
        EgressDenial::TopClearance => FlowDenial::TopClearance,
        EgressDenial::FlowViolation => FlowDenial::ManifestFlowViolation,
    }
}

#[cfg(any(feature = "std", test))]
fn map_declassification_consumption_error(error: DeclassificationError) -> FlowDenial {
    match error {
        DeclassificationError::AlreadyConsumed => FlowDenial::DeclassificationReplay,
        DeclassificationError::StoreFailure => FlowDenial::DeclassificationStoreFailure,
        _ => FlowDenial::DeclassificationBindingMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_post_invocation, evaluate_pre_invocation,
        evaluate_pre_invocation_with_declassification, prepare_egress_fence,
        prepare_pre_invocation, FlowDenial, PostInvocationFlow, ResolvedFlowRequest,
    };
    use crate::{
        canonical_request_hash, information_label_hash, verify_declassification, CategoryLabelMap,
        DeclassificationDispatchOutcome, DeclassificationVerificationRequest,
        InformationFlowLattice, VerifiedClassification,
    };
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec;
    use chio_core_types::{Keypair, SignedDeclassificationGrant};
    use chio_security_types::flow::{DeclassificationPurpose, ToolFlowDeclaration};
    use chio_security_types::ports::{
        BoundedVec, ByteRange, CanonicalBody, ClassificationFinding, ClassificationRequest,
        ClassificationResult, ClassifierId, ClassifierVersion, DeclassificationConsume,
        DeclassificationConsumeRequest, DeclassificationOutcomeRequest, DeclassificationUseState,
        DeclassificationUseStore, DestinationId, Digest32, FlowStateKey, FlowStateSnapshot,
        GrantId, IsolationEpochId, LineageId, PortError, PortResult, RecordId, RequestId,
        SessionId, TenantId,
    };
    use chio_security_types::{
        Compartment, DeclassificationGrantBody, DeclassificationGrantClaims, InformationLabel,
        PrincipalId,
    };
    use sha2::{Digest as _, Sha256};
    use std::sync::Mutex;

    #[derive(Default)]
    struct OneShotDeclassificationStore {
        state: Mutex<Option<(Digest32, DeclassificationUseState)>>,
    }

    impl DeclassificationUseStore for OneShotDeclassificationStore {
        fn consume(
            &self,
            request: &DeclassificationConsumeRequest,
        ) -> PortResult<DeclassificationConsume> {
            let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
            if let Some((request_hash, use_state)) = state.as_ref() {
                return Ok(DeclassificationConsume::AlreadyConsumed {
                    request_hash: *request_hash,
                    state: *use_state,
                });
            }
            *state = Some((
                request.request_hash,
                DeclassificationUseState::ConsumedPendingDispatch,
            ));
            Ok(DeclassificationConsume::Consumed)
        }

        fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()> {
            let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
            let Some((request_hash, use_state)) = state.as_mut() else {
                return Err(PortError::invalid_data());
            };
            if request_hash != &request.request_hash || use_state != &request.expected_state {
                return Err(PortError::conflict());
            }
            *use_state = request.new_state;
            Ok(())
        }
    }

    fn principal(value: &str) -> PrincipalId {
        PrincipalId::new(value).unwrap_or_else(|error| panic!("principal: {error}"))
    }

    fn compartment(value: &str) -> Compartment {
        Compartment::new(value).unwrap_or_else(|error| panic!("compartment: {error}"))
    }

    fn label(owner: &str, compartment_name: &str) -> InformationLabel {
        let owner = principal(owner);
        InformationLabel::try_known(
            BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
            BTreeSet::from([compartment(compartment_name)]),
        )
        .unwrap_or_else(|error| panic!("label: {error}"))
    }

    fn snapshot() -> FlowStateSnapshot {
        FlowStateSnapshot {
            key: FlowStateKey {
                tenant_id: TenantId::new("tenant-a")
                    .unwrap_or_else(|error| panic!("tenant: {error}")),
                principal_id: principal("subject-a"),
                lineage_id: LineageId::new("lineage-a")
                    .unwrap_or_else(|error| panic!("lineage: {error}")),
                session_id: SessionId::new("session-a")
                    .unwrap_or_else(|error| panic!("session: {error}")),
                isolation_epoch_id: IsolationEpochId::new("epoch-a")
                    .unwrap_or_else(|error| panic!("epoch: {error}")),
            },
            principal_label: label("owner-principal", "principal-known"),
            lineage_label: label("owner-lineage", "lineage-known"),
            session_label: label("owner-session", "session-known"),
            context_generation: 41,
        }
    }

    fn request() -> ResolvedFlowRequest {
        ResolvedFlowRequest {
            request_id: RequestId::new("request-a")
                .unwrap_or_else(|error| panic!("request: {error}")),
            request_hash: Digest32::new([7; 32]),
            transition_id: RecordId::new("flow-request-a")
                .unwrap_or_else(|error| panic!("transition: {error}")),
            state: snapshot(),
            payload_label: label("owner-payload", "payload-known"),
            operator_input_floor: label("owner-operator", "operator-floor"),
            runtime_egress: true,
            capability_id: RecordId::new("capability-a")
                .unwrap_or_else(|error| panic!("capability: {error}")),
            agent_id: RecordId::new("agent-a").unwrap_or_else(|error| panic!("agent: {error}")),
            tool_name: RecordId::new("tool-a").unwrap_or_else(|error| panic!("tool: {error}")),
            destination_id: DestinationId::new("server-a")
                .unwrap_or_else(|error| panic!("destination: {error}")),
            purpose: DeclassificationPurpose::new("support")
                .unwrap_or_else(|error| panic!("purpose: {error}")),
            effective_declassification_purposes: BTreeSet::new(),
            trusted_declassification_authorities: BTreeMap::new(),
            now_unix_ms: 150_000,
            declassification: None,
            policy_clearances: BoundedVec::new(vec![InformationLabel::Top])
                .unwrap_or_else(|error| panic!("clearances: {error}")),
            manifest: ToolFlowDeclaration::public_egress(),
            fence_expires_at_unix_ms: 9_999_999_999_999,
        }
    }

    fn unrestricted_clearance() -> InformationLabel {
        let state = snapshot();
        state
            .principal_label
            .join(&state.lineage_label)
            .and_then(|joined| joined.join(&state.session_label))
            .and_then(|joined| joined.join(&label("owner-payload", "payload-known")))
            .and_then(|joined| joined.join(&label("owner-operator", "operator-floor")))
            .unwrap_or_else(|error| panic!("clearance: {error}"))
    }

    fn egress_manifest(clearance: InformationLabel) -> ToolFlowDeclaration {
        ToolFlowDeclaration::new(None, Some(clearance), true, BTreeSet::new())
            .unwrap_or_else(|error| panic!("manifest: {error}"))
    }

    fn declassifying_request_with_binding(bind_complete_source: bool) -> ResolvedFlowRequest {
        let mut flow = request();
        let purpose = flow.purpose.clone();
        let target = InformationLabel::bottom();
        let complete_source = flow
            .payload_label
            .join(&flow.operator_input_floor)
            .and_then(|joined| joined.join(&flow.state.principal_label))
            .and_then(|joined| joined.join(&flow.state.lineage_label))
            .and_then(|joined| joined.join(&flow.state.session_label))
            .unwrap_or_else(|error| panic!("complete source: {error}"));
        flow.request_hash = canonical_request_hash(
            &CanonicalBody::new(br#"{"amount":1}"#.to_vec())
                .unwrap_or_else(|error| panic!("request body: {error}")),
        )
        .unwrap_or_else(|error| panic!("request hash: {error}"));
        flow.policy_clearances = BoundedVec::new(vec![target.clone()])
            .unwrap_or_else(|error| panic!("clearances: {error}"));
        flow.effective_declassification_purposes = BTreeSet::from([purpose.clone()]);
        flow.manifest =
            ToolFlowDeclaration::new(None, Some(target.clone()), true, BTreeSet::from([purpose]))
                .unwrap_or_else(|error| panic!("manifest: {error}"));

        let key = Keypair::from_seed(&[9; 32]);
        flow.trusted_declassification_authorities = BTreeMap::from([(
            RecordId::new("authority-a").unwrap_or_else(|error| panic!("authority: {error}")),
            key.public_key(),
        )]);
        let verification = DeclassificationVerificationRequest {
            capability_id: flow.capability_id.clone(),
            tenant_id: flow.state.key.tenant_id.clone(),
            subject_id: flow.state.key.principal_id.clone(),
            agent_id: flow.agent_id.clone(),
            session_id: flow.state.key.session_id.clone(),
            source_label: if bind_complete_source {
                complete_source
            } else {
                flow.payload_label.clone()
            },
            destination_id: flow.destination_id.clone(),
            tool_name: flow.tool_name.clone(),
            purpose: flow.purpose.clone(),
            policy_purposes: flow.effective_declassification_purposes.clone(),
            manifest_purposes: flow.manifest.declassification_purposes.clone(),
            canonical_request: CanonicalBody::new(br#"{"amount":1}"#.to_vec())
                .unwrap_or_else(|error| panic!("request body: {error}")),
            now_unix_ms: flow.now_unix_ms,
            trusted_authorities: flow.trusted_declassification_authorities.clone(),
        };
        let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("grant-engine-a")
                .unwrap_or_else(|error| panic!("grant: {error}")),
            capability_id: verification.capability_id.clone(),
            tenant_id: verification.tenant_id.clone(),
            subject_id: verification.subject_id.clone(),
            agent_id: verification.agent_id.clone(),
            session_id: verification.session_id.clone(),
            source_label_hash: information_label_hash(&verification.source_label)
                .unwrap_or_else(|error| panic!("source hash: {error}")),
            target_label: target,
            destination_id: verification.destination_id.clone(),
            tool_name: verification.tool_name.clone(),
            purpose: verification.purpose.clone(),
            request_hash: flow.request_hash,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            authority_key_id: RecordId::new("authority-a")
                .unwrap_or_else(|error| panic!("authority: {error}")),
        })
        .unwrap_or_else(|error| panic!("grant body: {error}"));
        let grant = SignedDeclassificationGrant::sign(body, &key)
            .unwrap_or_else(|error| panic!("sign grant: {error}"));
        flow.declassification = Some(
            verify_declassification(&grant, &verification)
                .unwrap_or_else(|error| panic!("verify grant: {error}")),
        );
        flow
    }

    fn declassifying_request() -> ResolvedFlowRequest {
        declassifying_request_with_binding(true)
    }

    fn payload_only_declassifying_request() -> ResolvedFlowRequest {
        declassifying_request_with_binding(false)
    }

    fn verified_classification(
        request_id_value: &str,
        classified_label: InformationLabel,
    ) -> VerifiedClassification {
        let classifier_id = ClassifierId::new("classifier.main")
            .unwrap_or_else(|error| panic!("classifier: {error}"));
        let classifier_version = ClassifierVersion::new("1")
            .unwrap_or_else(|error| panic!("classifier version: {error}"));
        let category =
            RecordId::new("classified").unwrap_or_else(|error| panic!("category: {error}"));
        let digest = classified_payload_digest();
        let request = ClassificationRequest {
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            request_id: RequestId::new(request_id_value)
                .unwrap_or_else(|error| panic!("request: {error}")),
            payload: CanonicalBody::new(vec![b'x'])
                .unwrap_or_else(|error| panic!("payload: {error}")),
            payload_digest: digest,
        };
        let result = ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: digest,
            classifier_id: classifier_id.clone(),
            classifier_version: classifier_version.clone(),
            findings: BoundedVec::new(vec![ClassificationFinding {
                category: category.clone(),
                confidence_basis_points: 10_000,
                byte_range: Some(ByteRange { start: 0, end: 1 }),
                field_path: None,
            }])
            .unwrap_or_else(|error| panic!("findings: {error}")),
        };
        CategoryLabelMap::new(
            classifier_id,
            classifier_version,
            BTreeMap::from([(category, classified_label)]),
        )
        .unwrap_or_else(|error| panic!("category map: {error}"))
        .verify_result(&request, result)
        .unwrap_or_else(|error| panic!("classification: {error}"))
    }

    fn classified_payload_digest() -> Digest32 {
        let bytes = Sha256::digest(b"x");
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes);
        Digest32::new(digest)
    }

    #[test]
    fn complete_source_joins_payload_floor_and_all_durable_labels() {
        let mut request = request();
        let clearance = unrestricted_clearance();
        request.policy_clearances = BoundedVec::new(vec![clearance.clone()])
            .unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = egress_manifest(clearance.clone());
        let admission =
            evaluate_pre_invocation(request).unwrap_or_else(|error| panic!("admission: {error}"));
        assert_eq!(admission.source_label, clearance);
        assert_eq!(admission.taint_transition.principal_join, clearance);
        assert_eq!(admission.taint_transition.lineage_join, clearance);
        assert_eq!(admission.taint_transition.session_join, clearance);
        assert!(admission.egress_fence_plan.is_some());
        let mut persisted = snapshot();
        persisted.principal_label = clearance.clone();
        persisted.lineage_label = clearance.clone();
        persisted.session_label = clearance;
        persisted.context_generation = 42;
        let fence = prepare_egress_fence(&admission, &persisted)
            .unwrap_or_else(|error| panic!("fence preparation: {error}"))
            .unwrap_or_else(|| panic!("egress fence missing"));
        assert_eq!(fence.expected_context_generation, 42);
    }

    #[test]
    fn one_shot_downgrade_substitutes_the_exact_signed_target_for_egress() {
        let flow = declassifying_request();
        let original_state = flow.state.clone();
        let full_source = flow
            .payload_label
            .join(&flow.operator_input_floor)
            .and_then(|joined| joined.join(&flow.state.principal_label))
            .and_then(|joined| joined.join(&flow.state.lineage_label))
            .and_then(|joined| joined.join(&flow.state.session_label))
            .unwrap_or_else(|error| panic!("full source: {error}"));
        let egress_source = InformationLabel::bottom();
        let store = OneShotDeclassificationStore::default();
        let admission = evaluate_pre_invocation_with_declassification(flow, &store)
            .unwrap_or_else(|error| panic!("admission: {error}"));

        assert_eq!(admission.source_label, full_source);
        assert_eq!(admission.egress_source_label, egress_source);
        assert_eq!(admission.taint_transition.principal_join, full_source);
        assert_eq!(admission.taint_transition.lineage_join, full_source);
        assert_eq!(admission.taint_transition.session_join, full_source);

        let mut persisted = original_state;
        persisted.principal_label = full_source.clone();
        persisted.lineage_label = full_source.clone();
        persisted.session_label = full_source;
        persisted.context_generation += 1;
        assert!(prepare_egress_fence(&admission, &persisted)
            .unwrap_or_else(|error| panic!("fence: {error}"))
            .is_some());

        admission
            .declassification
            .as_ref()
            .unwrap_or_else(|| panic!("consumed declassification missing"))
            .record_dispatch_outcome(
                &store,
                DeclassificationDispatchOutcome::DispatchFailed,
                RecordId::new("dispatch-failed-engine-a")
                    .unwrap_or_else(|error| panic!("transition: {error}")),
            )
            .unwrap_or_else(|error| panic!("dispatch outcome: {error}"));
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|_| panic!("declassification state lock"))
                .as_ref()
                .map(|(_, state)| *state),
            Some(DeclassificationUseState::DispatchFailed)
        );
    }

    #[test]
    fn pre_invocation_precheck_persists_full_taint_without_consuming_declassification() {
        let store = OneShotDeclassificationStore::default();
        let prepared = prepare_pre_invocation(declassifying_request())
            .unwrap_or_else(|error| panic!("prepare admission: {error}"));

        assert!(prepared.admission().declassification.is_none());
        assert!(store
            .state
            .lock()
            .unwrap_or_else(|_| panic!("declassification state lock"))
            .is_none());

        let admission = prepared
            .consume_declassification(&store)
            .unwrap_or_else(|error| panic!("consume declassification: {error}"));
        assert!(admission.declassification.is_some());
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|_| panic!("declassification state lock"))
                .as_ref()
                .map(|(_, state)| *state),
            Some(DeclassificationUseState::ConsumedPendingDispatch)
        );
    }

    #[test]
    fn payload_only_declassification_binding_cannot_downgrade_accumulated_knowledge() {
        let flow = payload_only_declassifying_request();
        let store = OneShotDeclassificationStore::default();
        assert_eq!(
            evaluate_pre_invocation_with_declassification(flow, &store),
            Err(FlowDenial::DeclassificationBindingMismatch)
        );
        assert!(store
            .state
            .lock()
            .unwrap_or_else(|_| panic!("declassification state lock"))
            .is_none());
    }

    #[test]
    fn static_denials_do_not_consume_and_replay_cannot_reenter() {
        let mut rebound = declassifying_request();
        rebound.destination_id =
            DestinationId::new("server-b").unwrap_or_else(|error| panic!("destination: {error}"));
        let rebound_store = OneShotDeclassificationStore::default();
        assert_eq!(
            evaluate_pre_invocation_with_declassification(rebound, &rebound_store),
            Err(FlowDenial::DeclassificationBindingMismatch)
        );
        assert!(rebound_store
            .state
            .lock()
            .unwrap_or_else(|_| panic!("declassification state lock"))
            .is_none());

        let mut denied = declassifying_request();
        denied.policy_clearances =
            BoundedVec::new(vec![]).unwrap_or_else(|error| panic!("clearances: {error}"));
        let denied_store = OneShotDeclassificationStore::default();
        assert_eq!(
            evaluate_pre_invocation_with_declassification(denied, &denied_store),
            Err(FlowDenial::MissingPolicyClearance)
        );
        assert!(denied_store
            .state
            .lock()
            .unwrap_or_else(|_| panic!("declassification state lock"))
            .is_none());

        let replay_store = OneShotDeclassificationStore::default();
        evaluate_pre_invocation_with_declassification(declassifying_request(), &replay_store)
            .unwrap_or_else(|error| panic!("first admission: {error}"));
        assert_eq!(
            evaluate_pre_invocation_with_declassification(declassifying_request(), &replay_store),
            Err(FlowDenial::DeclassificationReplay)
        );
    }

    #[test]
    fn verified_grant_cannot_cross_identity_authority_or_expiry_boundary() {
        fn assert_denied(request: ResolvedFlowRequest, expected: FlowDenial) {
            let store = OneShotDeclassificationStore::default();
            assert_eq!(
                evaluate_pre_invocation_with_declassification(request, &store),
                Err(expected)
            );
            assert!(store
                .state
                .lock()
                .unwrap_or_else(|_| panic!("declassification state lock"))
                .is_none());
        }

        let mut capability = declassifying_request();
        capability.capability_id =
            RecordId::new("capability-b").unwrap_or_else(|error| panic!("capability: {error}"));
        assert_denied(capability, FlowDenial::DeclassificationBindingMismatch);

        let mut subject = declassifying_request();
        subject.state.key.principal_id = principal("subject-b");
        assert_denied(subject, FlowDenial::DeclassificationBindingMismatch);

        let mut agent = declassifying_request();
        agent.agent_id = RecordId::new("agent-b").unwrap_or_else(|error| panic!("agent: {error}"));
        assert_denied(agent, FlowDenial::DeclassificationBindingMismatch);

        let mut session = declassifying_request();
        session.state.key.session_id =
            SessionId::new("session-b").unwrap_or_else(|error| panic!("session: {error}"));
        assert_denied(session, FlowDenial::DeclassificationBindingMismatch);

        let mut tool = declassifying_request();
        tool.tool_name = RecordId::new("tool-b").unwrap_or_else(|error| panic!("tool: {error}"));
        assert_denied(tool, FlowDenial::DeclassificationBindingMismatch);

        let mut authority = declassifying_request();
        authority.trusted_declassification_authorities.clear();
        assert_denied(authority, FlowDenial::DeclassificationUntrustedAuthority);

        let mut replaced_authority = declassifying_request();
        replaced_authority
            .trusted_declassification_authorities
            .insert(
                RecordId::new("authority-a").unwrap_or_else(|error| panic!("authority: {error}")),
                Keypair::from_seed(&[10; 32]).public_key(),
            );
        assert_denied(
            replaced_authority,
            FlowDenial::DeclassificationUntrustedAuthority,
        );

        let mut not_yet_valid = declassifying_request();
        not_yet_valid.now_unix_ms = 99_999;
        assert_denied(not_yet_valid, FlowDenial::DeclassificationNotYetValid);

        let mut expired = declassifying_request();
        expired.now_unix_ms = 200_000;
        assert_denied(expired, FlowDenial::DeclassificationExpired);
    }

    #[test]
    fn fence_is_prepared_only_after_taint_persistence() {
        let mut request = request();
        let clearance = unrestricted_clearance();
        request.policy_clearances = BoundedVec::new(vec![clearance.clone()])
            .unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = egress_manifest(clearance.clone());
        let admission =
            evaluate_pre_invocation(request).unwrap_or_else(|error| panic!("admission: {error}"));
        assert_eq!(
            prepare_egress_fence(&admission, &snapshot()),
            Err(FlowDenial::StateChanged)
        );

        let mut persisted = snapshot();
        persisted.principal_label = clearance.clone();
        persisted.lineage_label = clearance.clone();
        persisted.session_label = clearance.clone();
        persisted.context_generation = 42;
        let fence = prepare_egress_fence(&admission, &persisted)
            .unwrap_or_else(|error| panic!("fence: {error}"))
            .unwrap_or_else(|| panic!("fence missing"));
        assert_eq!(fence.expected_context_generation, 42);

        persisted.session_label = label("concurrent-owner", "concurrent-taint");
        persisted.context_generation = 43;
        assert_eq!(
            prepare_egress_fence(&admission, &persisted),
            Err(FlowDenial::StateChanged)
        );
    }

    #[test]
    fn accumulated_knowledge_blocks_unclassified_egress() {
        let mut request = request();
        request.payload_label = InformationLabel::bottom();
        request.operator_input_floor = InformationLabel::bottom();
        request.policy_clearances = BoundedVec::new(vec![InformationLabel::bottom()])
            .unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = egress_manifest(unrestricted_clearance());
        assert_eq!(
            evaluate_pre_invocation(request),
            Err(FlowDenial::PolicyFlowViolation)
        );
    }

    #[test]
    fn every_policy_clearance_must_accept_the_complete_source() {
        let mut request = request();
        request.policy_clearances =
            BoundedVec::new(vec![unrestricted_clearance(), InformationLabel::bottom()])
                .unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = egress_manifest(unrestricted_clearance());
        assert_eq!(
            evaluate_pre_invocation(request),
            Err(FlowDenial::PolicyFlowViolation)
        );
    }

    #[test]
    fn publisher_clearance_cannot_replace_policy_clearance() {
        let mut request = request();
        request.policy_clearances =
            BoundedVec::new(vec![]).unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = egress_manifest(unrestricted_clearance());
        assert_eq!(
            evaluate_pre_invocation(request),
            Err(FlowDenial::MissingPolicyClearance)
        );
    }

    #[test]
    fn remote_topology_overrides_publisher_non_egress_declaration() {
        let mut request = request();
        request.policy_clearances = BoundedVec::new(vec![unrestricted_clearance()])
            .unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = ToolFlowDeclaration::new(None, None, false, BTreeSet::new())
            .unwrap_or_else(|error| panic!("manifest: {error}"));
        assert_eq!(
            evaluate_pre_invocation(request),
            Err(FlowDenial::MissingManifestClearance)
        );
    }

    #[test]
    fn non_egress_call_retains_taint_without_clearance_or_fence() {
        let mut request = request();
        request.runtime_egress = false;
        request.policy_clearances =
            BoundedVec::new(vec![]).unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = ToolFlowDeclaration::new(None, None, false, BTreeSet::new())
            .unwrap_or_else(|error| panic!("manifest: {error}"));
        let admission =
            evaluate_pre_invocation(request).unwrap_or_else(|error| panic!("admission: {error}"));
        assert!(!admission.effective_egress);
        assert!(admission.egress_fence_plan.is_none());
        assert_ne!(
            admission.taint_transition.session_join,
            InformationLabel::bottom()
        );
    }

    #[test]
    fn top_source_and_top_policy_clearance_deny() {
        let mut top_source_request = request();
        top_source_request.payload_label = InformationLabel::Top;
        top_source_request.policy_clearances = BoundedVec::new(vec![unrestricted_clearance()])
            .unwrap_or_else(|error| panic!("clearances: {error}"));
        top_source_request.manifest = egress_manifest(unrestricted_clearance());
        assert_eq!(
            evaluate_pre_invocation(top_source_request),
            Err(FlowDenial::TopSource)
        );

        let mut request = request();
        request.policy_clearances = BoundedVec::new(vec![InformationLabel::Top])
            .unwrap_or_else(|error| panic!("clearances: {error}"));
        request.manifest = egress_manifest(unrestricted_clearance());
        assert_eq!(
            evaluate_pre_invocation(request),
            Err(FlowDenial::TopClearance)
        );
    }

    #[test]
    fn post_invocation_joins_classifier_and_declared_floors_before_delivery() {
        let state = snapshot();
        let classifier_label = label("owner-classifier", "classified-output");
        let operator_floor = label("owner-output", "operator-output");
        let manifest_floor = label("owner-manifest", "manifest-output");
        let response_request_id =
            RequestId::new("response-a").unwrap_or_else(|error| panic!("request: {error}"));
        let payload_digest = classified_payload_digest();
        let expected = state
            .principal_label
            .join(&state.lineage_label)
            .and_then(|joined| joined.join(&state.session_label))
            .and_then(|joined| joined.join(&classifier_label))
            .and_then(|joined| joined.join(&operator_floor))
            .and_then(|joined| joined.join(&manifest_floor))
            .unwrap_or_else(|error| panic!("expected join: {error}"));
        let transition = evaluate_post_invocation(PostInvocationFlow {
            request_id: response_request_id,
            payload_digest,
            state,
            classified: verified_classification("response-a", classifier_label),
            operator_output_floor: operator_floor,
            manifest: ToolFlowDeclaration::new(Some(manifest_floor), None, false, BTreeSet::new())
                .unwrap_or_else(|error| panic!("manifest: {error}")),
            transition_id: RecordId::new("output-transition")
                .unwrap_or_else(|error| panic!("transition: {error}")),
        })
        .unwrap_or_else(|error| panic!("post invocation: {error}"));
        assert_eq!(transition.principal_join, expected);
        assert_eq!(transition.lineage_join, expected);
        assert_eq!(transition.session_join, expected);
    }

    #[test]
    fn post_invocation_overflow_transitions_to_top() {
        let mut state = snapshot();
        let owners = (0_u8..64)
            .map(|value| {
                let owner = principal(&alloc::format!("owner-{value}"));
                (owner.clone(), BTreeSet::from([owner]))
            })
            .collect();
        state.principal_label = InformationLabel::try_known(owners, BTreeSet::new())
            .unwrap_or_else(|error| panic!("principal label: {error}"));
        let payload_digest = classified_payload_digest();
        let transition = evaluate_post_invocation(PostInvocationFlow {
            request_id: RequestId::new("overflow-response")
                .unwrap_or_else(|error| panic!("request: {error}")),
            payload_digest,
            state,
            classified: verified_classification(
                "overflow-response",
                label("overflow-owner", "overflow"),
            ),
            operator_output_floor: InformationLabel::bottom(),
            manifest: ToolFlowDeclaration::new(None, None, false, BTreeSet::new())
                .unwrap_or_else(|error| panic!("manifest: {error}")),
            transition_id: RecordId::new("overflow-transition")
                .unwrap_or_else(|error| panic!("transition: {error}")),
        })
        .unwrap_or_else(|error| panic!("post invocation: {error}"));
        assert_eq!(transition.principal_join, InformationLabel::Top);
        assert_eq!(transition.lineage_join, InformationLabel::Top);
        assert_eq!(transition.session_join, InformationLabel::Top);
    }

    #[test]
    fn post_invocation_rejects_classification_from_another_representation() {
        let result = evaluate_post_invocation(PostInvocationFlow {
            request_id: RequestId::new("response-binding")
                .unwrap_or_else(|error| panic!("request: {error}")),
            payload_digest: Digest32::new([7; 32]),
            state: snapshot(),
            classified: verified_classification(
                "response-binding",
                label("owner-classifier", "classified-output"),
            ),
            operator_output_floor: InformationLabel::bottom(),
            manifest: ToolFlowDeclaration::new(None, None, false, BTreeSet::new())
                .unwrap_or_else(|error| panic!("manifest: {error}")),
            transition_id: RecordId::new("binding-transition")
                .unwrap_or_else(|error| panic!("transition: {error}")),
        });
        assert_eq!(result, Err(FlowDenial::ClassifierBindingMismatch));
    }

    #[test]
    fn post_invocation_rejects_classification_from_another_tenant() {
        let payload_digest = classified_payload_digest();
        let mut state = snapshot();
        state.key.tenant_id =
            TenantId::new("tenant-b").unwrap_or_else(|error| panic!("tenant: {error}"));
        let result = evaluate_post_invocation(PostInvocationFlow {
            request_id: RequestId::new("response-tenant-binding")
                .unwrap_or_else(|error| panic!("request: {error}")),
            payload_digest,
            state,
            classified: verified_classification(
                "response-tenant-binding",
                label("owner-classifier", "classified-output"),
            ),
            operator_output_floor: InformationLabel::bottom(),
            manifest: ToolFlowDeclaration::new(None, None, false, BTreeSet::new())
                .unwrap_or_else(|error| panic!("manifest: {error}")),
            transition_id: RecordId::new("tenant-binding-transition")
                .unwrap_or_else(|error| panic!("transition: {error}")),
        });
        assert_eq!(result, Err(FlowDenial::ClassifierBindingMismatch));
    }

    #[test]
    fn many_small_outputs_accumulate_taint_monotonically() {
        let mut state = snapshot();
        for value in 0_u8..10 {
            let previous = state.session_label.clone();
            let digest = classified_payload_digest();
            let request_id_value = alloc::format!("response-{value}");
            let transition = evaluate_post_invocation(PostInvocationFlow {
                request_id: RequestId::new(&request_id_value)
                    .unwrap_or_else(|error| panic!("request: {error}")),
                payload_digest: digest,
                state: state.clone(),
                classified: verified_classification(
                    &request_id_value,
                    label(
                        &alloc::format!("output-owner-{value}"),
                        &alloc::format!("output-compartment-{value}"),
                    ),
                ),
                operator_output_floor: InformationLabel::bottom(),
                manifest: ToolFlowDeclaration::new(None, None, false, BTreeSet::new())
                    .unwrap_or_else(|error| panic!("manifest: {error}")),
                transition_id: RecordId::new(alloc::format!("output-transition-{value}"))
                    .unwrap_or_else(|error| panic!("transition: {error}")),
            })
            .unwrap_or_else(|error| panic!("post invocation: {error}"));
            assert!(previous.flows_to(&transition.session_join));
            state.principal_label = transition.principal_join;
            state.lineage_label = transition.lineage_join;
            state.session_label = transition.session_join;
            state.context_generation += 1;
        }
    }
}
