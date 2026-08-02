/// Policy-owned response fields for one authoritative finding.
///
/// Persistence identities and finding authority fields are absent by design.
/// The trusted durable planner supplies those fields after this selection is
/// returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedFindingResponsePolicySelection {
    pub affected_ids: Vec<RecordId>,
    pub effects: Vec<ResponseEffectSpec>,
    pub ttl_ms: u64,
    pub created_at_unix_ms: u64,
    pub operator_capability: OperatorCapabilityBinding,
    pub approval_requirement: ResponseApprovalRequirement,
    pub submitter: RecordId,
    pub reason_hash: Digest32,
    pub admission_artifact_ref: AdmissionArtifactRef,
}

const ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_SCHEMA: &str =
    "chio.attested-finding-admission-artifacts.v1";
const ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_DIGEST_DOMAIN: &[u8] =
    b"chio.attested-finding-admission-artifact-bundle-digest.v1\0";

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalAttestedFindingAdmissionArtifactBundle<'a> {
    schema: &'static str,
    artifact_ref: &'a AdmissionArtifactRef,
    authority_attestation: &'a ActiveResponseArtifactAuthorityAttestation,
    payload_digest: &'a Digest32,
}

/// Signed authorization material for one exact reserved response plan.
///
/// Policy code may select and retrieve these artifacts, but it cannot assert
/// that a response was admitted or executed. The production coordinator feeds
/// the artifacts and the trusted reserved plan into the kernel, which verifies
/// the operator capability for both automatic and governed plans and performs
/// approval replay reservation and dispatch commitment for governed plans.
#[derive(Clone, Debug)]
pub struct AttestedFindingAdmissionArtifacts {
    payload: AttestedFindingAdmissionArtifactPayload,
}

#[derive(Clone, Debug)]
enum AttestedFindingAdmissionArtifactPayload {
    Kernel(Box<KernelAttestedFindingAdmissionArtifactPayload>),
    #[cfg(test)]
    Synthetic { digest: Digest32 },
}

#[derive(Clone, Debug)]
struct KernelAttestedFindingAdmissionArtifactPayload {
    artifact_ref: AdmissionArtifactRef,
    operator_capability: CapabilityToken,
    governed_intent: GovernedTransactionIntent,
    submission_proof: ActiveResponseSubmissionProof,
    authority_attestation: ActiveResponseArtifactAuthorityAttestation,
    threshold_proposal: Option<ThresholdApprovalProposal>,
    approval_tokens: Vec<GovernedApprovalToken>,
}

impl AttestedFindingAdmissionArtifacts {
    #[must_use]
    pub fn new(
        artifact_ref: AdmissionArtifactRef,
        operator_capability: CapabilityToken,
        governed_intent: GovernedTransactionIntent,
        submission_proof: ActiveResponseSubmissionProof,
        authority_attestation: ActiveResponseArtifactAuthorityAttestation,
        threshold_proposal: Option<ThresholdApprovalProposal>,
        approval_tokens: Vec<GovernedApprovalToken>,
    ) -> Self {
        Self {
            payload: AttestedFindingAdmissionArtifactPayload::Kernel(Box::new(
                KernelAttestedFindingAdmissionArtifactPayload {
                    artifact_ref,
                    operator_capability,
                    governed_intent,
                    submission_proof,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                },
            )),
        }
    }

    pub fn canonical_digest(&self, response_plan: &ResponsePlan) -> PortResult<Digest32> {
        match &self.payload {
            AttestedFindingAdmissionArtifactPayload::Kernel(payload) => {
                let payload = payload.as_ref();
                let payload_digest = active_response_admission_artifact_payload_digest(
                    &response_plan.authorization_body(),
                    &payload.operator_capability,
                    &payload.governed_intent,
                    &payload.submission_proof,
                    &payload.threshold_proposal,
                    &payload.approval_tokens,
                )
                .map_err(|_| PortError::integrity_failure())?;
                canonical_admission_artifact_bundle_digest(
                    &payload.artifact_ref,
                    &payload.authority_attestation,
                    &payload_digest,
                )
            }
            #[cfg(test)]
            AttestedFindingAdmissionArtifactPayload::Synthetic { digest } => {
                if digest.is_zero() {
                    Err(PortError::integrity_failure())
                } else {
                    Ok(*digest)
                }
            }
        }
    }

    pub fn verify_authority_attestation(
        &self,
        expected_ref: &AdmissionArtifactRef,
        response_plan: &ResponsePlan,
        expected_authority: &PublicKey,
        admission_time_unix_ms: u64,
    ) -> PortResult<Digest32> {
        match &self.payload {
            AttestedFindingAdmissionArtifactPayload::Kernel(payload) => {
                let payload = payload.as_ref();
                let payload_digest = active_response_admission_artifact_payload_digest(
                    &response_plan.authorization_body(),
                    &payload.operator_capability,
                    &payload.governed_intent,
                    &payload.submission_proof,
                    &payload.threshold_proposal,
                    &payload.approval_tokens,
                )
                .map_err(|_| PortError::integrity_failure())?;
                let proof_digest =
                    active_response_submission_proof_digest(&payload.submission_proof)
                        .map_err(|_| PortError::integrity_failure())?;
                let attestation = &payload.authority_attestation.body;
                let plan_body_hash = digest_from_canonical_hex(
                    payload.submission_proof.body.plan_body_hash.as_str(),
                )?;
                let governed_intent_hash = digest_from_canonical_hex(
                    payload.submission_proof.body.governed_intent_hash.as_str(),
                )?;
                let signature_valid = payload.authority_attestation
                    .verify_signature()
                    .map_err(|_| PortError::integrity_failure())?;
                if &payload.artifact_ref != expected_ref
                    || &attestation.artifact_ref != expected_ref
                    || attestation.action_id != response_plan.action_id
                    || attestation.tenant_id != response_plan.tenant_id
                    || attestation.artifact_payload_digest != payload_digest
                    || attestation.submission_proof_digest != proof_digest
                    || attestation.plan_body_hash != plan_body_hash
                    || attestation.governed_intent_hash != governed_intent_hash
                    || attestation.submitter != payload.submission_proof.body.submitter
                    || &attestation.authority != expected_authority
                    || payload.submission_proof.body.action_id.as_str()
                        != response_plan.action_id.as_str()
                    || payload.submission_proof.body.tenant_id != response_plan.tenant_id
                    || !payload.submission_proof
                        .verify_signature()
                        .map_err(|_| PortError::integrity_failure())?
                    || attestation.issued_at_unix_ms
                        != payload.submission_proof.body.issued_at_unix_ms
                    || attestation.expires_at_unix_ms
                        != payload.submission_proof.body.expires_at_unix_ms
                    || attestation.issued_at_unix_ms < response_plan.created_at_unix_ms
                    || attestation.issued_at_unix_ms >= response_plan.expires_at_unix_ms
                    || attestation.issued_at_unix_ms > admission_time_unix_ms
                    || admission_time_unix_ms >= attestation.expires_at_unix_ms
                    || attestation.expires_at_unix_ms > response_plan.expires_at_unix_ms
                    || payload_digest.is_zero()
                    || proof_digest.is_zero()
                    || !signature_valid
                {
                    return Err(PortError::integrity_failure());
                }
                canonical_admission_artifact_bundle_digest(
                    &payload.artifact_ref,
                    &payload.authority_attestation,
                    &payload_digest,
                )
            }
            #[cfg(test)]
            AttestedFindingAdmissionArtifactPayload::Synthetic { digest } => {
                if digest.is_zero() {
                    Err(PortError::integrity_failure())
                } else {
                    Ok(*digest)
                }
            }
        }
    }

    #[cfg(test)]
    fn synthetic(digest: Digest32) -> Self {
        Self {
            payload: AttestedFindingAdmissionArtifactPayload::Synthetic { digest },
        }
    }

    fn into_admission_request(
        self,
        response_plan: ResponsePlan,
    ) -> Result<ActiveResponseAdmissionRequest, chio_kernel::KernelError> {
        match self.payload {
            AttestedFindingAdmissionArtifactPayload::Kernel(payload) => {
                let KernelAttestedFindingAdmissionArtifactPayload {
                    artifact_ref,
                    operator_capability,
                    governed_intent,
                    submission_proof,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                } = *payload;
                let authorization = ActiveResponseAuthorizationRequest::new(
                    operator_capability,
                    response_plan.authorization_body(),
                    governed_intent,
                    submission_proof,
                )?;
                ActiveResponseAdmissionRequest::new(
                    response_plan,
                    authorization,
                    artifact_ref,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                )
            }
            #[cfg(test)]
            AttestedFindingAdmissionArtifactPayload::Synthetic { .. } => Err(
                chio_kernel::KernelError::Internal(
                    "synthetic admission artifacts cannot reach the kernel".to_string(),
                ),
            ),
        }
    }
}

fn governed_approval_request_from_native(
    request: &ActiveResponseAdmissionRequest,
) -> PortResult<GovernedApprovalRequest> {
    let response_plan = request.response_plan();
    let ResponseApprovalRequirement::Governed { policy_id } =
        &response_plan.approval_requirement
    else {
        return Err(PortError::integrity_failure());
    };
    let proposal = request
        .threshold_proposal()
        .ok_or_else(PortError::integrity_failure)?;
    let proposal_digest = digest_from_canonical_hex(
        &proposal
            .proposal_hash()
            .map_err(|_| PortError::integrity_failure())?,
    )?;
    let governed_intent_hash = digest_from_canonical_hex(
        &request
            .authorization()
            .governed_intent()
            .binding_hash()
            .map_err(|_| PortError::integrity_failure())?,
    )?;
    let operator_capability_digest = digest_from_canonical_hex(
        &authorization_capability_hash(request.authorization().operator_capability())
            .map_err(|_| PortError::integrity_failure())?,
    )?;
    let proposal_expires_at_unix_ms = proposal
        .body()
        .proposal_deadline()
        .checked_mul(1_000)
        .ok_or_else(PortError::integrity_failure)?;
    let threshold_proposal = request.threshold_proposal().cloned();
    let payload_digest = active_response_admission_artifact_payload_digest(
        &response_plan.authorization_body(),
        request.authorization().operator_capability(),
        request.authorization().governed_intent(),
        request.authorization().submission_proof(),
        &threshold_proposal,
        request.approval_tokens(),
    )
    .map_err(|_| PortError::integrity_failure())?;
    let artifact_digest = canonical_admission_artifact_bundle_digest(
        request.admission_artifact_ref(),
        request.artifact_authority_attestation(),
        &payload_digest,
    )?;
    let admission_artifact = opaque_admission_artifact(
        request.admission_artifact_ref().clone(),
        artifact_digest,
    )
    .map_err(map_approval_coordinator_error)?;
    Ok(GovernedApprovalRequest {
        tenant_id: response_plan.tenant_id.clone(),
        action_id: response_plan.action_id.clone(),
        plan_hash: response_plan.plan_hash,
        policy_hash: response_plan.policy_hash,
        approval_policy_id: policy_id.clone(),
        operator_capability_digest,
        proposal_digest,
        proposal_expires_at_unix_ms,
        governed_intent_hash,
        plan_expires_at_unix_ms: response_plan.expires_at_unix_ms,
        admission_artifact,
    })
}

fn canonical_admission_artifact_bundle_digest(
    artifact_ref: &AdmissionArtifactRef,
    authority_attestation: &ActiveResponseArtifactAuthorityAttestation,
    payload_digest: &Digest32,
) -> PortResult<Digest32> {
    if payload_digest.is_zero() {
        return Err(PortError::integrity_failure());
    }
    let body = CanonicalAttestedFindingAdmissionArtifactBundle {
        schema: ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_SCHEMA,
        artifact_ref,
        authority_attestation,
        payload_digest,
    };
    let canonical = canonical_json_bytes(&body).map_err(|_| PortError::integrity_failure())?;
    Ok(domain_separated_artifact_digest(
        ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_DIGEST_DOMAIN,
        &canonical,
    ))
}

fn digest_from_canonical_hex(value: &str) -> PortResult<Digest32> {
    let parsed = Hash::from_hex(value).map_err(|_| PortError::integrity_failure())?;
    if parsed.to_hex() != value || parsed.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PortError::integrity_failure());
    }
    Ok(Digest32::new(*parsed.as_bytes()))
}

fn domain_separated_artifact_digest(domain: &[u8], canonical: &[u8]) -> Digest32 {
    let mut material = Vec::with_capacity(domain.len().saturating_add(canonical.len()));
    material.extend_from_slice(domain);
    material.extend_from_slice(canonical);
    Digest32::new(*sha256(&material).as_bytes())
}

/// Trusted response plan assembled from one durable reserved identity and one
/// policy selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedAttestedFindingResponsePlan {
    finding: AuthoritativeCorrelatedFindingEvidence,
    batch_id: RecordId,
    ordinal: u32,
    binding: AttestedFindingBatchBinding,
    response_plan: ResponsePlan,
    admission_artifact_ref: AdmissionArtifactRef,
    admission_artifact_digest: Option<Digest32>,
}

impl ReservedAttestedFindingResponsePlan {
    #[must_use]
    pub const fn batch_id(&self) -> &RecordId {
        &self.batch_id
    }

    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub const fn finding(&self) -> &AuthoritativeCorrelatedFindingEvidence {
        &self.finding
    }

    #[must_use]
    pub const fn binding(&self) -> &AttestedFindingBatchBinding {
        &self.binding
    }

    #[must_use]
    pub const fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }

    #[must_use]
    pub const fn reservation_id(&self) -> &RecordId {
        &self.binding.reservation_id
    }

    #[must_use]
    pub const fn admission_artifact_ref(&self) -> &AdmissionArtifactRef {
        &self.admission_artifact_ref
    }

    #[must_use]
    pub const fn admission_artifact_digest(&self) -> Option<&Digest32> {
        self.admission_artifact_digest.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedAttestedFindingResponseBatch {
    batch_id: RecordId,
    plans: Vec<ReservedAttestedFindingResponsePlan>,
}

impl ReservedAttestedFindingResponseBatch {
    #[must_use]
    pub const fn batch_id(&self) -> &RecordId {
        &self.batch_id
    }

    #[must_use]
    pub fn plans(&self) -> &[ReservedAttestedFindingResponsePlan] {
        self.plans.as_slice()
    }
}

/// Downstream response policy and authorization-artifact boundary.
///
/// The policy selects effects, TTL, approval, affected set, and operator
/// authority without authoring action or dispatch identities. It may retrieve
/// signed authorization artifacts for the complete trusted plan, but only the
/// private production coordinator can turn those artifacts into execution.
pub trait AttestedFindingResponsePolicyPlanner: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;

    fn trusted_artifact_authority(&self) -> PortResult<PublicKey> {
        Err(PortError::integrity_failure())
    }

    fn select_response_policy(
        &self,
        _finding: &AuthoritativeCorrelatedFindingEvidence,
        _binding: &AttestedFindingBatchBinding,
    ) -> PortResult<AttestedFindingResponsePolicySelection> {
        Err(PortError::integrity_failure())
    }

    fn load_admission_artifacts(
        &self,
        _plan: &ReservedAttestedFindingResponsePlan,
        _artifact_ref: &AdmissionArtifactRef,
    ) -> PortResult<AttestedFindingAdmissionArtifacts> {
        Err(PortError::integrity_failure())
    }
}

pub(crate) enum PreparedAttestedFindingResponse {
    Kernel(Box<KernelPreparedAttestedFindingResponse>),
    #[cfg(test)]
    Synthetic {
        dispatch_id: RecordId,
    },
}

pub(crate) struct KernelPreparedAttestedFindingResponse {
    request: ActiveResponseAdmissionRequest,
    prepared: PreparedActiveResponseAdmission,
    governed_approval: Option<GovernedApprovalReservation>,
}

impl PreparedAttestedFindingResponse {
    fn kernel_prepared(&self) -> PortResult<&KernelPreparedAttestedFindingResponse> {
        match self {
            Self::Kernel(response) => Ok(response.as_ref()),
            #[cfg(test)]
            Self::Synthetic { .. } => Err(PortError::integrity_failure()),
        }
    }

    #[must_use]
    pub(crate) fn dispatch_id(&self) -> &RecordId {
        match self {
            Self::Kernel(response) => response.prepared.dispatch_id(),
            #[cfg(test)]
            Self::Synthetic { dispatch_id } => dispatch_id,
        }
    }

    fn durable_dispatch_binding(
        &self,
        response_plan: &ResponsePlan,
    ) -> PortResult<PreparedActiveResponseDispatchBinding> {
        let binding = match self {
            Self::Kernel(response) => response
                .prepared
                .durable_dispatch_binding(response_plan)
                .map_err(map_active_response_kernel_error)?,
            #[cfg(test)]
            Self::Synthetic { dispatch_id } => synthetic_prepared_dispatch_binding(
                response_plan,
                dispatch_id.clone(),
            )?,
        };
        binding
            .validate_for_plan(response_plan)
            .map_err(|_| PortError::integrity_failure())?;
        if binding.dispatch_id != *self.dispatch_id() {
            return Err(PortError::integrity_failure());
        }
        match self {
            Self::Kernel(response) => match (
                &response_plan.approval_requirement,
                &response.governed_approval,
            ) {
                (ResponseApprovalRequirement::Automatic, None) => {}
                (
                    ResponseApprovalRequirement::Governed { .. },
                    Some(reservation),
                ) if reservation.prepared_dispatch_binding == binding => {}
                _ => return Err(PortError::integrity_failure()),
            },
            #[cfg(test)]
            Self::Synthetic { .. } => {}
        }
        Ok(binding)
    }

    #[cfg(test)]
    fn synthetic(dispatch_id: RecordId) -> Self {
        Self::Synthetic { dispatch_id }
    }
}

#[cfg(test)]
fn synthetic_prepared_dispatch_binding(
    response_plan: &ResponsePlan,
    dispatch_id: RecordId,
) -> PortResult<PreparedActiveResponseDispatchBinding> {
    let approval = match &response_plan.approval_requirement {
        ResponseApprovalRequirement::Automatic => ResponseDispatchApproval::Automatic,
        ResponseApprovalRequirement::Governed { .. } => ResponseDispatchApproval::Governed {
            admission_operation_id: RecordId::new(format!(
                "synthetic-admission-operation-{}",
                response_plan.action_id.as_str()
            ))
            .map_err(|_| PortError::integrity_failure())?,
            admission_operation_version: 1,
            approval_set_hash: Digest32::new([93_u8; 32]),
        },
    };
    let binding = PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: response_plan.tenant_id.clone(),
        action_id: response_plan.action_id.clone(),
        plan_hash: response_plan.plan_hash,
        dispatch_id,
        executor_authority_id: RecordId::new("synthetic-executor-authority")
            .map_err(|_| PortError::integrity_failure())?,
        executor_authority_generation: 1,
        authorized_at_unix_ms: response_plan.created_at_unix_ms,
        authorization_capability_hash: response_plan.operator_capability.capability_digest,
        governed_intent_hash: Digest32::new([94_u8; 32]),
        policy_decision_hash: Digest32::new([95_u8; 32]),
        approval,
    };
    binding
        .validate_for_plan(response_plan)
        .map_err(|_| PortError::integrity_failure())?;
    Ok(binding)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttestedFindingResponseCompletionProof {
    dispatch_id: RecordId,
    outcome: AttestedFindingResponseCompletionOutcome,
    evidence_id: OpaqueReceiptRef,
    evidence_body_hash: Digest32,
}

impl AttestedFindingResponseCompletionProof {
    #[must_use]
    fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    const fn outcome(&self) -> AttestedFindingResponseCompletionOutcome {
        self.outcome
    }

    #[must_use]
    fn evidence_id(&self) -> &OpaqueReceiptRef {
        &self.evidence_id
    }

    #[must_use]
    const fn evidence_body_hash(&self) -> &Digest32 {
        &self.evidence_body_hash
    }

    #[cfg(test)]
    fn synthetic(
        dispatch_id: RecordId,
        outcome: AttestedFindingResponseCompletionOutcome,
        evidence_id: OpaqueReceiptRef,
        evidence_body_hash: Digest32,
    ) -> Self {
        Self {
            dispatch_id,
            outcome,
            evidence_id,
            evidence_body_hash,
        }
    }
}

pub(crate) enum AttestedFindingDispatchCommittedResume {
    NotDispatchCommitted,
    Completed(AttestedFindingResponseCompletionProof),
}

pub(crate) enum AttestedFindingPreDispatchReconstruction {
    NotPrepared,
    Prepared(Box<PreparedAttestedFindingResponse>),
}

pub(crate) trait AttestedFindingResponseCoordinator: Send + Sync {
    fn ensure_configured(&self) -> PortResult<()> {
        self.ensure_ready()
    }

    fn ensure_ready(&self) -> PortResult<()>;

    /// Recover only an exact durable dispatch already committed by the
    /// executor. `None` is a point-in-time Missing result. An expired prepared
    /// row may enter exact never-committed termination; an unexpired row must
    /// first reconstruct the current live admission request.
    fn recover_committed(
        &self,
        response_plan: &ResponsePlan,
        dispatch_id: &RecordId,
    ) -> PortResult<Option<AttestedFindingResponseCompletionProof>>;

    fn resume_dispatch_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingDispatchCommittedResume>;

    fn reconstruct_pre_dispatch(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingPreDispatchReconstruction>;

    fn terminate_never_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
        current_artifacts: Option<&AttestedFindingAdmissionArtifacts>,
    ) -> PortResult<()>;

    fn prepare_admission(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<PreparedAttestedFindingResponse>;

    fn cancel_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: &PreparedAttestedFindingResponse,
    ) -> PortResult<()>;

    fn execute_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: PreparedAttestedFindingResponse,
    ) -> PortResult<AttestedFindingResponseCompletionProof>;
}

/// One-call adapter from the portable quarantine approval boundary to the
/// kernel's sole governed admission authority.
///
/// The adapter is scoped to one exact portable request and one exact native
/// request. It never keeps a process-global approval map. Crash recovery
/// recreates it from authenticated artifacts plus the durable dispatch
/// binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KernelActiveResponseApprovalVerifierScope {
    Prepare,
    Reconstruct,
    Commit,
    Cancel,
}

struct KernelActiveResponseApprovalVerifier<'a> {
    kernel: &'a ChioKernel,
    expected_request: &'a GovernedApprovalRequest,
    native_request: &'a ActiveResponseAdmissionRequest,
    prepared: Mutex<Option<PreparedActiveResponseAdmission>>,
    scope: KernelActiveResponseApprovalVerifierScope,
}

impl<'a> KernelActiveResponseApprovalVerifier<'a> {
    fn for_prepare(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(None),
            scope: KernelActiveResponseApprovalVerifierScope::Prepare,
        }
    }

    fn for_reconstruction(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(None),
            scope: KernelActiveResponseApprovalVerifierScope::Reconstruct,
        }
    }

    fn for_commit(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
        prepared: PreparedActiveResponseAdmission,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(Some(prepared)),
            scope: KernelActiveResponseApprovalVerifierScope::Commit,
        }
    }

    fn for_cancel(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
        prepared: PreparedActiveResponseAdmission,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(Some(prepared)),
            scope: KernelActiveResponseApprovalVerifierScope::Cancel,
        }
    }

    fn require_exact_request(
        &self,
        request: &GovernedApprovalRequest,
    ) -> PortResult<()> {
        let native_projection = governed_approval_request_from_native(self.native_request)?;
        if request != self.expected_request || request != &native_projection {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn retain_prepared(
        &self,
        prepared: PreparedActiveResponseAdmission,
    ) -> PortResult<()> {
        let mut retained = self
            .prepared
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if retained
            .as_ref()
            .is_some_and(|existing| existing != &prepared)
        {
            return Err(PortError::integrity_failure());
        }
        *retained = Some(prepared);
        Ok(())
    }

    fn retained_prepared(&self) -> PortResult<PreparedActiveResponseAdmission> {
        self.prepared
            .lock()
            .map_err(|_| PortError::unavailable())?
            .clone()
            .ok_or_else(PortError::integrity_failure)
    }

    fn reservation_for(
        &self,
        prepared: &PreparedActiveResponseAdmission,
    ) -> PortResult<GovernedApprovalReservation> {
        if !matches!(prepared, PreparedActiveResponseAdmission::Governed(_)) {
            return Err(PortError::integrity_failure());
        }
        let prepared_dispatch_binding = prepared
            .durable_dispatch_binding(self.native_request.response_plan())
            .map_err(map_active_response_kernel_error)?;
        Ok(GovernedApprovalReservation {
            request: self.expected_request.clone(),
            prepared_dispatch_binding,
            expires_at_unix_ms: self.expected_request.proposal_expires_at_unix_ms,
        })
    }
}

impl ApprovalVerifierPort for KernelActiveResponseApprovalVerifier<'_> {
    fn verify_and_reserve(
        &self,
        request: &GovernedApprovalRequest,
    ) -> PortResult<GovernedApprovalReservation> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Prepare {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(request)?;
        let prepared = self
            .kernel
            .prepare_active_response_admission(self.native_request)
            .map_err(map_active_response_kernel_error)?;
        let reservation = self.reservation_for(&prepared)?;
        self.retain_prepared(prepared)?;
        Ok(reservation)
    }

    fn reconstruct(
        &self,
        request: &GovernedApprovalRequest,
        retained: &GovernedApprovalReservation,
    ) -> PortResult<Option<GovernedApprovalReservation>> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Reconstruct {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(request)?;
        if &retained.request != request {
            return Err(PortError::integrity_failure());
        }
        let prepared = match self
            .kernel
            .reconstruct_pre_dispatch_active_response_admission(
                self.native_request,
                &retained.prepared_dispatch_binding,
            )
            .map_err(map_active_response_kernel_error)?
        {
            PreDispatchActiveResponseReconstruction::NotPrepared => return Ok(None),
            PreDispatchActiveResponseReconstruction::Prepared(prepared) => prepared,
        };
        let reconstructed = self.reservation_for(&prepared)?;
        if &reconstructed != retained {
            return Err(PortError::integrity_failure());
        }
        self.retain_prepared(prepared)?;
        Ok(Some(reconstructed))
    }

    fn commit(&self, mutation: &GovernedApprovalReservationMutation) -> PortResult<()> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Commit {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(&mutation.reservation.request)?;
        let prepared = self.retained_prepared()?;
        if self.reservation_for(&prepared)? != mutation.reservation {
            return Err(PortError::integrity_failure());
        }
        self.kernel
            .commit_prepared_active_response_admission(self.native_request, &prepared)
            .map_err(map_active_response_kernel_error)
    }

    fn cancel(&self, mutation: &GovernedApprovalReservationMutation) -> PortResult<()> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Cancel {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(&mutation.reservation.request)?;
        let prepared = self.retained_prepared()?;
        if self.reservation_for(&prepared)? != mutation.reservation {
            return Err(PortError::integrity_failure());
        }
        self.kernel
            .cancel_prepared_active_response_admission(
                &prepared,
                "durable response preparation was not published",
            )
            .map_err(map_active_response_kernel_error)
    }
}

/// Production-only bridge from correlation planning to the verified kernel
/// active-response admission and execution coordinator.
pub(crate) struct KernelAttestedFindingResponseCoordinator {
    kernel: Mutex<Option<Arc<ChioKernel>>>,
    executor_authority: ActiveResponseExecutorAuthorityIdentity,
    clock: Arc<dyn SecurityClock>,
}

impl KernelAttestedFindingResponseCoordinator {
    #[must_use]
    pub(crate) fn new_unbound(
        executor_authority: ActiveResponseExecutorAuthorityIdentity,
        clock: Arc<dyn SecurityClock>,
    ) -> Self {
        Self {
            kernel: Mutex::new(None),
            executor_authority,
            clock,
        }
    }

    pub(crate) fn bind_kernel(&self, kernel: Arc<ChioKernel>) -> PortResult<()> {
        self.validate_kernel(kernel.as_ref())?;
        let mut installed = self.kernel.lock().map_err(|_| PortError::unavailable())?;
        match installed.as_ref() {
            Some(retained) if Arc::ptr_eq(retained, &kernel) => Ok(()),
            Some(_) => Err(PortError::conflict()),
            None => {
                *installed = Some(kernel);
                Ok(())
            }
        }
    }

    #[must_use]
    pub(crate) fn expects_authority(
        &self,
        executor_authority: &ActiveResponseExecutorAuthorityIdentity,
    ) -> bool {
        &self.executor_authority == executor_authority
    }

    fn bound_kernel(&self) -> PortResult<Arc<ChioKernel>> {
        self.kernel
            .lock()
            .map_err(|_| PortError::unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(PortError::unavailable)
    }

    #[cfg(test)]
    pub(crate) fn retains_kernel(&self, kernel: &Arc<ChioKernel>) -> PortResult<bool> {
        self.bound_kernel()
            .map(|retained| Arc::ptr_eq(&retained, kernel))
    }

    fn validate_kernel(&self, kernel: &ChioKernel) -> PortResult<()> {
        let status = kernel.governed_security_runtime_status();
        if status.publication_generation == 0
            || !status.active_response_enabled
            || !status.threshold_approval_enabled
            || !status.capability_issuance_admission_enabled
            || status.executor_authority.as_ref() != Some(&self.executor_authority)
            || status.admission_operation_store_profile.is_none()
            || status.approval_store_profile.is_none()
        {
            return Err(PortError::unavailable());
        }
        Ok(())
    }
}

impl AttestedFindingResponseCoordinator for KernelAttestedFindingResponseCoordinator {
    fn ensure_configured(&self) -> PortResult<()> {
        if self.executor_authority.generation() == 0 {
            return Err(PortError::invalid_data());
        }
        self.clock.now_unix_ms()?;
        Ok(())
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.clock.now_unix_ms()?;
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())
    }

    fn recover_committed(
        &self,
        response_plan: &ResponsePlan,
        dispatch_id: &RecordId,
    ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
        let kernel = self.bound_kernel()?;
        kernel
            .recover_committed_active_response(response_plan, dispatch_id)
            .map_err(map_active_response_kernel_error)?
            .map(|evidence| {
                validated_active_response_completion_proof(
                    response_plan,
                    dispatch_id,
                    evidence,
                )
            })
            .transpose()
    }

    fn resume_dispatch_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingDispatchCommittedResume> {
        let kernel = self.bound_kernel()?;
        match kernel
            .resume_dispatch_committed_active_response(response_plan, binding)
            .map_err(map_active_response_kernel_error)?
        {
            DispatchCommittedActiveResponseResume::NotDispatchCommitted => {
                Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted)
            }
            DispatchCommittedActiveResponseResume::Completed(evidence) => {
                validated_active_response_completion_proof(
                    response_plan,
                    &binding.dispatch_id,
                    *evidence,
                )
                .map(AttestedFindingDispatchCommittedResume::Completed)
            }
        }
    }

    fn reconstruct_pre_dispatch(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let expected_artifact_digest = plan
            .admission_artifact_digest()
            .ok_or_else(PortError::integrity_failure)?;
        if &artifacts.canonical_digest(plan.response_plan())? != expected_artifact_digest {
            return Err(PortError::integrity_failure());
        }
        let request = artifacts
            .into_admission_request(plan.response_plan().clone())
            .map_err(map_active_response_kernel_error)?;
        let governed_request = match &request.response_plan().approval_requirement {
            ResponseApprovalRequirement::Automatic => None,
            ResponseApprovalRequirement::Governed { .. } => {
                Some(governed_approval_request_from_native(&request)?)
            }
        };
        let (prepared, governed_approval) = match governed_request {
            None => match kernel
                .reconstruct_pre_dispatch_active_response_admission(&request, binding)
                .map_err(map_active_response_kernel_error)?
            {
                PreDispatchActiveResponseReconstruction::NotPrepared => {
                    return Ok(AttestedFindingPreDispatchReconstruction::NotPrepared);
                }
                PreDispatchActiveResponseReconstruction::Prepared(prepared) => {
                    (prepared, None)
                }
            },
            Some(governed_request) => {
                let retained = GovernedApprovalReservation {
                    request: governed_request.clone(),
                    prepared_dispatch_binding: binding.clone(),
                    expires_at_unix_ms: governed_request.proposal_expires_at_unix_ms,
                };
                let verifier = KernelActiveResponseApprovalVerifier::for_reconstruction(
                    kernel.as_ref(),
                    &governed_request,
                    &request,
                );
                let coordinator = ResponseApprovalCoordinator::new(verifier);
                let reconstructed = coordinator
                    .reconstruct(
                        plan.response_plan(),
                        &governed_request,
                        &retained,
                        self.clock.now_unix_ms()?,
                    )
                    .map_err(map_approval_coordinator_error)?;
                let Some(reconstructed) = reconstructed else {
                    return Ok(AttestedFindingPreDispatchReconstruction::NotPrepared);
                };
                let prepared = coordinator.verifier().retained_prepared()?;
                (prepared, Some(reconstructed))
            }
        };
        Ok(AttestedFindingPreDispatchReconstruction::Prepared(
            Box::new(PreparedAttestedFindingResponse::Kernel(Box::new(
                KernelPreparedAttestedFindingResponse {
                    request,
                    prepared,
                    governed_approval,
                },
            ))),
        ))
    }

    fn terminate_never_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
        current_artifacts: Option<&AttestedFindingAdmissionArtifacts>,
    ) -> PortResult<()> {
        let kernel = self.bound_kernel()?;
        let current_request = current_artifacts
            .cloned()
            .map(|artifacts| artifacts.into_admission_request(response_plan.clone()))
            .transpose()
            .map_err(map_active_response_kernel_error)?;
        kernel
            .terminate_never_committed_active_response(
                response_plan,
                binding,
                current_request.as_ref(),
            )
            .map_err(map_active_response_kernel_error)
    }

    fn prepare_admission(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<PreparedAttestedFindingResponse> {
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let expected_artifact_digest = plan
            .admission_artifact_digest()
            .ok_or_else(PortError::integrity_failure)?;
        if &artifacts.canonical_digest(plan.response_plan())? != expected_artifact_digest {
            return Err(PortError::integrity_failure());
        }
        let request = artifacts
            .into_admission_request(plan.response_plan().clone())
            .map_err(map_active_response_kernel_error)?;
        let governed_request = match &request.response_plan().approval_requirement {
            ResponseApprovalRequirement::Automatic => None,
            ResponseApprovalRequirement::Governed { .. } => {
                Some(governed_approval_request_from_native(&request)?)
            }
        };
        let (prepared, governed_approval) = match governed_request {
            None => (
                kernel
                    .prepare_active_response_admission(&request)
                    .map_err(map_active_response_kernel_error)?,
                None,
            ),
            Some(governed_request) => {
                let verifier = KernelActiveResponseApprovalVerifier::for_prepare(
                    kernel.as_ref(),
                    &governed_request,
                    &request,
                );
                let coordinator = ResponseApprovalCoordinator::new(verifier);
                let reservation = coordinator
                    .prepare(
                        plan.response_plan(),
                        &governed_request,
                        self.clock.now_unix_ms()?,
                    )
                    .map_err(map_approval_coordinator_error)?;
                let prepared = coordinator.verifier().retained_prepared()?;
                (prepared, Some(reservation))
            }
        };
        Ok(PreparedAttestedFindingResponse::Kernel(Box::new(
            KernelPreparedAttestedFindingResponse {
                request,
                prepared,
                governed_approval,
            },
        )))
    }

    fn cancel_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: &PreparedAttestedFindingResponse,
    ) -> PortResult<()> {
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let prepared = prepared.kernel_prepared()?;
        match (
            &plan.response_plan().approval_requirement,
            &prepared.governed_approval,
        ) {
            (ResponseApprovalRequirement::Automatic, None) => {
                if !matches!(
                    &prepared.prepared,
                    PreparedActiveResponseAdmission::Automatic(_)
                ) {
                    return Err(PortError::integrity_failure());
                }
                Ok(())
            }
            (ResponseApprovalRequirement::Governed { .. }, Some(reservation)) => {
                let governed_request = governed_approval_request_from_native(&prepared.request)?;
                if governed_request != reservation.request {
                    return Err(PortError::integrity_failure());
                }
                let verifier = KernelActiveResponseApprovalVerifier::for_cancel(
                    kernel.as_ref(),
                    &governed_request,
                    &prepared.request,
                    prepared.prepared.clone(),
                );
                ResponseApprovalCoordinator::new(verifier)
                    .cancel(plan.response_plan(), reservation)
                    .map_err(map_approval_coordinator_error)
            }
            _ => Err(PortError::integrity_failure()),
        }
    }

    fn execute_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: PreparedAttestedFindingResponse,
    ) -> PortResult<AttestedFindingResponseCompletionProof> {
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let expected_dispatch_id = prepared.dispatch_id().clone();
        let (request, prepared, governed_approval) = match prepared {
            PreparedAttestedFindingResponse::Kernel(response) => {
                let KernelPreparedAttestedFindingResponse {
                    request,
                    prepared,
                    governed_approval,
                } = *response;
                (request, prepared, governed_approval)
            }
            #[cfg(test)]
            PreparedAttestedFindingResponse::Synthetic { .. } => {
                return Err(PortError::integrity_failure());
            }
        };
        match (&plan.response_plan().approval_requirement, governed_approval) {
            (ResponseApprovalRequirement::Automatic, None) => {}
            (ResponseApprovalRequirement::Governed { .. }, Some(reservation)) => {
                let native_binding = prepared
                    .durable_dispatch_binding(plan.response_plan())
                    .map_err(map_active_response_kernel_error)?;
                if native_binding != reservation.prepared_dispatch_binding {
                    return Err(PortError::integrity_failure());
                }
                let verifier = KernelActiveResponseApprovalVerifier::for_commit(
                    kernel.as_ref(),
                    &reservation.request,
                    &request,
                    prepared.clone(),
                );
                let coordinator = ResponseApprovalCoordinator::new(verifier);
                let committed_binding = coordinator
                    .commit(
                        plan.response_plan(),
                        &reservation,
                        self.clock.now_unix_ms()?,
                    )
                    .map_err(map_approval_coordinator_error)?;
                if committed_binding != native_binding {
                    return Err(PortError::integrity_failure());
                }
            }
            _ => return Err(PortError::integrity_failure()),
        }
        let evidence = kernel
            .execute_prepared_active_response(&request, &prepared)
            .map_err(map_active_response_kernel_error)?;
        validated_active_response_completion_proof(
            plan.response_plan(),
            &expected_dispatch_id,
            evidence,
        )
    }
}

fn validated_active_response_completion_proof(
    response_plan: &ResponsePlan,
    expected_dispatch_id: &RecordId,
    evidence: ActiveResponseExecutionEvidence,
) -> PortResult<AttestedFindingResponseCompletionProof> {
    if evidence.dispatch_id() != expected_dispatch_id
        || evidence.tenant_id() != &response_plan.tenant_id
        || evidence.action_id() != &response_plan.action_id
        || evidence.plan_hash() != &response_plan.plan_hash
    {
        return Err(PortError::integrity_failure());
    }
    match evidence.outcome() {
        ActiveResponseExecutionOutcome::Activated => {
            if evidence.effects().len() != response_plan.effects.len()
                || response_plan
                    .effects
                    .as_slice()
                    .iter()
                    .zip(evidence.effects())
                    .any(|(planned, applied)| &planned.effect_id != applied.effect_id())
            {
                return Err(PortError::integrity_failure());
            }
        }
        ActiveResponseExecutionOutcome::FailedBeforeAnyEffect => {
            if !evidence.effects().is_empty() {
                return Err(PortError::integrity_failure());
            }
        }
        ActiveResponseExecutionOutcome::RolledBackAfterPartial => {}
    }
    Ok(AttestedFindingResponseCompletionProof {
        dispatch_id: evidence.dispatch_id().clone(),
        outcome: match evidence.outcome() {
            ActiveResponseExecutionOutcome::Activated => {
                AttestedFindingResponseCompletionOutcome::Activated
            }
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect => {
                AttestedFindingResponseCompletionOutcome::FailedBeforeEffect
            }
            ActiveResponseExecutionOutcome::RolledBackAfterPartial => {
                AttestedFindingResponseCompletionOutcome::RolledBackAfterPartial
            }
        },
        evidence_id: evidence.proof_evidence_id().clone(),
        evidence_body_hash: *evidence.proof_body_hash(),
    })
}

fn map_approval_coordinator_error(error: ApprovalCoordinatorError) -> PortError {
    match error {
        ApprovalCoordinatorError::Authority(error) => error,
        ApprovalCoordinatorError::Expired | ApprovalCoordinatorError::InvalidPlan => {
            PortError::invalid_data()
        }
        ApprovalCoordinatorError::AutomaticPlan
        | ApprovalCoordinatorError::InvalidRequest
        | ApprovalCoordinatorError::InvalidAdmissionArtifact
        | ApprovalCoordinatorError::InvalidReservation
        | ApprovalCoordinatorError::Canonical => PortError::integrity_failure(),
    }
}

fn map_active_response_kernel_error(error: KernelError) -> PortError {
    let definitively_never_committed =
        matches!(&error, KernelError::ActiveResponseNeverCommitted(_));
    let retryable = matches!(
        &error,
        KernelError::Internal(_)
            | KernelError::ReceiptPersistence(_)
            | KernelError::RevocationStore(_)
            | KernelError::Overloaded { .. }
            | KernelError::SecurityDispatchOutcomeRecoveryRequired(_)
    );
    let code = match ErrorCode::new(error.report().code) {
        Ok(code) => code,
        Err(_) => return PortError::integrity_failure(),
    };
    if definitively_never_committed && code.as_str() != "active_response.never_committed" {
        return PortError::integrity_failure();
    }
    PortError::new(
        if retryable {
            PortErrorKind::Unavailable
        } else {
            PortErrorKind::InvalidData
        },
        code,
    )
}
