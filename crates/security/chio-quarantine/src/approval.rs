use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{
    AdmissionArtifactRef, ApprovalVerifierPort, CanonicalBody, Digest32, GovernedApprovalRequest,
    GovernedApprovalReservation, GovernedApprovalReservationMutation,
    OpaqueApprovalAdmissionArtifact, OpaqueApprovalAdmissionArtifactBody, PortError,
    PreparedActiveResponseDispatchBinding, ResponseDispatchApproval,
    OPAQUE_APPROVAL_ADMISSION_ARTIFACT_SCHEMA_VERSION,
};
use chio_security_types::{ResponseApprovalRequirement, ResponsePlan};
use thiserror::Error;

const OPAQUE_APPROVAL_ADMISSION_ARTIFACT_DIGEST_DOMAIN: &[u8] =
    b"chio.security.opaque-approval-admission-artifact.v1\0";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApprovalCoordinatorError {
    #[error("automatic response plans cannot traverse governed approval")]
    AutomaticPlan,
    #[error("response plan is structurally invalid")]
    InvalidPlan,
    #[error("governed approval request does not match the response plan")]
    InvalidRequest,
    #[error("opaque admission artifact is malformed or rebound")]
    InvalidAdmissionArtifact,
    #[error("governed approval reservation is malformed or rebound")]
    InvalidReservation,
    #[error("response approval is not live")]
    Expired,
    #[error("trusted approval authority failed closed: {0}")]
    Authority(PortError),
    #[error("canonical approval descriptor construction failed")]
    Canonical,
}

/// Build the only portable representation of native active-response admission
/// material.
///
/// The descriptor deliberately contains only the authenticated artifact
/// reference and digest. The trusted composition adapter reloads the complete
/// native artifact bundle by that reference, verifies its cryptographic digest,
/// and compares the complete governed request with its scoped expected request.
/// Quarantine never parses capability, intent, proof, proposal, or token bytes.
pub fn opaque_admission_artifact(
    artifact_ref: AdmissionArtifactRef,
    artifact_digest: Digest32,
) -> Result<OpaqueApprovalAdmissionArtifact, ApprovalCoordinatorError> {
    if artifact_digest.is_zero() {
        return Err(ApprovalCoordinatorError::InvalidAdmissionArtifact);
    }
    let body = OpaqueApprovalAdmissionArtifactBody {
        schema_version: OPAQUE_APPROVAL_ADMISSION_ARTIFACT_SCHEMA_VERSION,
        artifact_ref,
        artifact_digest,
    };
    let canonical = canonical_json_bytes(&body).map_err(|_| ApprovalCoordinatorError::Canonical)?;
    let canonical_digest = domain_digest(&canonical);
    let canonical_body =
        CanonicalBody::new(canonical).map_err(|_| ApprovalCoordinatorError::Canonical)?;
    Ok(OpaqueApprovalAdmissionArtifact {
        body,
        canonical_body,
        canonical_digest,
    })
}

/// Structural active-defense facade over the trusted governed-approval port.
///
/// This coordinator does not verify signatures, count approvers, reserve
/// replay state, or persist an admission operation. Those authorities stay in
/// the port implementation. Its only job is to prevent plan, descriptor, and
/// prepared-binding substitution at the dependency boundary.
pub struct ResponseApprovalCoordinator<V> {
    verifier: V,
}

impl<V> ResponseApprovalCoordinator<V> {
    #[must_use]
    pub const fn new(verifier: V) -> Self {
        Self { verifier }
    }

    #[must_use]
    pub const fn verifier(&self) -> &V {
        &self.verifier
    }

    #[must_use]
    pub fn into_verifier(self) -> V {
        self.verifier
    }
}

impl<V: ApprovalVerifierPort> ResponseApprovalCoordinator<V> {
    pub fn prepare(
        &self,
        plan: &ResponsePlan,
        request: &GovernedApprovalRequest,
        now_unix_ms: u64,
    ) -> Result<GovernedApprovalReservation, ApprovalCoordinatorError> {
        validate_plan_request(plan, request, Some(now_unix_ms))?;
        let reservation = self
            .verifier
            .verify_and_reserve(request)
            .map_err(ApprovalCoordinatorError::Authority)?;
        validate_reservation(plan, request, &reservation, Some(now_unix_ms))?;
        Ok(reservation)
    }

    /// Reconstruct one exact pre-dispatch preparation after a crash.
    ///
    /// A returned preparation must be byte-for-byte equal to the retained
    /// portable reservation. Rebinding any request, artifact, digest, expiry,
    /// dispatch identity, or admission-operation version fails closed.
    pub fn reconstruct(
        &self,
        plan: &ResponsePlan,
        request: &GovernedApprovalRequest,
        retained: &GovernedApprovalReservation,
        now_unix_ms: u64,
    ) -> Result<Option<GovernedApprovalReservation>, ApprovalCoordinatorError> {
        validate_plan_request(plan, request, Some(now_unix_ms))?;
        validate_reservation(plan, request, retained, Some(now_unix_ms))?;
        let reconstructed = self
            .verifier
            .reconstruct(request, retained)
            .map_err(ApprovalCoordinatorError::Authority)?;
        let Some(reconstructed) = reconstructed else {
            return Ok(None);
        };
        validate_reservation(plan, request, &reconstructed, Some(now_unix_ms))?;
        if reconstructed != *retained {
            return Err(ApprovalCoordinatorError::InvalidReservation);
        }
        Ok(Some(reconstructed))
    }

    /// Commit the already-reserved governed admission before response effects.
    ///
    /// Automatic plans are rejected before the port is invoked. The returned
    /// binding is the exact retained binding and carries no new authority.
    pub fn commit(
        &self,
        plan: &ResponsePlan,
        reservation: &GovernedApprovalReservation,
        now_unix_ms: u64,
    ) -> Result<PreparedActiveResponseDispatchBinding, ApprovalCoordinatorError> {
        validate_reservation(plan, &reservation.request, reservation, Some(now_unix_ms))?;
        self.verifier
            .commit(&GovernedApprovalReservationMutation {
                reservation: reservation.clone(),
            })
            .map_err(ApprovalCoordinatorError::Authority)?;
        Ok(reservation.prepared_dispatch_binding.clone())
    }

    /// Cancel one exact pre-dispatch governed reservation.
    ///
    /// Cancellation remains available after expiry so the trusted authority
    /// can retain replay tombstones and compensate a never-committed operation.
    pub fn cancel(
        &self,
        plan: &ResponsePlan,
        reservation: &GovernedApprovalReservation,
    ) -> Result<(), ApprovalCoordinatorError> {
        validate_reservation(plan, &reservation.request, reservation, None)?;
        self.verifier
            .cancel(&GovernedApprovalReservationMutation {
                reservation: reservation.clone(),
            })
            .map_err(ApprovalCoordinatorError::Authority)
    }
}

fn validate_plan_request(
    plan: &ResponsePlan,
    request: &GovernedApprovalRequest,
    now_unix_ms: Option<u64>,
) -> Result<(), ApprovalCoordinatorError> {
    let policy_id = match &plan.approval_requirement {
        ResponseApprovalRequirement::Automatic => {
            return Err(ApprovalCoordinatorError::AutomaticPlan);
        }
        ResponseApprovalRequirement::Governed { policy_id } => policy_id,
    };
    if plan.validate_shape().is_err()
        || id_is_zero(plan.tenant_id.as_str())
        || id_is_zero(plan.action_id.as_str())
        || id_is_zero(policy_id.as_str())
        || id_is_zero(plan.operator_capability.capability_id.as_str())
        || id_is_zero(plan.operator_capability.executor_subject.as_str())
    {
        return Err(ApprovalCoordinatorError::InvalidPlan);
    }
    if request.tenant_id != plan.tenant_id
        || request.action_id != plan.action_id
        || request.plan_hash != plan.plan_hash
        || request.policy_hash != plan.policy_hash
        || request.approval_policy_id != *policy_id
        || request.operator_capability_digest != plan.operator_capability.capability_digest
        || request.plan_expires_at_unix_ms != plan.expires_at_unix_ms
        || request.plan_hash.is_zero()
        || request.policy_hash.is_zero()
        || request.operator_capability_digest.is_zero()
        || request.proposal_digest.is_zero()
        || request.proposal_expires_at_unix_ms <= plan.created_at_unix_ms
        || request.proposal_expires_at_unix_ms > plan.expires_at_unix_ms
        || request.proposal_expires_at_unix_ms > plan.operator_capability.expires_at_unix_ms
        || request.governed_intent_hash.is_zero()
    {
        return Err(ApprovalCoordinatorError::InvalidRequest);
    }
    validate_admission_artifact(&request.admission_artifact)?;
    if let Some(now_unix_ms) = now_unix_ms {
        if now_unix_ms < plan.created_at_unix_ms
            || now_unix_ms >= request.proposal_expires_at_unix_ms
        {
            return Err(ApprovalCoordinatorError::Expired);
        }
    }
    Ok(())
}

fn validate_admission_artifact(
    artifact: &OpaqueApprovalAdmissionArtifact,
) -> Result<(), ApprovalCoordinatorError> {
    if artifact.body.schema_version != OPAQUE_APPROVAL_ADMISSION_ARTIFACT_SCHEMA_VERSION
        || artifact.body.artifact_digest.is_zero()
        || artifact.canonical_digest.is_zero()
    {
        return Err(ApprovalCoordinatorError::InvalidAdmissionArtifact);
    }
    let canonical = canonical_json_bytes(&artifact.body)
        .map_err(|_| ApprovalCoordinatorError::InvalidAdmissionArtifact)?;
    if artifact.canonical_body.as_bytes() != canonical.as_slice()
        || artifact.canonical_digest != domain_digest(&canonical)
    {
        return Err(ApprovalCoordinatorError::InvalidAdmissionArtifact);
    }
    Ok(())
}

fn validate_reservation(
    plan: &ResponsePlan,
    request: &GovernedApprovalRequest,
    reservation: &GovernedApprovalReservation,
    now_unix_ms: Option<u64>,
) -> Result<(), ApprovalCoordinatorError> {
    validate_plan_request(plan, request, now_unix_ms)?;
    if reservation.request != *request
        || reservation.expires_at_unix_ms != request.proposal_expires_at_unix_ms
        || reservation
            .prepared_dispatch_binding
            .validate_for_plan(plan)
            .is_err()
        || reservation
            .prepared_dispatch_binding
            .authorization_capability_hash
            != request.operator_capability_digest
        || reservation.prepared_dispatch_binding.governed_intent_hash
            != request.governed_intent_hash
        || reservation.prepared_dispatch_binding.authorized_at_unix_ms
            >= request.proposal_expires_at_unix_ms
        || !matches!(
            &reservation.prepared_dispatch_binding.approval,
            ResponseDispatchApproval::Governed { .. }
        )
    {
        return Err(ApprovalCoordinatorError::InvalidReservation);
    }
    Ok(())
}

fn id_is_zero(value: &str) -> bool {
    value.bytes().all(|byte| byte == b'0')
}

fn domain_digest(canonical: &[u8]) -> Digest32 {
    let mut material = Vec::with_capacity(
        OPAQUE_APPROVAL_ADMISSION_ARTIFACT_DIGEST_DOMAIN.len() + canonical.len(),
    );
    material.extend_from_slice(OPAQUE_APPROVAL_ADMISSION_ARTIFACT_DIGEST_DOMAIN);
    material.extend_from_slice(canonical);
    Digest32::new(*sha256(&material).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_security_types::ports::{
        ActionId, EffectId, OpaqueReceiptRef, PortErrorKind, RecordId, RecordIdSet,
        ResponseDispatchApproval, SessionId, TenantId,
        PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
    };
    use chio_security_types::{
        OperatorCapabilityBinding, PlannedResponseEffect, PlannedResponseEffects,
        ResponseEffectKind, ResponseTarget,
    };
    use std::sync::{Mutex, MutexGuard};

    const CREATED_AT: u64 = 1_000;
    const EXPIRES_AT: u64 = 2_000;
    const LIVE_NOW: u64 = 1_500;

    macro_rules! required {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => panic!("required test value failed: {error}"),
            }
        };
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct InvocationCounts {
        reserve: u32,
        reconstruct: u32,
        commit: u32,
        cancel: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReserveBehavior {
        Valid,
        WrongBinding,
        ZeroDigest,
        WrongRequest,
        WrongExpiry,
        AuthorizationAfterProposal,
        Error(PortErrorKind),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReconstructBehavior {
        Exact,
        Missing,
        WrongBinding,
        Error(PortErrorKind),
    }

    #[derive(Debug)]
    struct FakeState {
        counts: InvocationCounts,
        reserve: ReserveBehavior,
        reconstruct: ReconstructBehavior,
        commit_error: Option<PortErrorKind>,
        cancel_error: Option<PortErrorKind>,
    }

    struct FakeVerifier {
        state: Mutex<FakeState>,
    }

    impl FakeVerifier {
        fn valid() -> Self {
            Self {
                state: Mutex::new(FakeState {
                    counts: InvocationCounts::default(),
                    reserve: ReserveBehavior::Valid,
                    reconstruct: ReconstructBehavior::Exact,
                    commit_error: None,
                    cancel_error: None,
                }),
            }
        }

        fn state(&self) -> MutexGuard<'_, FakeState> {
            match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            }
        }

        fn counts(&self) -> InvocationCounts {
            self.state().counts
        }

        fn set_reserve(&self, behavior: ReserveBehavior) {
            self.state().reserve = behavior;
        }

        fn set_reconstruct(&self, behavior: ReconstructBehavior) {
            self.state().reconstruct = behavior;
        }

        fn set_commit_error(&self, kind: Option<PortErrorKind>) {
            self.state().commit_error = kind;
        }

        fn set_cancel_error(&self, kind: Option<PortErrorKind>) {
            self.state().cancel_error = kind;
        }
    }

    impl ApprovalVerifierPort for FakeVerifier {
        fn verify_and_reserve(
            &self,
            request: &GovernedApprovalRequest,
        ) -> Result<GovernedApprovalReservation, PortError> {
            let behavior = {
                let mut state = self.state();
                state.counts.reserve += 1;
                state.reserve
            };
            if let ReserveBehavior::Error(kind) = behavior {
                return Err(port_error(kind));
            }
            let mut reservation = reservation(request);
            match behavior {
                ReserveBehavior::Valid => {}
                ReserveBehavior::WrongBinding => {
                    reservation.prepared_dispatch_binding.plan_hash = digest(99);
                }
                ReserveBehavior::ZeroDigest => {
                    reservation.prepared_dispatch_binding.governed_intent_hash =
                        Digest32::new([0; 32]);
                }
                ReserveBehavior::WrongRequest => {
                    reservation.request.proposal_digest = digest(98);
                }
                ReserveBehavior::WrongExpiry => {
                    reservation.expires_at_unix_ms -= 1;
                }
                ReserveBehavior::AuthorizationAfterProposal => {
                    reservation.prepared_dispatch_binding.authorized_at_unix_ms =
                        request.proposal_expires_at_unix_ms;
                }
                ReserveBehavior::Error(_) => {}
            }
            Ok(reservation)
        }

        fn reconstruct(
            &self,
            _request: &GovernedApprovalRequest,
            retained: &GovernedApprovalReservation,
        ) -> Result<Option<GovernedApprovalReservation>, PortError> {
            let behavior = {
                let mut state = self.state();
                state.counts.reconstruct += 1;
                state.reconstruct
            };
            match behavior {
                ReconstructBehavior::Exact => Ok(Some(retained.clone())),
                ReconstructBehavior::Missing => Ok(None),
                ReconstructBehavior::WrongBinding => {
                    let mut rebound = retained.clone();
                    rebound.prepared_dispatch_binding.policy_decision_hash = digest(97);
                    Ok(Some(rebound))
                }
                ReconstructBehavior::Error(kind) => Err(port_error(kind)),
            }
        }

        fn commit(&self, _mutation: &GovernedApprovalReservationMutation) -> Result<(), PortError> {
            let error = {
                let mut state = self.state();
                state.counts.commit += 1;
                state.commit_error
            };
            error.map_or(Ok(()), |kind| Err(port_error(kind)))
        }

        fn cancel(&self, _mutation: &GovernedApprovalReservationMutation) -> Result<(), PortError> {
            let error = {
                let mut state = self.state();
                state.counts.cancel += 1;
                state.cancel_error
            };
            error.map_or(Ok(()), |kind| Err(port_error(kind)))
        }
    }

    #[test]
    fn opaque_artifact_is_fixed_canonical_and_tamper_evident() {
        let artifact = artifact();
        assert_eq!(
            artifact.body.schema_version,
            OPAQUE_APPROVAL_ADMISSION_ARTIFACT_SCHEMA_VERSION
        );
        assert_eq!(
            artifact.canonical_body.as_bytes(),
            required!(canonical_json_bytes(&artifact.body)).as_slice()
        );
        assert_eq!(
            artifact.canonical_digest,
            domain_digest(artifact.canonical_body.as_bytes())
        );

        let plan = governed_plan();
        let mut request = governed_request(&plan);
        request.admission_artifact.canonical_body = required!(CanonicalBody::new(vec![1, 2, 3]));
        let coordinator = ResponseApprovalCoordinator::new(FakeVerifier::valid());
        assert_eq!(
            coordinator.prepare(&plan, &request, LIVE_NOW),
            Err(ApprovalCoordinatorError::InvalidAdmissionArtifact)
        );
        assert_eq!(coordinator.verifier().counts().reserve, 0);
    }

    #[test]
    fn governed_prepare_returns_only_an_exact_live_kernel_binding() {
        let plan = governed_plan();
        let request = governed_request(&plan);
        let coordinator = ResponseApprovalCoordinator::new(FakeVerifier::valid());
        let prepared = required!(coordinator.prepare(&plan, &request, LIVE_NOW));
        assert_eq!(prepared, reservation(&request));
        assert_eq!(coordinator.verifier().counts().reserve, 1);
    }

    #[test]
    fn every_authority_failure_class_fails_closed() {
        for kind in [
            PortErrorKind::Unavailable,
            PortErrorKind::Conflict,
            PortErrorKind::InvalidData,
            PortErrorKind::IntegrityFailure,
        ] {
            let plan = governed_plan();
            let request = governed_request(&plan);
            let coordinator = ResponseApprovalCoordinator::new(FakeVerifier::valid());
            coordinator
                .verifier()
                .set_reserve(ReserveBehavior::Error(kind));
            assert_eq!(
                coordinator.prepare(&plan, &request, LIVE_NOW),
                Err(ApprovalCoordinatorError::Authority(port_error(kind)))
            );
            assert_eq!(coordinator.verifier().counts().reserve, 1);
        }
    }

    #[test]
    fn malformed_reservations_wrong_bindings_and_zero_digests_fail_closed() {
        for behavior in [
            ReserveBehavior::WrongBinding,
            ReserveBehavior::ZeroDigest,
            ReserveBehavior::WrongRequest,
            ReserveBehavior::WrongExpiry,
            ReserveBehavior::AuthorizationAfterProposal,
        ] {
            let plan = governed_plan();
            let request = governed_request(&plan);
            let coordinator = ResponseApprovalCoordinator::new(FakeVerifier::valid());
            coordinator.verifier().set_reserve(behavior);
            assert_eq!(
                coordinator.prepare(&plan, &request, LIVE_NOW),
                Err(ApprovalCoordinatorError::InvalidReservation)
            );
        }
    }

    #[test]
    fn reconstruction_is_exact_missing_aware_and_never_rebinds() {
        let plan = governed_plan();
        let request = governed_request(&plan);
        let retained = reservation(&request);
        let coordinator = ResponseApprovalCoordinator::new(FakeVerifier::valid());

        assert_eq!(
            required!(coordinator.reconstruct(&plan, &request, &retained, LIVE_NOW)),
            Some(retained.clone())
        );
        coordinator
            .verifier()
            .set_reconstruct(ReconstructBehavior::Missing);
        assert_eq!(
            required!(coordinator.reconstruct(&plan, &request, &retained, LIVE_NOW)),
            None
        );
        coordinator
            .verifier()
            .set_reconstruct(ReconstructBehavior::WrongBinding);
        assert_eq!(
            coordinator.reconstruct(&plan, &request, &retained, LIVE_NOW),
            Err(ApprovalCoordinatorError::InvalidReservation)
        );
        coordinator
            .verifier()
            .set_reconstruct(ReconstructBehavior::Error(PortErrorKind::Unavailable));
        assert_eq!(
            coordinator.reconstruct(&plan, &request, &retained, LIVE_NOW),
            Err(ApprovalCoordinatorError::Authority(port_error(
                PortErrorKind::Unavailable
            )))
        );
        assert_eq!(coordinator.verifier().counts().reconstruct, 4);
    }

    #[test]
    fn commit_and_cancel_delegate_exactly_once_and_preserve_tombstones() {
        let plan = governed_plan();
        let request = governed_request(&plan);
        let retained = reservation(&request);
        let coordinator = ResponseApprovalCoordinator::new(FakeVerifier::valid());

        let binding = required!(coordinator.commit(&plan, &retained, LIVE_NOW));
        assert_eq!(binding, retained.prepared_dispatch_binding);
        required!(coordinator.cancel(&plan, &retained));
        assert_eq!(
            coordinator.verifier().counts(),
            InvocationCounts {
                commit: 1,
                cancel: 1,
                ..InvocationCounts::default()
            }
        );

        coordinator
            .verifier()
            .set_commit_error(Some(PortErrorKind::Conflict));
        assert_eq!(
            coordinator.commit(&plan, &retained, LIVE_NOW),
            Err(ApprovalCoordinatorError::Authority(port_error(
                PortErrorKind::Conflict
            )))
        );
        coordinator
            .verifier()
            .set_cancel_error(Some(PortErrorKind::IntegrityFailure));
        assert_eq!(
            coordinator.cancel(&plan, &retained),
            Err(ApprovalCoordinatorError::Authority(port_error(
                PortErrorKind::IntegrityFailure
            )))
        );

        assert_eq!(
            coordinator.commit(&plan, &retained, EXPIRES_AT),
            Err(ApprovalCoordinatorError::Expired)
        );
        coordinator.verifier().set_cancel_error(None);
        required!(coordinator.cancel(&plan, &retained));
        assert_eq!(coordinator.verifier().counts().commit, 2);
        assert_eq!(coordinator.verifier().counts().cancel, 3);
    }

    #[test]
    fn automatic_plans_never_traverse_the_governed_port() {
        let mut plan = governed_plan();
        let request = governed_request(&plan);
        let retained = reservation(&request);
        plan.approval_requirement = ResponseApprovalRequirement::Automatic;
        let coordinator = ResponseApprovalCoordinator::new(FakeVerifier::valid());

        assert_eq!(
            coordinator.prepare(&plan, &request, LIVE_NOW),
            Err(ApprovalCoordinatorError::AutomaticPlan)
        );
        assert_eq!(
            coordinator.reconstruct(&plan, &request, &retained, LIVE_NOW),
            Err(ApprovalCoordinatorError::AutomaticPlan)
        );
        assert_eq!(
            coordinator.commit(&plan, &retained, LIVE_NOW),
            Err(ApprovalCoordinatorError::AutomaticPlan)
        );
        assert_eq!(
            coordinator.cancel(&plan, &retained),
            Err(ApprovalCoordinatorError::AutomaticPlan)
        );
        assert_eq!(coordinator.verifier().counts(), InvocationCounts::default());
    }

    fn governed_plan() -> ResponsePlan {
        ResponsePlan {
            action_id: required!(ActionId::new("action-1")),
            trigger_finding_id: required!(RecordId::new("finding-1")),
            trigger_finding_hash: digest(1),
            trigger_finding_receipt_id: required!(OpaqueReceiptRef::new("receipt-1")),
            tenant_id: required!(TenantId::new("tenant-1")),
            policy_version: required!(RecordId::new("policy-version-1")),
            policy_hash: digest(2),
            affected_ids: required!(RecordIdSet::new(vec![required!(RecordId::new(
                "subject-1"
            ))])),
            affected_set_hash: digest(3),
            effects: required!(PlannedResponseEffects::new(vec![PlannedResponseEffect {
                effect_id: required!(EffectId::new("effect-1")),
                ordinal: 0,
                kind: ResponseEffectKind::SuspendSession,
                target: ResponseTarget::Session {
                    session_id: required!(SessionId::new("session-1")),
                },
                canonical_contribution: required!(CanonicalBody::new(vec![1])),
                contribution_hash: digest(4),
                observed_base_version_hash: digest(5),
            }])),
            ttl_ms: EXPIRES_AT - CREATED_AT,
            created_at_unix_ms: CREATED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            operator_capability: OperatorCapabilityBinding {
                capability_id: required!(RecordId::new("operator-capability-1")),
                capability_digest: digest(6),
                expires_at_unix_ms: EXPIRES_AT + 100,
                executor_subject: required!(RecordId::new("executor-1")),
            },
            approval_requirement: ResponseApprovalRequirement::Governed {
                policy_id: required!(RecordId::new("approval-policy-1")),
            },
            submitter: required!(RecordId::new("submitter-1")),
            reason_hash: digest(7),
            plan_hash: digest(8),
        }
    }

    fn governed_request(plan: &ResponsePlan) -> GovernedApprovalRequest {
        let ResponseApprovalRequirement::Governed { policy_id } = &plan.approval_requirement else {
            panic!("test plan must be governed");
        };
        GovernedApprovalRequest {
            tenant_id: plan.tenant_id.clone(),
            action_id: plan.action_id.clone(),
            plan_hash: plan.plan_hash,
            policy_hash: plan.policy_hash,
            approval_policy_id: policy_id.clone(),
            operator_capability_digest: plan.operator_capability.capability_digest,
            proposal_digest: digest(9),
            proposal_expires_at_unix_ms: EXPIRES_AT - 100,
            governed_intent_hash: digest(10),
            plan_expires_at_unix_ms: plan.expires_at_unix_ms,
            admission_artifact: artifact(),
        }
    }

    fn artifact() -> OpaqueApprovalAdmissionArtifact {
        required!(opaque_admission_artifact(
            required!(AdmissionArtifactRef::new("artifact-1")),
            digest(11),
        ))
    }

    fn reservation(request: &GovernedApprovalRequest) -> GovernedApprovalReservation {
        GovernedApprovalReservation {
            request: request.clone(),
            prepared_dispatch_binding: PreparedActiveResponseDispatchBinding {
                schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
                tenant_id: request.tenant_id.clone(),
                action_id: request.action_id.clone(),
                plan_hash: request.plan_hash,
                dispatch_id: required!(RecordId::new("dispatch-1")),
                executor_authority_id: required!(RecordId::new("executor-authority-1")),
                executor_authority_generation: 1,
                authorized_at_unix_ms: CREATED_AT + 1,
                authorization_capability_hash: request.operator_capability_digest,
                governed_intent_hash: request.governed_intent_hash,
                policy_decision_hash: digest(12),
                approval: ResponseDispatchApproval::Governed {
                    admission_operation_id: required!(RecordId::new("admission-operation-1")),
                    admission_operation_version: 1,
                    approval_set_hash: digest(13),
                },
            },
            expires_at_unix_ms: request.proposal_expires_at_unix_ms,
        }
    }

    const fn digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32])
    }

    fn port_error(kind: PortErrorKind) -> PortError {
        match kind {
            PortErrorKind::Unavailable => PortError::unavailable(),
            PortErrorKind::Conflict => PortError::conflict(),
            PortErrorKind::InvalidData => PortError::invalid_data(),
            PortErrorKind::IntegrityFailure => PortError::integrity_failure(),
        }
    }
}
