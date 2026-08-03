#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use chio_core::capability::{
    aggregate_budget::{
        issue_aggregate_family_root, verify_aggregate_invocation_authority,
        verify_direct_aggregate_family_root, AggregateBudgetDelegationMarker,
        AggregateBudgetRootBinding, AggregateFamilyRootResolution, AggregateInvocationBudget,
        VerifiedAggregateFamilyRoot,
    },
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    governance::{GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::crypto::{sha256_hex, Keypair, SigningAlgorithm};
use chio_kernel::approval::ApprovalStore;
use chio_kernel::budget_store::{
    BudgetAdmissionOperationBinding, BudgetAuthorizeHoldDecision, BudgetCaptureHoldRequest,
    BudgetCaptureInvocationRequest, BudgetInvocationQuota, BudgetInvocationReservationState,
    BudgetMonetaryHoldState, BudgetQuotaKey, BudgetQuotaProfile, BudgetReconcileHoldRequest,
    BudgetReleaseHoldRequest, BudgetStore, BudgetStoreError,
};
use chio_kernel::security_admission_operation::{
    AdmissionOperation, AdmissionOperationKind, AdmissionRequestBindingInput,
    AdmissionRequestBindingParts, PreparedAdmissionOperation,
};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::threshold_approval::{
    verify_threshold_approval_set, ThresholdApprovalProposal, ThresholdApprovalProposalBody,
    ThresholdApprovalRequest, ThresholdApprovalRequirement, ThresholdApprovalResolutionError,
    ThresholdApprovalVerificationInput, VerifiedThresholdApprovalSet,
};
use chio_store_sqlite::budget_store::{
    SqliteAggregateFamilyEvidence, SqliteCompositeAuthorizeInput,
};
use chio_store_sqlite::{SqliteApprovalStore, SqliteBudgetStore};

fn grant(operations: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

#[test]
fn capability_unknown_schema_rejected() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = ChioScope {
        grants: vec![grant(vec![Operation::Invoke, Operation::Delegate])],
        ..ChioScope::default()
    };
    let child = ChioScope {
        grants: vec![grant(vec![Operation::Invoke])],
        ..ChioScope::default()
    };
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "cap-attenuated".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: child,
                issued_at: 1,
                expires_at: 2,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent).unwrap(),
                child_scope_hash: scope_hash(&ChioScope {
                    grants: vec![grant(vec![Operation::Invoke])],
                    ..ChioScope::default()
                })
                .unwrap(),
                normalized_subset_proof: witness,
                aggregate_family_preservation: None,
            },
            budget_share_bps: Some(10_000),
        },
        &issuer,
    )
    .unwrap();

    let mut bad = token;
    bad.schema = "chio.capability.v999".to_string();
    assert!(bad.verify_signature().is_err());
}

#[test]
fn forged_attenuation_proof_rejected() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = ChioScope {
        grants: vec![grant(vec![Operation::Invoke, Operation::Delegate])],
        ..ChioScope::default()
    };
    let child = ChioScope {
        grants: vec![grant(vec![Operation::Invoke])],
        ..ChioScope::default()
    };
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let result = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "cap-attenuated".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: child,
                issued_at: 1,
                expires_at: 2,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: "00".repeat(32),
                child_scope_hash: scope_hash(&ChioScope {
                    grants: vec![grant(vec![Operation::Invoke])],
                    ..ChioScope::default()
                })
                .unwrap(),
                normalized_subset_proof: witness,
                aggregate_family_preservation: None,
            },
            budget_share_bps: None,
        },
        &issuer,
    );
    assert!(result.is_err());
}

fn family_scope() -> ChioScope {
    ChioScope {
        grants: vec![grant(vec![Operation::Invoke, Operation::Delegate])],
        ..ChioScope::default()
    }
}

fn invoke_scope() -> ChioScope {
    ChioScope {
        grants: vec![grant(vec![Operation::Invoke])],
        ..ChioScope::default()
    }
}

struct AggregateFamilyFixture {
    root_issuer: Keypair,
    root_subject: Keypair,
    child_subject: Keypair,
    root_token: CapabilityToken,
    verified_root: VerifiedAggregateFamilyRoot,
}

impl AggregateFamilyFixture {
    fn new(id: &str, maximum: u32, seed_offset: u8) -> Self {
        let root_issuer = Keypair::from_seed(&[seed_offset; 32]);
        let root_subject = Keypair::from_seed(&[seed_offset.saturating_add(1); 32]);
        let child_subject = Keypair::from_seed(&[seed_offset.saturating_add(2); 32]);
        let root_token = issue_aggregate_family_root(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: root_issuer.public_key(),
                subject: root_subject.public_key(),
                scope: family_scope(),
                issued_at: 1_000,
                expires_at: 2_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            maximum,
            &root_issuer,
        )
        .unwrap();
        let verified_root =
            verify_direct_aggregate_family_root(&root_token, &[root_issuer.public_key()]).unwrap();
        Self {
            root_issuer,
            root_subject,
            child_subject,
            root_token,
            verified_root,
        }
    }

    fn family_budget(&self) -> AggregateInvocationBudget {
        self.root_token.aggregate_invocation_budget.clone().unwrap()
    }

    fn delegation_marker(&self) -> AggregateBudgetDelegationMarker {
        let evidence = self.verified_root.preservation_evidence();
        AggregateBudgetDelegationMarker {
            root_binding_digest: evidence.root_binding_digest,
            max_invocations: evidence.max_invocations,
        }
    }

    fn link(&self) -> DelegationLink {
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: self.root_token.id.clone(),
                delegator: self.root_subject.public_key(),
                delegatee: self.child_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 1_100,
                scope_hash: Some(scope_hash(&self.root_token.scope).unwrap()),
                aggregate_budget: Some(self.delegation_marker()),
                cumulative_approval: None,
                aggregate_family_preservation: Some(self.verified_root.preservation_evidence()),
            },
            &self.root_subject,
        )
        .unwrap()
    }

    fn descendant(&self, id: &str) -> CapabilityToken {
        let child_scope = invoke_scope();
        let mut normalized_subset_proof =
            compute_attenuation_witness(&self.root_token.scope, &child_scope).unwrap();
        normalized_subset_proof.aggregate_budget = Some(self.delegation_marker());
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: id.to_string(),
                    issuer: self.root_subject.public_key(),
                    subject: self.child_subject.public_key(),
                    scope: child_scope.clone(),
                    issued_at: 1_100,
                    expires_at: 1_900,
                    delegation_chain: vec![self.link()],
                    aggregate_invocation_budget: Some(self.family_budget()),
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: AttenuationProof {
                    parent_scope_hash: scope_hash(&self.root_token.scope).unwrap(),
                    child_scope_hash: scope_hash(&child_scope).unwrap(),
                    normalized_subset_proof,
                    aggregate_family_preservation: Some(self.verified_root.preservation_evidence()),
                },
                budget_share_bps: None,
            },
            &self.root_subject,
        )
        .unwrap()
    }

    fn verify_descendant(&self, token: &CapabilityToken) -> bool {
        verify_aggregate_invocation_authority(
            token,
            &[self.root_issuer.public_key()],
            &[self.root_subject.public_key()],
            &|root_id: &str| {
                assert_eq!(root_id, self.root_token.id);
                Ok(AggregateFamilyRootResolution::FamilyBound(
                    self.verified_root.clone(),
                ))
            },
        )
        .is_ok()
    }
}

fn family_binding_mut(token: &mut CapabilityToken) -> &mut AggregateBudgetRootBinding {
    token
        .aggregate_invocation_budget
        .as_mut()
        .and_then(|budget| budget.root_binding.as_mut())
        .unwrap()
}

fn resign_capability(token: &mut CapabilityToken, signer: &Keypair) {
    token.signature = signer.sign_canonical(&token.signing_body()).unwrap().0;
}

#[test]
fn aggregate_family_root_rejects_every_forged_authority_field() {
    let fixture = AggregateFamilyFixture::new("aggregate-root", 7, 31);
    let attacker = Keypair::from_seed(&[99; 32]);
    let mut mutations = Vec::new();

    let mut root_id = fixture.root_token.clone();
    family_binding_mut(&mut root_id).body.root_capability_id = "forged-root".to_string();
    mutations.push(root_id);

    let mut root_hash = fixture.root_token.clone();
    family_binding_mut(&mut root_hash).body.root_capability_hash = "00".repeat(32);
    mutations.push(root_hash);

    let mut issuer = fixture.root_token.clone();
    family_binding_mut(&mut issuer).body.root_issuer = attacker.public_key();
    mutations.push(issuer);

    let mut subject = fixture.root_token.clone();
    family_binding_mut(&mut subject).body.root_subject = attacker.public_key();
    mutations.push(subject);

    let mut scope = fixture.root_token.clone();
    family_binding_mut(&mut scope).body.root_scope_hash = "11".repeat(32);
    mutations.push(scope);

    let mut expiry = fixture.root_token.clone();
    family_binding_mut(&mut expiry).body.root_expires_at = 1_999;
    mutations.push(expiry);

    let mut maximum = fixture.root_token.clone();
    family_binding_mut(&mut maximum).body.max_invocations = 8;
    mutations.push(maximum);

    let mut signature = fixture.root_token.clone();
    family_binding_mut(&mut signature).signature = attacker.sign(b"forged-binding");
    mutations.push(signature);

    for mut token in mutations {
        resign_capability(&mut token, &fixture.root_issuer);
        assert!(
            verify_direct_aggregate_family_root(&token, &[fixture.root_issuer.public_key()])
                .is_err()
        );
    }
}

#[test]
fn aggregate_family_zero_is_valid_and_descendants_cannot_change_family_authority() {
    let zero = AggregateFamilyFixture::new("aggregate-zero", 0, 41);
    assert_eq!(zero.verified_root.max_invocations(), 0);

    let fixture = AggregateFamilyFixture::new("aggregate-family", 3, 51);
    let valid = fixture.descendant("family-child-valid");
    assert!(fixture.verify_descendant(&valid));

    let mut lowering = valid.clone();
    lowering
        .aggregate_invocation_budget
        .as_mut()
        .unwrap()
        .max_invocations = 2;
    resign_capability(&mut lowering, &fixture.root_subject);
    assert!(!fixture.verify_descendant(&lowering));

    let mut raising = valid.clone();
    raising
        .aggregate_invocation_budget
        .as_mut()
        .unwrap()
        .max_invocations = 4;
    resign_capability(&mut raising, &fixture.root_subject);
    assert!(!fixture.verify_descendant(&raising));

    let mut omitted = valid.clone();
    omitted.aggregate_invocation_budget = None;
    resign_capability(&mut omitted, &fixture.root_subject);
    assert!(!fixture.verify_descendant(&omitted));

    let second = AggregateFamilyFixture::new("other-family", 3, 61);
    let mut rebound = valid;
    rebound
        .aggregate_invocation_budget
        .as_mut()
        .unwrap()
        .root_binding = second
        .root_token
        .aggregate_invocation_budget
        .as_ref()
        .and_then(|budget| budget.root_binding.clone());
    resign_capability(&mut rebound, &fixture.root_subject);
    assert!(!fixture.verify_descendant(&rebound));
}

fn quota(
    profile: BudgetQuotaProfile,
    owner_id: &str,
    grant_index: Option<u32>,
    maximum: u32,
) -> BudgetInvocationQuota {
    BudgetInvocationQuota::from_persisted_parts(
        BudgetQuotaKey::from_persisted_parts(profile, owner_id.to_string(), grant_index).unwrap(),
        maximum,
    )
    .unwrap()
}

fn composite_request(
    capability_id: &str,
    grant_index: usize,
    family_owner: &str,
    family_maximum: u32,
    broker_owner: &str,
    hold_id: &str,
    event_id: &str,
) -> SqliteCompositeAuthorizeInput {
    let family_owner = sha256_hex(family_owner.as_bytes());
    let family_root_capability_id = format!("aggregate-root-{family_owner}");
    let broker_owner = sha256_hex(broker_owner.as_bytes());
    SqliteCompositeAuthorizeInput {
        operation_id: format!("operation-{hold_id}"),
        request_binding_hash: sha256_hex(event_id.as_bytes()),
        capability_id: capability_id.to_string(),
        grant_index,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: hold_id.to_string(),
        event_id: event_id.to_string(),
        authority: None,
        invocation_quotas: vec![
            quota(
                BudgetQuotaProfile::GrantInvocation,
                capability_id,
                Some(u32::try_from(grant_index).unwrap()),
                2,
            ),
            quota(
                BudgetQuotaProfile::AggregateFamilyInvocation,
                &family_owner,
                None,
                family_maximum,
            ),
            quota(
                BudgetQuotaProfile::SupplementalBrokerExecution,
                &broker_owner,
                None,
                4,
            ),
        ],
        revocation_set: CanonicalRevocationSet::new(
            capability_id,
            &[family_root_capability_id],
            &[],
        )
        .unwrap(),
        authorization_artifact_digests: Vec::new(),
        partition_escrow_evidence: None,
    }
}

fn authorize_family_composite_hold(
    store: &SqliteBudgetStore,
    request: SqliteCompositeAuthorizeInput,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    let family_owner = request
        .invocation_quotas
        .iter()
        .find(|quota| quota.key().profile() == BudgetQuotaProfile::AggregateFamilyInvocation)
        .map(|quota| quota.key().owner_id())
        .expect("aggregate-family quota");
    let root_capability_id = format!("aggregate-root-{family_owner}");
    let root_binding_digest = sha256_hex(
        format!("chio.conformance.aggregate-family-root-binding.v1\0{family_owner}").as_bytes(),
    );
    store.authorize_aggregate_family_composite_hold(
        request,
        SqliteAggregateFamilyEvidence {
            root_capability_id,
            root_binding_digest,
        },
    )
}

fn admission_operation(
    hold_id: &str,
    authorization_event_id: &str,
) -> BudgetAdmissionOperationBinding {
    BudgetAdmissionOperationBinding::new(
        format!("operation-{hold_id}"),
        sha256_hex(authorization_event_id.as_bytes()),
    )
    .unwrap()
}

#[test]
fn composite_quota_exhaustion_is_shared_across_grants_and_family_siblings() {
    let grant_store = SqliteBudgetStore::open_in_memory().unwrap();
    let first = composite_request(
        "same-leaf",
        0,
        "family-owner-grants",
        1,
        "broker-grants",
        "hold-grant-0",
        "event-grant-0",
    );
    assert!(authorize_family_composite_hold(&grant_store, first)
        .unwrap()
        .is_authorized());
    let second = composite_request(
        "same-leaf",
        1,
        "family-owner-grants",
        1,
        "broker-grants",
        "hold-grant-1",
        "event-grant-1",
    );
    let BudgetAuthorizeHoldDecision::Denied(denied) =
        authorize_family_composite_hold(&grant_store, second).unwrap()
    else {
        panic!("second grant must share the exhausted aggregate maximum");
    };
    let grant_usage = denied
        .invocation_counts_after
        .iter()
        .find(|usage| usage.quota.key().profile() == BudgetQuotaProfile::GrantInvocation)
        .unwrap();
    assert_eq!(grant_usage.invocation_count_after().unwrap(), 0);

    let sibling_store = SqliteBudgetStore::open_in_memory().unwrap();
    assert!(authorize_family_composite_hold(
        &sibling_store,
        composite_request(
            "sibling-a",
            0,
            "family-owner-siblings",
            1,
            "broker-sibling-a",
            "hold-sibling-a",
            "event-sibling-a",
        ),
    )
    .unwrap()
    .is_authorized());
    let sibling_denied = authorize_family_composite_hold(
        &sibling_store,
        composite_request(
            "sibling-b",
            0,
            "family-owner-siblings",
            1,
            "broker-sibling-b",
            "hold-sibling-b",
            "event-sibling-b",
        ),
    )
    .unwrap();
    assert!(!sibling_denied.is_authorized());
}

#[test]
fn composite_quota_mutation_is_atomic_idempotent_and_maximum_immutable() {
    let store = SqliteBudgetStore::open_in_memory().unwrap();
    let request = composite_request(
        "atomic-leaf",
        0,
        "atomic-family",
        1,
        "atomic-broker",
        "atomic-hold",
        "atomic-event",
    );
    let first = authorize_family_composite_hold(&store, request.clone()).unwrap();
    assert!(first.is_authorized());
    assert_eq!(
        authorize_family_composite_hold(&store, request.clone()).unwrap(),
        first
    );

    let mut conflicting_event = request.clone();
    conflicting_event.event_id = "different-event".to_string();
    assert!(authorize_family_composite_hold(&store, conflicting_event).is_err());
    let mut conflicting_hold = request.clone();
    conflicting_hold.hold_id = "different-hold".to_string();
    assert!(authorize_family_composite_hold(&store, conflicting_hold).is_err());

    let denied = authorize_family_composite_hold(
        &store,
        composite_request(
            "second-leaf",
            0,
            "atomic-family",
            1,
            "second-broker",
            "denied-hold",
            "denied-event",
        ),
    )
    .unwrap();
    let BudgetAuthorizeHoldDecision::Denied(denied) = denied else {
        panic!("exhausted family quota must deny");
    };
    assert!(denied
        .invocation_counts_after
        .iter()
        .any(
            |usage| usage.quota.key().profile() == BudgetQuotaProfile::GrantInvocation
                && usage.invocation_count_after().unwrap() == 0
        ));
    assert!(denied
        .invocation_counts_after
        .iter()
        .any(|usage| usage.quota.key().profile()
            == BudgetQuotaProfile::SupplementalBrokerExecution
            && usage.invocation_count_after().unwrap() == 0));

    let mut maximum_change = composite_request(
        "third-leaf",
        0,
        "atomic-family",
        2,
        "third-broker",
        "maximum-hold",
        "maximum-event",
    );
    maximum_change.requested_exposure_units = 0;
    assert!(authorize_family_composite_hold(&store, maximum_change).is_err());
}

#[test]
fn invocation_capture_and_monetary_terminalization_recover_independently() {
    let store = SqliteBudgetStore::open_in_memory().unwrap();
    let authorize = composite_request(
        "independent-leaf",
        0,
        "independent-family",
        3,
        "independent-broker",
        "independent-hold",
        "independent-authorize",
    );
    assert!(authorize_family_composite_hold(&store, authorize)
        .unwrap()
        .is_authorized());

    let captured = store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "independent-leaf".to_string(),
            grant_index: 0,
            hold_id: Some("independent-hold".to_string()),
            event_id: Some("independent-invocation".to_string()),
            authority: None,
            admission_operation: Some(admission_operation(
                "independent-hold",
                "independent-authorize",
            )),
        })
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Exposed);

    let released = store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: "independent-leaf".to_string(),
            grant_index: 0,
            released_exposure_units: 100,
            hold_id: Some("independent-hold".to_string()),
            event_id: Some("independent-release".to_string()),
            authority: None,
            admission_operation: Some(admission_operation(
                "independent-hold",
                "independent-authorize",
            )),
        })
        .unwrap();
    assert_eq!(
        released.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(released.monetary_state, BudgetMonetaryHoldState::Released);

    let reconciled_store = SqliteBudgetStore::open_in_memory().unwrap();
    assert!(authorize_family_composite_hold(
        &reconciled_store,
        composite_request(
            "reconcile-leaf",
            0,
            "reconcile-family",
            1,
            "reconcile-broker",
            "reconcile-hold",
            "reconcile-authorize",
        ),
    )
    .unwrap()
    .is_authorized());
    let reconciled = reconciled_store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "reconcile-leaf".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 25,
            hold_id: Some("reconcile-hold".to_string()),
            event_id: Some("reconcile-terminal".to_string()),
            authority: None,
            admission_operation: Some(admission_operation("reconcile-hold", "reconcile-authorize")),
        })
        .unwrap();
    assert_eq!(
        reconciled.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(
        reconciled.monetary_state,
        BudgetMonetaryHoldState::Reconciled
    );

    let capture_store = SqliteBudgetStore::open_in_memory().unwrap();
    assert!(authorize_family_composite_hold(
        &capture_store,
        composite_request(
            "capture-leaf",
            0,
            "capture-family",
            1,
            "capture-broker",
            "capture-hold",
            "capture-authorize",
        ),
    )
    .unwrap()
    .is_authorized());
    let monetary_capture = capture_store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "capture-leaf".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 100,
            hold_id: Some("capture-hold".to_string()),
            event_id: Some("capture-terminal".to_string()),
            authority: None,
            admission_operation: Some(admission_operation("capture-hold", "capture-authorize")),
        })
        .unwrap();
    assert_eq!(
        monetary_capture.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(
        monetary_capture.monetary_state,
        BudgetMonetaryHoldState::Captured
    );
}

struct ThresholdFixture {
    authority: Keypair,
    subject: Keypair,
    approvers: Vec<Keypair>,
    requirement: ThresholdApprovalRequirement,
    proposal: ThresholdApprovalProposal,
    intent_hash: String,
    capability_hash: String,
}

impl ThresholdFixture {
    fn new() -> Self {
        let authority = Keypair::from_seed(&[71; 32]);
        let subject = Keypair::from_seed(&[72; 32]);
        let approvers = vec![Keypair::from_seed(&[73; 32]), Keypair::from_seed(&[74; 32])];
        let policy_hash = "33".repeat(32);
        let intent_hash = "11".repeat(32);
        let capability_hash = "22".repeat(32);
        let requirement = ThresholdApprovalRequirement::new(
            2,
            BTreeMap::from([
                ("alice".to_string(), approvers[0].public_key()),
                ("bob".to_string(), approvers[1].public_key()),
            ]),
            900,
            policy_hash.clone(),
            1,
        )
        .unwrap();
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody::new(
                "threshold-proposal",
                "threshold-request",
                intent_hash.clone(),
                subject.public_key(),
                capability_hash.clone(),
                policy_hash,
                requirement.required(),
                requirement.eligible_set_digest(),
                1_000,
                requirement.proposal_timeout_seconds(),
                1_900,
                1_900,
            )
            .unwrap(),
            &authority,
        )
        .unwrap();
        Self {
            authority,
            subject,
            approvers,
            requirement,
            proposal,
            intent_hash,
            capability_hash,
        }
    }

    fn token_for(
        &self,
        proposal: &ThresholdApprovalProposal,
        index: usize,
        id: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> GovernedApprovalToken {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: self.approvers[index].public_key(),
                subject: self.subject.public_key(),
                governed_intent_hash: self.intent_hash.clone(),
                threshold_proposal_hash: Some(proposal.proposal_hash().unwrap()),
                request_id: "threshold-request".to_string(),
                issued_at,
                expires_at,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approvers[index],
        )
        .unwrap()
    }

    fn tokens_for(&self, proposal: &ThresholdApprovalProposal) -> Vec<GovernedApprovalToken> {
        vec![
            self.token_for(proposal, 0, "approval-a", 1_100, 1_800),
            self.token_for(proposal, 1, "approval-b", 1_100, 1_800),
        ]
    }

    fn verify(
        &self,
        proposal: &ThresholdApprovalProposal,
        tokens: &[GovernedApprovalToken],
        now: u64,
    ) -> Result<VerifiedThresholdApprovalSet, String> {
        let trusted_authorities = [self.authority.public_key()];
        verify_threshold_approval_set(
            &ThresholdApprovalVerificationInput {
                request_id: "threshold-request",
                server_id: "payments",
                tool_name: "transfer",
                governed_intent_hash: &self.intent_hash,
                subject: &self.subject.public_key(),
                authorization_capability_hash: &self.capability_hash,
                authorizing_capability_expires_at: 1_900,
                governed_operation_expires_at: 1_900,
                policy_hash: self.requirement.policy_hash(),
                proposal,
                approval_tokens: tokens,
                trusted_policy_authorities: &trusted_authorities,
                allowed_token_algorithms: &[SigningAlgorithm::Ed25519],
                now,
            },
            &|_: &ThresholdApprovalRequest, _: &str| Ok(self.requirement.clone()),
        )
        .map_err(|error| error.to_string())
    }

    fn mutated_proposal(&self, field: &str, value: serde_json::Value) -> ThresholdApprovalProposal {
        let mut body = serde_json::to_value(self.proposal.body()).unwrap();
        body[field] = value;
        ThresholdApprovalProposal::sign(serde_json::from_value(body).unwrap(), &self.authority)
            .unwrap()
    }
}

fn threshold_operation(
    request_fingerprint_hash: &str,
    verified: &VerifiedThresholdApprovalSet,
    fixture: &ThresholdFixture,
) -> AdmissionOperation {
    let approval_set_hash = verified.approval_set_hash().unwrap();
    let request_binding_hash = AdmissionRequestBindingInput::new(AdmissionRequestBindingParts {
        action_hash: request_fingerprint_hash.to_string(),
        policy_hash: fixture.requirement.policy_hash().to_string(),
        governed_intent_hash: Some(fixture.intent_hash.clone()),
        threshold_proposal_hash: Some(verified.body().threshold_proposal_hash().to_string()),
        verified_approval_set_hash: Some(approval_set_hash.clone()),
        approval_token_digests: verified.body().token_digests().to_vec(),
        budget_hold_reference: Some("threshold-budget-hold".to_string()),
        supplemental_authorization_reference: Some("supplemental-reference".to_string()),
        supplemental_authorization_digest: Some("44".repeat(32)),
        execution_nonce_reference: Some("threshold-nonce".to_string()),
    })
    .unwrap()
    .derive_hash()
    .unwrap();
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "threshold-coordinator".to_string(),
        request_id: "threshold-request".to_string(),
        capability_id: "threshold-capability".to_string(),
        authorization_capability_hash: fixture.capability_hash.clone(),
        request_binding_hash,
        policy_hash: fixture.requirement.policy_hash().to_string(),
        broker_attempt_id: None,
        budget_hold_id: Some("threshold-budget-hold".to_string()),
        approval_set_hash: Some(approval_set_hash),
        execution_nonce_id: Some("threshold-nonce".to_string()),
        coordinator_lease_epoch: 1,
    })
    .unwrap()
}

#[test]
fn threshold_exact_n_is_order_independent_and_request_replay_separated() {
    let fixture = ThresholdFixture::new();
    let tokens = fixture.tokens_for(&fixture.proposal);
    let forward = fixture.verify(&fixture.proposal, &tokens, 1_200).unwrap();
    let reverse = fixture
        .verify(
            &fixture.proposal,
            &[tokens[1].clone(), tokens[0].clone()],
            1_200,
        )
        .unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(
        forward.approval_set_hash().unwrap(),
        reverse.approval_set_hash().unwrap()
    );

    let request_fingerprint_hash = "55".repeat(32);
    let operation = threshold_operation(&request_fingerprint_hash, &forward, &fixture);
    let reversed_operation = threshold_operation(&request_fingerprint_hash, &reverse, &fixture);
    assert_eq!(operation.operation_id(), reversed_operation.operation_id());

    let replayed_request_fingerprint_hash = "66".repeat(32);
    let changed = threshold_operation(&replayed_request_fingerprint_hash, &forward, &fixture);
    assert_ne!(operation.operation_id(), changed.operation_id());
    assert_ne!(
        operation.request_binding_hash(),
        changed.request_binding_hash()
    );
}

#[test]
fn threshold_rejects_subthreshold_duplicates_replay_and_wrong_bindings() {
    let fixture = ThresholdFixture::new();
    let tokens = fixture.tokens_for(&fixture.proposal);
    assert!(fixture
        .verify(&fixture.proposal, std::slice::from_ref(&tokens[0]), 1_200)
        .is_err());

    let duplicate_signer = fixture.token_for(
        &fixture.proposal,
        0,
        "approval-duplicate-signer",
        1_100,
        1_800,
    );
    assert!(fixture
        .verify(
            &fixture.proposal,
            &[tokens[0].clone(), duplicate_signer],
            1_200,
        )
        .unwrap_err()
        .contains("signer is duplicated"));
    assert!(fixture
        .verify(
            &fixture.proposal,
            &[tokens[0].clone(), tokens[0].clone()],
            1_200,
        )
        .is_err());

    let mut wrong_subject_body = tokens[0].body();
    wrong_subject_body.subject = Keypair::from_seed(&[88; 32]).public_key();
    let wrong_subject =
        GovernedApprovalToken::sign(wrong_subject_body, &fixture.approvers[0]).unwrap();
    assert!(fixture
        .verify(
            &fixture.proposal,
            &[wrong_subject, tokens[1].clone()],
            1_200,
        )
        .is_err());

    let mut wrong_request_body = tokens[0].body();
    wrong_request_body.request_id = "other-request".to_string();
    let wrong_request =
        GovernedApprovalToken::sign(wrong_request_body, &fixture.approvers[0]).unwrap();
    assert!(fixture
        .verify(
            &fixture.proposal,
            &[wrong_request, tokens[1].clone()],
            1_200,
        )
        .is_err());

    let verified = fixture.verify(&fixture.proposal, &tokens, 1_200).unwrap();
    let approval_set = verified.reservation_input().unwrap();
    let store = SqliteApprovalStore::open_in_memory().unwrap();
    let first_operation = "01".repeat(32);
    let second_operation = "02".repeat(32);
    store
        .reserve_approval_set(&first_operation, &approval_set)
        .unwrap();
    assert!(store
        .reserve_approval_set(&second_operation, &approval_set)
        .is_err());
}

#[test]
fn threshold_rejects_proposal_and_token_window_mutations() {
    let fixture = ThresholdFixture::new();
    let valid_tokens = fixture.tokens_for(&fixture.proposal);

    let deadline = fixture.mutated_proposal(
        "proposalDeadline",
        serde_json::Value::Number(1_899_u64.into()),
    );
    assert!(fixture
        .verify(&deadline, &fixture.tokens_for(&deadline), 1_200)
        .is_err());

    let eligible = fixture.mutated_proposal(
        "eligibleSetDigest",
        serde_json::Value::String("55".repeat(32)),
    );
    assert!(fixture
        .verify(&eligible, &fixture.tokens_for(&eligible), 1_200)
        .is_err());

    assert!(fixture
        .verify(&fixture.proposal, &valid_tokens, 1_900)
        .is_err());

    let future_body = ThresholdApprovalProposalBody::new(
        "future-proposal",
        "threshold-request",
        fixture.intent_hash.clone(),
        fixture.subject.public_key(),
        fixture.capability_hash.clone(),
        fixture.requirement.policy_hash(),
        fixture.requirement.required(),
        fixture.requirement.eligible_set_digest(),
        1_300,
        500,
        1_900,
        1_900,
    )
    .unwrap();
    let future = ThresholdApprovalProposal::sign(future_body, &fixture.authority).unwrap();
    assert!(fixture
        .verify(&future, &fixture.tokens_for(&future), 1_200)
        .is_err());

    let early = fixture.token_for(&fixture.proposal, 0, "approval-early", 999, 1_800);
    assert!(fixture
        .verify(&fixture.proposal, &[early, valid_tokens[1].clone()], 1_200,)
        .is_err());
    let future_token = fixture.token_for(&fixture.proposal, 0, "approval-future", 1_300, 1_800);
    assert!(fixture
        .verify(
            &fixture.proposal,
            &[future_token, valid_tokens[1].clone()],
            1_200,
        )
        .is_err());

    let trusted_authorities = [fixture.authority.public_key()];
    let stale = verify_threshold_approval_set(
        &ThresholdApprovalVerificationInput {
            request_id: "threshold-request",
            server_id: "payments",
            tool_name: "transfer",
            governed_intent_hash: &fixture.intent_hash,
            subject: &fixture.subject.public_key(),
            authorization_capability_hash: &fixture.capability_hash,
            authorizing_capability_expires_at: 1_900,
            governed_operation_expires_at: 1_900,
            policy_hash: fixture.requirement.policy_hash(),
            proposal: &fixture.proposal,
            approval_tokens: &valid_tokens,
            trusted_policy_authorities: &trusted_authorities,
            allowed_token_algorithms: &[SigningAlgorithm::Ed25519],
            now: 1_200,
        },
        &|_: &ThresholdApprovalRequest, _: &str| {
            Err(ThresholdApprovalResolutionError::StalePolicy {
                expected: "44".repeat(32),
                received: fixture.requirement.policy_hash().to_string(),
            })
        },
    );
    assert!(stale.is_err());
}
