//! Governance routes trust and sign only through the admitted authority view.
//! A node whose replicated authority is stale, unconfirmed or expired refuses
//! with that view's admission response before it evaluates or signs anything.
use super::*;
use chio_core::capability::scope::MonetaryAmount;

#[path = "governed_fee_binding.rs"]
mod governed_fee_binding;
use chio_open_market::evidence::{OpenMarketEvidenceKind, OpenMarketEvidenceReference};
use chio_open_market::fee_schedule::{
    OpenMarketBondClass, OpenMarketBondRequirement, OpenMarketCollateralReferenceKind,
    OpenMarketEconomicsScope,
};
use chio_open_market::governance::generic::{
    GenericGovernanceAuthorityScope, GenericGovernanceCaseKind, GenericGovernanceCaseState,
    GenericGovernanceEvidenceKind, GenericGovernanceEvidenceReference,
};
use chio_open_market::listing::{
    GenericListingFreshnessState, GenericListingReplicaFreshness,
    GenericTrustActivationDisposition, GenericTrustActivationEligibility,
    GenericTrustActivationReviewContext, GenericTrustAdmissionClass,
};
use chio_open_market::penalty::{
    OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyState,
};

/// Artifact times. They are independent of every authority clock below.
const ISSUED_AT: u64 = 1_750_000_000;
const LISTING_ID: &str = "governance-authority-listing";

/// A former signing custodian that missed the elected leader's root
/// recovery: its import was refused, so its local head and signing seed are
/// still the issuer that the recovery revoked.
struct StaleFormerCustodian {
    _directory: tempfile::TempDir,
    leader: ServedPeer,
    state: TrustServiceState,
    revoked: Keypair,
    recovered: Keypair,
    now: u64,
}

fn stale_former_custodian() -> StaleFormerCustodian {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let custodian_path = directory.path().join("former-custodian.sqlite3");
    let recovered_path = directory.path().join("recovered-leader.sqlite3");
    let recovery_root = Keypair::generate();
    let custodian =
        SqliteCapabilityAuthority::open_with_clock(&custodian_path, fixed_clock(now)).test_unwrap();
    let revoked = custodian.local_keypair().test_unwrap();
    assert_eq!(
        custodian.status().test_unwrap().public_key,
        revoked.public_key()
    );
    let anchor = custodian
        .initialize_replication_with_recovery(
            "governance-authority-recovery",
            Some(&recovery_root.public_key()),
        )
        .test_unwrap();
    let replica =
        SqliteCapabilityAuthority::open_with_clock(&recovered_path, fixed_clock(now)).test_unwrap();
    replica.pin_replication_anchor(&anchor).test_unwrap();
    replica
        .apply_signed_snapshot(&custodian.signed_snapshot().test_unwrap())
        .test_unwrap();
    let recovered =
        SqliteCapabilityAuthority::open_with_clock(&recovered_path, fixed_clock(now + 1))
            .test_unwrap();
    recovered.recover_authority(&recovery_root).test_unwrap();
    let recovered_status = recovered.status().test_unwrap();
    assert!(!recovered_status
        .trusted_public_keys
        .contains(&revoked.public_key()));
    let recovered_head = recovered.local_keypair().test_unwrap();
    assert_eq!(recovered_status.public_key, recovered_head.public_key());

    let (listener, recovered_url) = ServedPeer::reserve();
    let mut leader_state = state_with_cluster(&recovered_url, &[IMPORTER_URL], None, None, None);
    leader_state.config.authority_db_path = Some(recovered_path);
    leader_state.finding_challenge_clock = fixed_clock(now + 1);
    let leader = ServedPeer::serve(listener, recovered_url, leader_state, None);

    let mut state = state_with_cluster(IMPORTER_URL, &[&leader.url], None, None, None);
    state.config.authority_db_path = Some(custodian_path);
    state.finding_challenge_clock = fixed_clock(now);
    // One second behind the leader at zero configured skew.
    let refused = sync_peer(&state, &leader.url).test_unwrap_err();
    assert!(
        matches!(&refused, CliError::AuthorityStore(AuthorityStoreError::Fence(message)) if message == OUTSIDE_FRESHNESS),
        "unexpected import refusal: {refused:?}"
    );
    assert_eq!(
        current_leader_url(&state).as_deref(),
        Some(leader.url.as_str())
    );
    StaleFormerCustodian {
        _directory: directory,
        leader,
        state,
        revoked,
        recovered: recovered_head,
        now,
    }
}

async fn status_and_body(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    (status, String::from_utf8(bytes.to_vec()).test_unwrap())
}

/// The route must answer exactly as the admitted authority read does for the
/// same node: unavailable, with that read's refusal.
async fn assert_refused_by_admission(node: &StaleFormerCustodian, response: Response) {
    let admission = load_authority_status_for_state(&node.state)
        .map(|_| ())
        .test_unwrap_err();
    let (admission_status, admission_body) = status_and_body(admission).await;
    assert_eq!(admission_status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, body) = status_and_body(response).await;
    let names_revoked_issuer = body.contains(&node.revoked.public_key().to_hex());
    assert_eq!(
        (status, body.as_str()),
        (admission_status, admission_body.as_str()),
        "governance route acted on stale authority; response names the revoked issuer: {names_revoked_issuer}"
    );
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn local_publisher(state: &TrustServiceState) -> GenericRegistryPublisher {
    public_generic_registry_publisher(&state.config).test_unwrap()
}

fn freshness() -> GenericListingReplicaFreshness {
    GenericListingReplicaFreshness {
        state: GenericListingFreshnessState::Fresh,
        age_secs: 0,
        max_age_secs: 300,
        valid_until: ISSUED_AT + 1_000_000,
        generated_at: ISSUED_AT - 1_000,
    }
}

/// A listing in this operator's namespace, signed by its namespace owner.
fn signed_listing(publisher: &GenericRegistryPublisher) -> SignedGenericListing {
    let owner = Keypair::generate();
    let ownership = GenericNamespaceOwnership {
        namespace: publisher.registry_url.clone(),
        owner_id: publisher.operator_id.clone(),
        owner_name: None,
        registry_url: publisher.registry_url.clone(),
        signer_public_key: owner.public_key(),
        registered_at: ISSUED_AT - 2_000,
        transferred_from_owner_id: None,
    };
    let listing = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: LISTING_ID.to_string(),
        namespace: ownership.namespace.clone(),
        published_at: ISSUED_AT - 1_000,
        expires_at: Some(ISSUED_AT + 1_000_000),
        status: GenericListingStatus::Active,
        namespace_ownership: ownership,
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: "governance-tool-server".to_string(),
            display_name: None,
            metadata_url: None,
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: "cert-check-governance".to_string(),
            source_artifact_sha256: "sha256-governance".to_string(),
        },
        boundary: GenericListingBoundary::default(),
    };
    SignedGenericListing::sign(listing, &owner).test_unwrap()
}

fn activation_issue_request(
    publisher: &GenericRegistryPublisher,
    listing: &SignedGenericListing,
) -> GenericTrustActivationIssueRequest {
    GenericTrustActivationIssueRequest {
        listing: listing.clone(),
        admission_class: GenericTrustAdmissionClass::BondBacked,
        disposition: GenericTrustActivationDisposition::Approved,
        eligibility: GenericTrustActivationEligibility {
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
            allowed_statuses: vec![GenericListingStatus::Active],
            require_fresh_listing: true,
            require_bond_backing: true,
            required_listing_operator_ids: vec![publisher.operator_id.clone()],
            policy_reference: Some("policy/open-market/default".to_string()),
        },
        review_context: GenericTrustActivationReviewContext {
            publisher: publisher.clone(),
            freshness: freshness(),
        },
        requested_by: "ops@chio.example".to_string(),
        reviewed_by: Some("reviewer@chio.example".to_string()),
        requested_at: Some(ISSUED_AT),
        reviewed_at: Some(ISSUED_AT + 1),
        expires_at: Some(ISSUED_AT + 900_000),
        note: None,
    }
}

fn charter_issue_request(
    publisher: &GenericRegistryPublisher,
) -> GenericGovernanceCharterIssueRequest {
    GenericGovernanceCharterIssueRequest {
        authority_scope: GenericGovernanceAuthorityScope {
            namespace: publisher.registry_url.clone(),
            allowed_listing_operator_ids: vec![publisher.operator_id.clone()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            policy_reference: Some("policy/open-market/governance".to_string()),
        },
        allowed_case_kinds: vec![
            GenericGovernanceCaseKind::Sanction,
            GenericGovernanceCaseKind::Appeal,
        ],
        escalation_operator_ids: Vec::new(),
        issued_by: "governance@chio.example".to_string(),
        issued_at: Some(ISSUED_AT + 2),
        expires_at: Some(ISSUED_AT + 900_000),
        note: None,
    }
}

fn case_issue_request(
    publisher: &GenericRegistryPublisher,
    listing: &SignedGenericListing,
    activation: &SignedGenericTrustActivation,
    charter: &SignedGenericGovernanceCharter,
) -> GenericGovernanceCaseIssueRequest {
    GenericGovernanceCaseIssueRequest {
        charter: charter.clone(),
        listing: listing.clone(),
        activation: Some(activation.clone()),
        kind: GenericGovernanceCaseKind::Sanction,
        state: GenericGovernanceCaseState::Enforced,
        subject_operator_id: Some(publisher.operator_id.clone()),
        escalated_to_operator_ids: Vec::new(),
        evidence_refs: vec![GenericGovernanceEvidenceReference {
            kind: GenericGovernanceEvidenceKind::TrustActivation,
            reference_id: activation.body.activation_id.clone(),
            uri: None,
            sha256: None,
        }],
        appeal_of_case_id: None,
        supersedes_case_id: None,
        issued_by: "governance@chio.example".to_string(),
        opened_at: Some(ISSUED_AT + 3),
        updated_at: Some(ISSUED_AT + 3),
        expires_at: Some(ISSUED_AT + 900_000),
        note: None,
    }
}

fn fee_schedule_issue_request(
    publisher: &GenericRegistryPublisher,
) -> OpenMarketFeeScheduleIssueRequest {
    OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: publisher.registry_url.clone(),
            allowed_listing_operator_ids: vec![publisher.operator_id.clone()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
            policy_reference: Some("policy/open-market/default".to_string()),
        },
        publication_fee: usd(100),
        dispute_fee: usd(2_500),
        market_participation_fee: usd(500),
        bond_requirements: vec![OpenMarketBondRequirement {
            bond_class: OpenMarketBondClass::Listing,
            required_amount: usd(5_000),
            collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
            slashable: true,
        }],
        issued_by: "market@chio.example".to_string(),
        issued_at: Some(ISSUED_AT + 4),
        expires_at: Some(ISSUED_AT + 900_000),
        note: None,
    }
}

/// Every governance input this operator would issue, signed by `signer`.
struct GovernanceBundle {
    publisher: GenericRegistryPublisher,
    listing: SignedGenericListing,
    activation: SignedGenericTrustActivation,
    charter: SignedGenericGovernanceCharter,
    case: SignedGenericGovernanceCase,
    fee_schedule: SignedOpenMarketFeeSchedule,
}

fn governance_bundle(state: &TrustServiceState, signer: &Keypair) -> GovernanceBundle {
    let publisher = local_publisher(state);
    let operator_id = publisher.operator_id.clone();
    let listing = signed_listing(&publisher);
    let activation = SignedGenericTrustActivation::sign(
        build_generic_trust_activation_artifact(
            &operator_id,
            None,
            &activation_issue_request(&publisher, &listing),
            ISSUED_AT,
        )
        .test_unwrap(),
        signer,
    )
    .test_unwrap();
    let charter = SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            &operator_id,
            None,
            &charter_issue_request(&publisher),
            ISSUED_AT + 2,
        )
        .test_unwrap(),
        signer,
    )
    .test_unwrap();
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact(
            &operator_id,
            &case_issue_request(&publisher, &listing, &activation, &charter),
            ISSUED_AT + 3,
        )
        .test_unwrap(),
        signer,
    )
    .test_unwrap();
    let fee_schedule = SignedOpenMarketFeeSchedule::sign(
        build_open_market_fee_schedule_artifact(
            &operator_id,
            None,
            &fee_schedule_issue_request(&publisher),
            ISSUED_AT + 4,
        )
        .test_unwrap(),
        signer,
    )
    .test_unwrap();
    GovernanceBundle {
        publisher,
        listing,
        activation,
        charter,
        case,
        fee_schedule,
    }
}

fn penalty_issue_request(bundle: &GovernanceBundle) -> OpenMarketPenaltyIssueRequest {
    OpenMarketPenaltyIssueRequest {
        fee_schedule: bundle.fee_schedule.clone(),
        charter: bundle.charter.clone(),
        case: bundle.case.clone(),
        listing: bundle.listing.clone(),
        activation: Some(bundle.activation.clone()),
        abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
        bond_class: OpenMarketBondClass::Listing,
        action: OpenMarketPenaltyAction::SlashBond,
        state: OpenMarketPenaltyState::Enforced,
        penalty_amount: usd(2_500),
        evidence_refs: vec![OpenMarketEvidenceReference {
            kind: OpenMarketEvidenceKind::GovernanceCase,
            reference_id: bundle.case.body.case_id.clone(),
            uri: None,
            sha256: None,
        }],
        subject_operator_id: Some(bundle.publisher.operator_id.clone()),
        supersedes_penalty_id: None,
        issued_by: "market@chio.example".to_string(),
        opened_at: Some(ISSUED_AT + 5),
        updated_at: Some(ISSUED_AT + 5),
        expires_at: Some(ISSUED_AT + 900_000),
        note: None,
    }
}

fn signed_penalty(bundle: &GovernanceBundle, signer: &Keypair) -> SignedOpenMarketPenalty {
    SignedOpenMarketPenalty::sign(
        build_open_market_penalty_artifact_with_trusted_signers(
            &bundle.publisher.operator_id,
            &penalty_issue_request(bundle),
            ISSUED_AT + 5,
            &[signer.public_key()],
        )
        .test_unwrap(),
        signer,
    )
    .test_unwrap()
}

fn activation_evaluation_request(
    bundle: &GovernanceBundle,
) -> GenericTrustActivationEvaluationRequest {
    GenericTrustActivationEvaluationRequest {
        listing: bundle.listing.clone(),
        current_publisher: bundle.publisher.clone(),
        current_freshness: freshness(),
        activation: Some(bundle.activation.clone()),
        evaluated_at: Some(ISSUED_AT + 10),
    }
}

fn penalty_evaluation_request(
    bundle: &GovernanceBundle,
    penalty: SignedOpenMarketPenalty,
) -> OpenMarketPenaltyEvaluationRequest {
    OpenMarketPenaltyEvaluationRequest {
        fee_schedule: bundle.fee_schedule.clone(),
        listing: bundle.listing.clone(),
        current_publisher: bundle.publisher.clone(),
        activation: Some(bundle.activation.clone()),
        charter: bundle.charter.clone(),
        case: bundle.case.clone(),
        penalty,
        prior_penalty: None,
        evaluated_at: Some(ISSUED_AT + 10),
    }
}

#[tokio::test]
async fn stale_authority_refuses_trust_activation_evaluation() {
    let node = stale_former_custodian();
    let bundle = governance_bundle(&node.state, &node.revoked);
    let response = handle_evaluate_generic_trust_activation(
        State(node.state.clone()),
        workload_headers(),
        Json(activation_evaluation_request(&bundle)),
    )
    .await;
    assert_refused_by_admission(&node, response).await;
}

#[tokio::test]
async fn stale_authority_refuses_open_market_penalty_evaluation() {
    let node = stale_former_custodian();
    let bundle = governance_bundle(&node.state, &node.revoked);
    let penalty = signed_penalty(&bundle, &node.revoked);
    let response = handle_evaluate_open_market_penalty(
        State(node.state.clone()),
        workload_headers(),
        Json(penalty_evaluation_request(&bundle, penalty)),
    )
    .await;
    assert_refused_by_admission(&node, response).await;
}

#[tokio::test]
async fn stale_authority_refuses_open_market_penalty_issuance() {
    let node = stale_former_custodian();
    let bundle = governance_bundle(&node.state, &node.revoked);
    let response = handle_issue_open_market_penalty(
        State(node.state.clone()),
        workload_headers(),
        Json(penalty_issue_request(&bundle)),
    )
    .await;
    assert_refused_by_admission(&node, response).await;
}

#[tokio::test]
async fn stale_authority_refuses_trust_activation_issuance() {
    let node = stale_former_custodian();
    let publisher = local_publisher(&node.state);
    let listing = signed_listing(&publisher);
    let response = handle_issue_generic_trust_activation(
        State(node.state.clone()),
        workload_headers(),
        Json(activation_issue_request(&publisher, &listing)),
    )
    .await;
    assert_refused_by_admission(&node, response).await;
}

#[tokio::test]
async fn stale_authority_refuses_governance_charter_issuance() {
    let node = stale_former_custodian();
    let publisher = local_publisher(&node.state);
    let response = handle_issue_generic_governance_charter(
        State(node.state.clone()),
        workload_headers(),
        Json(charter_issue_request(&publisher)),
    )
    .await;
    assert_refused_by_admission(&node, response).await;
}

#[tokio::test]
async fn stale_authority_refuses_governance_case_issuance() {
    let node = stale_former_custodian();
    let bundle = governance_bundle(&node.state, &node.revoked);
    let response = handle_issue_generic_governance_case(
        State(node.state.clone()),
        workload_headers(),
        Json(case_issue_request(
            &bundle.publisher,
            &bundle.listing,
            &bundle.activation,
            &bundle.charter,
        )),
    )
    .await;
    assert_refused_by_admission(&node, response).await;
}

#[tokio::test]
async fn stale_authority_refuses_open_market_fee_schedule_issuance() {
    let node = stale_former_custodian();
    let publisher = local_publisher(&node.state);
    let response = handle_issue_open_market_fee_schedule(
        State(node.state.clone()),
        workload_headers(),
        Json(fee_schedule_issue_request(&publisher)),
    )
    .await;
    assert_refused_by_admission(&node, response).await;
}

#[derive(Clone, Copy, Debug)]
enum GovernanceRoute {
    EvaluateTrustActivation,
    EvaluateOpenMarketPenalty,
    IssueOpenMarketPenalty,
    IssueTrustActivation,
    IssueGovernanceCharter,
    IssueGovernanceCase,
    IssueOpenMarketFeeSchedule,
}

const GOVERNANCE_ROUTES: [GovernanceRoute; 7] = [
    GovernanceRoute::EvaluateTrustActivation,
    GovernanceRoute::EvaluateOpenMarketPenalty,
    GovernanceRoute::IssueOpenMarketPenalty,
    GovernanceRoute::IssueTrustActivation,
    GovernanceRoute::IssueGovernanceCharter,
    GovernanceRoute::IssueGovernanceCase,
    GovernanceRoute::IssueOpenMarketFeeSchedule,
];

/// Calls one governance route with inputs taken from `bundle`.
async fn call_governance_route(
    route: GovernanceRoute,
    state: &TrustServiceState,
    headers: HeaderMap,
    bundle: &GovernanceBundle,
    penalty: &SignedOpenMarketPenalty,
) -> Response {
    let state = State(state.clone());
    match route {
        GovernanceRoute::EvaluateTrustActivation => {
            handle_evaluate_generic_trust_activation(
                state,
                headers,
                Json(activation_evaluation_request(bundle)),
            )
            .await
        }
        GovernanceRoute::EvaluateOpenMarketPenalty => {
            handle_evaluate_open_market_penalty(
                state,
                headers,
                Json(penalty_evaluation_request(bundle, penalty.clone())),
            )
            .await
        }
        GovernanceRoute::IssueOpenMarketPenalty => {
            handle_issue_open_market_penalty(state, headers, Json(penalty_issue_request(bundle)))
                .await
        }
        GovernanceRoute::IssueTrustActivation => {
            handle_issue_generic_trust_activation(
                state,
                headers,
                Json(activation_issue_request(&bundle.publisher, &bundle.listing)),
            )
            .await
        }
        GovernanceRoute::IssueGovernanceCharter => {
            handle_issue_generic_governance_charter(
                state,
                headers,
                Json(charter_issue_request(&bundle.publisher)),
            )
            .await
        }
        GovernanceRoute::IssueGovernanceCase => {
            handle_issue_generic_governance_case(
                state,
                headers,
                Json(case_issue_request(
                    &bundle.publisher,
                    &bundle.listing,
                    &bundle.activation,
                    &bundle.charter,
                )),
            )
            .await
        }
        GovernanceRoute::IssueOpenMarketFeeSchedule => {
            handle_issue_open_market_fee_schedule(
                state,
                headers,
                Json(fee_schedule_issue_request(&bundle.publisher)),
            )
            .await
        }
    }
}

fn directory_entries(path: &std::path::Path) -> Vec<String> {
    let mut entries = std::fs::read_dir(path)
        .test_unwrap()
        .map(|entry| {
            entry
                .test_unwrap()
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

/// A standalone node whose configured authority its owner never provisioned.
fn unprovisioned_authority_node(
    directory: &tempfile::TempDir,
    seed_file: bool,
) -> TrustServiceState {
    let mut state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    let path = directory.path().join("unprovisioned-authority");
    if seed_file {
        state.config.authority_seed_path = Some(path);
    } else {
        state.config.authority_db_path = Some(path);
    }
    state.finding_challenge_clock = fixed_clock(unix_timestamp_now().test_unwrap());
    state
}

/// Every route refuses with `expected`, and none of them bootstraps
/// authority storage on the way.
async fn assert_refused_without_bootstrap(
    directory: &tempfile::TempDir,
    state: &TrustServiceState,
    expected: (StatusCode, String),
) {
    let signer = Keypair::generate();
    let bundle = governance_bundle(state, &signer);
    let penalty = signed_penalty(&bundle, &signer);
    for route in GOVERNANCE_ROUTES {
        let response =
            call_governance_route(route, state, workload_headers(), &bundle, &penalty).await;
        let refusal = status_and_body(response).await;
        assert_eq!(
            refusal,
            expected,
            "{route:?}; authority storage now holds {:?}",
            directory_entries(directory.path())
        );
        assert_eq!(
            directory_entries(directory.path()),
            Vec::<String>::new(),
            "{route:?} bootstrapped authority storage"
        );
    }
}

#[tokio::test]
async fn unprovisioned_authority_database_refuses_without_bootstrap() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let state = unprovisioned_authority_node(&directory, false);
    let admission = load_authority_status_for_state(&state)
        .map(|_| ())
        .test_unwrap_err();
    let expected = status_and_body(admission).await;
    assert_eq!(expected.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_refused_without_bootstrap(&directory, &state, expected).await;
}

#[tokio::test]
async fn unprovisioned_authority_seed_refuses_without_bootstrap() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let state = unprovisioned_authority_node(&directory, true);
    let expected = status_and_body(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "trust-control authority did not publish any trusted signing keys",
    ))
    .await;
    assert_refused_without_bootstrap(&directory, &state, expected).await;
}

use crate::trust_control::service_runtime::issuance::{
    admitted_authority_signers, admitted_signers_from_status,
    evaluate_generic_trust_activation_with_signers, evaluate_open_market_penalty_with_signers,
    sign_with_admitted_authority, sign_with_admitted_signers, AUTHORITY_CHANGED_DURING_SIGNING,
    SIGNER_NOT_ADMITTED_HEAD,
};

const ISSUING_ROUTES: [GovernanceRoute; 5] = [
    GovernanceRoute::IssueOpenMarketPenalty,
    GovernanceRoute::IssueTrustActivation,
    GovernanceRoute::IssueGovernanceCharter,
    GovernanceRoute::IssueGovernanceCase,
    GovernanceRoute::IssueOpenMarketFeeSchedule,
];

async fn unavailable(reason: &str) -> (StatusCode, String) {
    status_and_body(plain_http_error(StatusCode::SERVICE_UNAVAILABLE, reason)).await
}

async fn rejected(message: &str) -> (StatusCode, String) {
    status_and_body(plain_http_error(
        StatusCode::BAD_REQUEST,
        &CliError::cli_other_error(message.to_string()).to_string(),
    ))
    .await
}

fn public_keys(hex: &[String]) -> Vec<PublicKey> {
    hex.iter()
        .map(|value| PublicKey::from_hex(value).test_unwrap())
        .collect()
}

fn response_json(body: &str) -> Value {
    serde_json::from_str(body).test_unwrap()
}

/// A standalone signing custodian that rotated once, so its live set holds
/// the verification-only predecessor and the signing head.
struct StandaloneCustodian {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    state: TrustServiceState,
    previous: Keypair,
    head: Keypair,
    now: u64,
}

fn standalone_custodian() -> StandaloneCustodian {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let path = directory.path().join("custodian.sqlite3");
    let previous = SqliteCapabilityAuthority::open_with_clock(&path, fixed_clock(now))
        .test_unwrap()
        .local_keypair()
        .test_unwrap();
    let rotated =
        SqliteCapabilityAuthority::open_with_clock(&path, fixed_clock(now + 1)).test_unwrap();
    rotated.rotate().test_unwrap();
    let head = rotated.local_keypair().test_unwrap();
    assert_ne!(head.public_key(), previous.public_key());
    let mut state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    state.config.authority_db_path = Some(path.clone());
    state.finding_challenge_clock = fixed_clock(now + 2);
    StandaloneCustodian {
        _directory: directory,
        path,
        state,
        previous,
        head,
        now,
    }
}

#[tokio::test]
async fn standalone_custodian_signs_and_evaluates_with_its_exact_live_set() {
    let custodian = standalone_custodian();
    let admitted = load_authority_status_for_state(&custodian.state).test_unwrap();
    let signers = admitted_authority_signers(&custodian.state).test_unwrap();
    assert_eq!(
        signers.trusted(),
        public_keys(&admitted.trusted_public_keys).as_slice()
    );
    assert_eq!(signers.trusted().len(), 2);
    assert!(signers.trusted().contains(&custodian.previous.public_key()));
    assert_eq!(signers.head(), &custodian.head.public_key());

    let bundle = governance_bundle(&custodian.state, &custodian.head);
    let penalty = signed_penalty(&bundle, &custodian.head);
    for route in ISSUING_ROUTES {
        let (status, body) = status_and_body(
            call_governance_route(
                route,
                &custodian.state,
                workload_headers(),
                &bundle,
                &penalty,
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{route:?}: {body}");
        assert_eq!(
            response_json(&body)["signerKey"],
            custodian.head.public_key().to_hex(),
            "{route:?}"
        );
    }

    // The verification-only predecessor is still a trusted signer.
    for signer in [&custodian.head, &custodian.previous] {
        let bundle = governance_bundle(&custodian.state, signer);
        let penalty = signed_penalty(&bundle, signer);
        let request = activation_evaluation_request(&bundle);
        let (status, body) = status_and_body(
            call_governance_route(
                GovernanceRoute::EvaluateTrustActivation,
                &custodian.state,
                workload_headers(),
                &bundle,
                &penalty,
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let expected =
            evaluate_generic_trust_activation(&request, ISSUED_AT + 10, &signer.public_key())
                .test_unwrap();
        assert_eq!(
            response_json(&body),
            serde_json::to_value(expected).test_unwrap()
        );

        let request = penalty_evaluation_request(&bundle, penalty.clone());
        let (status, body) = status_and_body(
            call_governance_route(
                GovernanceRoute::EvaluateOpenMarketPenalty,
                &custodian.state,
                workload_headers(),
                &bundle,
                &penalty,
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let expected = evaluate_open_market_penalty_with_trusted_signers(
            &request,
            ISSUED_AT + 10,
            signers.trusted(),
        )
        .test_unwrap();
        assert_eq!(
            response_json(&body),
            serde_json::to_value(expected).test_unwrap()
        );
    }
}

#[tokio::test]
async fn confirmed_follower_trusts_only_the_admitted_set_and_never_signs_with_its_revoked_seed() {
    let mut node = stale_former_custodian();
    let revoked_bundle = governance_bundle(&node.state, &node.revoked);
    let revoked_penalty = signed_penalty(&revoked_bundle, &node.revoked);
    let current_bundle = governance_bundle(&node.state, &node.recovered);
    let current_penalty = signed_penalty(&current_bundle, &node.recovered);
    // One second of configured skew admits the leader's recovery.
    node.state
        .config
        .authority_replication_max_future_skew_seconds = 1;
    sync_peer(&node.state, &node.leader.url).test_unwrap();
    node.state.finding_challenge_clock = fixed_clock(node.now + 1);

    let admitted = load_authority_status_for_state(&node.state).test_unwrap();
    let current = node.recovered.public_key();
    assert_eq!(admitted.trusted_public_keys, vec![current.to_hex()]);
    let signers = admitted_authority_signers(&node.state).test_unwrap();
    assert_eq!(signers.trusted(), [current.clone()].as_slice());
    assert_eq!(signers.head(), &current);

    let refusal = status_and_body(
        call_governance_route(
            GovernanceRoute::EvaluateTrustActivation,
            &node.state,
            workload_headers(),
            &revoked_bundle,
            &revoked_penalty,
        )
        .await,
    )
    .await;
    assert_eq!(
        refusal,
        rejected("trust activation signer does not match a trusted trust-control authority signer")
            .await
    );
    let refusal = status_and_body(
        call_governance_route(
            GovernanceRoute::EvaluateOpenMarketPenalty,
            &node.state,
            workload_headers(),
            &revoked_bundle,
            &revoked_penalty,
        )
        .await,
    )
    .await;
    assert_eq!(
        refusal,
        rejected(
            "open-market fee schedule signer does not match a trusted trust-control authority signer"
        )
        .await
    );

    let (status, body) = status_and_body(
        call_governance_route(
            GovernanceRoute::EvaluateTrustActivation,
            &node.state,
            workload_headers(),
            &current_bundle,
            &current_penalty,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let expected = evaluate_generic_trust_activation(
        &activation_evaluation_request(&current_bundle),
        ISSUED_AT + 10,
        &current,
    )
    .test_unwrap();
    assert_eq!(
        response_json(&body),
        serde_json::to_value(expected).test_unwrap()
    );

    // The follower's local seed is the revoked issuer, never the admitted head.
    for route in ISSUING_ROUTES {
        let refusal = status_and_body(
            call_governance_route(
                route,
                &node.state,
                workload_headers(),
                &current_bundle,
                &current_penalty,
            )
            .await,
        )
        .await;
        assert_eq!(
            refusal,
            unavailable(SIGNER_NOT_ADMITTED_HEAD).await,
            "{route:?}"
        );
    }
}

#[tokio::test]
async fn authority_rotation_between_preflight_and_return_discards_the_artifact() {
    let custodian = standalone_custodian();
    let publisher = local_publisher(&custodian.state);
    let rotated_at = custodian.now + 2;
    let result = sign_with_admitted_authority(
        &custodian.state,
        |keypair, preflight| {
            assert_eq!(preflight.head(), &keypair.public_key());
            let artifact = build_generic_governance_charter_artifact(
                &publisher.operator_id,
                None,
                &charter_issue_request(&publisher),
                ISSUED_AT + 2,
            )
            .map_err(CliError::cli_other_error)?;
            let signed = SignedGenericGovernanceCharter::sign(artifact, keypair)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            SqliteCapabilityAuthority::open_with_clock(&custodian.path, fixed_clock(rotated_at))?
                .rotate()?;
            Ok(signed)
        },
        |signed| signed.signer_key.clone(),
    );
    let refusal = result.map(|_| ()).test_unwrap_err();
    assert_eq!(
        status_and_body(refusal).await,
        unavailable(AUTHORITY_CHANGED_DURING_SIGNING).await
    );
    let head = admitted_authority_signers(&custodian.state).test_unwrap();
    assert_ne!(head.head(), &custodian.head.public_key());
}

#[test]
fn lifecycle_projection_never_admits_a_head_that_is_not_live() {
    let custodian = standalone_custodian();
    let mut status = load_authority_status_for_state(&custodian.state).test_unwrap();
    assert!(status.issuer_state.is_some());
    let successor = Keypair::generate().public_key();
    status.public_key = Some(successor.to_hex());
    let signers = admitted_signers_from_status(&status).test_unwrap();
    assert_eq!(
        signers.trusted(),
        public_keys(&status.trusted_public_keys).as_slice()
    );
    assert!(!signers.trusted().contains(&successor));
    assert!(!signers.admits_signer(&successor));
    assert!(!signers.admits_signer(&custodian.head.public_key()));

    status.trusted_public_keys.clear();
    assert_eq!(
        admitted_signers_from_status(&status).map(|_| ()),
        Err(crate::trust_control::service_runtime::issuance::NO_TRUSTED_SIGNING_KEYS)
    );
    status.configured = false;
    assert_eq!(
        admitted_signers_from_status(&status).map(|_| ()),
        Err(crate::trust_control::service_runtime::issuance::AUTHORITY_NOT_CONFIGURED)
    );
}

/// The shape the enterprise keyring backend's admitted read takes.
fn keyring_status(head: &PublicKey, witnessed: &[PublicKey]) -> TrustAuthorityStatus {
    TrustAuthorityStatus {
        configured: true,
        backend: Some("enterprise_keyring".to_string()),
        public_key: Some(head.to_hex()),
        generation: Some(2),
        rotated_at: Some(ISSUED_AT),
        issuer_state: None,
        applies_to_future_sessions_only: true,
        trusted_public_keys: witnessed.iter().map(PublicKey::to_hex).collect(),
    }
}

#[tokio::test]
async fn keyring_witnessed_set_evaluates_and_a_keyring_without_signing_material_refuses_issuance() {
    let witness_signed = Keypair::generate();
    let head = Keypair::generate();
    let witnessed = [witness_signed.public_key(), head.public_key()];
    let signers =
        admitted_signers_from_status(&keyring_status(&head.public_key(), &witnessed)).test_unwrap();
    assert_eq!(signers.trusted(), witnessed.as_slice());
    assert_eq!(signers.head(), &head.public_key());

    let mut state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    state.finding_challenge_clock = fixed_clock(ISSUED_AT);
    let bundle = governance_bundle(&state, &witness_signed);
    let request = activation_evaluation_request(&bundle);
    assert_eq!(
        evaluate_generic_trust_activation_with_signers(&signers, &request).test_unwrap(),
        evaluate_generic_trust_activation(&request, ISSUED_AT + 10, &witness_signed.public_key())
            .test_unwrap()
    );
    let penalty = signed_penalty(&bundle, &witness_signed);
    let request = penalty_evaluation_request(&bundle, penalty);
    assert_eq!(
        evaluate_open_market_penalty_with_signers(&signers, &request, None).test_unwrap(),
        evaluate_open_market_penalty_with_trusted_signers(&request, ISSUED_AT + 10, &witnessed)
            .test_unwrap()
    );

    // A head outside the witnessed list is still trusted as the signing head.
    let unwitnessed = Keypair::generate().public_key();
    let signers =
        admitted_signers_from_status(&keyring_status(&unwitnessed, &witnessed)).test_unwrap();
    assert_eq!(
        signers.trusted(),
        [witnessed[0].clone(), witnessed[1].clone(), unwitnessed].as_slice()
    );

    // A keyring service holds no seed or database in its configuration, so
    // issuance refuses before it builds or signs anything.
    let signers =
        admitted_signers_from_status(&keyring_status(&head.public_key(), &witnessed)).test_unwrap();
    let refusal = sign_with_admitted_signers(
        &state,
        &signers,
        |_, _| -> Result<SignedGenericGovernanceCharter, CliError> {
            panic!("issuance ran without signing material")
        },
        |signed| signed.signer_key.clone(),
    )
    .map(|_| ())
    .test_unwrap_err();
    assert_eq!(
        status_and_body(refusal).await,
        rejected(
            "behavioral feed export requires --authority-seed-file or --authority-db so the export can be signed"
        )
        .await
    );
}

#[tokio::test]
async fn governance_routes_authenticate_before_reading_authority() {
    let node = stale_former_custodian();
    let bundle = governance_bundle(&node.state, &node.revoked);
    let penalty = signed_penalty(&bundle, &node.revoked);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer not-the-token".parse().test_unwrap());
    let expected = status_and_body(plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid control bearer token",
    ))
    .await;
    for route in GOVERNANCE_ROUTES {
        let response =
            call_governance_route(route, &node.state, headers.clone(), &bundle, &penalty).await;
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer")),
            "{route:?}"
        );
        assert_eq!(status_and_body(response).await, expected, "{route:?}");
    }
    assert_eq!(node.state.authority_inspection_lane.available_permits(), 8);
}

#[tokio::test]
async fn saturated_inspection_lane_refuses_governance_work_before_it_runs() {
    let custodian = standalone_custodian();
    let bundle = governance_bundle(&custodian.state, &custodian.head);
    let penalty = signed_penalty(&bundle, &custodian.head);
    let held = custodian
        .state
        .authority_inspection_lane
        .clone()
        .acquire_many_owned(8)
        .await
        .test_unwrap();
    for route in GOVERNANCE_ROUTES {
        let refusal = status_and_body(
            call_governance_route(
                route,
                &custodian.state,
                workload_headers(),
                &bundle,
                &penalty,
            )
            .await,
        )
        .await;
        assert_eq!(
            refusal,
            unavailable("authority inspection is at capacity").await,
            "{route:?}"
        );
    }
    drop(held);
    let (status, body) = status_and_body(
        call_governance_route(
            GovernanceRoute::IssueGovernanceCharter,
            &custodian.state,
            workload_headers(),
            &bundle,
            &penalty,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        custodian
            .state
            .authority_inspection_lane
            .available_permits(),
        8
    );
}
