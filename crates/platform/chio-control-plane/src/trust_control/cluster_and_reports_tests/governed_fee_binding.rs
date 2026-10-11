//! A governed open-market fee schedule is bound only when the caller receives
//! it. A refused issuance leaves no binding, and a returned schedule is the
//! exact envelope the fiscal store bound.
use super::*;
use chio_core::crypto::sha256_hex;
use chio_fiscal::{
    FiscalActivationBuilder, FiscalActivationTarget, FiscalAdmissionAuthority,
    FiscalAdmissionTrustRegistry, FiscalApprovalBuilder, FiscalAuthorityState,
    FiscalBootstrapState, FiscalCharterBuilder, FiscalCharterRegistry, FiscalContinuityChange,
    FiscalContinuityCheckpointBuilder, FiscalDomain, FiscalDomainState, FiscalGenesisPolicy,
    FiscalParams, FiscalProposalAdmissionBuilder, FiscalProposalAdmissionState,
    FiscalProposalBuilder, FiscalProposalTarget, FiscalRuntimeReadinessBuilder,
    FiscalScheduleBuilder, FiscalScheduleHead, FiscalStagedTransition, FiscalStateAnchor,
    FiscalStateAnchorError, SignedFiscalContinuityCheckpoint, VerifiedFiscalActivation,
    VerifiedFiscalCharter, VerifiedFiscalContinuityAdvance, VerifiedFiscalContinuityCheckpoint,
    VerifiedFiscalProposal, VerifiedFiscalProposalAdmission, VerifiedFiscalRuntimeReadiness,
    VerifiedFiscalSchedule,
};
use chio_store_sqlite::SqliteAuthorityStore;
use std::sync::atomic::{AtomicUsize, Ordering};

const OPERATOR: &str = "operator.example";
/// Composition reconciles once, issuance resolves once, binding reconciles
/// once: the third anchor read happens inside the binding step.
const BINDING_RECONCILE_READ: usize = 3;

fn fiscal_key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn genesis_domains() -> Vec<FiscalDomainState> {
    [
        FiscalDomain::TierLimits,
        FiscalDomain::MarketplaceDiscountPerHundred,
        FiscalDomain::DecisionPremiumBasisPoints,
        FiscalDomain::InsurancePremiumSchedule,
        FiscalDomain::OpenMarketFeeAndBondSchedule,
    ]
    .into_iter()
    .map(FiscalDomainState::never_activated)
    .collect()
}

/// Serves one finalized checkpoint. On the configured read it rotates the
/// capability authority first, which models a rotation that commits while a
/// governed issuance is between signing and binding.
struct RotatingAnchor {
    checkpoint: SignedFiscalContinuityCheckpoint,
    reads: AtomicUsize,
    rotate_on_read: Option<usize>,
    authority_path: std::path::PathBuf,
    rotate_at: u64,
    rotations: AtomicUsize,
}

impl FiscalStateAnchor for RotatingAnchor {
    fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if self.rotate_on_read == Some(read) {
            SqliteCapabilityAuthority::open_with_clock(
                &self.authority_path,
                fixed_clock(self.rotate_at),
            )
            .and_then(|authority| authority.rotate())
            .map_err(|_| FiscalStateAnchorError::Unavailable)?;
            self.rotations.fetch_add(1, Ordering::SeqCst);
        }
        Ok(self.checkpoint.clone())
    }

    fn compare_and_swap(
        &self,
        _expected_checkpoint_digest: &str,
        _advance: &VerifiedFiscalContinuityAdvance,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        Err(FiscalStateAnchorError::Conflict)
    }
}

/// A standalone signing custodian whose fiscal runtime governs the
/// open-market fee schedule through one activated schedule.
struct GovernedFeeNode {
    _directory: tempfile::TempDir,
    custodian: StandaloneCustodian,
    runtime: Arc<TrustFiscalRuntime>,
    anchor: Arc<RotatingAnchor>,
    schedule_id: String,
    database: std::path::PathBuf,
}

fn governed_fee_node(rotate_on_read: Option<usize>) -> GovernedFeeNode {
    fiscal_fee_node(rotate_on_read, true)
}

/// As `governed_fee_node`, but with `governed` false the schedule is never
/// activated, so the fiscal runtime resolves the fee schedule by fallback.
fn fiscal_fee_node(rotate_on_read: Option<usize>, governed: bool) -> GovernedFeeNode {
    let mut custodian = standalone_custodian();
    let directory = chio_test_support::private_tempdir().test_unwrap();

    let charter = VerifiedFiscalCharter::verify(
        FiscalCharterBuilder {
            governing_operator_id: OPERATOR.to_owned(),
            governed_domains: vec![
                FiscalDomain::TierLimits,
                FiscalDomain::MarketplaceDiscountPerHundred,
                FiscalDomain::DecisionPremiumBasisPoints,
                FiscalDomain::InsurancePremiumSchedule,
                FiscalDomain::OpenMarketFeeAndBondSchedule,
            ],
            signer_keys: vec![fiscal_key(1).public_key(), fiscal_key(2).public_key()],
            approval_threshold: 2,
            timelock_seconds: 10,
            proposal_ttl_seconds: 100,
            approval_ttl_seconds: 50,
            issued_at: 10,
            expires_at: 1_000,
            issued_by: OPERATOR.to_owned(),
            sequence: 1,
            predecessor_charter_digest: None,
        }
        .sign(&fiscal_key(9))
        .test_unwrap(),
    )
    .test_unwrap();
    let anchor_key = fiscal_key(8);
    let mut bootstrap = std::collections::BTreeMap::new();
    bootstrap.insert("USD".to_owned(), [100, 200, 300, 400]);
    let policy = FiscalGenesisPolicy::new(
        OPERATOR.to_owned(),
        &charter,
        fiscal_key(9).public_key(),
        "fiscal-anchor".to_owned(),
        "fiscal-main".to_owned(),
        1,
        anchor_key.public_key(),
        bootstrap,
    )
    .test_unwrap();
    let registry = crate::fiscal_runtime_readiness::production_fiscal_runtime_assembler()
        .test_unwrap()
        .self_test_and_build_registry(env!("CARGO_PKG_VERSION"), "chio.fiscal.runtime.v1")
        .test_unwrap();
    let readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 1,
            runtime_registry: registry.clone(),
            attested_at: 50,
        }
        .sign(&policy, &anchor_key)
        .test_unwrap(),
        &policy,
        registry,
    )
    .test_unwrap();
    let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()]).test_unwrap();
    let genesis = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 0,
            previous_checkpoint_digest: None,
            pinned_charter_id: charter.body().charter_id.clone(),
            pinned_charter_digest: charter.digest().to_owned(),
            pinned_charter_sequence: 1,
            runtime_readiness_digest: readiness.digest().to_owned(),
            domains: genesis_domains(),
            trusted_clock_high_water: 50,
            staged_transition: None,
        }
        .sign(&policy, &anchor_key)
        .test_unwrap(),
        &policy,
        &charters,
    )
    .test_unwrap();
    let genesis_authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &genesis,
        FiscalBootstrapState::CharterPinned,
    )
    .test_unwrap();

    let legacy_request = OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: "https://registry.operator.example".to_string(),
            allowed_listing_operator_ids: vec![OPERATOR.to_string()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
            policy_reference: None,
        },
        publication_fee: usd(1),
        dispute_fee: usd(2),
        market_participation_fee: usd(3),
        bond_requirements: vec![OpenMarketBondRequirement {
            bond_class: OpenMarketBondClass::Listing,
            required_amount: usd(10),
            collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
            slashable: true,
        }],
        issued_by: OPERATOR.to_string(),
        issued_at: Some(70),
        expires_at: Some(900),
        note: None,
    };
    let schedule = VerifiedFiscalSchedule::verify(
        FiscalScheduleBuilder {
            domain: FiscalDomain::OpenMarketFeeAndBondSchedule,
            params: FiscalParams::OpenMarketFeeAndBondSchedule {
                legacy_body: Box::new(
                    build_open_market_fee_schedule_artifact(OPERATOR, None, &legacy_request, 70)
                        .test_unwrap(),
                ),
            },
            valid_from: 70,
            valid_until: 900,
            issued_at: 70,
            issued_by: OPERATOR.to_owned(),
        }
        .sign(&charter, None, &fiscal_key(9))
        .test_unwrap(),
        &charter,
        None,
    )
    .test_unwrap();
    let proposal = VerifiedFiscalProposal::verify(
        FiscalProposalBuilder {
            target: FiscalProposalTarget::Schedule {
                candidate: Box::new(schedule.signed().clone()),
            },
            rationale_digest: sha256_hex(b"open-market fee schedule"),
            proposed_at: 50,
        }
        .sign(&fiscal_key(1))
        .test_unwrap(),
        &charter,
        None,
    )
    .test_unwrap();
    let admission_key = fiscal_key(7);
    let trust = FiscalAdmissionTrustRegistry::new(vec![FiscalAdmissionAuthority::new(
        OPERATOR.to_owned(),
        "local-admission".to_owned(),
        1,
        admission_key.public_key(),
    )
    .test_unwrap()])
    .test_unwrap();
    let admission = VerifiedFiscalProposalAdmission::verify(
        FiscalProposalAdmissionBuilder {
            admission_sequence: 1,
            admitted_at: 55,
            admission_authority_id: "local-admission".to_owned(),
            signer_key_epoch: 1,
        }
        .sign(&proposal, &charter, &admission_key)
        .test_unwrap(),
        &proposal,
        &charter,
        &trust,
        55,
    )
    .test_unwrap();
    let admitted = FiscalProposalAdmissionState::admitted(&admission);
    let approvals = [fiscal_key(1), fiscal_key(2)]
        .into_iter()
        .map(|signer| {
            FiscalApprovalBuilder { approved_at: 56 }.sign(&proposal, &admission, &charter, &signer)
        })
        .collect::<Result<Vec<_>, _>>()
        .test_unwrap();
    let signed_activation = FiscalActivationBuilder {
        target: FiscalActivationTarget::Schedule {
            schedule_id: schedule.body().schedule_id.clone(),
            supersedes_schedule_id: None,
        },
        approvals,
        activated_at: 70,
    }
    .sign(&proposal, &admission, &charter, &fiscal_key(1))
    .test_unwrap();
    let staged_activation = VerifiedFiscalActivation::verify(
        signed_activation.clone(),
        &proposal,
        &admission,
        &admitted,
        &charter,
        &trust,
        None,
        &[],
        70,
    )
    .test_unwrap();
    let activated = admitted
        .activate(staged_activation.digest().to_owned(), 1)
        .test_unwrap();
    let activation = VerifiedFiscalActivation::verify(
        signed_activation,
        &proposal,
        &admission,
        &activated,
        &charter,
        &trust,
        None,
        &[],
        70,
    )
    .test_unwrap();
    let head = FiscalScheduleHead::from_signed(schedule.signed()).test_unwrap();
    let mut next_domains = genesis_domains();
    next_domains[4] = FiscalDomainState::activated(
        FiscalDomain::OpenMarketFeeAndBondSchedule,
        head.clone(),
        head,
    )
    .test_unwrap();
    let next_signed = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(genesis.digest().to_owned()),
        pinned_charter_id: charter.body().charter_id.clone(),
        pinned_charter_digest: charter.digest().to_owned(),
        pinned_charter_sequence: charter.body().sequence,
        runtime_readiness_digest: readiness.digest().to_owned(),
        domains: next_domains,
        trusted_clock_high_water: 70,
        staged_transition: Some(
            FiscalStagedTransition::new(
                activation.body().activation_id.clone(),
                activation.digest().to_owned(),
            )
            .test_unwrap(),
        ),
    }
    .sign(&policy, &anchor_key)
    .test_unwrap();
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &genesis,
        next_signed,
        &policy,
        &charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(activation.clone()),
            readiness: Box::new(readiness.clone()),
            domain: FiscalDomain::OpenMarketFeeAndBondSchedule,
            schedule: Box::new(schedule.clone()),
        },
    )
    .test_unwrap();
    let next_checkpoint = advance.next().clone();
    let next_authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &next_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )
    .test_unwrap();

    crate::create_private_directory(directory.path()).test_unwrap();
    let database = directory.path().join("joint-authority.db");
    let lock_root = directory.path().join("locks");
    crate::create_private_directory(&lock_root).test_unwrap();
    SqliteAuthorityStore::provision(&database, &lock_root).test_unwrap();
    let joint = SqliteAuthorityStore::open_serving(&database, &lock_root).test_unwrap();
    let fence = joint.mutation_fence();
    let store = joint.fiscal_store();
    store
        .initialize_genesis(
            &policy,
            &genesis_authority,
            &charter,
            &readiness,
            &genesis,
            &fence,
        )
        .test_unwrap();
    let anchored = if governed {
        store.persist_schedule(&schedule, &fence).test_unwrap();
        store.persist_proposal(&proposal, &fence).test_unwrap();
        store
            .persist_admission_state(&admitted, None, &fence)
            .test_unwrap();
        store.persist_activation(&activation, &fence).test_unwrap();
        let staged = store
            .stage_activation_advance(
                &advance,
                &next_authority,
                &activation,
                &activated,
                &schedule,
                None,
                &fence,
            )
            .test_unwrap();
        store
            .mark_anchor_advanced(&staged.transition_id, &next_checkpoint, &fence)
            .test_unwrap();
        store
            .finalize_advance(
                &staged.transition_id,
                &next_checkpoint,
                &next_authority,
                &fence,
            )
            .test_unwrap();
        next_checkpoint.signed().clone()
    } else {
        genesis.signed().clone()
    };

    let admission_seed_path = directory.path().join("fiscal-admission.seed");
    std::fs::write(
        &admission_seed_path,
        format!("{}\n", admission_key.seed_hex()),
    )
    .test_unwrap();
    let config = TrustFiscalRuntimeConfig {
        genesis_policy: policy,
        anchor_url: "https://fiscal-anchor.example".to_owned(),
        anchor_bearer_token: "fixture-token".to_owned(),
        anchor_timeout: Duration::from_secs(1),
        admission_authority_id: "local-admission".to_owned(),
        admission_signer_key_epoch: 1,
        admission_signing_seed_path: admission_seed_path,
    };
    let anchor = Arc::new(RotatingAnchor {
        checkpoint: anchored,
        reads: AtomicUsize::new(0),
        rotate_on_read,
        authority_path: custodian.path.clone(),
        rotate_at: custodian.now + 2,
        rotations: AtomicUsize::new(0),
    });
    let runtime =
        compose_trust_fiscal_runtime_with_anchor(&joint, &config, anchor.clone()).test_unwrap();
    custodian.state.fiscal_runtime = Some(Arc::clone(&runtime));
    GovernedFeeNode {
        _directory: directory,
        custodian,
        runtime,
        anchor,
        schedule_id: schedule.body().schedule_id.clone(),
        database,
    }
}

fn bound_envelope_digest(node: &GovernedFeeNode) -> Option<String> {
    node.runtime
        .legacy_fee_schedule_binding(&node.schedule_id)
        .test_unwrap()
        .map(|binding| binding.legacy_envelope_digest)
}

fn envelope_digest(signed: &SignedOpenMarketFeeSchedule) -> String {
    sha256_hex(&canonical_json_bytes(signed).test_unwrap())
}

async fn issue_governed_fee_schedule(node: &GovernedFeeNode) -> (StatusCode, String) {
    let publisher = local_publisher(&node.custodian.state);
    status_and_body(
        handle_issue_open_market_fee_schedule(
            State(node.custodian.state.clone()),
            workload_headers(),
            Json(fee_schedule_issue_request(&publisher)),
        )
        .await,
    )
    .await
}

#[tokio::test]
async fn governed_fee_schedule_is_never_bound_for_a_refused_issuance() {
    let node = governed_fee_node(Some(BINDING_RECONCILE_READ));
    let (status, body) = issue_governed_fee_schedule(&node).await;
    assert_eq!(node.anchor.rotations.load(Ordering::SeqCst), 1);
    if status == StatusCode::OK {
        let signed: SignedOpenMarketFeeSchedule = serde_json::from_str(&body).test_unwrap();
        assert_eq!(bound_envelope_digest(&node), Some(envelope_digest(&signed)));
    } else {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(
            bound_envelope_digest(&node),
            None,
            "refused issuance ({body}) left a persisted fee-schedule binding"
        );
    }
}

/// Rows in `table` of the fiscal store, read without a write lock.
fn fiscal_rows(node: &GovernedFeeNode, table: &str) -> i64 {
    rusqlite::Connection::open_with_flags(
        &node.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .test_unwrap()
    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .test_unwrap()
}

#[tokio::test]
async fn refused_final_authorization_rolls_back_the_binding_and_its_projection_commit() {
    let node = governed_fee_node(Some(BINDING_RECONCILE_READ));
    let projection_commits = fiscal_rows(&node, "fiscal_projection_commits");
    let bindings = fiscal_rows(&node, "fiscal_legacy_fee_schedule_bindings");
    let refusal = issue_governed_fee_schedule(&node).await;
    assert_eq!(node.anchor.rotations.load(Ordering::SeqCst), 1);
    assert_eq!(refusal, unavailable(AUTHORITY_CHANGED_DURING_SIGNING).await);
    assert_eq!(bound_envelope_digest(&node), None);
    assert_eq!(
        fiscal_rows(&node, "fiscal_projection_commits"),
        projection_commits
    );
    assert_eq!(
        fiscal_rows(&node, "fiscal_legacy_fee_schedule_bindings"),
        bindings
    );
}

#[tokio::test]
async fn governed_fee_schedule_binds_exactly_the_returned_envelope_and_retries_identically() {
    let node = governed_fee_node(None);
    let projection_commits = fiscal_rows(&node, "fiscal_projection_commits");
    let (status, body) = issue_governed_fee_schedule(&node).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let signed: SignedOpenMarketFeeSchedule = serde_json::from_str(&body).test_unwrap();
    assert_eq!(signed.signer_key, node.custodian.head.public_key());
    assert_eq!(bound_envelope_digest(&node), Some(envelope_digest(&signed)));
    assert_eq!(
        fiscal_rows(&node, "fiscal_projection_commits"),
        projection_commits + 1
    );

    let retry = issue_governed_fee_schedule(&node).await;
    assert_eq!(retry, (StatusCode::OK, body));
    assert_eq!(bound_envelope_digest(&node), Some(envelope_digest(&signed)));
    assert_eq!(
        fiscal_rows(&node, "fiscal_projection_commits"),
        projection_commits + 1
    );
    assert_eq!(node.anchor.rotations.load(Ordering::SeqCst), 0);
}

/// Composition, first issue, first bind, retried issue, retried bind.
const RETRIED_BINDING_RECONCILE_READ: usize = 5;

#[tokio::test]
async fn retained_binding_retry_refuses_without_change_after_the_authority_moved() {
    let node = governed_fee_node(Some(RETRIED_BINDING_RECONCILE_READ));
    let (status, body) = issue_governed_fee_schedule(&node).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let signed: SignedOpenMarketFeeSchedule = serde_json::from_str(&body).test_unwrap();
    let projection_commits = fiscal_rows(&node, "fiscal_projection_commits");

    let refusal = issue_governed_fee_schedule(&node).await;
    assert_eq!(node.anchor.rotations.load(Ordering::SeqCst), 1);
    assert_eq!(refusal, unavailable(AUTHORITY_CHANGED_DURING_SIGNING).await);
    assert_eq!(bound_envelope_digest(&node), Some(envelope_digest(&signed)));
    assert_eq!(
        fiscal_rows(&node, "fiscal_projection_commits"),
        projection_commits
    );
}

#[tokio::test]
async fn fallback_fee_schedule_under_a_fiscal_runtime_binds_nothing() {
    let node = fiscal_fee_node(None, false);
    let projection_commits = fiscal_rows(&node, "fiscal_projection_commits");
    let (status, body) = issue_governed_fee_schedule(&node).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let signed: SignedOpenMarketFeeSchedule = serde_json::from_str(&body).test_unwrap();
    assert_eq!(signed.signer_key, node.custodian.head.public_key());
    assert_eq!(bound_envelope_digest(&node), None);
    assert_eq!(fiscal_rows(&node, "fiscal_legacy_fee_schedule_bindings"), 0);
    assert_eq!(
        fiscal_rows(&node, "fiscal_projection_commits"),
        projection_commits
    );
}
