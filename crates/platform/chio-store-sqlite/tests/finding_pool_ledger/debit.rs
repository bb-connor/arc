use super::*;

pub(super) fn debit_at(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    debit_at_with_status(
        ledger,
        fixture,
        purchase_id,
        amount_units,
        now_unix_ms,
        None,
        None,
    )
}

pub(super) fn debit_at_with_status(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
    status_verifier: Option<Arc<dyn FindingStatusProofVerifier>>,
    status_proof_b64: Option<&str>,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    debit_at_with_policy(
        ledger,
        fixture,
        purchase_id,
        amount_units,
        now_unix_ms,
        DebitStatusPolicy {
            status_verifier,
            status_proof_b64,
            purchase_admissions: Arc::new(AtomicU64::new(0)),
            reject_purchase_admission: false,
        },
    )
}

pub(super) struct DebitStatusPolicy<'a> {
    pub(super) status_verifier: Option<Arc<dyn FindingStatusProofVerifier>>,
    pub(super) status_proof_b64: Option<&'a str>,
    pub(super) purchase_admissions: Arc<AtomicU64>,
    pub(super) reject_purchase_admission: bool,
}

pub(super) fn debit_at_with_policy(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
    params: DebitStatusPolicy<'_>,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    let DebitStatusPolicy {
        status_verifier,
        status_proof_b64,
        purchase_admissions,
        reject_purchase_admission,
    } = params;
    debit_at_with_policy_and_kernel_key(
        ledger,
        fixture,
        purchase_id,
        amount_units,
        now_unix_ms,
        DebitKernelPolicy {
            status_verifier,
            status_proof_b64,
            purchase_admissions,
            reject_purchase_admission,
            kernel_key: Keypair::from_seed(&[99_u8; 32]),
        },
    )
}

pub(super) struct DebitKernelPolicy<'a> {
    pub(super) status_verifier: Option<Arc<dyn FindingStatusProofVerifier>>,
    pub(super) status_proof_b64: Option<&'a str>,
    pub(super) purchase_admissions: Arc<AtomicU64>,
    pub(super) reject_purchase_admission: bool,
    pub(super) kernel_key: Keypair,
}

pub(super) fn debit_at_with_policy_and_kernel_key(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
    params: DebitKernelPolicy<'_>,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    let DebitKernelPolicy {
        status_verifier,
        status_proof_b64,
        purchase_admissions,
        reject_purchase_admission,
        kernel_key,
    } = params;
    debit_at_with_policy_and_authority(
        ledger,
        fixture,
        purchase_id,
        amount_units,
        now_unix_ms,
        DebitAuthorityPolicy {
            status_verifier,
            status_proof_b64,
            purchase_admissions,
            reject_purchase_admission,
            kernel_key,
            allocation_authority: fixture.authority.public_key(),
            reject_purchase_verification: false,
        },
    )
}

pub(super) struct DebitAuthorityPolicy<'a> {
    pub(super) status_verifier: Option<Arc<dyn FindingStatusProofVerifier>>,
    pub(super) status_proof_b64: Option<&'a str>,
    pub(super) purchase_admissions: Arc<AtomicU64>,
    pub(super) reject_purchase_admission: bool,
    pub(super) kernel_key: Keypair,
    pub(super) allocation_authority: PublicKey,
    pub(super) reject_purchase_verification: bool,
}

pub(super) fn debit_at_with_policy_and_authority(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
    params: DebitAuthorityPolicy<'_>,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    let DebitAuthorityPolicy {
        status_verifier,
        status_proof_b64,
        purchase_admissions,
        reject_purchase_admission,
        kernel_key,
        allocation_authority,
        reject_purchase_verification,
    } = params;
    debit_at_with_policy_and_authority_and_tenant(
        ledger,
        fixture,
        purchase_id,
        amount_units,
        now_unix_ms,
        DebitPolicy {
            status_verifier,
            status_proof_b64,
            purchase_admissions,
            reject_purchase_admission,
            kernel_key,
            allocation_authority,
            reject_purchase_verification,
            tenant_id: None,
            session_state: SessionState::Ready,
        },
    )
}

pub(super) struct DebitPolicy<'a> {
    pub(super) status_verifier: Option<Arc<dyn FindingStatusProofVerifier>>,
    pub(super) status_proof_b64: Option<&'a str>,
    pub(super) purchase_admissions: Arc<AtomicU64>,
    pub(super) reject_purchase_admission: bool,
    pub(super) kernel_key: Keypair,
    pub(super) allocation_authority: PublicKey,
    pub(super) reject_purchase_verification: bool,
    pub(super) tenant_id: Option<&'a str>,
    pub(super) session_state: SessionState,
}

pub(super) fn debit_at_with_policy_and_authority_and_tenant(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
    params: DebitPolicy<'_>,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    let DebitPolicy {
        status_verifier,
        status_proof_b64,
        purchase_admissions,
        reject_purchase_admission,
        kernel_key,
        allocation_authority,
        reject_purchase_verification,
        tenant_id,
        session_state,
    } = params;
    let verified_purchase = VerifiedFindingPurchase {
        finding_id: "a".repeat(64),
        listing_id: "listing:cognition-market:1".to_string(),
        payload_sha256: "c".repeat(64),
        payload_media_type: "application/json".to_string(),
        expected_status_feed_id: "status-feed/test".to_string(),
        accepted_price: MonetaryAmount {
            units: amount_units,
            currency: "USD".to_string(),
        },
        payer_key_hex: fixture.purchaser.public_key().to_hex(),
        reservation_id: format!("reservation:{purchase_id}"),
        purchase_intent_id: purchase_id.to_string(),
        authoritative_payment_operation_id: format!("payment:{purchase_id}"),
        accepted_bid_envelope_sha256: sha256_hex(purchase_id.as_bytes()),
        venue_admission_envelope_sha256: "d".repeat(64),
        status_proof: None,
    };
    let verifier = StaticPurchaseVerifier {
        purchase: verified_purchase,
        admissions: purchase_admissions,
        reject_verification: reject_purchase_verification,
        reject_admission: reject_purchase_admission,
    };
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: kernel_key,
            ca_public_keys: Vec::new(),
            max_delegation_depth: 1,
            policy_hash: "finding-pool-ledger-test".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: HotPathDeadlineConfig::default(),
        },
        chio_test_support::clock::clock(),
    );
    kernel
        .set_receipt_store_handle(fixture.receipt_store.clone())
        .test_expect("configure durable receipt store");
    kernel.set_finding_purchase_verifier(Arc::new(verifier));
    kernel
        .set_finding_pool_allocation_authority(allocation_authority)
        .test_expect("configure pool allocation authority");
    kernel
        .set_finding_pool_receipt_authority(fixture.receipt_authority.clone())
        .test_expect("configure stable pool receipt authority");
    kernel
        .set_finding_pool_ledger(Arc::new(ledger.clone()))
        .test_expect("configure qualified pool ledger");
    if let Some(status_verifier) = status_verifier {
        kernel.set_finding_status_proof_verifier(status_verifier);
    }
    let marker = FindingPurchaseMarkerV1 {
        finding_id: "a".repeat(64),
        listing_id: "listing:cognition-market:1".to_string(),
        settlement: FindingSettlementSelector::LocalReversibleHold,
    };
    let capability = CapabilityToken {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        id: format!("capability:{purchase_id}"),
        issuer: fixture.authority.public_key(),
        subject: fixture.purchaser.public_key(),
        scope: ChioScope::default(),
        issued_at: 1,
        expires_at: u64::MAX,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
        algorithm: None,
        caveats: Vec::new(),
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
        signature: fixture.authority.sign(purchase_id.as_bytes()),
    };
    let agent_id = fixture.purchaser.public_key().to_hex();
    let session_id = kernel
        .open_session(agent_id.clone(), vec![capability.clone()])
        .test_expect("open authenticated purchaser session");
    if let Some(tenant_id) = tenant_id {
        kernel
            .set_session_auth_context(
                &session_id,
                SessionAuthContext::streamable_http_oauth_bearer_with_claims(
                    OAuthBearerSessionAuthInput {
                        principal: Some(format!("oidc:https://issuer.example#sub:{agent_id}")),
                        issuer: Some("https://issuer.example".to_owned()),
                        subject: Some(agent_id.clone()),
                        audience: Some("chio-mcp".to_owned()),
                        scopes: vec!["mcp:invoke".to_owned()],
                        federated_claims: OAuthBearerFederatedClaims {
                            sender_public_key: None,
                            tenant_id: Some(tenant_id.to_owned()),
                            ..OAuthBearerFederatedClaims::default()
                        },
                        enterprise_identity: None,
                        token_fingerprint: Some("finding-pool-test-token".to_owned()),
                        origin: Some("https://app.example".to_owned()),
                    },
                ),
            )
            .test_expect("install authenticated purchaser tenant");
    }
    match session_state {
        SessionState::Initializing => {}
        SessionState::Ready => kernel
            .activate_session(&session_id)
            .test_expect("activate purchaser session"),
        SessionState::Draining => {
            kernel
                .activate_session(&session_id)
                .test_expect("activate purchaser session before draining");
            kernel
                .begin_draining_session(&session_id)
                .test_expect("begin draining purchaser session");
        }
        SessionState::Closed => kernel
            .close_session(&session_id)
            .test_expect("close purchaser session"),
    }
    let operation_context = OperationContext::new(
        session_id,
        RequestId::new(format!("request:{purchase_id}")),
        agent_id,
    );
    let arguments = serde_json::Value::Null;
    let context_b64 = "test-purchase-context";
    let expected_output_digest = "c".repeat(64);
    let purchaser_authorization = SignedExportEnvelope::sign(
        FindingPoolDebitAuthorization {
            schema: FINDING_POOL_DEBIT_AUTHORIZATION_SCHEMA_V1.to_owned(),
            purchase_id: purchase_id.to_owned(),
            allocation_envelope_sha256: fixture.envelope_sha256.clone(),
            purchaser_id: fixture.allocation.body.purchaser_id.clone(),
            purchase_context_sha256: sha256_hex(context_b64.as_bytes()),
            capability_id: capability.id.clone(),
            server_id: "finding-server".to_owned(),
            tool_name: "read_finding".to_owned(),
            arguments_sha256: sha256_hex(
                &canonical_json_bytes(&arguments).test_expect("canonicalize debit arguments"),
            ),
            expected_output_digest: expected_output_digest.clone(),
            expires_at_unix_ms: now_unix_ms.saturating_add(60_000).to_string(),
        },
        &fixture.debit_signer,
    )
    .test_expect("sign purchaser debit authorization");
    let _runtime = chio_test_support::clock::scope_unix_secs(now_unix_ms / 1_000);
    kernel.debit_finding_pool_purchase(FindingPoolDebitRequest {
        operation_context: &operation_context,
        allocation: &fixture.allocation,
        pool: &fixture.pool,
        expected_allocation_envelope_sha256: &fixture.envelope_sha256,
        purchaser_id: &fixture.allocation.body.purchaser_id,
        purchaser_authorization: &purchaser_authorization,
        purchase_context: FindingPurchaseContextView {
            marker: &marker,
            context_b64,
            capability: &capability,
            server_id: "finding-server",
            tool_name: "read_finding",
            arguments: &arguments,
            expected_output_digest: &expected_output_digest,
        },
        status_proof_b64,
    })
}
