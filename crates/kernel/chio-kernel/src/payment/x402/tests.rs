use super::*;
use crate::execution_nonce::InMemoryExecutionNonceStore;
use crate::payment::test_http::{spawn_json_server, spawn_once_json_server};
use crate::payment::{PaymentJournalRecord, PaymentJournalTransition};
use chio_security_types::clock::{
    ClockError, ClockReading, FixedClock, MonotonicInstant, UnixMillis,
};
use std::sync::atomic::{AtomicU64, Ordering};

const NETWORK: &str = "eip155:84532";
const ASSET: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PAY_TO: &str = "0x2000000000000000000000000000000000000002";
const PAYER: &str = "0x1000000000000000000000000000000000000001";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRANSACTION: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VALID_AFTER: u64 = 1_744_000_000;
const VALID_BEFORE: u64 = 1_744_000_600;
const NOW: u64 = VALID_AFTER + 60;
const OTHER_NONCE: &str = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const UNREACHABLE: &str = "http://127.0.0.1:1";

fn identity_string() -> String {
    format!(
        "x402/{NETWORK}/{}/{PAYER}/{NONCE}/{VALID_BEFORE}",
        ASSET.to_ascii_lowercase()
    )
}

fn settled_authorization_id() -> String {
    format!(
        "{}/{TRANSACTION}/{}/{}",
        identity_string(),
        canonical_digest(&context().payment_payload).expect("payload digest"),
        canonical_digest(&settle_success()).expect("response digest")
    )
}

fn test_rail() -> X402RailConfig {
    X402RailConfig::new(
        X402Network::allowlisted(NETWORK).expect("allowlisted network"),
        ASSET,
        "USDC",
        6,
        PAY_TO,
    )
    .expect("valid rail")
}

fn clock_at(unix_secs: u64) -> Arc<dyn Clock> {
    Arc::new(FixedClock::from_millis(unix_secs * 1_000))
}

fn replay_store() -> Arc<dyn ExecutionNonceStore> {
    Arc::new(InMemoryExecutionNonceStore::with_clock(16, clock_at(NOW)))
}

fn adapter_with(
    facilitator: &str,
    clock: Arc<dyn Clock>,
    replay: Arc<dyn ExecutionNonceStore>,
) -> X402PaymentAdapter {
    X402PaymentAdapter::new(
        facilitator,
        test_rail(),
        &crate::payment::EgressAllowanceSet::default(),
        clock,
        replay,
    )
    .expect("valid facilitator")
    .with_timeout(Duration::from_secs(2))
}

fn adapter(facilitator: &str) -> X402PaymentAdapter {
    adapter_with(facilitator, clock_at(NOW), replay_store())
}

fn requirements() -> X402PaymentRequirements {
    X402PaymentRequirements {
        scheme: "exact".to_owned(),
        network: NETWORK.to_owned(),
        amount: "125".to_owned(),
        asset: ASSET.to_owned(),
        pay_to: PAY_TO.to_owned(),
        max_timeout_seconds: 60,
        extra: Some(serde_json::json!({ "name": "USDC", "version": "2" })),
    }
}

fn context() -> X402PaymentContext {
    X402PaymentContext {
        payment_payload: X402PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: requirements(),
            payload: X402ExactEvmPayload {
                signature: format!("0x{}", "c".repeat(130)),
                authorization: X402Eip3009Authorization {
                    from: PAYER.to_owned(),
                    to: PAY_TO.to_owned(),
                    value: "125".to_owned(),
                    valid_after: VALID_AFTER.to_string(),
                    valid_before: VALID_BEFORE.to_string(),
                    nonce: NONCE.to_owned(),
                },
            },
            extensions: None,
        },
        payment_requirements: requirements(),
    }
}

fn request(context: Option<X402PaymentContext>) -> PaymentAuthorizeRequest {
    PaymentAuthorizeRequest {
        amount_units: 125,
        currency: "USDC".to_owned(),
        payer: "agent-1".to_owned(),
        payee: "tool-server".to_owned(),
        reference: "operation-1".to_owned(),
        governed: None,
        commerce: None,
        x402: context,
        authority_expires_at: Some(VALID_BEFORE),
        reference_is_durable: true,
    }
}

fn settle_success() -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "payer": PAYER,
        "transaction": TRANSACTION,
        "network": NETWORK,
    })
}

fn refused(error: PaymentError, refusal: X402Refusal) -> bool {
    matches!(error, PaymentError::Declined(message) if message == refusal.to_string())
}

fn refuse_before_network(mutate: impl FnOnce(&mut PaymentAuthorizeRequest)) -> PaymentError {
    let mut request = request(Some(context()));
    mutate(&mut request);
    adapter(UNREACHABLE)
        .authorize(&request)
        .expect_err("the payment must be refused")
}

fn x402_mut(request: &mut PaymentAuthorizeRequest) -> &mut X402PaymentContext {
    request.x402.as_mut().expect("x402 context")
}

#[test]
fn authorize_verifies_then_settles_and_returns_the_rail_identity() {
    let (url, requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true, "payer": PAYER })),
        (200, settle_success()),
    ]);
    let authorization = adapter(&url)
        .with_bearer_token("facilitator-token")
        .authorize(&request(Some(context())))
        .expect("payment settles");

    let verify = requests.recv().expect("verify request");
    let settle = requests.recv().expect("settle request");
    handle.join().expect("facilitator stub exits");
    assert!(verify.starts_with("POST /verify HTTP/1.1"));
    assert!(settle.starts_with("POST /settle HTTP/1.1"));
    for captured in [&verify, &settle] {
        assert!(captured.contains("Authorization: Bearer facilitator-token"));
        assert!(captured.contains("\"x402Version\":2"));
        assert!(captured.contains("\"paymentPayload\":{"));
        assert!(captured.contains("\"paymentRequirements\":{"));
    }

    assert_eq!(authorization.authorization_id, settled_authorization_id());
    assert_eq!(authorization.state, PaymentAuthorizationState::PrepaidFinal);
    assert_eq!(authorization.metadata["adapter"], "x402");
    let settlement: X402SettlementRef =
        serde_json::from_value(authorization.metadata["x402"].clone()).expect("typed reference");
    assert_eq!(settlement.x402_version, 2);
    assert_eq!(settlement.scheme, "exact");
    assert_eq!(settlement.network, NETWORK);
    assert_eq!(settlement.transaction, TRANSACTION);
    assert_eq!(settlement.payer, PAYER);
    assert_eq!(
        settlement.payment_payload_digest,
        canonical_digest(&context().payment_payload).expect("payload digest")
    );
    assert_eq!(
        settlement.settlement_response_digest,
        canonical_digest(&settle_success()).expect("response digest")
    );
}

#[test]
fn authorize_refuses_a_missing_payment() {
    let error = adapter(UNREACHABLE)
        .authorize(&request(None))
        .expect_err("no payment presented");
    assert!(refused(error, X402Refusal::PaymentMissing));
}

#[test]
fn authorize_refuses_an_authorization_that_outlives_its_authority() {
    let error = refuse_before_network(|request| {
        request.authority_expires_at = Some(VALID_BEFORE - 1);
    });
    assert!(refused(error, X402Refusal::OutlivesAuthority));
}

#[test]
fn authorize_refuses_an_unknown_authority_expiry() {
    let error = refuse_before_network(|request| request.authority_expires_at = None);
    assert!(refused(error, X402Refusal::AuthorityExpiryMissing));
}

#[test]
fn authorize_refuses_other_protocol_versions_and_schemes() {
    let error = refuse_before_network(|request| x402_mut(request).payment_payload.x402_version = 1);
    assert!(refused(error, X402Refusal::UnsupportedVersion));

    let error = refuse_before_network(|request| {
        let context = x402_mut(request);
        context.payment_requirements.scheme = "upto".to_owned();
        context.payment_payload.accepted.scheme = "upto".to_owned();
    });
    assert!(refused(error, X402Refusal::UnsupportedScheme));
}

#[test]
fn authorize_refuses_a_payload_that_does_not_echo_the_requirements() {
    let error = refuse_before_network(|request| {
        x402_mut(request)
            .payment_payload
            .accepted
            .max_timeout_seconds = 120;
    });
    assert!(refused(error, X402Refusal::RequirementsMismatch));
}

#[test]
fn authorize_refuses_networks_off_the_testnet_allowlist() {
    let error = refuse_before_network(|request| {
        let context = x402_mut(request);
        context.payment_requirements.network = "eip155:8453".to_owned();
        context.payment_payload.accepted.network = "eip155:8453".to_owned();
    });
    assert!(refused(error, X402Refusal::NetworkNotAllowlisted));
    assert_eq!(
        X402Network::allowlisted("eip155:8453"),
        Err(X402Refusal::NetworkNotAllowlisted)
    );
}

#[test]
fn authorize_refuses_a_payment_to_another_rail() {
    let error = refuse_before_network(|request| {
        let context = x402_mut(request);
        context.payment_requirements.pay_to = PAYER.to_owned();
        context.payment_payload.accepted.pay_to = PAYER.to_owned();
    });
    assert!(refused(error, X402Refusal::RailMismatch));

    let error = refuse_before_network(|request| {
        let context = x402_mut(request);
        context.payment_requirements.asset = PAY_TO.to_owned();
        context.payment_payload.accepted.asset = PAY_TO.to_owned();
    });
    assert!(refused(error, X402Refusal::RailMismatch));

    let error = refuse_before_network(|request| {
        x402_mut(request).payment_payload.payload.authorization.to = PAYER.to_owned();
    });
    assert!(refused(error, X402Refusal::RailMismatch));
}

#[test]
fn authorize_refuses_an_amount_other_than_the_charge() {
    let error = refuse_before_network(|request| request.amount_units = 126);
    assert!(refused(error, X402Refusal::AmountMismatch));

    let error = refuse_before_network(|request| {
        x402_mut(request)
            .payment_payload
            .payload
            .authorization
            .value = "124".to_owned();
    });
    assert!(refused(error, X402Refusal::AmountMismatch));
}

#[test]
fn authorize_refuses_a_malformed_authorization() {
    let error = refuse_before_network(|request| {
        x402_mut(request)
            .payment_payload
            .payload
            .authorization
            .nonce = "0x01".to_owned();
    });
    assert!(refused(error, X402Refusal::MalformedAuthorization));

    let error = refuse_before_network(|request| {
        x402_mut(request)
            .payment_payload
            .payload
            .authorization
            .valid_after = VALID_BEFORE.to_string();
    });
    assert!(refused(error, X402Refusal::MalformedAuthorization));

    let error = refuse_before_network(|request| {
        x402_mut(request)
            .payment_payload
            .payload
            .authorization
            .value = "0125".to_owned();
    });
    assert!(refused(error, X402Refusal::MalformedAuthorization));

    let error = refuse_before_network(|request| {
        x402_mut(request).payment_payload.payload.signature = "0x".to_owned();
    });
    assert!(refused(error, X402Refusal::MalformedAuthorization));
}

#[test]
fn authorize_stops_at_a_rejected_verification() {
    let (url, requests, handle) =
        spawn_once_json_server(200, serde_json::json!({ "isValid": false }));
    let error = adapter(&url)
        .authorize(&request(Some(context())))
        .expect_err("verification rejected");
    handle.join().expect("facilitator stub exits");
    assert!(refused(error, X402Refusal::VerifyRejected));
    assert!(requests
        .recv()
        .expect("verify request")
        .starts_with("POST /verify HTTP/1.1"));
    assert_eq!(
        requests.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected),
        "settle must not be called"
    );
}

#[test]
fn authorize_refuses_when_verification_is_unavailable() {
    let (url, _requests, handle) = spawn_once_json_server(503, serde_json::json!({}));
    let error = adapter(&url)
        .authorize(&request(Some(context())))
        .expect_err("verification unavailable");
    handle.join().expect("facilitator stub exits");
    assert!(refused(error, X402Refusal::VerifyFailed));
}

#[test]
fn unconfirmed_settlement_is_ambiguous() {
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (
            200,
            serde_json::json!({
                "success": false,
                "errorReason": "insufficient_funds",
                "transaction": "",
                "network": NETWORK,
            }),
        ),
    ]);
    let error = adapter(&url)
        .authorize(&request(Some(context())))
        .expect_err("settlement not confirmed");
    handle.join().expect("facilitator stub exits");
    assert!(
        matches!(error, PaymentError::RailError(message) if message == "x402 facilitator did not confirm settlement")
    );
}

#[test]
fn settlement_on_another_network_is_rejected() {
    let mut response = settle_success();
    response["network"] = serde_json::json!("eip155:8453");
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (200, response),
    ]);
    let error = adapter(&url)
        .authorize(&request(Some(context())))
        .expect_err("settlement binding invalid");
    handle.join().expect("facilitator stub exits");
    assert!(
        matches!(error, PaymentError::RailError(message) if message == "x402 settlement response binding is invalid")
    );
}

#[test]
fn unavailable_settlement_stays_unavailable() {
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (503, serde_json::json!({})),
    ]);
    let error = adapter(&url)
        .authorize(&request(Some(context())))
        .expect_err("settlement unavailable");
    handle.join().expect("facilitator stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 facilitator settlement is unavailable")
    );
}

fn no_status_query(error: PaymentError) -> bool {
    matches!(error, PaymentError::Unavailable(message) if message == "x402 has no settlement status query")
}

#[test]
fn recovery_has_no_rail_status_query() {
    let adapter = adapter(UNREACHABLE);
    assert!(no_status_query(
        adapter
            .settlement_state("operation-1", None)
            .expect_err("no status query")
    ));
    assert!(no_status_query(
        adapter
            .settlement_state("operation-1", Some(&settled_authorization_id()))
            .expect_err("no status query")
    ));
}

#[test]
fn authorize_refuses_a_reference_without_durable_admission() {
    let error = refuse_before_network(|request| request.reference_is_durable = false);
    assert!(refused(error, X402Refusal::DurableReferenceRequired));
}

#[test]
fn authorize_refuses_a_charge_outside_the_token_base_unit() {
    let error = refuse_before_network(|request| request.currency = "USD".to_owned());
    assert!(refused(error, X402Refusal::UnitMismatch));
}

#[test]
fn rail_config_refuses_invalid_values() {
    let network = || X402Network::allowlisted(NETWORK).expect("allowlisted network");
    assert_eq!(
        X402RailConfig::new(network(), ASSET, "USDC", 37, PAY_TO),
        Err(X402Refusal::InvalidRailConfig)
    );
    assert_eq!(
        X402RailConfig::new(network(), ASSET, "US DC", 6, PAY_TO),
        Err(X402Refusal::InvalidRailConfig)
    );
    assert_eq!(
        X402RailConfig::new(network(), "0x1234", "USDC", 6, PAY_TO),
        Err(X402Refusal::InvalidRailConfig)
    );
}

#[test]
fn facilitator_url_is_validated_at_construction() {
    for url in [
        "http://facilitator.example",
        "https://facilitator.example?key=secret",
        "https://user:pass@facilitator.example",
        "https://facilitator.example#fragment",
        "not a url",
    ] {
        let error = X402PaymentAdapter::new(
            url,
            test_rail(),
            &crate::payment::EgressAllowanceSet::default(),
            clock_at(NOW),
            replay_store(),
        )
        .expect_err(url);
        assert!(
            matches!(&error, PaymentError::RailError(message) if message == "payment rail URL is invalid"),
            "{url}: {error:?}"
        );
    }
    X402PaymentAdapter::new(
        "https://facilitator.example/x402",
        test_rail(),
        &crate::payment::EgressAllowanceSet::default(),
        clock_at(NOW),
        replay_store(),
    )
    .expect("an https facilitator with a path is valid");
}

#[test]
fn facilitator_outside_the_public_network_is_refused_at_construction() {
    for url in [
        "https://10.0.0.1",
        "https://localhost",
        "https://[fd00::1]",
        "https://169.254.169.254",
    ] {
        let error = X402PaymentAdapter::new(
            url,
            test_rail(),
            &crate::payment::EgressAllowanceSet::default(),
            clock_at(NOW),
            replay_store(),
        )
        .expect_err(url);
        assert!(
            matches!(&error, PaymentError::RailError(message) if message == "payment rail egress denied"),
            "{url}: {error:?}"
        );
    }
}

#[test]
fn settlement_without_a_payer_is_rejected() {
    let mut response = settle_success();
    response
        .as_object_mut()
        .expect("settle response object")
        .remove("payer");
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (200, response),
    ]);
    let error = adapter(&url)
        .authorize(&request(Some(context())))
        .expect_err("payer missing");
    handle.join().expect("facilitator stub exits");
    assert!(
        matches!(error, PaymentError::RailError(message) if message == "x402 settlement response binding is invalid")
    );
}

#[test]
fn recovery_refuses_an_identity_outside_the_configured_rail() {
    let other_asset = settled_authorization_id().replace(&ASSET.to_ascii_lowercase(), PAY_TO);
    let error = adapter(UNREACHABLE)
        .settlement_state("operation-1", Some(&other_asset))
        .expect_err("other asset");
    assert!(
        matches!(error, PaymentError::RailError(message) if message == "x402 authorization identity is outside the configured rail")
    );
}

#[test]
fn settled_authorization_round_trips_through_its_canonical_form() {
    let settled = X402SettledAuthorization::parse(&settled_authorization_id())
        .expect("settled authorization parses");
    assert_eq!(settled.identity.network, NETWORK);
    assert_eq!(settled.identity.asset, ASSET.to_ascii_lowercase());
    assert_eq!(settled.identity.from, PAYER);
    assert_eq!(settled.identity.nonce, NONCE);
    assert_eq!(settled.identity.valid_before, VALID_BEFORE);
    assert_eq!(settled.identity.to_string(), identity_string());
    assert_eq!(settled.transaction, TRANSACTION);
    assert_eq!(settled.to_string(), settled_authorization_id());
    assert!(payment_identifier_is_valid(&settled.to_string()));
}

#[test]
fn non_canonical_authorization_identities_are_refused_exactly() {
    let canonical = settled_authorization_id();
    let asset = ASSET.to_ascii_lowercase();
    let payload_digest = canonical_digest(&context().payment_payload).expect("payload digest");
    for invalid in [
        identity_string(),
        canonical.to_ascii_uppercase(),
        canonical.replace(&asset, ASSET),
        canonical.replace(&format!("/{PAYER}/"), &format!("/0X{}/", &PAYER[2..])),
        canonical.replace(&format!("/{PAYER}/"), &format!("/{}/", &PAYER[2..])),
        canonical.replace(NONCE, &NONCE[..64]),
        canonical.replace(NONCE, &NONCE.replace('a', "A")),
        canonical.replace(NETWORK, "eip155:8453"),
        canonical.replace(NETWORK, "eip155:084532"),
        canonical.replace("/1744000600", "/01744000600"),
        canonical.replace("x402/", "X402/"),
        canonical.replace(TRANSACTION, &TRANSACTION.replace('b', "B")),
        canonical.replace(&payload_digest, &payload_digest[..63]),
        canonical.replace(&payload_digest, &payload_digest.to_ascii_uppercase()),
        format!("{canonical}/extra"),
        format!(" {canonical}"),
        format!("{canonical} "),
        canonical.replacen('/', "//", 1),
    ] {
        let error = adapter(UNREACHABLE)
            .settlement_state("operation-1", Some(&invalid))
            .expect_err("non-canonical identity");
        assert!(
            matches!(&error, PaymentError::RailError(message) if message == "x402 authorization identity is invalid"),
            "{invalid}: {error:?}"
        );
    }
}

#[test]
fn valid_before_is_bound_to_exactly_the_authority_expiry() {
    let (url, requests, handle) =
        spawn_once_json_server(200, serde_json::json!({ "isValid": false }));
    let mut at_expiry = request(Some(context()));
    at_expiry.authority_expires_at = Some(VALID_BEFORE);
    let error = adapter(&url)
        .authorize(&at_expiry)
        .expect_err("verification stub rejects");
    handle.join().expect("facilitator stub exits");
    assert!(refused(error, X402Refusal::VerifyRejected));
    assert!(requests
        .recv()
        .expect("an authorization ending at the authority expiry reaches the facilitator")
        .starts_with("POST /verify HTTP/1.1"));

    let mut one_second_past = request(Some(context()));
    one_second_past.authority_expires_at = Some(VALID_BEFORE - 1);
    let error = adapter(UNREACHABLE)
        .authorize(&one_second_past)
        .expect_err("one second past the authority expiry");
    assert!(refused(error, X402Refusal::OutlivesAuthority));
}

#[test]
fn final_prepayment_has_no_release_or_refund() {
    let adapter = adapter(UNREACHABLE);
    assert!(
        matches!(adapter.release("authorization", "operation-1"), Err(PaymentError::Unavailable(message)) if message == "x402 final prepayment has no releasable hold")
    );
    assert!(
        matches!(adapter.refund("transaction", 125, "USDC", "operation-1"), Err(PaymentError::Unavailable(message)) if message == "x402 remote refund is unsupported")
    );
}

fn pending_settlement(transaction: &str, network: &str) -> serde_json::Value {
    serde_json::json!({
        "success": false,
        "errorReason": "settlement_pending",
        "transaction": transaction,
        "network": network,
    })
}

#[test]
fn pending_settlement_preserves_the_broadcast_transaction() {
    let pending = pending_settlement(TRANSACTION, NETWORK);
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (200, pending.clone()),
    ]);
    let error = adapter(&url)
        .authorize(&request(Some(context())))
        .expect_err("a pending settlement is not a confirmed prepayment");
    handle.join().expect("facilitator stub exits");
    let PaymentError::OutcomeUnknown { evidence, .. } = error else {
        panic!("a pending settlement must be outcome-unknown, got {error:?}");
    };
    assert_eq!(evidence["adapter"], "x402");
    assert_eq!(evidence["settlement"], "pending");
    assert_eq!(evidence["authorization_identity"], identity_string());
    let settlement: X402SettlementRef =
        serde_json::from_value(evidence["x402"].clone()).expect("typed reference");
    assert_eq!(settlement.network, NETWORK);
    assert_eq!(settlement.transaction, TRANSACTION);
    assert_eq!(settlement.payer, PAYER);
    assert_eq!(
        settlement.payment_payload_digest,
        canonical_digest(&context().payment_payload).expect("payload digest")
    );
    assert_eq!(
        settlement.settlement_response_digest,
        canonical_digest(&pending).expect("response digest")
    );
}

#[test]
fn pending_settlement_without_a_bound_transaction_is_rejected() {
    for pending in [
        pending_settlement("", NETWORK),
        pending_settlement(TRANSACTION, "eip155:8453"),
        pending_settlement(&TRANSACTION[..64], NETWORK),
    ] {
        let (url, _requests, handle) = spawn_json_server(vec![
            (200, serde_json::json!({ "isValid": true })),
            (200, pending.clone()),
        ]);
        let error = adapter(&url)
            .authorize(&request(Some(context())))
            .expect_err("pending settlement binding invalid");
        handle.join().expect("facilitator stub exits");
        assert!(
            matches!(&error, PaymentError::RailError(message) if message == "x402 settlement response binding is invalid"),
            "{pending}: {error:?}"
        );
    }
}

fn settled_prepaid_journal(authorization_id: &str) -> PaymentJournalRecord {
    PaymentJournalRecord {
        operation_id: "operation-1".to_owned(),
        journal_version: 1,
        request_namespace_digest: "a".repeat(64),
        request_id: "request-1".to_owned(),
        capability_id: "capability-1".to_owned(),
        grant_index: 0,
        hold_id: Some("hold-1".to_owned()),
        rail: "x402".to_owned(),
        rail_mode: PaymentRailMode::PrepaidFinal,
        rail_egress_allowance_digest: crate::payment::EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST
            .to_owned(),
        authorization_id: None,
        transaction_id: None,
        amount_units: 125,
        authorized_amount_units: Some(125),
        authorization_attempt: Some(crate::payment::PaymentAuthorizationAttempt::NotStarted),
        settle_action: None,
        settle_amount_units: None,
        release_authority: None,
        currency: "USD".to_owned(),
        state: crate::payment::PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1_700_000_000_000,
    }
    .apply_transition(&PaymentJournalTransition::BeginAuthorizationAttempt)
    .and_then(|journal| {
        journal.apply_transition(&PaymentJournalTransition::PrepaymentSettled {
            authorization_id: authorization_id.to_owned(),
        })
    })
    .expect("settled prepaid journal")
}

#[test]
fn durable_replay_restores_the_settlement_reference() {
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (200, settle_success()),
    ]);
    let adapter = adapter(&url);
    let authorization = adapter
        .authorize(&request(Some(context())))
        .expect("payment settles");
    handle.join().expect("facilitator stub exits");

    let replayed = crate::payment::replayed_payment_authorization(
        &adapter,
        &settled_prepaid_journal(&authorization.authorization_id),
    )
    .expect("replay succeeds")
    .expect("settled journal replays its authorization");
    assert_eq!(replayed.authorization_id, authorization.authorization_id);
    assert_eq!(replayed.state, PaymentAuthorizationState::PrepaidFinal);
    assert_eq!(replayed.metadata["adapter"], "x402");
    assert_eq!(replayed.metadata["mode"], "prepaid");
    assert_eq!(replayed.metadata["durable_replay"], true);
    assert_eq!(replayed.metadata["x402"], authorization.metadata["x402"]);
}

#[test]
fn durable_replay_refuses_an_identifier_it_cannot_bind() {
    let adapter = adapter(UNREACHABLE);
    for authorization_id in [
        identity_string(),
        settled_authorization_id().replace(&ASSET.to_ascii_lowercase(), PAY_TO),
        settled_authorization_id().replace(TRANSACTION, &TRANSACTION[..64]),
        format!("{}/extra", settled_authorization_id()),
    ] {
        let error = crate::payment::replayed_payment_authorization(
            &adapter,
            &settled_prepaid_journal(&authorization_id),
        )
        .expect_err("replay must not drop the settlement reference");
        assert!(
            matches!(&error, PaymentError::RailError(_)),
            "{authorization_id}: {error:?}"
        );
    }
}

fn settling_facilitator(
    settlements: usize,
) -> (
    String,
    std::sync::mpsc::Receiver<String>,
    std::thread::JoinHandle<()>,
) {
    spawn_json_server(
        (0..settlements)
            .flat_map(|_| {
                [
                    (200, serde_json::json!({ "isValid": true })),
                    (200, settle_success()),
                ]
            })
            .collect(),
    )
}

fn with_nonce(nonce: &str) -> X402PaymentContext {
    let mut context = context();
    context.payment_payload.payload.authorization.nonce = nonce.to_owned();
    context
}

#[test]
fn authorize_refuses_an_authorization_before_its_valid_after() {
    for now in [VALID_AFTER - 1, VALID_AFTER] {
        let error = adapter_with(UNREACHABLE, clock_at(now), replay_store())
            .authorize(&request(Some(context())))
            .expect_err("authorization is not yet valid");
        assert!(refused(
            error,
            X402Refusal::NotYetValid {
                now,
                valid_after: VALID_AFTER,
            }
        ));
    }
}

#[test]
fn authorize_refuses_an_expired_authorization() {
    for now in [VALID_BEFORE, VALID_BEFORE + 1] {
        let error = adapter_with(UNREACHABLE, clock_at(now), replay_store())
            .authorize(&request(Some(context())))
            .expect_err("authorization expired");
        assert!(refused(
            error,
            X402Refusal::Expired {
                now,
                valid_before: VALID_BEFORE,
            }
        ));
    }
}

#[test]
fn authorize_reaches_the_facilitator_inside_the_validity_window() {
    for now in [VALID_AFTER + 1, VALID_BEFORE - 1] {
        let (url, requests, handle) = settling_facilitator(1);
        let replay: Arc<dyn ExecutionNonceStore> =
            Arc::new(InMemoryExecutionNonceStore::with_clock(16, clock_at(now)));
        let authorization = adapter_with(&url, clock_at(now), replay)
            .authorize(&request(Some(context())))
            .expect("payment settles inside the window");
        handle.join().expect("facilitator stub exits");
        assert_eq!(authorization.authorization_id, settled_authorization_id());
        assert!(requests
            .recv()
            .expect("verify request")
            .starts_with("POST /verify HTTP/1.1"));
        assert!(requests
            .recv()
            .expect("settle request")
            .starts_with("POST /settle HTTP/1.1"));
    }
}

#[test]
fn authorize_refuses_a_nonce_already_settled() {
    let (url, requests, handle) = settling_facilitator(1);
    let adapter = adapter(&url);
    adapter
        .authorize(&request(Some(context())))
        .expect("first use settles");
    handle.join().expect("facilitator stub exits");
    assert_eq!(requests.iter().count(), 2);

    let error = adapter
        .authorize(&request(Some(context())))
        .expect_err("second use refused");
    assert!(refused(error, X402Refusal::NonceReused));
}

#[test]
fn authorize_refuses_a_nonce_settled_before_a_restart() {
    let replay = replay_store();
    let (url, _requests, handle) = settling_facilitator(1);
    adapter_with(&url, clock_at(NOW), replay.clone())
        .authorize(&request(Some(context())))
        .expect("first use settles");
    handle.join().expect("facilitator stub exits");

    let error = adapter_with(UNREACHABLE, clock_at(NOW), replay)
        .authorize(&request(Some(context())))
        .expect_err("restarted adapter refuses the reused nonce");
    assert!(refused(error, X402Refusal::NonceReused));
}

#[test]
fn authorize_accepts_distinct_nonces_from_one_payer() {
    let (url, _requests, handle) = settling_facilitator(2);
    let adapter = adapter(&url);
    adapter
        .authorize(&request(Some(with_nonce(NONCE))))
        .expect("first nonce settles");
    adapter
        .authorize(&request(Some(with_nonce(OTHER_NONCE))))
        .expect("second nonce settles");
    handle.join().expect("facilitator stub exits");
}

#[test]
fn rejected_verification_leaves_the_nonce_unspent() {
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": false })),
        (200, serde_json::json!({ "isValid": true })),
        (200, settle_success()),
    ]);
    let adapter = adapter(&url);
    let error = adapter
        .authorize(&request(Some(context())))
        .expect_err("verification rejected");
    assert!(refused(error, X402Refusal::VerifyRejected));
    adapter
        .authorize(&request(Some(context())))
        .expect("the unspent nonce settles");
    handle.join().expect("facilitator stub exits");
}

#[test]
fn settlement_without_confirmation_spends_the_nonce() {
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (503, serde_json::json!({})),
    ]);
    let adapter = adapter(&url);
    let error = adapter
        .authorize(&request(Some(context())))
        .expect_err("settlement unavailable");
    handle.join().expect("facilitator stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 facilitator settlement is unavailable")
    );
    let error = adapter
        .authorize(&request(Some(context())))
        .expect_err("a possibly broadcast nonce is spent");
    assert!(refused(error, X402Refusal::NonceReused));
}

/// Answers `NOW` for the first read and `VALID_BEFORE` afterwards, so the
/// verification round trip crosses the authorization's expiry.
struct ExpiringClock(AtomicU64);

impl Clock for ExpiringClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let reads = self.0.fetch_add(1, Ordering::SeqCst);
        let unix_secs = if reads == 0 { NOW } else { VALID_BEFORE };
        Ok(ClockReading::new(
            UnixMillis::from_secs(unix_secs)?,
            MonotonicInstant::from_nanos(reads),
        ))
    }
}

#[test]
fn expiry_during_verification_refuses_before_settlement() {
    let (url, requests, handle) =
        spawn_once_json_server(200, serde_json::json!({ "isValid": true }));
    let replay = replay_store();
    let error = adapter_with(
        &url,
        Arc::new(ExpiringClock(AtomicU64::new(0))),
        replay.clone(),
    )
    .authorize(&request(Some(context())))
    .expect_err("authorization expired while verifying");
    handle.join().expect("facilitator stub exits");
    assert!(refused(
        error,
        X402Refusal::Expired {
            now: VALID_BEFORE,
            valid_before: VALID_BEFORE,
        }
    ));
    assert_eq!(requests.iter().count(), 1, "settle must not be called");
    assert!(matches!(
        replay.is_consumed(&format!(
            "x402/{NETWORK}/{}/{PAYER}/{NONCE}",
            ASSET.to_ascii_lowercase()
        )),
        Ok(false)
    ));
}

#[test]
fn a_spent_nonce_is_refused_under_another_signed_expiry() {
    let (url, _requests, handle) = settling_facilitator(1);
    let adapter = adapter(&url);
    adapter
        .authorize(&request(Some(context())))
        .expect("first use settles");
    handle.join().expect("facilitator stub exits");

    let mut shorter = request(Some(context()));
    x402_mut(&mut shorter)
        .payment_payload
        .payload
        .authorization
        .valid_before = (VALID_BEFORE - 1).to_string();
    let error = adapter
        .authorize(&shorter)
        .expect_err("the nonce is spent whatever its expiry");
    assert!(refused(error, X402Refusal::NonceReused));
}

#[test]
fn a_malformed_authorization_leaves_the_nonce_unspent() {
    let (url, _requests, handle) = settling_facilitator(1);
    let adapter = adapter(&url);
    let mut malformed = request(Some(context()));
    x402_mut(&mut malformed).payment_payload.payload.signature = "0x".to_owned();
    let error = adapter
        .authorize(&malformed)
        .expect_err("malformed authorization refused");
    assert!(refused(error, X402Refusal::MalformedAuthorization));
    adapter
        .authorize(&request(Some(context())))
        .expect("the unspent nonce settles");
    handle.join().expect("facilitator stub exits");
}

#[test]
fn journal_replay_of_a_spent_nonce_restores_its_settlement() {
    let (url, _requests, handle) = settling_facilitator(1);
    let adapter = adapter(&url);
    let authorization = adapter
        .authorize(&request(Some(context())))
        .expect("first use settles");
    handle.join().expect("facilitator stub exits");

    let mut other_operation = request(Some(context()));
    other_operation.reference = "operation-2".to_owned();
    let error = adapter
        .authorize(&other_operation)
        .expect_err("another operation cannot reuse the nonce");
    assert!(refused(error, X402Refusal::NonceReused));
    assert_eq!(
        adapter
            .replayed_authorization_metadata(&authorization.authorization_id)
            .expect("the owning operation replays from its journal"),
        authorization.metadata
    );
}

#[test]
fn an_unavailable_clock_refuses_before_the_facilitator() {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::new(u64::MAX));
    let error = adapter_with(UNREACHABLE, clock, replay_store())
        .authorize(&request(Some(context())))
        .expect_err("no trusted time");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 trusted clock is unavailable")
    );
}

/// Trusted clock whose wall and monotonic time advance together on demand.
struct AdvancingClock(AtomicU64);

impl AdvancingClock {
    fn starting_at(unix_secs: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(unix_secs)))
    }

    fn advance_to(&self, unix_secs: u64) {
        self.0.store(unix_secs, Ordering::SeqCst);
    }
}

impl Clock for AdvancingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let unix_secs = self.0.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            UnixMillis::from_secs(unix_secs)?,
            MonotonicInstant::from_nanos(unix_secs * 1_000_000_000),
        ))
    }
}

const SHORT_VALID_BEFORE: u64 = NOW + 100;
/// Past the short authorization's expiry plus the replay store's grace, and
/// still inside the long authorization's window.
const AFTER_SHORT_RETENTION: u64 = SHORT_VALID_BEFORE + 61;

fn expiring_at(valid_before: u64) -> PaymentAuthorizeRequest {
    let mut request = request(Some(context()));
    x402_mut(&mut request)
        .payment_payload
        .payload
        .authorization
        .valid_before = valid_before.to_string();
    request
}

#[test]
fn a_spent_nonce_outlives_the_expiry_it_was_signed_with() {
    let clock = AdvancingClock::starting_at(NOW);
    let replay: Arc<dyn ExecutionNonceStore> =
        Arc::new(InMemoryExecutionNonceStore::with_clock(16, clock.clone()));
    let (url, _requests, handle) = settling_facilitator(1);
    adapter_with(&url, clock.clone(), replay.clone())
        .authorize(&expiring_at(SHORT_VALID_BEFORE))
        .expect("the short authorization settles");
    handle.join().expect("facilitator stub exits");

    clock.advance_to(AFTER_SHORT_RETENTION);
    let error = adapter_with(UNREACHABLE, clock.clone(), replay.clone())
        .authorize(&expiring_at(VALID_BEFORE))
        .expect_err("the nonce stays spent under a later expiry");
    assert!(refused(error, X402Refusal::NonceReused));

    let (url, _requests, handle) = settling_facilitator(1);
    let mut other = expiring_at(VALID_BEFORE);
    x402_mut(&mut other)
        .payment_payload
        .payload
        .authorization
        .nonce = OTHER_NONCE.to_owned();
    adapter_with(&url, clock, replay)
        .authorize(&other)
        .expect("a distinct nonce still settles");
    handle.join().expect("facilitator stub exits");
}

#[test]
fn an_uncertain_settlement_keeps_the_nonce_past_its_expiry() {
    let clock = AdvancingClock::starting_at(NOW);
    let replay: Arc<dyn ExecutionNonceStore> =
        Arc::new(InMemoryExecutionNonceStore::with_clock(16, clock.clone()));
    let (url, _requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (503, serde_json::json!({})),
    ]);
    let error = adapter_with(&url, clock.clone(), replay.clone())
        .authorize(&expiring_at(SHORT_VALID_BEFORE))
        .expect_err("settlement unavailable");
    handle.join().expect("facilitator stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 facilitator settlement is unavailable")
    );

    clock.advance_to(AFTER_SHORT_RETENTION);
    let error = adapter_with(UNREACHABLE, clock, replay)
        .authorize(&expiring_at(VALID_BEFORE))
        .expect_err("a possibly broadcast nonce stays spent");
    assert!(refused(error, X402Refusal::NonceReused));
}

#[test]
fn a_full_replay_store_refuses_before_settlement() {
    let replay: Arc<dyn ExecutionNonceStore> =
        Arc::new(InMemoryExecutionNonceStore::with_clock(1, clock_at(NOW)));
    let (url, requests, handle) = spawn_json_server(vec![
        (200, serde_json::json!({ "isValid": true })),
        (200, settle_success()),
        (200, serde_json::json!({ "isValid": true })),
    ]);
    let adapter = adapter_with(&url, clock_at(NOW), replay);
    adapter
        .authorize(&request(Some(with_nonce(NONCE))))
        .expect("the first nonce settles");
    let error = adapter
        .authorize(&request(Some(with_nonce(OTHER_NONCE))))
        .expect_err("no capacity for a second nonce");
    handle.join().expect("facilitator stub exits");
    assert!(refused(error, X402Refusal::ReplayCapacityExhausted));
    let paths: Vec<String> = requests
        .iter()
        .map(|request| request.lines().next().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        paths,
        [
            "POST /verify HTTP/1.1",
            "POST /settle HTTP/1.1",
            "POST /verify HTTP/1.1"
        ]
    );
}
