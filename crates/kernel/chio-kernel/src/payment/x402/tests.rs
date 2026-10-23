use super::*;
use crate::payment::test_http::{spawn_json_server, spawn_once_json_server};

const NETWORK: &str = "eip155:84532";
const ASSET: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PAY_TO: &str = "0x2000000000000000000000000000000000000002";
const PAYER: &str = "0x1000000000000000000000000000000000000001";
const NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRANSACTION: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VALID_AFTER: u64 = 1_744_000_000;
const VALID_BEFORE: u64 = 1_744_000_600;
const UNREACHABLE: &str = "http://127.0.0.1:1";

fn identity_string() -> String {
    format!(
        "x402/{NETWORK}/{}/{PAYER}/{NONCE}/{VALID_BEFORE}",
        ASSET.to_ascii_lowercase()
    )
}

fn test_rail() -> X402RailConfig {
    X402RailConfig::new(
        X402Network::allowlisted(NETWORK).expect("allowlisted network"),
        ASSET,
        "USDC",
        PAY_TO,
    )
    .expect("valid rail")
}

fn adapter(facilitator: &str, rpc: &str) -> X402PaymentAdapter {
    X402PaymentAdapter::new(facilitator, rpc, test_rail()).with_timeout(Duration::from_secs(2))
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
    adapter(UNREACHABLE, UNREACHABLE)
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
    let authorization = adapter(&url, UNREACHABLE)
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

    assert_eq!(authorization.authorization_id, identity_string());
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
    let error = adapter(UNREACHABLE, UNREACHABLE)
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

    let error = refuse_before_network(|request| request.currency = "USD".to_owned());
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
    let error = adapter(&url, UNREACHABLE)
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
    let error = adapter(&url, UNREACHABLE)
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
    let error = adapter(&url, UNREACHABLE)
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
    let error = adapter(&url, UNREACHABLE)
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
    let error = adapter(&url, UNREACHABLE)
        .authorize(&request(Some(context())))
        .expect_err("settlement unavailable");
    handle.join().expect("facilitator stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 facilitator settlement is unavailable")
    );
}

#[test]
fn recovery_without_the_authorization_identity_is_unavailable() {
    let error = adapter(UNREACHABLE, UNREACHABLE)
        .settlement_state("operation-1", None)
        .expect_err("no identity");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 settlement state requires the authorization identity")
    );
}

fn rpc_result(result: serde_json::Value) -> (u16, serde_json::Value) {
    (
        200,
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
    )
}

fn state_word(used: bool) -> serde_json::Value {
    serde_json::json!(format!("0x{:064}", u8::from(used)))
}

fn log(topic: &str) -> serde_json::Value {
    serde_json::json!([{
        "address": ASSET,
        "topics": [topic, format!("0x{:0>64}", &PAYER[2..]), NONCE],
        "transactionHash": TRANSACTION,
        "removed": false,
    }])
}

#[test]
fn used_authorization_with_its_event_is_settled() {
    let (rpc, requests, handle) = spawn_json_server(vec![
        rpc_result(state_word(true)),
        rpc_result(log(AUTHORIZATION_USED_TOPIC)),
    ]);
    let identity = identity_string();
    let state = adapter(UNREACHABLE, &format!("{rpc}/rpc"))
        .settlement_state("operation-1", Some(&identity))
        .expect("rail state");
    handle.join().expect("rpc stub exits");

    let RailSettlementState::Settled {
        authorization_id,
        result,
    } = state
    else {
        panic!("expected a settled state, got {state:?}");
    };
    assert_eq!(authorization_id, identity);
    assert_eq!(result.transaction_id, identity);
    assert_eq!(result.settlement_status, RailSettlementStatus::Settled);
    assert_eq!(result.metadata["transaction"], TRANSACTION);

    let call = requests.recv().expect("eth_call request");
    assert!(call.starts_with("POST /rpc HTTP/1.1"));
    assert!(call.contains("\"method\":\"eth_call\""));
    assert!(call.contains(&format!(
        "\"data\":\"0xe94a0102{:0>64}{}\"",
        &PAYER[2..],
        &NONCE[2..]
    )));
    let logs = requests.recv().expect("eth_getLogs request");
    assert!(logs.contains("\"method\":\"eth_getLogs\""));
    assert!(logs.contains(AUTHORIZATION_USED_TOPIC));
}

#[test]
fn canceled_authorization_moved_no_money() {
    let (rpc, _requests, handle) = spawn_json_server(vec![
        rpc_result(state_word(true)),
        rpc_result(serde_json::json!([])),
        rpc_result(log(AUTHORIZATION_CANCELED_TOPIC)),
    ]);
    let state = adapter(UNREACHABLE, &rpc)
        .settlement_state("operation-1", Some(&identity_string()))
        .expect("rail state");
    handle.join().expect("rpc stub exits");
    assert_eq!(state, RailSettlementState::NoAuthorization);
}

#[test]
fn consumed_authorization_without_an_event_is_unavailable() {
    let (rpc, _requests, handle) = spawn_json_server(vec![
        rpc_result(state_word(true)),
        rpc_result(serde_json::json!([])),
        rpc_result(serde_json::json!([])),
    ]);
    let error = adapter(UNREACHABLE, &rpc)
        .settlement_state("operation-1", Some(&identity_string()))
        .expect_err("no event");
    handle.join().expect("rpc stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 authorization is consumed but its rail event was not found")
    );
}

#[test]
fn unused_authorization_past_valid_before_moved_no_money() {
    let (rpc, _requests, handle) = spawn_json_server(vec![
        rpc_result(state_word(false)),
        rpc_result(serde_json::json!({ "timestamp": format!("0x{VALID_BEFORE:x}") })),
    ]);
    let state = adapter(UNREACHABLE, &rpc)
        .settlement_state("operation-1", Some(&identity_string()))
        .expect("rail state");
    handle.join().expect("rpc stub exits");
    assert_eq!(state, RailSettlementState::NoAuthorization);
}

#[test]
fn unused_live_authorization_is_unavailable() {
    let (rpc, _requests, handle) = spawn_json_server(vec![
        rpc_result(state_word(false)),
        rpc_result(serde_json::json!({ "timestamp": format!("0x{:x}", VALID_BEFORE - 1) })),
    ]);
    let error = adapter(UNREACHABLE, &rpc)
        .settlement_state("operation-1", Some(&identity_string()))
        .expect_err("still live");
    handle.join().expect("rpc stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 authorization is unused and still valid")
    );
}

#[test]
fn rpc_errors_are_unavailable() {
    let (rpc, _requests, handle) = spawn_once_json_server(
        200,
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "boom" } }),
    );
    let error = adapter(UNREACHABLE, &rpc)
        .settlement_state("operation-1", Some(&identity_string()))
        .expect_err("rpc error");
    handle.join().expect("rpc stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 rail RPC is unavailable")
    );
}

#[test]
fn recovery_refuses_an_identity_outside_the_configured_rail() {
    let other_asset = identity_string().replace(&ASSET.to_ascii_lowercase(), PAY_TO);
    let error = adapter(UNREACHABLE, UNREACHABLE)
        .settlement_state("operation-1", Some(&other_asset))
        .expect_err("other asset");
    assert!(
        matches!(error, PaymentError::RailError(message) if message == "x402 authorization identity is outside the configured rail")
    );
}

#[test]
fn authorization_identity_round_trips_through_its_canonical_form() {
    let identity = X402AuthorizationIdentity::parse(&identity_string()).expect("identity parses");
    assert_eq!(identity.network, NETWORK);
    assert_eq!(identity.asset, ASSET.to_ascii_lowercase());
    assert_eq!(identity.from, PAYER);
    assert_eq!(identity.nonce, NONCE);
    assert_eq!(identity.valid_before, VALID_BEFORE);
    assert_eq!(identity.to_string(), identity_string());
    assert_eq!(
        X402AuthorizationIdentity::parse(&identity.to_string()),
        Some(identity)
    );
}

#[test]
fn non_canonical_authorization_identities_are_refused_exactly() {
    let canonical = identity_string();
    let asset = ASSET.to_ascii_lowercase();
    for invalid in [
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
        format!("{canonical}/extra"),
        format!(" {canonical}"),
        format!("{canonical} "),
        canonical.replacen('/', "//", 1),
    ] {
        assert_eq!(
            X402AuthorizationIdentity::parse(&invalid),
            None,
            "{invalid}"
        );
        let error = adapter(UNREACHABLE, UNREACHABLE)
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
    let error = adapter(&url, UNREACHABLE)
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
    let error = adapter(UNREACHABLE, UNREACHABLE)
        .authorize(&one_second_past)
        .expect_err("one second past the authority expiry");
    assert!(refused(error, X402Refusal::OutlivesAuthority));
}

#[test]
fn missing_chain_time_is_unavailable() {
    let (rpc, _requests, handle) = spawn_json_server(vec![
        rpc_result(state_word(false)),
        (
            200,
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "no block" } }),
        ),
    ]);
    let error = adapter(UNREACHABLE, &rpc)
        .settlement_state("operation-1", Some(&identity_string()))
        .expect_err("no chain time");
    handle.join().expect("rpc stub exits");
    assert!(
        matches!(error, PaymentError::Unavailable(message) if message == "x402 rail RPC is unavailable")
    );
}

#[test]
fn final_prepayment_has_no_release_or_refund() {
    let adapter = adapter(UNREACHABLE, UNREACHABLE);
    assert!(
        matches!(adapter.release("authorization", "operation-1"), Err(PaymentError::Unavailable(message)) if message == "x402 final prepayment has no releasable hold")
    );
    assert!(
        matches!(adapter.refund("transaction", 125, "USDC", "operation-1"), Err(PaymentError::Unavailable(message)) if message == "x402 remote refund is unsupported")
    );
}
