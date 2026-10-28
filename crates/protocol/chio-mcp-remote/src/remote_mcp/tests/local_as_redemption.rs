//! A redeemed local authorization code verifies into `chio_local_as`
//! issuance evidence bound to that redemption.

use super::*;
use crate::root_exchange::kinds::local_as::{self, PresentedSender};
use crate::root_exchange::{ReplayNamespace, RootExchangeError, SenderConstraintFailure};
use chio_core::root_authority::Sha256Digest;
use chio_core::sha256;

const THUMBPRINT: &str = "cert-thumbprint";

fn approved(server: &LocalAuthorizationServer, request: AuthorizationRequest) -> String {
    let form = test_authorization_approval_form(server, &request, "approve");
    authorization_code_from_redirect(server.approve_authorization(form).expect("approval"))
}

fn code_request() -> AuthorizationRequest {
    let mut request = test_authorization_request();
    request.code_challenge = Some(pkce_s256("verifier"));
    request
}

fn token_form(code: &str) -> TokenRequestForm {
    serde_json::from_value(json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://client.example/callback",
        "client_id": "client-abc",
        "code_verifier": "verifier",
    }))
    .expect("token form")
}

fn access_token_claims(response: &Value) -> Value {
    let token = response["access_token"].as_str().expect("access token");
    let payload = token.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("decode JWT payload"))
        .expect("JWT claims")
}

#[test]
fn redeemed_code_verifies_into_issue_evidence() {
    let server = test_local_authorization_server();
    let code = approved(&server, code_request());
    let headers = HeaderMap::new();
    let (response, redeemed) = server
        .redeem_authorization_code(SenderRequest::from(&headers), token_form(&code))
        .expect("redemption");
    let claims = access_token_claims(&response);
    let now = claims["iat"].as_u64().expect("iat");
    let key = server.signing_key.public_key();
    let local = local_as::LocalAuthorizationServer {
        key: &key,
        issuer: &server.issuer,
    };
    let evidence = local_as::verify_issue(
        &local,
        &redeemed,
        PresentedSender::from(SenderRequest::from(&headers)),
        now,
    )
    .expect("issue evidence");
    let code_digest = Sha256Digest::from_hash(sha256(code.as_bytes()));
    assert_eq!(
        evidence.replay_key().namespace,
        ReplayNamespace::LocalAsIssue
    );
    assert_eq!(evidence.replay_key().id, code_digest.to_bare_hex());
    assert_eq!(evidence.artifact_digest(), Some(&code_digest));
    assert_eq!(Some(evidence.token_exp()), claims["exp"].as_u64());
    assert_eq!(evidence.sender_constraint(), None);
    assert_eq!(redeemed.subject(), "operator");
    assert_eq!(redeemed.client_id(), "client-abc");
    assert_eq!(redeemed.resource(), "https://edge.example/mcp");
    assert_eq!(redeemed.scopes(), ["mcp:invoke"]);
    assert_eq!(
        server
            .redeem_authorization_code(SenderRequest::from(&headers), token_form(&code))
            .map(|_| ())
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn redeemed_code_refuses_another_local_authorization_server() {
    let server = test_local_authorization_server();
    let code = approved(&server, code_request());
    let headers = HeaderMap::new();
    let (response, redeemed) = server
        .redeem_authorization_code(SenderRequest::from(&headers), token_form(&code))
        .expect("redemption");
    let now = access_token_claims(&response)["iat"].as_u64().expect("iat");
    let key = server.signing_key.public_key();
    let other = local_as::LocalAuthorizationServer {
        key: &key,
        issuer: "https://other-as.example",
    };
    assert_eq!(
        local_as::verify_issue(
            &other,
            &redeemed,
            PresentedSender::from(SenderRequest::from(&headers)),
            now,
        )
        .unwrap_err(),
        RootExchangeError::IssuerMismatch
    );
}

#[test]
fn sender_bound_redemption_carries_the_bound_cnf() {
    let server = test_local_authorization_server();
    let mut request = code_request();
    request.chio_sender_mtls_thumbprint_sha256 = Some(THUMBPRINT.to_owned());
    let code = approved(&server, request);
    let headers = HeaderMap::new();
    let transport = TransportIdentity::for_tests(Some(THUMBPRINT), None);
    let sender = SenderRequest::from_extension(&headers, Some(&transport));
    let (response, redeemed) = server
        .redeem_authorization_code(sender, token_form(&code))
        .expect("redemption");
    let claims = access_token_claims(&response);
    let now = claims["iat"].as_u64().expect("iat");
    let key = server.signing_key.public_key();
    let local = local_as::LocalAuthorizationServer {
        key: &key,
        issuer: &server.issuer,
    };
    let evidence = local_as::verify_issue(&local, &redeemed, PresentedSender::from(sender), now)
        .expect("issue evidence");
    let bound: ChioSenderConstraintClaims =
        serde_json::from_value(json!({ "x5t#S256": THUMBPRINT })).expect("constraint");
    assert_eq!(evidence.sender_constraint(), Some(&bound));
    assert_eq!(claims["cnf"], json!({ "x5t#S256": THUMBPRINT }));
    assert_eq!(
        local_as::verify_issue(
            &local,
            &redeemed,
            PresentedSender::from(SenderRequest::from(&headers)),
            now,
        )
        .unwrap_err(),
        RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Mtls)
    );
}
