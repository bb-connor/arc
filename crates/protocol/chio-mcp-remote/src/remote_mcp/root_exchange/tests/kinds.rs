//! The kept anchor kinds: each verifier's refusals, the load-time Entra
//! rules, and every kind reaching the same preparation.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use super::*;
use crate::root_exchange::kinds::local_as::{
    CodeRedemption, LocalAuthorizationServer, PresentedSender, ReExchangeRequest, RedeemedCode,
    SubjectRoot, LOCAL_AS_ISSUER,
};
use crate::root_exchange::kinds::oauth_introspection::TokenIntrospector;
use crate::root_exchange::kinds::operator_key::{
    OperatorRootRequest, VerifiedOperatorRootRequest, OPERATOR_KEY_ISSUER,
};
use crate::root_exchange::kinds::operator_static_bearer::StaticBearerToken;
use crate::root_exchange::kinds::{
    entra_jwt, local_as, oauth_introspection, oidc_jwt, operator_key, operator_static_bearer,
};
use crate::root_exchange::{
    AnchorEvidence, ReplayNamespace, RootExchangeConfigError, SenderConstraintFailure,
};
use crate::{ChioSenderConstraintClaims, SenderRequest, TransportIdentity};
use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::HttpsUrl;

const OIDC_ISSUER: &str = "https://idp.acme.example";
const OIDC_JWKS: &str = "https://idp.acme.example/keys";
const ENTRA_TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
const INTROSPECTION_ISSUER: &str = "https://as.acme.example";
const INTROSPECTION_URL: &str = "https://as.acme.example/introspect";
const STATIC_TOKEN: &str = "dev-static-token";

fn entra_issuer() -> String {
    format!("https://login.microsoftonline.com/{ENTRA_TENANT}/v2.0")
}

fn record(
    provider_id: &str,
    issuer: &str,
    mapping: (&str, &str),
    edit: impl FnOnce(&mut Value),
) -> EnterpriseProviderRecord {
    provider_record(|value| {
        value["provider_id"] = json!(provider_id);
        value["issuer"] = json!(issuer);
        value["jwks_url"] = json!(OIDC_JWKS);
        value["trust_boundary"] = json!({ "allowed_audiences": [RESOURCE] });
        value["subject_mapping"] =
            json!({ "principal_source": mapping.0, "tenant_id_field": mapping.1 });
        edit(value);
    })
}

fn oidc_record() -> EnterpriseProviderRecord {
    record("acme-oidc", OIDC_ISSUER, ("sub", "iss"), |_| {})
}

fn entra_record(issuer: &str) -> EnterpriseProviderRecord {
    record("acme-entra", issuer, ("oid", "tid"), |_| {})
}

fn introspection_record(provider_id: &str) -> EnterpriseProviderRecord {
    record(provider_id, INTROSPECTION_ISSUER, ("sub", "iss"), |value| {
        value["kind"] = json!("oauth_introspection");
        value.as_object_mut().unwrap().remove("jwks_url");
        value["introspection_url"] = json!(INTROSPECTION_URL);
    })
}

fn ceiling() -> ChioScope {
    ChioScope {
        grants: vec![grant("search"), grant("get"), grant("update")],
        ..ChioScope::default()
    }
}

fn base_rule(rule_id: &str, kind: &str) -> Value {
    json!({
        "rule_id": rule_id,
        "match": { "anchor_kind": kind },
        "ceiling_scope": ceiling(),
        "ceiling_scope_hash": digest_of(&ceiling()),
        "recorded_claims": {},
        "holder_classes": ["edge_session", "caller"],
        "capability_ttl_secs": 300,
        "max_clock_skew_secs": 30
    })
}

fn provider_rule(rule_id: &str, kind: &str, record: &EnterpriseProviderRecord) -> Value {
    let mut rule = base_rule(rule_id, kind);
    let identity = ProviderRecord::from_record(record).unwrap();
    rule["match"]["provider_record_id"] = json!(record.provider_id);
    rule["match"]["provider_identity_digest"] = json!(identity.identity_digest());
    if kind != "oauth_introspection" {
        rule["match"]["allowed_algs"] = json!(["EdDSA"]);
    }
    rule["idp_scope_projection"] = json!({
        "crm.read": ["crm/search", "crm/get"],
        "crm.write": ["crm/update"]
    });
    rule
}

fn static_rule() -> Value {
    let mut rule = base_rule("dev-static", "operator_static_bearer");
    rule["principal"] = json!("dev:alice");
    rule["tenant_value"] = json!("dev");
    rule
}

fn build(
    rules: Vec<Value>,
    records: &[EnterpriseProviderRecord],
) -> Result<RootExchange, RootExchangeConfigError> {
    let policy = loaded_policy(Sha256Digest::from_hash(sha256(b"unused")), |value| {
        value["rules"] = Value::Array(rules);
    });
    let providers = records
        .iter()
        .map(|record| {
            (
                record.provider_id.clone(),
                ProviderRecord::from_record(record).unwrap(),
            )
        })
        .collect();
    RootExchange::new(RootExchangeConfig {
        policy,
        providers,
        clients: ClientRegistry::new(&[]).unwrap(),
        exchange_key: exchange_keypair().public_key(),
        authorization_server: AS_ISSUER.to_owned(),
        token_endpoint: TOKEN_ENDPOINT.to_owned(),
        protected_resource: RESOURCE.to_owned(),
        client_assertion_skew_secs: 5,
    })
}

/// One rule of every kept kind.
fn every_kind() -> RootExchange {
    build(
        vec![
            provider_rule("oidc-agents", "oidc_jwt", &oidc_record()),
            provider_rule("entra-agents", "entra_jwt", &entra_record(&entra_issuer())),
            provider_rule(
                "introspected-agents",
                "oauth_introspection",
                &introspection_record("acme-introspect"),
            ),
            static_rule(),
            base_rule("local-users", "chio_local_as"),
            base_rule("operator-roots", "chio_operator_key"),
        ],
        &[
            oidc_record(),
            entra_record(&entra_issuer()),
            introspection_record("acme-introspect"),
        ],
    )
    .unwrap()
}

/// Keys for any provider record, by `kid`.
struct AnyRecordKeys(Vec<Jwk>);

impl AnyRecordKeys {
    fn idp() -> Self {
        Self(vec![serde_json::from_value(idp_jwk(IDP_KID)).unwrap()])
    }
}

#[async_trait]
impl IdpKeyLookup for AnyRecordKeys {
    async fn resolve(
        &self,
        _provider: &EnterpriseProviderIdentity,
        kid: &str,
        _alg: JwsAlgorithm,
        _now: u64,
    ) -> Result<IdpKey, RootExchangeError> {
        self.0
            .iter()
            .find(|key| key.kid.as_str() == kid)
            .map(|jwk| IdpKey {
                jwk: jwk.clone(),
                snapshot_digest: snapshot_digest(&[idp_jwk(IDP_KID)]),
            })
            .ok_or(RootExchangeError::UnknownKid)
    }
}

struct StubIntrospector {
    response: Result<Vec<u8>, RootExchangeError>,
    calls: AtomicUsize,
}

impl StubIntrospector {
    fn answering(response: Value) -> Self {
        Self {
            response: Ok(serde_json::to_vec(&response).unwrap()),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl TokenIntrospector for StubIntrospector {
    async fn introspect(
        &self,
        endpoint: &HttpsUrl,
        token: &str,
    ) -> Result<Vec<u8>, RootExchangeError> {
        assert_eq!(endpoint.as_str(), INTROSPECTION_URL);
        assert_eq!(token, "opaque-token");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.response.clone()
    }
}

fn idp_header() -> Value {
    json!({ "alg": "EdDSA", "kid": IDP_KID })
}

fn oidc_claims() -> Value {
    json!({ "iss": OIDC_ISSUER, "sub": "alice", "aud": RESOURCE, "jti": "oidc-1",
            "iat": NOW - 10, "exp": NOW + 600, "scope": "crm.read" })
}

fn entra_claims() -> Value {
    json!({ "iss": entra_issuer(), "oid": "oid-alice", "tid": ENTRA_TENANT, "aud": RESOURCE,
            "uti": "uti-1", "iat": NOW - 10, "exp": NOW + 3600, "scp": "crm.read" })
}

fn introspection_response() -> Value {
    json!({ "active": true, "iss": INTROSPECTION_ISSUER, "sub": "bob", "aud": RESOURCE,
            "exp": NOW + 600, "iat": NOW - 10, "scope": "crm.read" })
}

fn local_keypair() -> Keypair {
    Keypair::from_seed(&[5; 32])
}

fn local_server(key: &PublicKey) -> LocalAuthorizationServer<'_> {
    LocalAuthorizationServer {
        key,
        issuer: AS_ISSUER,
    }
}

fn local_claims() -> Value {
    json!({ "iss": AS_ISSUER, "sub": "local-user", "aud": RESOURCE, "resource": RESOURCE,
            "scope": "mcp:invoke mcp:read", "client_id": CLIENT_ID, "iat": NOW - 5,
            "exp": NOW + 300, "jti": "local-1" })
}

fn local_token(claims: &Value) -> String {
    compact(
        &json!({ "alg": "EdDSA", "kid": "chio-local", "typ": "JWT" }),
        claims,
        |input| {
            local_keypair()
                .sign_exempt(chio_core::crypto::ExemptFormat::JwsSigningInput, input)
                .to_bytes()
                .to_vec()
        },
    )
}

fn with_cnf(cnf: Value) -> Value {
    edit(local_claims(), |claims| {
        claims.insert("cnf".into(), cnf);
    })
}

fn no_headers() -> HeaderMap {
    HeaderMap::new()
}

const AUTHORIZATION_CODE: &str = "code-1";

fn constraint(cnf: Value) -> ChioSenderConstraintClaims {
    serde_json::from_value(cnf).unwrap()
}

/// The members of a redeemed code; `issue` borrows them into a
/// [`CodeRedemption`].
struct CodeFixture {
    code: String,
    issuer: String,
    issued_at: u64,
    code_expires_at: u64,
    subject: String,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
    sender_constraint: Option<ChioSenderConstraintClaims>,
    token_exp: u64,
}

fn code_fixture() -> CodeFixture {
    CodeFixture {
        code: AUTHORIZATION_CODE.to_owned(),
        issuer: AS_ISSUER.to_owned(),
        issued_at: NOW,
        code_expires_at: NOW + 60,
        subject: "local-user".to_owned(),
        client_id: CLIENT_ID.to_owned(),
        resource: RESOURCE.to_owned(),
        scopes: vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()],
        sender_constraint: None,
        token_exp: NOW + 300,
    }
}

fn issue_with(
    edit_code: impl FnOnce(&mut CodeFixture),
    sender: SenderRequest<'_>,
) -> Result<AnchorEvidence, RootExchangeError> {
    let key = local_keypair().public_key();
    let mut fixture = code_fixture();
    edit_code(&mut fixture);
    let redeemed = RedeemedCode::from_redemption(CodeRedemption {
        code: &fixture.code,
        issuer: &fixture.issuer,
        subject: &fixture.subject,
        client_id: &fixture.client_id,
        redirect_uri: "https://client.example/callback",
        resource: &fixture.resource,
        scopes: &fixture.scopes,
        sender_constraint: fixture.sender_constraint.as_ref(),
        issued_at: fixture.issued_at,
        code_expires_at: fixture.code_expires_at,
        token_exp: fixture.token_exp,
    })
    .unwrap();
    local_as::verify_issue(
        &local_server(&key),
        &redeemed,
        PresentedSender::from(sender),
        NOW,
    )
}

fn issue(edit_code: impl FnOnce(&mut CodeFixture)) -> Result<AnchorEvidence, RootExchangeError> {
    let headers = no_headers();
    issue_with(edit_code, SenderRequest::from(&headers))
}

fn operator_body(edit_request: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut request = json!({
        "request_id": "req-1",
        "principal": "ops:carol",
        "tenant_value": "acme",
        "scope": { "grants": [grant("search")] },
        "holder": "edge_session",
        "expires_at": NOW + 120
    });
    edit_request(&mut request);
    serde_json::to_vec(&request).unwrap()
}

fn operator_request(edit_request: impl FnOnce(&mut Value)) -> VerifiedOperatorRootRequest {
    let body = operator_body(edit_request);
    VerifiedOperatorRootRequest::from_verified(OperatorRootRequest::parse(&body).unwrap(), &body)
}

fn entropy() -> CountingRng {
    CountingRng::new()
}

fn refusal_code(error: &RootExchangeError, expected: OAuthErrorCode) {
    assert_eq!(error.oauth_error(), expected, "{error:?}");
}

fn consistent(exchange: &RootExchange, prepared: &PreparedAnchoredRoot) {
    let root = CapabilityToken::sign(prepared.body.clone(), &exchange_keypair()).unwrap();
    check_root_consistency(RootConsistencyInput {
        root: &root,
        anchor: prepared.anchor(),
        context: prepared.context(),
        policy: &exchange.policy,
        sender_key: None,
    })
    .unwrap();
}

fn tools(prepared: &PreparedAnchoredRoot) -> Vec<&str> {
    prepared
        .scope()
        .grants
        .iter()
        .map(|grant| grant.tool_name.as_str())
        .collect()
}

#[tokio::test]
async fn every_kind_reaches_the_same_prepare() {
    let exchange = every_kind();
    let keys = AnyRecordKeys::idp();
    let introspector = StubIntrospector::answering(introspection_response());
    let local_key = local_keypair().public_key();
    let headers = no_headers();
    let subject_scope = ChioScope {
        grants: vec![grant("get")],
        ..ChioScope::default()
    };
    let cases: Vec<(AnchorEvidence, AnchorKind, &str, Vec<&str>)> = vec![
        (
            oidc_jwt::verify(
                &exchange,
                &compact(&idp_header(), &oidc_claims(), idp_sign),
                NOW,
                &keys,
            )
            .await
            .unwrap(),
            AnchorKind::OidcJwt,
            OIDC_ISSUER,
            vec!["search", "get"],
        ),
        (
            entra_jwt::verify(
                &exchange,
                &compact(&idp_header(), &entra_claims(), idp_sign),
                NOW,
                &keys,
            )
            .await
            .unwrap(),
            AnchorKind::EntraJwt,
            "",
            vec!["search", "get"],
        ),
        (
            oauth_introspection::verify(&exchange, "opaque-token", NOW, &introspector)
                .await
                .unwrap(),
            AnchorKind::OauthIntrospection,
            INTROSPECTION_ISSUER,
            vec!["search", "get"],
        ),
        (
            operator_static_bearer::verify(
                &exchange,
                &StaticBearerToken::new(STATIC_TOKEN),
                STATIC_TOKEN,
                NOW,
            )
            .unwrap(),
            AnchorKind::OperatorStaticBearer,
            "urn:chio:operator",
            vec!["search", "get", "update"],
        ),
        (
            issue(|_| {}).unwrap(),
            AnchorKind::ChioLocalAs,
            LOCAL_AS_ISSUER,
            vec!["search", "get", "update"],
        ),
        (
            local_as::verify_reexchange(
                &local_server(&local_key),
                &local_token(&local_claims()),
                ReExchangeRequest {
                    scope: Some(&["mcp:read".to_owned()]),
                    resource: Some(RESOURCE),
                    client_id: Some(CLIENT_ID),
                    root_scope: None,
                    request_digest: Sha256Digest::from_hash(sha256(b"re-exchange")),
                },
                SubjectRoot {
                    scope: &subject_scope,
                    assertion_exp: NOW + 200,
                },
                PresentedSender::from(crate::SenderRequest::from(&headers)),
                NOW,
            )
            .unwrap(),
            AnchorKind::ChioLocalAs,
            LOCAL_AS_ISSUER,
            vec!["get"],
        ),
        (
            operator_key::verify(&operator_request(|_| {}), NOW).unwrap(),
            AnchorKind::ChioOperatorKey,
            OPERATOR_KEY_ISSUER,
            vec!["search"],
        ),
    ];
    let entra = entra_issuer();
    for (evidence, kind, issuer, expected_tools) in cases {
        let issuer = if kind == AnchorKind::EntraJwt {
            entra.as_str()
        } else {
            issuer
        };
        let artifact_digest = evidence.artifact_digest().copied();
        let prepared = exchange
            .prepare(evidence, None, None, NOW, &entropy())
            .unwrap();
        if kind.is_jws_verified() {
            assert!(artifact_digest.is_some(), "{kind:?}");
            assert_eq!(
                prepared.context().anchor.artifact_digest,
                artifact_digest,
                "{kind:?}"
            );
        } else {
            assert_eq!(prepared.context().anchor.artifact_digest, None, "{kind:?}");
        }
        assert_eq!(
            prepared.artifact_digest(),
            artifact_digest.as_ref(),
            "{kind:?}"
        );
        assert_eq!(prepared.anchor().kind, kind);
        assert_eq!(prepared.context().anchor.kind, kind);
        assert_eq!(prepared.context().anchor.issuer.as_str(), issuer);
        assert_eq!(prepared.holder(), HolderClass::EdgeSession);
        assert_eq!(tools(&prepared), expected_tools, "{kind:?}");
        assert!(prepared.expires_at() > NOW);
        consistent(&exchange, &prepared);
    }
}

#[test]
fn oidc_jwt_rule_with_entra_issuer_rejects_at_load() {
    let refused = |issuer: String| {
        let record = record("acme-oidc", &issuer, ("sub", "iss"), |_| {});
        build(
            vec![provider_rule("oidc-agents", "oidc_jwt", &record)],
            &[record],
        )
        .err()
        .unwrap()
    };
    for host in entra_jwt::ENTRA_AUTHORITY_HOSTS {
        assert_eq!(
            refused(format!("https://{host}/{ENTRA_TENANT}/v2.0")),
            RootExchangeConfigError::EntraIssuerOnOidcRule {
                rule_id: "oidc-agents".to_owned()
            },
            "{host}"
        );
    }
    assert_eq!(
        refused("https://LOGIN.MicrosoftOnline.com./common/v2.0".to_owned()),
        RootExchangeConfigError::EntraIssuerOnOidcRule {
            rule_id: "oidc-agents".to_owned()
        }
    );
    for issuer in [
        "https://login.microsoftonline.com.idp.example/tenant",
        "https://idp.login.microsoftonline.com.example/tenant",
    ] {
        let record = record("acme-oidc", issuer, ("sub", "iss"), |_| {});
        assert!(
            build(
                vec![provider_rule("oidc-agents", "oidc_jwt", &record)],
                &[record]
            )
            .is_ok(),
            "{issuer}"
        );
    }
}

#[test]
fn entra_jwt_rule_accepts_each_cloud_tenant_issuer() {
    for host in entra_jwt::ENTRA_AUTHORITY_HOSTS {
        let record = entra_record(&format!("https://{host}/{ENTRA_TENANT}/v2.0"));
        assert!(
            build(
                vec![provider_rule("entra-agents", "entra_jwt", &record)],
                &[record]
            )
            .is_ok(),
            "{host}"
        );
    }
}

#[test]
fn entra_common_issuer_refuses() {
    for issuer in [
        "https://login.microsoftonline.com/common/v2.0",
        "https://login.microsoftonline.com/organizations/v2.0",
        "https://login.microsoftonline.com/consumers/v2.0",
        "https://login.microsoftonline.com/{tenantid}/v2.0",
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0",
        "https://idp.acme.example/72f988bf-86f1-41af-91ab-2d7cd011db47",
    ] {
        let record = entra_record(issuer);
        let refusal = build(
            vec![provider_rule("entra-agents", "entra_jwt", &record)],
            &[record],
        )
        .err()
        .unwrap();
        assert_eq!(
            refusal,
            RootExchangeConfigError::IssuerNotTenantSpecific {
                rule_id: "entra-agents".to_owned()
            },
            "{issuer}"
        );
    }
}

async fn oidc_refusal(claims: Value) -> RootExchangeError {
    oidc_jwt::verify(
        &every_kind(),
        &compact(&idp_header(), &claims, idp_sign),
        NOW,
        &AnyRecordKeys::idp(),
    )
    .await
    .unwrap_err()
}

#[tokio::test]
async fn oidc_jwt_refusals() {
    let cases = [
        (
            edit(oidc_claims(), |claims| {
                claims.insert("aud".into(), json!("https://other.example/mcp"));
            }),
            RootExchangeError::AudienceMismatch,
            OAuthErrorCode::InvalidGrant,
        ),
        (
            edit(oidc_claims(), |claims| {
                claims.insert("exp".into(), json!(NOW - 31));
            }),
            RootExchangeError::AssertionExpired,
            OAuthErrorCode::InvalidGrant,
        ),
        (
            edit(oidc_claims(), |claims| {
                claims.remove("iat");
            }),
            RootExchangeError::ClaimMissing("iat"),
            OAuthErrorCode::InvalidGrant,
        ),
        (
            edit(oidc_claims(), |claims| {
                claims.remove("sub");
            }),
            RootExchangeError::ClaimMissing("principal"),
            OAuthErrorCode::InvalidGrant,
        ),
        (
            edit(oidc_claims(), |claims| {
                claims.insert("iss".into(), json!("https://other-idp.example"));
            }),
            RootExchangeError::RuleMatchCount { matched: 0 },
            OAuthErrorCode::InvalidGrant,
        ),
    ];
    for (claims, expected, code) in cases {
        let error = oidc_refusal(claims).await;
        assert_eq!(error, expected);
        refusal_code(&error, code);
    }
    let unsigned = compact(&idp_header(), &oidc_claims(), |input| {
        Keypair::from_seed(&[99; 32])
            .sign_exempt(chio_core::crypto::ExemptFormat::JwsSigningInput, input)
            .to_bytes()
            .to_vec()
    });
    let error = oidc_jwt::verify(&every_kind(), &unsigned, NOW, &AnyRecordKeys::idp())
        .await
        .unwrap_err();
    assert_eq!(error, RootExchangeError::SignatureInvalid);
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
}

#[tokio::test]
async fn oidc_jwt_replay_key_is_the_jti_or_the_token_digest() {
    let exchange = every_kind();
    let keys = AnyRecordKeys::idp();
    let with_jti = oidc_jwt::verify(
        &exchange,
        &compact(&idp_header(), &oidc_claims(), idp_sign),
        NOW,
        &keys,
    )
    .await
    .unwrap();
    assert_eq!(
        with_jti.replay_key().namespace,
        ReplayNamespace::Assertion(AnchorKind::OidcJwt)
    );
    assert_eq!(with_jti.replay_key().id, "jti:oidc-1");
    let token = compact(
        &idp_header(),
        &edit(oidc_claims(), |claims| {
            claims.remove("jti");
        }),
        idp_sign,
    );
    let without_jti = oidc_jwt::verify(&exchange, &token, NOW, &keys)
        .await
        .unwrap();
    assert_eq!(
        without_jti.replay_key().id,
        format!(
            "token:{}",
            Sha256Digest::from_hash(sha256(token.as_bytes()))
        )
    );
}

#[tokio::test]
async fn entra_jwt_refusals_and_permissions() {
    let exchange = every_kind();
    let keys = AnyRecordKeys::idp();
    let verify = |claims: Value| {
        let token = compact(&idp_header(), &claims, idp_sign);
        let exchange = &exchange;
        let keys = &keys;
        async move { entra_jwt::verify(exchange, &token, NOW, keys).await }
    };
    for (claims, expected) in [
        (
            edit(entra_claims(), |claims| {
                claims.remove("uti");
            }),
            RootExchangeError::ClaimMissing("uti"),
        ),
        (
            edit(entra_claims(), |claims| {
                claims.remove("oid");
            }),
            RootExchangeError::ClaimMissing("principal"),
        ),
        (
            edit(entra_claims(), |claims| {
                claims.insert("roles".into(), json!("crm.write"));
            }),
            RootExchangeError::ClaimInvalid("roles"),
        ),
    ] {
        let error = verify(claims).await.unwrap_err();
        assert_eq!(error, expected);
        refusal_code(&error, OAuthErrorCode::InvalidGrant);
    }
    let evidence = verify(edit(entra_claims(), |claims| {
        claims.insert("roles".into(), json!(["crm.write"]));
    }))
    .await
    .unwrap();
    assert_eq!(
        evidence.replay_key().namespace,
        ReplayNamespace::Assertion(AnchorKind::EntraJwt)
    );
    assert_eq!(evidence.replay_key().id, "uti-1");
    let prepared = exchange
        .prepare(evidence, None, None, NOW, &entropy())
        .unwrap();
    assert_eq!(tools(&prepared), ["search", "get", "update"]);
}

async fn introspection_refusal(introspector: &StubIntrospector) -> RootExchangeError {
    oauth_introspection::verify(&every_kind(), "opaque-token", NOW, introspector)
        .await
        .unwrap_err()
}

#[tokio::test]
async fn introspection_inactive_refuses() {
    let introspector = StubIntrospector::answering(json!({ "active": false }));
    let error = introspection_refusal(&introspector).await;
    assert_eq!(error, RootExchangeError::IntrospectionInactive);
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
}

#[tokio::test]
async fn introspection_without_exp_refuses() {
    let introspector = StubIntrospector::answering(edit(introspection_response(), |response| {
        response.remove("exp");
    }));
    let error = introspection_refusal(&introspector).await;
    assert_eq!(error, RootExchangeError::ClaimMissing("exp"));
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
}

#[tokio::test]
async fn introspection_without_iat_refuses() {
    let introspector = StubIntrospector::answering(edit(introspection_response(), |response| {
        response.remove("iat");
    }));
    let error = introspection_refusal(&introspector).await;
    assert_eq!(error, RootExchangeError::ClaimMissing("iat"));
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
    let valid = StubIntrospector::answering(introspection_response());
    oauth_introspection::verify(&every_kind(), "opaque-token", NOW, &valid)
        .await
        .unwrap();
}

#[tokio::test]
async fn introspection_response_refusals() {
    let cases = [
        (
            StubIntrospector::answering(edit(introspection_response(), |response| {
                response.remove("active");
            })),
            RootExchangeError::IntrospectionInvalid("active is not a boolean"),
            OAuthErrorCode::ServerError,
        ),
        (
            StubIntrospector::answering(edit(introspection_response(), |response| {
                response.insert("iss".into(), json!("https://other-as.example"));
            })),
            RootExchangeError::IssuerMismatch,
            OAuthErrorCode::InvalidGrant,
        ),
        (
            StubIntrospector::answering(edit(introspection_response(), |response| {
                response.insert("aud".into(), json!("https://other.example/mcp"));
            })),
            RootExchangeError::AudienceMismatch,
            OAuthErrorCode::InvalidGrant,
        ),
        (
            StubIntrospector {
                response: Ok(b"[]".to_vec()),
                calls: AtomicUsize::new(0),
            },
            RootExchangeError::IntrospectionInvalid("response is not a duplicate-free JSON object"),
            OAuthErrorCode::ServerError,
        ),
        (
            StubIntrospector {
                response: Err(RootExchangeError::IntrospectionUnavailable(
                    "status 503".to_owned(),
                )),
                calls: AtomicUsize::new(0),
            },
            RootExchangeError::IntrospectionUnavailable("status 503".to_owned()),
            OAuthErrorCode::TemporarilyUnavailable,
        ),
    ];
    for (introspector, expected, code) in cases {
        let error = introspection_refusal(&introspector).await;
        assert_eq!(error, expected);
        refusal_code(&error, code);
        assert_eq!(
            error.client_description().is_none(),
            code != OAuthErrorCode::InvalidGrant
        );
    }
}

#[tokio::test]
async fn introspection_response_is_read_strictly() {
    let repeated = br#"{"active":true,"active":false,"sub":"bob","exp":1792235400}"#.to_vec();
    let oversized = vec![b' '; oauth_introspection::MAX_INTROSPECTION_RESPONSE_BYTES + 1];
    for (body, expected) in [
        (
            repeated,
            RootExchangeError::IntrospectionInvalid("response is not a duplicate-free JSON object"),
        ),
        (
            oversized,
            RootExchangeError::IntrospectionInvalid("response exceeds the size bound"),
        ),
    ] {
        let introspector = StubIntrospector {
            response: Ok(body),
            calls: AtomicUsize::new(0),
        };
        let error = introspection_refusal(&introspector).await;
        assert_eq!(error, expected);
        refusal_code(&error, OAuthErrorCode::ServerError);
    }
}

#[test]
fn local_token_confirmation_is_read_strictly() {
    let key = local_keypair().public_key();
    let headers = no_headers();
    let claims = serde_json::to_string(&local_claims()).unwrap();
    let repeated = format!(
        "{},\"cnf\":{{\"x5t#S256\":\"a\"}},\"cnf\":{{\"x5t#S256\":\"b\"}}}}",
        &claims[..claims.len() - 1]
    );
    let header = b64(br#"{"alg":"EdDSA","kid":"chio-local"}"#);
    let input = format!("{header}.{}", b64(repeated.as_bytes()));
    let token = format!(
        "{input}.{}",
        b64(&local_keypair()
            .sign_exempt(
                chio_core::crypto::ExemptFormat::JwsSigningInput,
                input.as_bytes(),
            )
            .to_bytes())
    );
    let verify = |token: &str| {
        reexchange_from(&local_server(&key), token, SenderRequest::from(&headers)).unwrap_err()
    };
    let error = verify(&token);
    assert_eq!(error, RootExchangeError::MalformedJws("payload"));
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
    let error = verify(&local_token(&with_cnf(
        json!({ "x5t#S256": "a", "jkt": "b" }),
    )));
    assert_eq!(
        error,
        RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Confirmation)
    );
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
}

#[tokio::test]
async fn introspection_evidence_is_the_response_digest() {
    let introspector = StubIntrospector::answering(introspection_response());
    let evidence = oauth_introspection::verify(&every_kind(), "opaque-token", NOW, &introspector)
        .await
        .unwrap();
    let body = serde_json::to_vec(&introspection_response()).unwrap();
    assert_eq!(
        evidence.artifact_digest(),
        Some(&Sha256Digest::from_hash(sha256(&body)))
    );
    assert_eq!(
        evidence.replay_key().id,
        format!("token:{}", Sha256Digest::from_hash(sha256(b"opaque-token")))
    );
}

#[tokio::test]
async fn introspection_needs_one_enabled_record() {
    let two = build(
        vec![
            provider_rule("a", "oauth_introspection", &introspection_record("as-a")),
            provider_rule("b", "oauth_introspection", &introspection_record("as-b")),
        ],
        &[introspection_record("as-a"), introspection_record("as-b")],
    )
    .unwrap();
    let introspector = StubIntrospector::answering(introspection_response());
    let error = oauth_introspection::verify(&two, "opaque-token", NOW, &introspector)
        .await
        .unwrap_err();
    assert_eq!(error, RootExchangeError::IntrospectionRecordAmbiguous);
    refusal_code(&error, OAuthErrorCode::ServerError);

    let disabled_record = introspection_record("acme-introspect");
    let mut disabled = disabled_record.clone();
    disabled.enabled = false;
    let exchange = build(
        vec![provider_rule(
            "introspected-agents",
            "oauth_introspection",
            &disabled_record,
        )],
        &[disabled],
    )
    .unwrap();
    let error = oauth_introspection::verify(&exchange, "opaque-token", NOW, &introspector)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::ProviderRecordDisabled("acme-introspect".to_owned())
    );
    refusal_code(&error, OAuthErrorCode::ServerError);
    assert_eq!(introspector.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn static_bearer_wrong_token_refuses_in_constant_time_path() {
    let exchange = every_kind();
    let configured = StaticBearerToken::new(STATIC_TOKEN);
    for presented in [
        "",
        "dev-static-toke",
        "dev-static-tokenX",
        "DEV-STATIC-TOKEN",
    ] {
        let error =
            operator_static_bearer::verify(&exchange, &configured, presented, NOW).unwrap_err();
        assert_eq!(error, RootExchangeError::StaticBearerMismatch);
        refusal_code(&error, OAuthErrorCode::InvalidGrant);
    }
    let evidence =
        operator_static_bearer::verify(&exchange, &configured, STATIC_TOKEN, NOW).unwrap();
    assert_eq!(evidence.token_exp(), NOW + 300);
    assert_eq!(
        evidence.replay_key().id,
        format!(
            "{}:{}",
            Sha256Digest::from_hash(sha256(STATIC_TOKEN.as_bytes())),
            NOW + 300
        )
    );
}

#[test]
fn kinds_without_a_projection_take_no_requested_scope() {
    let exchange = every_kind();
    let evidence = operator_static_bearer::verify(
        &exchange,
        &StaticBearerToken::new(STATIC_TOKEN),
        STATIC_TOKEN,
        NOW,
    )
    .unwrap();
    let error = exchange
        .prepare(
            evidence,
            None,
            Some(&["crm.read".to_owned()]),
            NOW,
            &entropy(),
        )
        .unwrap_err();
    assert_eq!(error, RootExchangeError::ScopeNotProjected);
    refusal_code(&error, OAuthErrorCode::InvalidScope);
}

#[test]
fn local_token_refusals() {
    let key = local_keypair().public_key();
    let other_key = Keypair::from_seed(&[6; 32]).public_key();
    let headers = no_headers();
    let mut dpop = HeaderMap::new();
    dpop.insert(
        HeaderName::from_static(crate::DPOP_HEADER),
        HeaderValue::from_static("proof"),
    );
    let cases = [
        (
            local_server(&other_key),
            local_token(&local_claims()),
            &headers,
            RootExchangeError::SignatureInvalid,
        ),
        (
            LocalAuthorizationServer {
                key: &key,
                issuer: "https://other-as.example",
            },
            local_token(&local_claims()),
            &headers,
            RootExchangeError::IssuerMismatch,
        ),
        (
            local_server(&key),
            local_token(&edit(local_claims(), |claims| {
                claims.insert("exp".into(), json!(NOW));
            })),
            &headers,
            RootExchangeError::AssertionExpired,
        ),
        (
            local_server(&key),
            local_token(&with_cnf(json!({ "chioSenderKey": "ab".repeat(32) }))),
            &headers,
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::DpopUnavailable),
        ),
        (
            local_server(&key),
            local_token(&with_cnf(json!({ "x5t#S256": "cert-thumbprint" }))),
            &headers,
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Mtls),
        ),
        (
            local_server(&key),
            local_token(&with_cnf(json!({ "jkt": "other-profile" }))),
            &headers,
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Confirmation),
        ),
        (
            local_server(&key),
            local_token(&local_claims()),
            &dpop,
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::DpopUnavailable),
        ),
    ];
    for (server, token, headers, expected) in cases {
        let error = reexchange_from(&server, &token, SenderRequest::from(headers)).unwrap_err();
        assert_eq!(error, expected);
        refusal_code(&error, OAuthErrorCode::InvalidGrant);
    }
}

fn reexchange(
    token: &str,
    scope: Option<&[String]>,
    resource: Option<&str>,
    client_id: Option<&str>,
) -> Result<AnchorEvidence, RootExchangeError> {
    reexchange_to(token, scope, resource, client_id, None)
}

fn reexchange_to(
    token: &str,
    scope: Option<&[String]>,
    resource: Option<&str>,
    client_id: Option<&str>,
    root_scope: Option<&ChioScope>,
) -> Result<AnchorEvidence, RootExchangeError> {
    let key = local_keypair().public_key();
    let headers = no_headers();
    reexchange_request(
        &local_server(&key),
        token,
        ReExchangeRequest {
            scope,
            resource,
            client_id,
            root_scope,
            request_digest: Sha256Digest::from_hash(sha256(b"re-exchange")),
        },
        SenderRequest::from(&headers),
    )
}

fn reexchange_from(
    server: &LocalAuthorizationServer<'_>,
    token: &str,
    sender: SenderRequest<'_>,
) -> Result<AnchorEvidence, RootExchangeError> {
    reexchange_request(
        server,
        token,
        ReExchangeRequest {
            scope: None,
            resource: None,
            client_id: None,
            root_scope: None,
            request_digest: Sha256Digest::from_hash(sha256(b"re-exchange")),
        },
        sender,
    )
}

fn reexchange_request(
    server: &LocalAuthorizationServer<'_>,
    token: &str,
    request: ReExchangeRequest<'_>,
    sender: SenderRequest<'_>,
) -> Result<AnchorEvidence, RootExchangeError> {
    let subject_scope = ceiling();
    local_as::verify_reexchange(
        server,
        token,
        request,
        SubjectRoot {
            scope: &subject_scope,
            assertion_exp: NOW + 200,
        },
        PresentedSender::from(sender),
        NOW,
    )
}

fn mtls_sender(thumbprint: &str) -> TransportIdentity {
    TransportIdentity::for_tests(Some(thumbprint), None)
}

#[test]
fn local_reexchange_requires_the_sender_constraint() {
    let bound = local_token(&with_cnf(json!({ "x5t#S256": "cert-thumbprint" })));
    let error = reexchange(&bound, None, None, None).unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Mtls)
    );
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
    let sender_key_bound = local_token(&with_cnf(json!({ "chioSenderKey": "ab".repeat(32) })));
    assert_eq!(
        reexchange(&sender_key_bound, None, None, None).unwrap_err(),
        RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::DpopUnavailable)
    );
}

#[test]
fn local_reexchange_widening_refuses() {
    let token = local_token(&local_claims());
    for (scope, resource, client_id, expected, code) in [
        (
            Some(vec!["mcp:admin".to_owned()]),
            None,
            None,
            RootExchangeError::ReExchangeWidens,
            OAuthErrorCode::InvalidScope,
        ),
        (
            Some(vec!["mcp:read".to_owned(), "mcp:write".to_owned()]),
            None,
            None,
            RootExchangeError::ReExchangeWidens,
            OAuthErrorCode::InvalidScope,
        ),
        (
            None,
            Some("https://other.example/mcp"),
            None,
            RootExchangeError::ReExchangeWidens,
            OAuthErrorCode::InvalidScope,
        ),
        (
            None,
            None,
            Some("another-client"),
            RootExchangeError::ReExchangeClientMismatch,
            OAuthErrorCode::InvalidGrant,
        ),
    ] {
        let error = reexchange(&token, scope.as_deref(), resource, client_id).unwrap_err();
        assert_eq!(error, expected);
        refusal_code(&error, code);
    }
}

#[test]
fn local_issue_replay_key_is_the_authorization_code_digest() {
    let issued = issue(|_| {}).unwrap();
    let code_digest = Sha256Digest::from_hash(sha256(AUTHORIZATION_CODE.as_bytes()));
    assert_eq!(
        issued.replay_key(),
        &ReplayKey {
            namespace: ReplayNamespace::LocalAsIssue,
            issuer: LOCAL_AS_ISSUER.to_owned(),
            id: code_digest.to_bare_hex(),
        }
    );
    assert_eq!(
        issued.replay_key().namespace.as_str(),
        "chio_local_as_issue"
    );
    assert_eq!(issued.artifact_digest(), Some(&code_digest));
    assert_eq!(issued.token_exp(), NOW + 300);
    assert_eq!(issued.principal, "local-user");
    assert_eq!(issued.tenant, AS_ISSUER);
    assert_eq!(issued.scope_values, ["mcp:invoke", "mcp:read"]);
    assert_ne!(
        issued.replay_key(),
        issue(|code| code.code = "code-2".to_owned())
            .unwrap()
            .replay_key()
    );
}

#[test]
fn local_reexchange_replay_key_is_the_subject_jti() {
    let narrowed = reexchange(
        &local_token(&local_claims()),
        Some(&["mcp:read".to_owned()]),
        Some(RESOURCE),
        None,
    )
    .unwrap();
    assert_eq!(
        narrowed.replay_key(),
        &ReplayKey {
            namespace: ReplayNamespace::Assertion(AnchorKind::ChioLocalAs),
            issuer: LOCAL_AS_ISSUER.to_owned(),
            id: "local-1".to_owned(),
        }
    );
    assert_eq!(narrowed.replay_key().namespace.as_str(), "chio_local_as");
    assert_eq!(narrowed.token_exp(), NOW + 200);
}

#[test]
fn local_issue_and_reexchange_spend_apart_and_a_second_reexchange_refuses() {
    let exchange = every_kind();
    let replay = MemoryReplay::default();
    let issued = exchange
        .prepare(issue(|_| {}).unwrap(), None, None, NOW, &entropy())
        .unwrap();
    exchange.spend_replay_key(&issued, &replay, NOW).unwrap();
    let token = local_token(&local_claims());
    let narrowed = || {
        exchange
            .prepare(
                reexchange(&token, Some(&["mcp:read".to_owned()]), Some(RESOURCE), None).unwrap(),
                None,
                None,
                NOW,
                &entropy(),
            )
            .unwrap()
    };
    let first = narrowed();
    assert_eq!(first.anchor().assertion_exp, NOW + 200);
    assert!(first.expires_at() <= NOW + 200);
    exchange.spend_replay_key(&first, &replay, NOW).unwrap();
    assert_eq!(
        exchange
            .spend_replay_key(&narrowed(), &replay, NOW)
            .unwrap_err(),
        RootExchangeError::AssertionReplay
    );
    assert_eq!(
        exchange
            .spend_replay_key(&issued, &replay, NOW)
            .unwrap_err(),
        RootExchangeError::AssertionReplay
    );
}

#[test]
fn sender_bound_code_issue_carries_cnf_to_the_issued_token() {
    let bound = constraint(json!({ "x5t#S256": "cert-thumbprint" }));
    let transport = mtls_sender("cert-thumbprint");
    let headers = no_headers();
    let issued = issue_with(
        |code| code.sender_constraint = Some(bound.clone()),
        SenderRequest::from_extension(&headers, Some(&transport)),
    )
    .unwrap();
    assert_eq!(issued.sender_constraint(), Some(&bound));
    assert_eq!(issue(|_| {}).unwrap().sender_constraint(), None);
}

#[test]
fn sender_bound_reexchange_carries_cnf_to_the_issued_token() {
    let key = local_keypair().public_key();
    let token = local_token(&with_cnf(json!({ "x5t#S256": "cert-thumbprint" })));
    let transport = mtls_sender("cert-thumbprint");
    let headers = no_headers();
    let narrowed = reexchange_from(
        &local_server(&key),
        &token,
        SenderRequest::from_extension(&headers, Some(&transport)),
    )
    .unwrap();
    assert_eq!(
        narrowed.sender_constraint(),
        Some(&constraint(json!({ "x5t#S256": "cert-thumbprint" })))
    );
    assert_eq!(
        reexchange(&local_token(&local_claims()), None, None, None)
            .unwrap()
            .sender_constraint(),
        None
    );
}

#[test]
fn local_issue_refusals() {
    let mtls = || Some(constraint(json!({ "x5t#S256": "cert-thumbprint" })));
    let headers = no_headers();
    let mut dpop = HeaderMap::new();
    dpop.insert(
        HeaderName::from_static(crate::DPOP_HEADER),
        HeaderValue::from_static("proof"),
    );
    let other_cert = mtls_sender("other-thumbprint");
    type CodeEdit = Box<dyn FnOnce(&mut CodeFixture)>;
    let cases: Vec<(
        CodeEdit,
        SenderRequest<'_>,
        RootExchangeError,
        OAuthErrorCode,
    )> = vec![
        (
            Box::new(|code| code.code_expires_at = NOW),
            SenderRequest::from(&headers),
            RootExchangeError::AssertionExpired,
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(|code| code.token_exp = NOW),
            SenderRequest::from(&headers),
            RootExchangeError::ClaimInvalid("exp"),
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(|code| code.issuer = "https://other-as.example".to_owned()),
            SenderRequest::from(&headers),
            RootExchangeError::IssuerMismatch,
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(|code| code.issued_at = NOW + 1),
            SenderRequest::from(&headers),
            RootExchangeError::AssertionIssuedInFuture,
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(|code| code.subject = String::new()),
            SenderRequest::from(&headers),
            RootExchangeError::ClaimInvalid("sub"),
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(move |code| code.sender_constraint = mtls()),
            SenderRequest::from(&headers),
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Mtls),
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(move |code| code.sender_constraint = mtls()),
            SenderRequest::from_extension(&headers, Some(&other_cert)),
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Mtls),
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(|code| {
                code.sender_constraint =
                    Some(constraint(json!({ "chioSenderKey": "ab".repeat(32) })));
            }),
            SenderRequest::from(&headers),
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::DpopUnavailable),
            OAuthErrorCode::InvalidGrant,
        ),
        (
            Box::new(|_| {}),
            SenderRequest::from(&dpop),
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::DpopUnavailable),
            OAuthErrorCode::InvalidGrant,
        ),
    ];
    for (edit_code, sender, expected, code) in cases {
        let error = issue_with(edit_code, sender).unwrap_err();
        assert_eq!(error, expected);
        refusal_code(&error, code);
    }
}

#[test]
fn operator_request_refusals() {
    let exchange = every_kind();
    let error = operator_key::verify(
        &operator_request(|request| {
            request.as_object_mut().unwrap().remove("tenant_value");
        }),
        NOW,
    )
    .unwrap_err();
    assert_eq!(error, RootExchangeError::OperatorRootRequestMissingTenant);
    refusal_code(&error, OAuthErrorCode::InvalidRequest);

    let mut repeated = operator_body(|_| {});
    repeated.pop();
    repeated.extend_from_slice(br#","request_id":"req-2"}"#);
    let oversized = vec![b' '; operator_key::MAX_OPERATOR_ROOT_REQUEST_BYTES + 1];
    for (body, reason) in [
        (
            operator_body(|request| {
                request["pad"] = json!(1);
            }),
            "body does not have the request shape",
        ),
        (repeated, "body is not duplicate-free UTF-8 JSON"),
        (oversized, "body exceeds the size bound"),
    ] {
        let error = OperatorRootRequest::parse(&body).unwrap_err();
        assert_eq!(error, RootExchangeError::OperatorRootRequestMalformed(reason));
        refusal_code(&error, OAuthErrorCode::InvalidRequest);
    }

    let error = operator_key::verify(
        &operator_request(|request| {
            request["expires_at"] = json!(NOW);
        }),
        NOW,
    )
    .unwrap_err();
    assert_eq!(error, RootExchangeError::RootLifetimeEmpty);
    refusal_code(&error, OAuthErrorCode::InvalidGrant);

    let caller_held = operator_key::verify(
        &operator_request(|request| {
            request["holder"] = json!("caller");
        }),
        NOW,
    )
    .unwrap();
    let error = exchange
        .prepare(caller_held, None, None, NOW, &entropy())
        .unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::RequestedHolderMismatch(HolderClass::EdgeSession)
    );
    refusal_code(&error, OAuthErrorCode::InvalidRequest);

    let beyond = operator_key::verify(
        &operator_request(|request| {
            request["scope"] = json!({ "grants": [grant("delete")] });
        }),
        NOW,
    )
    .unwrap();
    let error = exchange
        .prepare(beyond, None, None, NOW, &entropy())
        .unwrap_err();
    assert_eq!(error, RootExchangeError::ScopeExceedsCeiling);
    refusal_code(&error, OAuthErrorCode::InvalidScope);
}

#[test]
fn local_reexchange_takes_the_requested_root_scope() {
    let exchange = every_kind();
    let token = local_token(&local_claims());
    let narrowed_scope = ChioScope {
        grants: vec![grant("get")],
        ..ChioScope::default()
    };
    let narrowed = reexchange_to(
        &token,
        Some(&["mcp:read".to_owned()]),
        None,
        None,
        Some(&narrowed_scope),
    )
    .unwrap();
    let prepared = exchange
        .prepare(narrowed, None, None, NOW, &entropy())
        .unwrap();
    assert_eq!(tools(&prepared), ["get"]);
    consistent(&exchange, &prepared);

    let wider = ChioScope {
        grants: vec![grant("get"), grant("delete")],
        ..ChioScope::default()
    };
    let error = reexchange_to(&token, None, None, None, Some(&wider)).unwrap_err();
    assert_eq!(error, RootExchangeError::ReExchangeWidens);
    refusal_code(&error, OAuthErrorCode::InvalidScope);
}

#[test]
fn static_bearer_replay_key_is_stable_within_a_window() {
    let exchange = every_kind();
    let configured = StaticBearerToken::new(STATIC_TOKEN);
    let at = |now: u64| {
        operator_static_bearer::verify(&exchange, &configured, STATIC_TOKEN, now).unwrap()
    };
    let first = at(NOW);
    let later = at(NOW + 299);
    let next = at(NOW + 300);
    assert_eq!(first.token_exp(), NOW + 300);
    assert_eq!(later.token_exp(), NOW + 300);
    assert_eq!(first.replay_key(), later.replay_key());
    assert_eq!(next.token_exp(), NOW + 600);
    assert_ne!(first.replay_key(), next.replay_key());
}

#[tokio::test]
async fn introspection_record_is_pinned_before_the_request() {
    let pinned = introspection_record("acme-introspect");
    let moved = record(
        "acme-introspect",
        INTROSPECTION_ISSUER,
        ("sub", "iss"),
        |value| {
            value["kind"] = json!("oauth_introspection");
            value.as_object_mut().unwrap().remove("jwks_url");
            value["introspection_url"] = json!("https://elsewhere.example/introspect");
        },
    );
    let exchange = build(
        vec![provider_rule(
            "introspected-agents",
            "oauth_introspection",
            &pinned,
        )],
        &[moved],
    )
    .unwrap();
    let introspector = StubIntrospector::answering(introspection_response());
    let error = oauth_introspection::verify(&exchange, "opaque-token", NOW, &introspector)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::ProviderIdentityMismatch("acme-introspect".to_owned())
    );
    refusal_code(&error, OAuthErrorCode::ServerError);
    assert_eq!(introspector.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn introspection_issued_after_expiry_refuses() {
    let introspector = StubIntrospector::answering(edit(introspection_response(), |response| {
        response.insert("exp".into(), json!(NOW + 10));
        response.insert("iat".into(), json!(NOW + 20));
    }));
    let error = introspection_refusal(&introspector).await;
    assert_eq!(error, RootExchangeError::ClaimInvalid("exp"));
    refusal_code(&error, OAuthErrorCode::InvalidGrant);
}

fn local_rule(edit_rule: impl FnOnce(&mut Value)) -> RootExchange {
    let mut rule = base_rule("local-users", "chio_local_as");
    edit_rule(&mut rule);
    build(vec![rule], &[]).unwrap()
}

fn local_evidence() -> AnchorEvidence {
    issue(|_| {}).unwrap()
}

fn recorded_scope(prepared: &PreparedAnchoredRoot) -> Vec<&str> {
    match &prepared.context().anchor.claims.scope {
        Some(ClaimValue::List(values)) => values.iter().map(|value| value.as_str()).collect(),
        other => panic!("scope recorded as {other:?}"),
    }
}

#[test]
fn local_token_scope_is_recorded_and_matched() {
    let plain = local_rule(|rule| rule["recorded_claims"] = json!({ "scope": "plain" }));
    let prepared = plain
        .prepare(local_evidence(), None, None, NOW, &entropy())
        .unwrap();
    assert_eq!(recorded_scope(&prepared), ["mcp:invoke", "mcp:read"]);
    consistent(&plain, &prepared);

    let committed = local_rule(|rule| rule["recorded_claims"] = json!({ "scope": "committed" }));
    let prepared = committed
        .prepare(local_evidence(), None, None, NOW, &entropy())
        .unwrap();
    assert!(matches!(
        prepared.context().anchor.claims.scope,
        Some(ClaimValue::Committed(_))
    ));
    consistent(&committed, &prepared);

    let listed = local_rule(|rule| {
        rule["match"]["claims"] = json!({ "scope": ["mcp:invoke", "mcp:read"] });
    });
    listed
        .prepare(local_evidence(), None, None, NOW, &entropy())
        .unwrap();
    let narrower = local_rule(|rule| rule["match"]["claims"] = json!({ "scope": ["mcp:read"] }));
    assert_eq!(
        narrower
            .prepare(local_evidence(), None, None, NOW, &entropy())
            .unwrap_err(),
        RootExchangeError::RuleMatchCount { matched: 0 }
    );
}

#[test]
fn local_issue_records_the_token_audience() {
    let exchange = local_rule(|rule| rule["recorded_claims"] = json!({ "aud": "plain" }));
    let prepared = exchange
        .prepare(issue(|_| {}).unwrap(), None, None, NOW, &entropy())
        .unwrap();
    match &prepared.context().anchor.claims.aud {
        Some(ClaimValue::Plain(aud)) => assert_eq!(aud.as_str(), RESOURCE),
        other => panic!("aud recorded as {other:?}"),
    }
    consistent(&exchange, &prepared);
}

#[test]
fn local_reexchange_scope_is_the_narrowed_request() {
    let token = local_token(&local_claims());
    let narrowed = ["mcp:read".to_owned()];
    let evidence = || reexchange(&token, Some(&narrowed), Some(RESOURCE), Some(CLIENT_ID)).unwrap();
    assert_eq!(evidence().scope_values, ["mcp:read"]);

    let exchange = local_rule(|rule| {
        rule["recorded_claims"] = json!({ "scope": "plain" });
        rule["match"]["claims"] = json!({ "scope": ["mcp:read"] });
    });
    let prepared = exchange
        .prepare(evidence(), None, None, NOW, &entropy())
        .unwrap();
    assert_eq!(recorded_scope(&prepared), ["mcp:read"]);

    let invoke_only =
        local_rule(|rule| rule["match"]["claims"] = json!({ "scope": ["mcp:invoke"] }));
    assert_eq!(
        invoke_only
            .prepare(evidence(), None, None, NOW, &entropy())
            .unwrap_err(),
        RootExchangeError::RuleMatchCount { matched: 0 }
    );
}

#[tokio::test]
async fn sender_bound_provider_tokens_refuse() {
    let keys = AnyRecordKeys::idp();
    for (cnf, failure) in [
        (
            json!({ "x5t#S256": "cert-thumbprint" }),
            SenderConstraintFailure::Mtls,
        ),
        (
            json!({ "chioSenderKey": "ab".repeat(32) }),
            SenderConstraintFailure::DpopUnavailable,
        ),
        (
            json!({ "jkt": "dpop-thumbprint" }),
            SenderConstraintFailure::Confirmation,
        ),
    ] {
        let expected = RootExchangeError::SenderConstraintUnmet(failure);
        let bound = |claims: Value| {
            edit(claims, |claims| {
                claims.insert("cnf".into(), cnf.clone());
            })
        };
        let error = oidc_refusal(bound(oidc_claims())).await;
        assert_eq!(error, expected);
        refusal_code(&error, OAuthErrorCode::InvalidGrant);
        let entra = compact(&idp_header(), &bound(entra_claims()), idp_sign);
        assert_eq!(
            entra_jwt::verify(&every_kind(), &entra, NOW, &keys)
                .await
                .unwrap_err(),
            expected
        );
        let introspector = StubIntrospector::answering(bound(introspection_response()));
        assert_eq!(introspection_refusal(&introspector).await, expected);
    }
}

#[test]
fn operator_scope_of_only_resource_grants_is_not_empty() {
    let ceiling: ChioScope = serde_json::from_value(json!({
        "grants": [grant("search")],
        "resource_grants": [{ "uri_pattern": "crm://records/*", "operations": ["read"] }]
    }))
    .unwrap();
    let mut rule = base_rule("operator-roots", "chio_operator_key");
    rule["ceiling_scope"] = json!(ceiling);
    rule["ceiling_scope_hash"] = json!(digest_of(&ceiling));
    let exchange = build(vec![rule], &[]).unwrap();
    let resources_only = json!({
        "resource_grants": [{ "uri_pattern": "crm://records/*", "operations": ["read"] }]
    });
    let evidence = operator_key::verify(
        &operator_request(|request| request["scope"] = resources_only.clone()),
        NOW,
    )
    .unwrap();
    let prepared = exchange
        .prepare(evidence, None, None, NOW, &entropy())
        .unwrap();
    assert!(prepared.body.scope.grants.is_empty());
    assert_eq!(prepared.body.scope.resource_grants.len(), 1);
    consistent(&exchange, &prepared);
    let empty = operator_key::verify(
        &operator_request(|request| request["scope"] = json!({})),
        NOW,
    )
    .unwrap();
    assert_eq!(
        exchange
            .prepare(empty, None, None, NOW, &entropy())
            .unwrap_err(),
        RootExchangeError::EmptyEffectiveScope
    );
}
