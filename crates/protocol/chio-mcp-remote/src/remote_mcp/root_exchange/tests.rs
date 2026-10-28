//! The ID-JAG root exchange: confidential client authentication, key
//! lookup, claim rules, replay keys and the prepared anchored root. Every
//! refusal is pinned to its exact error.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod kinds;

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::root_exchange::OAuthErrorCode;
use crate::root_exchange::{
    jws::{CompactJws, VerifyingKey},
    ClientRegistry, ExchangeReplayStore, ExchangeServices, IdJagGrant, IdpKey, IdpKeyLookup,
    PreparedAnchoredRoot, ProviderRecord, ReplayBinding, ReplayKey, RequestedTokenType,
    RootExchange, RootExchangeConfig, RootExchangeConfigError, RootExchangeError,
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_control_plane::enterprise_federation::EnterpriseProviderRecord;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::rng::{Rng, RngError};
use chio_core::root_authority::{
    check_root_consistency, ClaimValue, EnterpriseProviderIdentity, HolderClass, IdpKeySnapshot,
    Jwk, JwsAlgorithm, LoadedRootPolicy, RootConsistencyInput, RootPolicy, Sha256Digest,
};
use chio_core::{canonical_json_bytes, sha256};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{json, Map, Value};

const NOW: u64 = 1_792_234_800;
const ISSUER: &str = "https://acme.okta.com";
const JWKS_URL: &str = "https://acme.okta.com/oauth2/v1/keys";
const AS_ISSUER: &str = "https://mcp.provider.example";
const TOKEN_ENDPOINT: &str = "https://mcp.provider.example/oauth/token";
const RESOURCE: &str = "https://mcp.provider.example/mcp";
const CLIENT_ID: &str = "mcp-client-claude";
const IDP_KID: &str = "k-okta-1";
const CLIENT_KID: &str = "client-key-1";
const RULE_ID: &str = "okta-crm-agents";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn idp_keypair() -> Keypair {
    Keypair::from_seed(&[11; 32])
}

fn client_key() -> P256SigningKey {
    P256SigningKey::from_slice(&[7; 32]).unwrap()
}

fn exchange_keypair() -> Keypair {
    Keypair::from_seed(&[2; 32])
}

fn policy_keypair() -> Keypair {
    Keypair::from_seed(&[1; 32])
}

/// The digest of a signed snapshot holding `keys`, as the key source reports it.
fn snapshot_digest(keys: &[Value]) -> Sha256Digest {
    let unsigned: IdpKeySnapshot = serde_json::from_value(json!({
        "schema": "chio.idp-key-snapshot.v1",
        "issuer": ISSUER,
        "source": JWKS_URL,
        "keys": keys,
        "observed_at": NOW - 60,
        "exchange_key": exchange_keypair().public_key(),
        "signature": "00".repeat(64)
    }))
    .unwrap();
    let signature = exchange_keypair()
        .sign_canonical(&unsigned.signing_body())
        .unwrap()
        .0;
    let mut fields = unsigned.into_fields();
    fields.signature = signature;
    let snapshot = IdpKeySnapshot::new(fields).unwrap();
    snapshot
        .verify_signature(&exchange_keypair().public_key())
        .unwrap();
    snapshot.digest().unwrap()
}

fn idp_jwk(kid: &str) -> Value {
    json!({ "kid": kid, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
            "x": b64(&idp_keypair().public_key_bytes()) })
}

fn client_jwk() -> Value {
    let point = client_key().verifying_key().to_encoded_point(false);
    json!({ "kid": CLIENT_KID, "kty": "EC", "crv": "P-256", "alg": "ES256",
            "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()) })
}

fn compact(header: &Value, claims: &Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(header).unwrap()),
        b64(&serde_json::to_vec(claims).unwrap())
    );
    let signature = sign(input.as_bytes());
    format!("{input}.{}", b64(&signature))
}

fn idp_sign(input: &[u8]) -> Vec<u8> {
    idp_keypair().sign(input).to_bytes().to_vec()
}

fn client_sign(input: &[u8]) -> Vec<u8> {
    let signature: P256Signature = client_key().sign(input);
    signature.to_bytes().to_vec()
}

fn id_jag_header() -> Value {
    json!({ "alg": "EdDSA", "kid": IDP_KID, "typ": "oauth-id-jag+jwt" })
}

fn id_jag_claims() -> Value {
    json!({
        "iss": ISSUER, "sub": "00u-alice", "aud": AS_ISSUER, "client_id": CLIENT_ID,
        "jti": "id-jag-1", "iat": NOW - 10, "exp": NOW + 290, "scope": "crm.read",
        "resource": RESOURCE
    })
}

fn client_assertion_claims() -> Value {
    json!({ "iss": CLIENT_ID, "sub": CLIENT_ID, "aud": TOKEN_ENDPOINT,
            "jti": "client-assertion-1", "iat": NOW - 5, "exp": NOW + 30 })
}

fn client_assertion(claims: &Value) -> String {
    compact(
        &json!({ "alg": "ES256", "kid": CLIENT_KID }),
        claims,
        client_sign,
    )
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish().into_bytes()
}

fn jwt_bearer_body(id_jag: &str, assertion: &str) -> Vec<u8> {
    form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", id_jag),
        ("client_id", CLIENT_ID),
        ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
        ("client_assertion", assertion),
    ])
}

fn grant(tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: "crm".into(),
        tool_name: tool.into(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn digest_of(scope: &ChioScope) -> Sha256Digest {
    Sha256Digest::from_hash(sha256(&canonical_json_bytes(scope).unwrap()))
}

fn provider_record(edit: impl FnOnce(&mut Value)) -> EnterpriseProviderRecord {
    let mut value = json!({
        "provider_id": "acme-okta",
        "kind": "oidc_jwks",
        "enabled": true,
        "provenance": { "configured_from": "file", "trust_material_ref": "okta-org-acme" },
        "trust_boundary": {},
        "issuer": ISSUER,
        "jwks_url": JWKS_URL,
        "subject_mapping": { "principal_source": "sub", "tenant_id_field": "iss" }
    });
    edit(&mut value);
    serde_json::from_value(value).unwrap()
}

fn rule_json(identity_digest: Sha256Digest, ceiling: &ChioScope) -> Value {
    json!({
        "rule_id": RULE_ID,
        "match": {
            "anchor_kind": "oauth_id_jag",
            "provider_record_id": "acme-okta",
            "provider_identity_digest": identity_digest,
            "allowed_algs": ["EdDSA"],
            "claims": { "client_id": [CLIENT_ID] }
        },
        "idp_scope_projection": {
            "crm.read": ["crm/search", "crm/get"],
            "crm.admin": ["crm/delete"],
            "crm.write": ["crm/update"]
        },
        "ceiling_scope": ceiling,
        "ceiling_scope_hash": digest_of(ceiling),
        "recorded_claims": { "client_id": "plain", "scope": "plain" },
        "holder_classes": ["edge_session", "caller"],
        "capability_ttl_secs": 300,
        "max_assertion_lifetime_secs": 300,
        "max_clock_skew_secs": 30
    })
}

fn loaded_policy(identity_digest: Sha256Digest, edit: impl FnOnce(&mut Value)) -> LoadedRootPolicy {
    let ceiling = ChioScope {
        grants: vec![grant("search"), grant("get"), grant("update")],
        ..ChioScope::default()
    };
    let mut value = json!({
        "schema": "chio.root-policy.v1",
        "policy_id": "rp_acme_prod",
        "policy_key": policy_keypair().public_key(),
        "exchange_keys": [exchange_keypair().public_key()],
        "rules": [rule_json(identity_digest, &ceiling)],
        "disclosure": { "default": "committed" },
        "valid_from": NOW - 1_000,
        "valid_until": NOW + 100_000,
        "signature": "00".repeat(64)
    });
    edit(&mut value);
    let unsigned: RootPolicy = serde_json::from_value(value).unwrap();
    let signature = policy_keypair()
        .sign_canonical(&unsigned.signing_body())
        .unwrap()
        .0;
    let mut fields = unsigned.into_fields();
    fields.signature = signature;
    RootPolicy::new(fields)
        .unwrap()
        .load(&policy_keypair().public_key(), NOW)
        .unwrap()
}

#[derive(Default)]
struct MemoryReplay {
    bound: Mutex<HashMap<ReplayKey, u64>>,
}

impl ExchangeReplayStore for MemoryReplay {
    fn bind(&self, key: &ReplayKey, retain_until: u64, now: u64) -> Result<ReplayBinding, String> {
        let mut bound = self.bound.lock().unwrap();
        if bound.get(key).is_some_and(|until| *until > now) {
            return Ok(ReplayBinding::AlreadyBound);
        }
        bound.insert(key.clone(), retain_until);
        Ok(ReplayBinding::Bound)
    }
}

/// Deterministic bytes per draw. Only draw `fail_at` (0-based), when set,
/// fails; every other draw succeeds.
struct CountingRng {
    draws: AtomicU64,
    fail_at: Option<u64>,
}

impl CountingRng {
    fn new() -> Self {
        Self {
            draws: AtomicU64::new(0),
            fail_at: None,
        }
    }
}

impl Rng for CountingRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        let draw = self.draws.fetch_add(1, Ordering::SeqCst);
        if self.fail_at == Some(draw) {
            return Err(RngError("fixture source offline"));
        }
        let seed = draw + 1;
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = (seed as u8).wrapping_mul(31).wrapping_add(index as u8);
        }
        Ok(())
    }
}

struct StubKeys {
    keys: Vec<Jwk>,
    snapshot_digest: Sha256Digest,
    failure: Option<RootExchangeError>,
    any_kid: bool,
    calls: AtomicUsize,
}

impl StubKeys {
    fn serving(keys: &[Value]) -> Self {
        Self {
            keys: keys
                .iter()
                .map(|key| serde_json::from_value(key.clone()).unwrap())
                .collect(),
            snapshot_digest: snapshot_digest(keys),
            failure: None,
            any_kid: false,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl IdpKeyLookup for StubKeys {
    async fn resolve(
        &self,
        provider: &EnterpriseProviderIdentity,
        kid: &str,
        _alg: JwsAlgorithm,
        _now: u64,
    ) -> Result<IdpKey, RootExchangeError> {
        assert_eq!(provider.provider_id.as_str(), "acme-okta");
        assert_eq!(provider.jwks_url.as_ref().unwrap().as_str(), JWKS_URL);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        self.keys
            .iter()
            .find(|key| self.any_kid || key.kid.as_str() == kid)
            .map(|jwk| IdpKey {
                jwk: jwk.clone(),
                snapshot_digest: self.snapshot_digest,
            })
            .ok_or(RootExchangeError::UnknownKid)
    }
}

struct Harness {
    exchange: RootExchange,
    keys: StubKeys,
    replay: MemoryReplay,
    entropy: CountingRng,
}

fn exchange_config(
    edit_record: impl FnOnce(&mut Value),
    edit_policy: impl FnOnce(&mut Value),
) -> RootExchangeConfig {
    let pinned = ProviderRecord::from_record(&provider_record(|_| {})).unwrap();
    let record = ProviderRecord::from_record(&provider_record(edit_record)).unwrap();
    let policy = loaded_policy(*pinned.identity_digest(), edit_policy);
    let mut providers = BTreeMap::new();
    providers.insert("acme-okta".to_owned(), record);
    let clients = ClientRegistry::new(&[crate::OAuthClientRegistration {
        client_id: CLIENT_ID.to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        token_endpoint_auth: crate::TokenEndpointAuth::PrivateKeyJwt(Box::new(
            serde_json::from_value(client_jwk()).unwrap(),
        )),
    }])
    .unwrap();
    RootExchangeConfig {
        policy,
        providers,
        clients,
        exchange_key: exchange_keypair().public_key(),
        authorization_server: AS_ISSUER.to_owned(),
        token_endpoint: TOKEN_ENDPOINT.to_owned(),
        protected_resource: RESOURCE.to_owned(),
        client_assertion_skew_secs: 5,
    }
}

impl Harness {
    fn new() -> Self {
        Self::with(|_| {}, |_| {})
    }

    fn with(edit_record: impl FnOnce(&mut Value), edit_policy: impl FnOnce(&mut Value)) -> Self {
        Self {
            exchange: RootExchange::new(exchange_config(edit_record, edit_policy)).unwrap(),
            keys: StubKeys::serving(&[idp_jwk(IDP_KID)]),
            replay: MemoryReplay::default(),
            entropy: CountingRng::new(),
        }
    }

    async fn run_body(
        &self,
        body: &[u8],
        sender_key: Option<&PublicKey>,
        now: u64,
    ) -> Result<PreparedAnchoredRoot, RootExchangeError> {
        let grant = IdJagGrant::parse(body, None)?;
        self.exchange
            .exchange_id_jag(
                &grant,
                sender_key,
                now,
                ExchangeServices {
                    keys: &self.keys,
                    replay: &self.replay,
                    entropy: &self.entropy,
                },
            )
            .await
    }

    async fn run(
        &self,
        header: Value,
        claims: Value,
    ) -> Result<PreparedAnchoredRoot, RootExchangeError> {
        let id_jag = compact(&header, &claims, idp_sign);
        let body = jwt_bearer_body(&id_jag, &client_assertion(&client_assertion_claims()));
        self.run_body(&body, None, NOW).await
    }
}

fn edit(mut value: Value, change: impl FnOnce(&mut Map<String, Value>)) -> Value {
    change(value.as_object_mut().unwrap());
    value
}

async fn refusal(header: Value, claims: Value) -> RootExchangeError {
    Harness::new().run(header, claims).await.unwrap_err()
}

#[tokio::test]
async fn id_jag_exchange_prepares_a_root_consistent_with_its_anchor() {
    let harness = Harness::new();
    let prepared = harness.run(id_jag_header(), id_jag_claims()).await.unwrap();

    assert_eq!(prepared.holder(), HolderClass::EdgeSession);
    assert_eq!(prepared.body.issued_at, NOW);
    assert_eq!(prepared.body.expires_at, NOW + 290);
    assert_eq!(prepared.anchor().assertion_exp, NOW + 290);
    assert_eq!(prepared.anchor().anchored_at, NOW);
    let tools: Vec<_> = prepared
        .body
        .scope
        .grants
        .iter()
        .map(|grant| grant.tool_name.as_str())
        .collect();
    assert_eq!(tools, ["search", "get"]);
    assert_eq!(
        prepared.context().anchor.claims.client_id,
        Some(ClaimValue::Plain(
            chio_core::root_authority::Text::new(CLIENT_ID).unwrap()
        ))
    );
    assert_eq!(
        prepared.context().anchor.key_snapshot_digest,
        Some(snapshot_digest(&[idp_jwk(IDP_KID)]))
    );
    assert_eq!(harness.keys.calls.load(Ordering::SeqCst), 1);
    assert_eq!(prepared.openings().len(), 2);

    let root = CapabilityToken::sign(prepared.body.clone(), &exchange_keypair()).unwrap();
    check_root_consistency(RootConsistencyInput {
        root: &root,
        anchor: prepared.anchor(),
        context: prepared.context(),
        policy: &harness.exchange.policy,
        sender_key: None,
    })
    .unwrap();
}

#[tokio::test]
async fn caller_held_root_takes_the_sender_key_as_subject() {
    let harness = Harness::new();
    let id_jag = compact(&id_jag_header(), &id_jag_claims(), idp_sign);
    let body = jwt_bearer_body(&id_jag, &client_assertion(&client_assertion_claims()));
    let sender = Keypair::from_seed(&[9; 32]).public_key();
    let prepared = harness.run_body(&body, Some(&sender), NOW).await.unwrap();
    assert_eq!(prepared.holder(), HolderClass::Caller);
    assert_eq!(prepared.body.subject, sender);
}

#[tokio::test]
async fn token_exchange_grant_with_an_id_jag_subject_token_is_accepted() {
    let harness = Harness::new();
    let id_jag = compact(&id_jag_header(), &id_jag_claims(), idp_sign);
    let assertion = client_assertion(&client_assertion_claims());
    let body = form(&[
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", &id_jag),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:id-jag",
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
        ("client_assertion", &assertion),
    ]);
    harness.run_body(&body, None, NOW).await.unwrap();
}

#[test]
fn capability_requested_token_type_is_accepted_on_token_exchange() {
    let body = |requested: Option<&str>| {
        let mut pairs = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", "token"),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:id-jag",
            ),
        ];
        if let Some(requested) = requested {
            pairs.push(("requested_token_type", requested));
        }
        form(&pairs)
    };
    let capability = IdJagGrant::parse(
        &body(Some("urn:chio:params:oauth:token-type:capability-v1")),
        None,
    )
    .unwrap();
    assert_eq!(
        capability.requested_token_type(),
        RequestedTokenType::ChioCapability
    );
    let access = IdJagGrant::parse(
        &body(Some("urn:ietf:params:oauth:token-type:access_token")),
        None,
    )
    .unwrap();
    assert_eq!(
        access.requested_token_type(),
        RequestedTokenType::AccessToken
    );
    let absent = IdJagGrant::parse(&body(None), None).unwrap();
    assert_eq!(
        absent.requested_token_type(),
        RequestedTokenType::AccessToken
    );
    assert_ne!(capability.request_digest(), access.request_digest());
    assert_eq!(access.request_digest(), absent.request_digest());
}

#[test]
fn request_digest_excludes_client_authentication() {
    let body = |assertion: &str| {
        form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", "id-jag"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
            ("client_assertion", assertion),
        ])
    };
    let first = IdJagGrant::parse(&body("first-assertion"), None).unwrap();
    let retry = IdJagGrant::parse(&body("fresh-assertion"), None).unwrap();
    assert_eq!(first.request_digest(), retry.request_digest());
    let other = IdJagGrant::parse(
        &form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", "other-id-jag"),
        ]),
        None,
    )
    .unwrap();
    assert_ne!(first.request_digest(), other.request_digest());
}

#[test]
fn token_requests_outside_the_id_jag_grants_are_refused() {
    let unsupported = form(&[("grant_type", "client_credentials")]);
    assert_eq!(
        IdJagGrant::parse(&unsupported, None).unwrap_err(),
        RootExchangeError::UnsupportedGrantType
    );
    let other_subject = form(&[
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", "token"),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
    ]);
    assert_eq!(
        IdJagGrant::parse(&other_subject, None).unwrap_err(),
        RootExchangeError::UnsupportedSubjectTokenType
    );
    let other_requested = form(&[
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", "token"),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:id-jag",
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:refresh_token",
        ),
    ]);
    assert_eq!(
        IdJagGrant::parse(&other_requested, None).unwrap_err(),
        RootExchangeError::UnsupportedRequestedTokenType
    );
    let repeated = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", "a"),
        ("assertion", "b"),
    ]);
    assert_eq!(
        IdJagGrant::parse(&repeated, None).unwrap_err(),
        RootExchangeError::MalformedRequest("repeated parameter")
    );
    let unknown = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", "a"),
        ("scope", "crm.read"),
        ("resource", "https://mcp.provider.example/mcp"),
    ]);
    assert_eq!(IdJagGrant::parse(&unknown, None).unwrap().id_jag(), "a");
    let not_utf8 =
        b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=%FF".to_vec();
    assert_eq!(
        IdJagGrant::parse(&not_utf8, None).unwrap_err(),
        RootExchangeError::MalformedRequest("parameter is not valid UTF-8")
    );
    let not_utf8_unknown =
        b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=a&extra=%FF"
            .to_vec();
    assert!(IdJagGrant::parse(&not_utf8_unknown, None).is_ok());
}

#[test]
fn single_empty_parameter_is_omitted() {
    let empty_known = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", "a"),
        ("client_id", ""),
        ("scope", ""),
    ]);
    let grant = IdJagGrant::parse(&empty_known, None).unwrap();
    assert_eq!(grant.client_credentials().client_id, None);
    assert_eq!(grant.requested_scope(), None);
}

#[test]
fn empty_duplicate_parameter_refuses() {
    for pair in [["", "a"], ["a", ""], ["", ""]] {
        let body = form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", pair[0]),
            ("assertion", pair[1]),
        ]);
        let error = IdJagGrant::parse(&body, None).unwrap_err();
        assert_eq!(
            error,
            RootExchangeError::MalformedRequest("repeated parameter")
        );
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidRequest);
    }
}

#[tokio::test]
async fn client_secret_with_client_assertion_refuses() {
    let harness = Harness::new();
    let assertion = client_assertion(&client_assertion_claims());
    let mut with_secret = jwt_bearer_body(&id_jag(), &assertion);
    with_secret.extend_from_slice(b"&client_secret=s3cret");
    let error = IdJagGrant::parse(&with_secret, None).unwrap_err();
    assert_eq!(error, RootExchangeError::ClientAuthenticationAmbiguous);
    assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidRequest);

    let body = jwt_bearer_body(&id_jag(), &assertion);
    for authorization in [&b"Basic bWNwOnMzY3JldA=="[..], b"basic bWNwOnMzY3JldA=="] {
        let error = IdJagGrant::parse(&body, Some(authorization)).unwrap_err();
        assert_eq!(error, RootExchangeError::ClientAuthenticationAmbiguous);
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidRequest);
    }
    assert!(harness.replay.bound.lock().unwrap().is_empty());
    harness.run_body(&body, None, NOW).await.unwrap();
}

#[tokio::test]
async fn client_secret_alone_is_not_client_authentication() {
    let body = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &id_jag()),
        ("client_id", CLIENT_ID),
        ("client_secret", "s3cret"),
    ]);
    assert_eq!(
        client_refusal(body).await,
        RootExchangeError::ClientAssertionMissing
    );
}

#[test]
fn requested_scope_outside_the_rfc6749_syntax_refuses() {
    for scope in [
        "crm.read  crm.write",
        " crm.read",
        "crm.read ",
        "crm\"read",
        "crm\\read",
        "crm.read\tcrm.write",
        "cr\u{e9}m.read",
    ] {
        let body = form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", "a"),
            ("scope", scope),
        ]);
        let error = IdJagGrant::parse(&body, None).unwrap_err();
        assert_eq!(error, RootExchangeError::RequestedScopeMalformed);
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidScope);
    }
}

#[tokio::test]
async fn token_response_carries_scope_when_it_differs_from_the_request() {
    let cases = [
        (None, Some("crm.read")),
        (Some("crm.read"), None),
        (Some("crm.read crm.read"), None),
    ];
    for (requested, expected) in cases {
        let mut body = jwt_bearer_body(&id_jag(), &client_assertion(&client_assertion_claims()));
        if let Some(requested) = requested {
            body.extend_from_slice(b"&");
            body.extend_from_slice(&form(&[("scope", requested)]));
        }
        let prepared = Harness::new().run_body(&body, None, NOW).await.unwrap();
        assert_eq!(
            prepared.response_scope(),
            expected,
            "requested {requested:?}"
        );
    }
}

fn read_write_body(requested: Option<&str>) -> Vec<u8> {
    let claims = edit(id_jag_claims(), |claims| {
        claims.insert("scope".into(), json!("crm.read crm.write"));
    });
    let id_jag = compact(&id_jag_header(), &claims, idp_sign);
    let mut body = jwt_bearer_body(&id_jag, &client_assertion(&client_assertion_claims()));
    if let Some(requested) = requested {
        body.extend_from_slice(b"&");
        body.extend_from_slice(&form(&[("scope", requested)]));
    }
    body
}

#[tokio::test]
async fn requested_scope_narrows_the_root() {
    let cases = [
        (None, vec!["search", "get", "update"]),
        (Some("crm.read"), vec!["search", "get"]),
        (Some("crm.write"), vec!["update"]),
        (Some("crm.read crm.write"), vec!["search", "get", "update"]),
    ];
    for (requested, tools) in cases {
        let harness = Harness::new();
        let prepared = harness
            .run_body(&read_write_body(requested), None, NOW)
            .await
            .unwrap();
        let granted: Vec<_> = prepared
            .scope()
            .grants
            .iter()
            .map(|grant| grant.tool_name.as_str())
            .collect();
        assert_eq!(granted, tools, "requested {requested:?}");
        let expected_scope = requested.is_none().then_some("crm.read crm.write");
        assert_eq!(prepared.response_scope(), expected_scope);
        let root = CapabilityToken::sign(prepared.body.clone(), &exchange_keypair()).unwrap();
        check_root_consistency(RootConsistencyInput {
            root: &root,
            anchor: prepared.anchor(),
            context: prepared.context(),
            policy: &harness.exchange.policy,
            sender_key: None,
        })
        .unwrap();
    }
}

#[tokio::test]
async fn requested_scope_beyond_the_assertion_refuses() {
    for requested in ["crm.export", "crm.read crm.export", "crm.admin"] {
        let harness = Harness::new();
        let error = harness
            .run_body(&read_write_body(Some(requested)), None, NOW)
            .await
            .unwrap_err();
        assert_eq!(error, RootExchangeError::RequestedScopeExceedsAssertion);
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidScope);
        let bound = harness.replay.bound.lock().unwrap();
        assert_eq!(bound.len(), 1);
        assert!(bound.keys().all(|key| key.id != "id-jag-1"));
    }
}

async fn client_refusal(body: Vec<u8>) -> RootExchangeError {
    Harness::new().run_body(&body, None, NOW).await.unwrap_err()
}

fn id_jag() -> String {
    compact(&id_jag_header(), &id_jag_claims(), idp_sign)
}

#[tokio::test]
async fn public_clients_cannot_redeem_an_id_jag() {
    let body = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &id_jag()),
        ("client_id", CLIENT_ID),
    ]);
    assert_eq!(
        client_refusal(body).await,
        RootExchangeError::ClientAssertionMissing
    );
}

#[tokio::test]
async fn client_assertion_rules_are_enforced() {
    let assertion = client_assertion(&client_assertion_claims());
    let wrong_type = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &id_jag()),
        ("client_assertion_type", "urn:example:other"),
        ("client_assertion", &assertion),
    ]);
    assert_eq!(
        client_refusal(wrong_type).await,
        RootExchangeError::ClientAssertionTypeUnsupported
    );

    let unregistered = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.insert("iss".into(), json!("other-client"));
        claims.insert("sub".into(), json!("other-client"));
    }));
    let body = form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &id_jag()),
        ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
        ("client_assertion", &unregistered),
    ]);
    assert_eq!(
        client_refusal(body).await,
        RootExchangeError::ClientNotConfidential
    );

    let forged = compact(
        &json!({ "alg": "ES256", "kid": CLIENT_KID }),
        &client_assertion_claims(),
        |input| {
            let other = P256SigningKey::from_slice(&[8; 32]).unwrap();
            let signature: P256Signature = other.sign(input);
            signature.to_bytes().to_vec()
        },
    );
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &forged)).await,
        RootExchangeError::ClientAssertionSignatureInvalid
    );

    let wrong_audience = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.insert("aud".into(), json!(AS_ISSUER));
    }));
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &wrong_audience)).await,
        RootExchangeError::ClientAssertionInvalid("aud is not the token endpoint")
    );

    let long_lived = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.insert("exp".into(), json!(NOW + 60));
    }));
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &long_lived)).await,
        RootExchangeError::ClientAssertionInvalid("lifetime exceeds 60 seconds")
    );

    let without_jti = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.remove("jti");
    }));
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &without_jti)).await,
        RootExchangeError::ClientAssertionInvalid("claim missing")
    );

    let expired = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.insert("iat".into(), json!(NOW - 60));
        claims.insert("exp".into(), json!(NOW - 10));
    }));
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &expired)).await,
        RootExchangeError::ClientAssertionInvalid("expired")
    );
}

#[tokio::test]
async fn client_assertion_jti_is_single_use() {
    let harness = Harness::new();
    let assertion = client_assertion(&client_assertion_claims());
    harness
        .run_body(&jwt_bearer_body(&id_jag(), &assertion), None, NOW)
        .await
        .unwrap();
    let second_id_jag = compact(
        &id_jag_header(),
        &edit(id_jag_claims(), |claims| {
            claims.insert("jti".into(), json!("id-jag-2"));
        }),
        idp_sign,
    );
    assert_eq!(
        harness
            .run_body(&jwt_bearer_body(&second_id_jag, &assertion), None, NOW)
            .await
            .unwrap_err(),
        RootExchangeError::ClientAssertionReplay
    );
}

#[tokio::test]
async fn id_jag_jti_is_single_use() {
    let harness = Harness::new();
    let id_jag = id_jag();
    harness
        .run_body(
            &jwt_bearer_body(&id_jag, &client_assertion(&client_assertion_claims())),
            None,
            NOW,
        )
        .await
        .unwrap();
    let fresh_assertion = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.insert("jti".into(), json!("client-assertion-2"));
    }));
    assert_eq!(
        harness
            .run_body(&jwt_bearer_body(&id_jag, &fresh_assertion), None, NOW)
            .await
            .unwrap_err(),
        RootExchangeError::AssertionReplay
    );
}

#[tokio::test]
async fn jws_header_rules_are_enforced() {
    let with_jku = edit(id_jag_header(), |header| {
        header.insert("jku".into(), json!("https://attacker.example/keys"));
    });
    assert_eq!(
        refusal(with_jku, id_jag_claims()).await,
        RootExchangeError::ForbiddenHeaderMember("jku")
    );
    let with_crit = edit(id_jag_header(), |header| {
        header.insert("crit".into(), json!(["exp"]));
    });
    assert_eq!(
        refusal(with_crit, id_jag_claims()).await,
        RootExchangeError::ForbiddenHeaderMember("crit")
    );
    for alg in ["HS256", "none", "ES512"] {
        let header = edit(id_jag_header(), |header| {
            header.insert("alg".into(), json!(alg));
        });
        assert_eq!(
            refusal(header, id_jag_claims()).await,
            RootExchangeError::AlgorithmNotAdmitted
        );
    }
    let without_kid = edit(id_jag_header(), |header| {
        header.remove("kid");
    });
    assert_eq!(
        refusal(without_kid, id_jag_claims()).await,
        RootExchangeError::KidMissing
    );
    let wrong_typ = edit(id_jag_header(), |header| {
        header.insert("typ".into(), json!("JWT"));
    });
    assert_eq!(
        refusal(wrong_typ, id_jag_claims()).await,
        RootExchangeError::TypMismatch
    );
}

#[tokio::test]
async fn forged_id_jag_signature_is_refused() {
    let harness = Harness::new();
    let forged = compact(&id_jag_header(), &id_jag_claims(), |input| {
        Keypair::from_seed(&[12; 32])
            .sign(input)
            .to_bytes()
            .to_vec()
    });
    let body = jwt_bearer_body(&forged, &client_assertion(&client_assertion_claims()));
    assert_eq!(
        harness.run_body(&body, None, NOW).await.unwrap_err(),
        RootExchangeError::SignatureInvalid
    );
}

#[tokio::test]
async fn key_lookup_refusals_deny_the_exchange() {
    let unknown = edit(id_jag_header(), |header| {
        header.insert("kid".into(), json!("k-okta-rotated"));
    });
    assert_eq!(
        refusal(unknown, id_jag_claims()).await,
        RootExchangeError::UnknownKid
    );
    let mut unavailable = Harness::new();
    unavailable.keys.failure = Some(RootExchangeError::KeysUnavailable(
        "jwks endpoint unreachable".to_owned(),
    ));
    assert_eq!(
        unavailable
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::KeysUnavailable("jwks endpoint unreachable".to_owned())
    );
    let mut mismatched = Harness::new();
    mismatched.keys = StubKeys::serving(&[edit(idp_jwk(IDP_KID), |key| {
        key.insert("alg".into(), json!("ES256"));
        key.insert("kty".into(), json!("EC"));
        key.insert("crv".into(), json!("P-256"));
        key.insert("y".into(), key["x"].clone());
    })]);
    assert_eq!(
        mismatched
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::IdpKeyUnusable
    );
}

#[tokio::test]
async fn id_jag_claim_rules_are_enforced() {
    let cases: Vec<(Value, RootExchangeError)> = vec![
        (
            edit(id_jag_claims(), |claims| {
                claims.insert("aud".into(), json!("https://other.example"));
            }),
            RootExchangeError::AudienceMismatch,
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.insert("resource".into(), json!("https://other.example/mcp"));
            }),
            RootExchangeError::ResourceMismatch,
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.insert("iat".into(), json!(NOW - 400));
                claims.insert("exp".into(), json!(NOW - 31));
            }),
            RootExchangeError::AssertionExpired,
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.insert("iat".into(), json!(NOW + 31));
                claims.insert("exp".into(), json!(NOW + 300));
            }),
            RootExchangeError::AssertionIssuedInFuture,
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.insert("nbf".into(), json!(NOW + 31));
            }),
            RootExchangeError::AssertionNotYetValid,
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.insert("iat".into(), json!(NOW - 100));
                claims.insert("exp".into(), json!(NOW + 201));
            }),
            RootExchangeError::AssertionLifetimeTooLong {
                lifetime: 301,
                max: 300,
            },
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.remove("jti");
            }),
            RootExchangeError::ClaimMissing("jti"),
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.remove("sub");
            }),
            RootExchangeError::ClaimMissing("principal"),
        ),
        (
            edit(id_jag_claims(), |claims| {
                claims.insert("sub".into(), json!("alice\u{0}admin"));
            }),
            RootExchangeError::ClaimInvalid("principal"),
        ),
    ];
    for (claims, expected) in cases {
        assert_eq!(refusal(id_jag_header(), claims).await, expected);
    }
}

#[tokio::test]
async fn id_jag_client_id_must_be_the_authenticated_client() {
    let harness = Harness::with(
        |_| {},
        |policy| {
            policy["rules"][0]["match"]
                .as_object_mut()
                .unwrap()
                .remove("claims");
        },
    );
    let claims = edit(id_jag_claims(), |claims| {
        claims.insert("client_id".into(), json!("other-client"));
    });
    assert_eq!(
        harness.run(id_jag_header(), claims).await.unwrap_err(),
        RootExchangeError::ClientIdMismatch
    );
}

#[tokio::test]
async fn exactly_one_rule_must_match() {
    let other_issuer = edit(id_jag_claims(), |claims| {
        claims.insert("iss".into(), json!("https://other.okta.com"));
    });
    assert_eq!(
        refusal(id_jag_header(), other_issuer).await,
        RootExchangeError::RuleMatchCount { matched: 0 }
    );
    let duplicate = Harness::with(
        |_| {},
        |policy| {
            let mut second = policy["rules"][0].clone();
            second["rule_id"] = json!("okta-crm-agents-2");
            policy["rules"].as_array_mut().unwrap().push(second);
        },
    );
    assert_eq!(
        duplicate
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::RuleMatchCount { matched: 2 }
    );
}

#[tokio::test]
async fn scope_projection_rules_are_enforced() {
    let unprojected = edit(id_jag_claims(), |claims| {
        claims.insert("scope".into(), json!("crm.read crm.export"));
    });
    assert_eq!(
        refusal(id_jag_header(), unprojected).await,
        RootExchangeError::ScopeNotProjected
    );
    let outside_ceiling = edit(id_jag_claims(), |claims| {
        claims.insert("scope".into(), json!("crm.admin"));
    });
    assert_eq!(
        refusal(id_jag_header(), outside_ceiling).await,
        RootExchangeError::EmptyEffectiveScope
    );
    let no_scope = edit(id_jag_claims(), |claims| {
        claims.remove("scope");
    });
    assert_eq!(
        refusal(id_jag_header(), no_scope).await,
        RootExchangeError::EmptyEffectiveScope
    );
}

#[tokio::test]
async fn wildcard_ceiling_grant_issues_the_projected_tools() {
    let mut wildcard = grant("*");
    wildcard.operations = vec![Operation::Invoke];
    let ceiling = ChioScope {
        grants: vec![wildcard],
        ..ChioScope::default()
    };
    let harness = Harness::with(
        |_| {},
        |policy| {
            policy["rules"][0]["ceiling_scope"] = serde_json::to_value(&ceiling).unwrap();
            policy["rules"][0]["ceiling_scope_hash"] =
                serde_json::to_value(digest_of(&ceiling)).unwrap();
        },
    );
    let prepared = harness.run(id_jag_header(), id_jag_claims()).await.unwrap();
    let tools: Vec<_> = prepared
        .body
        .scope
        .grants
        .iter()
        .map(|grant| (grant.server_id.as_str(), grant.tool_name.as_str()))
        .collect();
    assert_eq!(tools, [("crm", "get"), ("crm", "search")]);
}

#[tokio::test]
async fn resource_parameter_must_name_the_protected_resource() {
    let harness = Harness::new();
    let assertion = client_assertion(&client_assertion_claims());
    let body = |resource: &str| {
        form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &id_jag()),
            ("client_id", CLIENT_ID),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
            ("client_assertion", &assertion),
            ("resource", resource),
        ])
    };
    assert_eq!(
        harness
            .run_body(&body("https://other.example/mcp"), None, NOW)
            .await
            .unwrap_err(),
        RootExchangeError::ResourceMismatch
    );
    harness.run_body(&body(RESOURCE), None, NOW).await.unwrap();
}

#[test]
fn exchange_key_outside_the_policy_refuses_when_the_exchange_is_built() {
    let mut config = exchange_config(|_| {}, |_| {});
    config.exchange_key = policy_keypair().public_key();
    assert_eq!(
        RootExchange::new(config).err(),
        Some(RootExchangeConfigError::ExchangeKeyNotListed)
    );
    assert!(RootExchange::new(exchange_config(|_| {}, |_| {})).is_ok());
}

#[tokio::test]
async fn response_scope_omits_scope_values_the_ceiling_removes() {
    let cases = [
        (None, Some("crm.read")),
        (Some("crm.read"), None),
        (Some("crm.read crm.admin"), Some("crm.read")),
    ];
    for (requested, expected) in cases {
        let harness = Harness::new();
        let claims = edit(id_jag_claims(), |claims| {
            claims.insert("scope".into(), json!("crm.read crm.admin"));
        });
        let id_jag = compact(&id_jag_header(), &claims, idp_sign);
        let mut body = jwt_bearer_body(&id_jag, &client_assertion(&client_assertion_claims()));
        if let Some(requested) = requested {
            body.extend_from_slice(b"&");
            body.extend_from_slice(&form(&[("scope", requested)]));
        }
        let prepared = harness.run_body(&body, None, NOW).await.unwrap();
        let tools: Vec<_> = prepared
            .scope()
            .grants
            .iter()
            .map(|grant| grant.tool_name.as_str())
            .collect();
        assert_eq!(tools, ["search", "get"]);
        assert_eq!(
            prepared.response_scope(),
            expected,
            "requested {requested:?}"
        );
    }
}

#[tokio::test]
async fn id_jag_scope_outside_the_rfc6749_syntax_refuses() {
    for scope in [
        "crm.read caf\u{e9}",
        "crm.read crm\"write",
        "crm.read crm\\write",
        "crm.read\tcrm.write",
    ] {
        let claims = edit(id_jag_claims(), |claims| {
            claims.insert("scope".into(), json!(scope));
        });
        let error = refusal(id_jag_header(), claims).await;
        assert_eq!(error, RootExchangeError::ClaimInvalid("scope"));
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidGrant);
    }
}

#[tokio::test]
async fn holder_class_rules_are_enforced() {
    let edge_only = Harness::with(
        |_| {},
        |policy| policy["rules"][0]["holder_classes"] = json!(["edge_session"]),
    );
    let body = jwt_bearer_body(&id_jag(), &client_assertion(&client_assertion_claims()));
    let sender = Keypair::from_seed(&[9; 32]).public_key();
    assert_eq!(
        edge_only
            .run_body(&body, Some(&sender), NOW)
            .await
            .unwrap_err(),
        RootExchangeError::HolderClassNotAllowed(HolderClass::Caller)
    );

    let proof_required = Harness::with(
        |_| {},
        |policy| {
            let mut ceiling: ChioScope =
                serde_json::from_value(policy["rules"][0]["ceiling_scope"].clone()).unwrap();
            for grant in &mut ceiling.grants {
                grant.dpop_required = Some(true);
            }
            policy["rules"][0]["ceiling_scope_hash"] = json!(digest_of(&ceiling));
            policy["rules"][0]["ceiling_scope"] = json!(ceiling);
        },
    );
    assert_eq!(
        proof_required
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::ProofRequiredGrantForEdgeSession
    );
}

#[tokio::test]
async fn provider_record_rules_are_enforced() {
    let disabled = Harness::with(|record| record["enabled"] = json!(false), |_| {});
    assert_eq!(
        disabled
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::ProviderRecordDisabled("acme-okta".to_owned())
    );
    let changed = Harness::with(
        |record| record["provenance"]["trust_material_ref"] = json!("okta-org-other"),
        |_| {},
    );
    assert_eq!(
        changed
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::ProviderIdentityMismatch("acme-okta".to_owned())
    );
    let scim = provider_record(|record| record["kind"] = json!("scim"));
    assert_eq!(
        ProviderRecord::from_record(&scim).unwrap_err(),
        RootExchangeError::ProviderRecordInvalid {
            record: "acme-okta".to_owned(),
            reason: "record kind is never referenced by a rule".to_owned()
        }
    );
}

#[tokio::test]
async fn root_lifetime_is_capped_by_the_assertion() {
    let harness = Harness::new();
    let claims = edit(id_jag_claims(), |claims| {
        claims.insert("exp".into(), json!(NOW + 20));
    });
    let prepared = harness.run(id_jag_header(), claims).await.unwrap();
    assert_eq!(prepared.body.expires_at, NOW + 20);
    assert_eq!(prepared.anchor().assertion_exp, NOW + 20);
}

#[tokio::test]
async fn policy_out_of_force_denies() {
    let harness = Harness::new();
    let id_jag = id_jag();
    let body = jwt_bearer_body(&id_jag, &client_assertion(&client_assertion_claims()));
    assert_eq!(
        harness
            .run_body(&body, None, NOW + 100_000)
            .await
            .unwrap_err(),
        RootExchangeError::PolicyOutOfForce
    );
}

#[tokio::test]
async fn committed_claims_carry_openings() {
    let harness = Harness::with(
        |_| {},
        |policy| {
            policy["rules"][0]["recorded_claims"] =
                json!({ "client_id": "plain", "scope": "committed" })
        },
    );
    let prepared = harness.run(id_jag_header(), id_jag_claims()).await.unwrap();
    let Some(ClaimValue::Committed(commitment)) = &prepared.context().anchor.claims.scope else {
        panic!("scope is not committed");
    };
    assert_eq!(commitment.salt_ref.as_str(), "anchor.claims.scope");
    let opening = prepared
        .openings()
        .iter()
        .find(|opening| opening.salt_ref.as_str() == "anchor.claims.scope")
        .unwrap();
    assert_eq!(opening.value, json!(["crm.read"]));
    let mut preimage = b"chio.delegation-context.claim.v1\0scope\0".to_vec();
    preimage.extend_from_slice(&opening.salt);
    preimage.extend_from_slice(&canonical_json_bytes(&opening.value).unwrap());
    assert_eq!(
        commitment.commit,
        Sha256Digest::from_hash(sha256(&preimage))
    );
}

#[tokio::test]
async fn every_key_location_header_and_hmac_alg_is_refused() {
    for member in ["x5u", "jwk", "x5c"] {
        let header = edit(id_jag_header(), |header| {
            header.insert(member.into(), json!("https://attacker.example/key"));
        });
        assert_eq!(
            refusal(header, id_jag_claims()).await,
            RootExchangeError::ForbiddenHeaderMember(member)
        );
    }
    for alg in ["HS384", "HS512"] {
        let header = edit(id_jag_header(), |header| {
            header.insert("alg".into(), json!(alg));
        });
        assert_eq!(
            refusal(header, id_jag_claims()).await,
            RootExchangeError::AlgorithmNotAdmitted
        );
    }
}

#[tokio::test]
async fn key_that_does_not_admit_the_token_alg_is_refused() {
    let mut harness = Harness::new();
    harness.keys = StubKeys::serving(&[edit(client_jwk(), |key| {
        key.insert("kid".into(), json!(IDP_KID));
    })]);
    assert_eq!(
        harness
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::KeyAlgorithmMismatch
    );
}

#[tokio::test]
async fn client_assertion_nbf_sub_and_skew_rules_are_enforced() {
    let not_yet_valid = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.insert("nbf".into(), json!(NOW + 6));
    }));
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &not_yet_valid)).await,
        RootExchangeError::ClientAssertionInvalid("not yet valid")
    );
    let without_sub = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.remove("sub");
    }));
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &without_sub)).await,
        RootExchangeError::ClientAssertionInvalid("claim missing")
    );
    let mut wide_skew = Harness::new();
    wide_skew.exchange.client_assertion_skew_secs = 600;
    let future = client_assertion(&edit(client_assertion_claims(), |claims| {
        claims.insert("iat".into(), json!(NOW + 61));
        claims.insert("exp".into(), json!(NOW + 100));
    }));
    assert_eq!(
        wide_skew
            .run_body(&jwt_bearer_body(&id_jag(), &future), None, NOW)
            .await
            .unwrap_err(),
        RootExchangeError::ClientAssertionInvalid("issued in the future")
    );
}

#[tokio::test]
async fn parse_refusal_does_not_spend_the_id_jag() {
    let mut harness = Harness::new();
    harness.keys.any_kid = true;
    let oversized_kid = edit(id_jag_header(), |header| {
        header.insert("kid".into(), json!("k".repeat(129)));
    });
    let id_jag = compact(&oversized_kid, &id_jag_claims(), idp_sign);
    let assertion = client_assertion(&client_assertion_claims());
    assert_eq!(
        harness
            .run_body(&jwt_bearer_body(&id_jag, &assertion), None, NOW)
            .await
            .unwrap_err(),
        RootExchangeError::MalformedJws("kid is not an identifier")
    );
    let bound = harness.replay.bound.lock().unwrap();
    assert!(bound.keys().all(|key| key.id != "id-jag-1"));
    assert_eq!(bound.len(), 1);
}

fn parse_refusal(header: Value) -> RootExchangeError {
    CompactJws::parse(&compact(&header, &id_jag_claims(), idp_sign)).unwrap_err()
}

#[test]
fn compact_jws_parse_refuses_key_location_members_and_symmetric_algs() {
    for member in ["jku", "x5u", "jwk", "x5c", "crit"] {
        let header = edit(id_jag_header(), |header| {
            header.insert(member.into(), json!("present"));
        });
        assert_eq!(
            parse_refusal(header),
            RootExchangeError::ForbiddenHeaderMember(member)
        );
    }
    for alg in ["HS256", "HS384", "HS512", "none"] {
        let header = edit(id_jag_header(), |header| {
            header.insert("alg".into(), json!(alg));
        });
        assert_eq!(
            parse_refusal(header),
            RootExchangeError::AlgorithmNotAdmitted
        );
    }
    let without_kid = edit(id_jag_header(), |header| {
        header.remove("kid");
    });
    assert_eq!(parse_refusal(without_kid), RootExchangeError::KidMissing);
    for kid in [
        json!(""),
        json!("k".repeat(129)),
        json!("k\u{0}1"),
        json!(7),
    ] {
        let header = edit(id_jag_header(), |header| {
            header.insert("kid".into(), kid.clone());
        });
        assert_eq!(
            parse_refusal(header),
            RootExchangeError::MalformedJws("kid is not an identifier")
        );
    }
}

fn second_rule(policy: &mut Value, rule_id: &str, record_id: &str) {
    let mut rule = policy["rules"][0].clone();
    rule["rule_id"] = json!(rule_id);
    rule["match"]["provider_record_id"] = json!(record_id);
    policy["rules"].as_array_mut().unwrap().push(rule);
}

#[tokio::test]
async fn a_missing_provider_record_refuses_only_its_own_rules() {
    let harness = Harness::with(
        |_| {},
        |policy| second_rule(policy, "other-agents", "missing-okta"),
    );
    harness.run(id_jag_header(), id_jag_claims()).await.unwrap();

    let mut orphaned = Harness::new();
    orphaned.exchange.providers.clear();
    let error = orphaned
        .run(id_jag_header(), id_jag_claims())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::ProviderRecordMissing("acme-okta".to_owned())
    );
    assert_eq!(error.oauth_error(), OAuthErrorCode::ServerError);
    assert_eq!(error.client_description(), None);
}

#[tokio::test]
async fn a_record_registered_under_another_id_cannot_match() {
    let mut harness = Harness::new();
    let foreign = ProviderRecord::from_record(&provider_record(|record| {
        record["provider_id"] = json!("other-okta")
    }))
    .unwrap();
    harness
        .exchange
        .providers
        .insert("acme-okta".to_owned(), foreign);
    assert_eq!(
        harness
            .run(id_jag_header(), id_jag_claims())
            .await
            .unwrap_err(),
        RootExchangeError::ProviderRecordInvalid {
            record: "acme-okta".to_owned(),
            reason: "registered under another provider_id".to_owned()
        }
    );
}

#[tokio::test]
async fn root_lifetime_is_capped_by_the_policy_validity() {
    let harness = Harness::with(|_| {}, |policy| policy["valid_until"] = json!(NOW + 100));
    let prepared = harness.run(id_jag_header(), id_jag_claims()).await.unwrap();
    assert_eq!(prepared.expires_at(), NOW + 100);
    assert_eq!(prepared.anchor().assertion_exp, NOW + 290);
}

fn assert_entropy_denied_before_the_bind(harness: &Harness, error: RootExchangeError) {
    assert_eq!(error, RootExchangeError::EntropyUnavailable);
    assert_eq!(error.to_string(), "entropy source failed");
    assert_eq!(error.oauth_error(), OAuthErrorCode::ServerError);
    let bound = harness.replay.bound.lock().unwrap();
    let ids: Vec<&str> = bound.keys().map(|key| key.id.as_str()).collect();
    assert_eq!(ids, vec!["client-assertion-1"]);
}

/// Counts the draws of a successful run of `harness()`, then fails exactly
/// one draw per run for every draw index. Each run must refuse before the
/// ID-JAG replay bind and stop at the failed draw. Returns the draw count.
async fn each_failed_draw_denies_before_the_bind(harness: impl Fn() -> Harness) -> u64 {
    let counted = harness();
    counted.run(id_jag_header(), id_jag_claims()).await.unwrap();
    let draws = counted.entropy.draws.load(Ordering::SeqCst);
    for k in 0..draws {
        let mut failing = harness();
        failing.entropy.fail_at = Some(k);
        let error = failing
            .run(id_jag_header(), id_jag_claims())
            .await
            .expect_err("a failed draw must deny the exchange");
        assert_entropy_denied_before_the_bind(&failing, error);
        assert_eq!(
            failing.entropy.draws.load(Ordering::SeqCst),
            k + 1,
            "failed draw {k}"
        );
    }
    draws
}

#[tokio::test]
async fn failing_rng_denies_before_the_replay_bind_and_root_insert() {
    let mut harness = Harness::new();
    harness.entropy.fail_at = Some(0);
    let error = harness
        .run(id_jag_header(), id_jag_claims())
        .await
        .unwrap_err();
    assert_entropy_denied_before_the_bind(&harness, error);
    assert_eq!(harness.entropy.draws.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn every_single_failed_draw_denies_before_the_replay_bind() {
    // Edge-session subject seed, anchor.sub salt, anchor.tenant salt,
    // capability id.
    assert_eq!(
        each_failed_draw_denies_before_the_bind(Harness::new).await,
        4
    );
}

#[tokio::test]
async fn every_single_failed_draw_with_a_committed_claim_denies_before_the_replay_bind() {
    // Committed scope claim salt, then the four draws of the default run.
    let committed = || {
        Harness::with(
            |_| {},
            |policy| {
                policy["rules"][0]["recorded_claims"] =
                    json!({ "client_id": "plain", "scope": "committed" })
            },
        )
    };
    assert_eq!(each_failed_draw_denies_before_the_bind(committed).await, 5);
}

#[tokio::test]
async fn refusal_after_signature_and_claims_does_not_spend_the_id_jag() {
    let edge_only = Harness::with(
        |_| {},
        |policy| policy["rules"][0]["holder_classes"] = json!(["edge_session"]),
    );
    let sender = Keypair::from_seed(&[9; 32]).public_key();
    let body = jwt_bearer_body(&id_jag(), &client_assertion(&client_assertion_claims()));
    assert_eq!(
        edge_only
            .run_body(&body, Some(&sender), NOW)
            .await
            .unwrap_err(),
        RootExchangeError::HolderClassNotAllowed(HolderClass::Caller)
    );
    let bound = edge_only.replay.bound.lock().unwrap();
    assert_eq!(bound.len(), 1);
    assert!(bound.keys().all(|key| key.id != "id-jag-1"));
}

#[tokio::test]
async fn proof_required_ceiling_grant_outside_the_projection_refuses_an_edge_session() {
    let harness = Harness::with(
        |_| {},
        |policy| {
            let mut ceiling: ChioScope =
                serde_json::from_value(policy["rules"][0]["ceiling_scope"].clone()).unwrap();
            for grant in &mut ceiling.grants {
                if grant.tool_name == "update" {
                    grant.dpop_required = Some(true);
                }
            }
            policy["rules"][0]["ceiling_scope_hash"] = json!(digest_of(&ceiling));
            policy["rules"][0]["ceiling_scope"] = json!(ceiling);
        },
    );
    let body = jwt_bearer_body(&id_jag(), &client_assertion(&client_assertion_claims()));
    assert_eq!(
        harness.run_body(&body, None, NOW).await.unwrap_err(),
        RootExchangeError::ProofRequiredGrantForEdgeSession
    );
    let bound = harness.replay.bound.lock().unwrap();
    assert_eq!(bound.len(), 1);
    assert!(bound.keys().all(|key| key.id != "id-jag-1"));
}

#[tokio::test]
async fn client_assertion_header_refusals_keep_their_reason() {
    let with_crit = compact(
        &json!({ "alg": "ES256", "kid": CLIENT_KID, "crit": ["exp"] }),
        &client_assertion_claims(),
        client_sign,
    );
    assert_eq!(
        client_refusal(jwt_bearer_body(&id_jag(), &with_crit)).await,
        RootExchangeError::ClientAssertionMalformed(Box::new(
            RootExchangeError::ForbiddenHeaderMember("crit")
        ))
    );
}

#[test]
fn signed_claims_reach_the_claim_rules_only_through_verification() {
    let jws = CompactJws::parse(&id_jag()).unwrap();
    let key = VerifyingKey::from_jwk(&serde_json::from_value(idp_jwk(IDP_KID)).unwrap()).unwrap();
    let signed_iss = jws.claims()["iss"].clone();
    let verified = jws.verify_with(&key).unwrap();
    assert_eq!(verified.claims()["iss"], signed_iss);
    assert_eq!(verified.header().kid.as_str(), IDP_KID);
}

#[test]
fn client_registry_coalesces_one_client_across_redirect_uris() {
    let registration =
        |redirect_uri: &str, auth: crate::TokenEndpointAuth| crate::OAuthClientRegistration {
            client_id: CLIENT_ID.to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            token_endpoint_auth: auth,
        };
    let jwt = |jwk: Value| {
        crate::TokenEndpointAuth::PrivateKeyJwt(Box::new(serde_json::from_value(jwk).unwrap()))
    };
    ClientRegistry::new(&[
        registration("https://client.example/callback", jwt(client_jwk())),
        registration("https://client.example/other", jwt(client_jwk())),
    ])
    .unwrap();
    for second in [jwt(idp_jwk(IDP_KID)), crate::TokenEndpointAuth::None] {
        assert_eq!(
            ClientRegistry::new(&[
                registration("https://client.example/callback", jwt(client_jwk())),
                registration("https://client.example/other", second),
            ])
            .unwrap_err(),
            RootExchangeError::ClientAssertionInvalid(
                "client id is registered with different authentication"
            )
        );
    }
}
