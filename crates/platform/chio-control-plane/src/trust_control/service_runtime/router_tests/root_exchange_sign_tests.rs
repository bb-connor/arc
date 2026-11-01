//! `POST /v1/root-exchange/sign` signs only what the provider registry
//! authorizes, and only under an authority with lifecycle state.

use super::*;
use chio_core::crypto::PublicKey;
use chio_core_types::root_authority::{IdpKeySnapshot, RootExchangeSignResponse, Sha256Digest};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::enterprise_federation::{EnterpriseProviderRecord, EnterpriseProviderRegistry};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const JWKS_URL: &str = "https://issuer.example/jwks";
const SIGN_SECRET: &str = "sign-secret";

fn record(edit: impl FnOnce(&mut Value)) -> Result<EnterpriseProviderRecord, serde_json::Error> {
    let mut value = json!({
        "provider_id": "acme-okta",
        "kind": "oidc_jwks",
        "enabled": true,
        "provenance": { "configured_from": "file", "trust_material_ref": "okta-org-acme" },
        "trust_boundary": {},
        "issuer": "https://issuer.example",
        "jwks_url": JWKS_URL,
        "subject_mapping": { "principal_source": "sub", "tenant_id_field": "iss" }
    });
    edit(&mut value);
    serde_json::from_value(value)
}

struct Fixture {
    state: TrustServiceState,
    exchange_key: PublicKey,
    digest: Sha256Digest,
    now: u64,
    _directory: tempfile::TempDir,
}

fn fixture(edit: impl FnOnce(&mut Value)) -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let mut state = metrics_state("service-secret");
    state.finding_challenge_clock = chio_test_support::clock::clock();
    state.config.access =
        crate::trust_control::caller_credentials::tests::test_access_with_deployment_scopes(
            SIGN_SECRET,
            &["root-exchange:sign"],
        );
    let authority_path = directory.path().join("authority.sqlite3");
    state.config.authority_db_path = Some(authority_path.clone());
    let registry_path = directory.path().join("providers.json");
    state.config.enterprise_providers_file = Some(registry_path.clone());
    let record = record(edit)?;
    let digest = record.identity()?.digest()?;
    let mut registry = EnterpriseProviderRegistry::default();
    registry
        .providers
        .insert(record.provider_id.clone(), record);
    registry.save(&registry_path)?;
    let exchange_key =
        crate::trust_control::report_validation::open_authority_for_state(&state, &authority_path)?
            .status()?
            .public_key;
    let now = state.finding_challenge_clock.unix_millis()?.as_secs();
    Ok(Fixture {
        state,
        exchange_key,
        digest,
        now,
        _directory: directory,
    })
}

fn request(fixture: &Fixture) -> Value {
    json!({
        "kind": "idp_key_snapshot",
        "provider_record_id": "acme-okta",
        "provider_identity_digest": fixture.digest,
        "body": {
            "schema": "chio.idp-key-snapshot.v1",
            "issuer": "https://issuer.example",
            "source": JWKS_URL,
            "keys": [],
            "observed_at": fixture.now,
            "exchange_key": fixture.exchange_key
        }
    })
}

async fn post(
    state: &TrustServiceState,
    secret: &str,
    body: &Value,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let response = super::super::build_router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(ROOT_EXCHANGE_SIGN_PATH)
                .header(AUTHORIZATION, format!("Bearer {secret}"))
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(body)?))?,
        )
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

async fn refused(fixture: &Fixture, body: &Value, status: StatusCode, error: &str) -> TestResult {
    let (actual, value) = post(&fixture.state, SIGN_SECRET, body).await?;
    assert_eq!((actual, value["error"].as_str()), (status, Some(error)));
    Ok(())
}

#[tokio::test]
async fn sign_returns_a_snapshot_verifying_under_the_exchange_key() -> TestResult {
    let fixture = fixture(|_| {})?;
    let (status, value) = post(&fixture.state, SIGN_SECRET, &request(&fixture)).await?;
    assert_eq!(status, StatusCode::OK, "{value}");
    let response: RootExchangeSignResponse = serde_json::from_value(value)?;
    let RootExchangeSignResponse::IdpKeySnapshot { schema, artifact } = response;
    assert_eq!(schema, "chio.idp-key-snapshot.v1");
    let snapshot: &IdpKeySnapshot = &artifact;
    snapshot.verify_signature(&fixture.exchange_key)?;
    Ok(())
}

#[tokio::test]
async fn sign_refuses_records_the_registry_does_not_serve() -> TestResult {
    let fixture_unknown = fixture(|_| {})?;
    let mut unknown = request(&fixture_unknown);
    unknown["provider_record_id"] = json!("other");
    refused(
        &fixture_unknown,
        &unknown,
        StatusCode::FORBIDDEN,
        "provider record is unknown",
    )
    .await?;
    let disabled = fixture(|value| value["enabled"] = json!(false))?;
    refused(
        &disabled,
        &request(&disabled),
        StatusCode::FORBIDDEN,
        "provider record is disabled",
    )
    .await
}

#[tokio::test]
async fn sign_reads_the_registry_on_every_request() -> TestResult {
    let fixture = fixture(|_| {})?;
    let (status, _) = post(&fixture.state, SIGN_SECRET, &request(&fixture)).await?;
    assert_eq!(status, StatusCode::OK);
    let mut registry = EnterpriseProviderRegistry::default();
    let record = record(|value| value["enabled"] = json!(false))?;
    registry
        .providers
        .insert(record.provider_id.clone(), record);
    let path = fixture.state.config.enterprise_providers_file.as_deref();
    registry.save(path.ok_or("registry path")?)?;
    refused(
        &fixture,
        &request(&fixture),
        StatusCode::FORBIDDEN,
        "provider record is disabled",
    )
    .await
}

#[tokio::test]
async fn sign_refuses_a_foreign_exchange_key_before_signing() -> TestResult {
    let fixture = fixture(|_| {})?;
    let mut foreign = request(&fixture);
    foreign["body"]["exchange_key"] = json!(Keypair::generate().public_key());
    refused(
        &fixture,
        &foreign,
        StatusCode::FORBIDDEN,
        "snapshot exchange_key is not the current exchange key",
    )
    .await
}

#[tokio::test]
async fn sign_without_a_registry_is_not_configured() -> TestResult {
    let mut fixture = fixture(|_| {})?;
    fixture.state.config.enterprise_providers_file = None;
    let body = request(&fixture);
    refused(
        &fixture,
        &body,
        StatusCode::CONFLICT,
        "root exchange signing is not configured",
    )
    .await
}

#[tokio::test]
async fn sign_refuses_an_authority_without_lifecycle_state() -> TestResult {
    let mut fixture = fixture(|_| {})?;
    fixture.state.config.authority_db_path = None;
    let body = request(&fixture);
    refused(
        &fixture,
        &body,
        StatusCode::CONFLICT,
        "trust-control exchange signer requires lifecycle state",
    )
    .await
}

#[tokio::test]
async fn sign_requires_its_scope() -> TestResult {
    let mut fixture = fixture(|_| {})?;
    fixture.state.config.access =
        crate::trust_control::caller_credentials::tests::test_access_with_deployment_scopes(
            SIGN_SECRET,
            &["capabilities:issue"],
        );
    let body = request(&fixture);
    let (status, _) = post(&fixture.state, SIGN_SECRET, &body).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn sign_refuses_an_unknown_kind_and_an_unknown_member() -> TestResult {
    let fixture = fixture(|_| {})?;
    for edit in [
        (|value: &mut Value| value["kind"] = json!("message")) as fn(&mut Value),
        |value: &mut Value| value["bytes"] = json!("AQAB"),
    ] {
        let mut body = request(&fixture);
        edit(&mut body);
        let (status, _) = post(&fixture.state, SIGN_SECRET, &body).await?;
        assert!(status.is_client_error(), "{status}");
    }
    Ok(())
}
