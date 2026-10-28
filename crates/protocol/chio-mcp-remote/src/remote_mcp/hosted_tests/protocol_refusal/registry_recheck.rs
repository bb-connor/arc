use super::*;

const ISSUER: &str = "https://issuer.enterprise.example";
const PING: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;

fn provider_record(enabled: bool, issuer: &str, jwks_url: &str) -> Value {
    json!({
        "provider_id": "enterprise-login",
        "kind": "oidc_jwks",
        "enabled": enabled,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": "jwks:enterprise-login",
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_issuers": [issuer],
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": ["org-789"]
        },
        "issuer": issuer,
        "jwks_url": jwks_url,
        "tenant_id": "tenant-123",
        "organization_id": "org-789",
        "subject_mapping": {
            "principal_source": "sub",
            "tenant_id_field": "tid",
            "organization_id_field": "org_id",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    })
}

fn enabled_record() -> Value {
    provider_record(true, ISSUER, "https://issuer.enterprise.example/jwks")
}

fn write_providers(path: &FsPath, providers: Value) -> TestResult {
    let registry = json!({
        "version": "chio.enterprise-providers.v1",
        "providers": providers
    });
    std::fs::write(path, serde_json::to_vec(&registry)?)?;
    Ok(())
}

fn write_record(path: &FsPath, record: Value) -> TestResult {
    write_providers(path, json!({ "enterprise-login": record }))
}

struct RegistryFixture {
    http: HttpFixture,
    registry_path: PathBuf,
    session: String,
    token: String,
}

impl RegistryFixture {
    /// An admitted session holding a credential that works under the
    /// registry as written at admission.
    async fn admitted() -> TestResult<Self> {
        let http = fixture_configured(None, |directory, config| {
            let path = directory.join("enterprise-providers.json");
            write_record(&path, enabled_record())?;
            config.enterprise_providers_file = Some(path);
            Ok(())
        })?;
        let registry_path = http
            .state
            .factory
            .config
            .enterprise_providers_file
            .clone()
            .ok_or("registry path")?;
        let session = initialize(&http).await?;
        let Some(RemoteSessionEntry::Active(bound)) = http.state.sessions.lookup(&session).await
        else {
            return Err("initialized session is not active".into());
        };
        assert!(matches!(
            bound.auth_context.method,
            SessionAuthMethod::StaticBearer { .. }
        ));
        let token = credential(&http, &session).await?;
        let fixture = Self {
            http,
            registry_path,
            session,
            token,
        };
        fixture.assert_accepted().await?;
        Ok(fixture)
    }

    async fn ping(&self) -> TestResult<Response> {
        request(
            &self.http,
            MCP_ENDPOINT_PATH,
            &self.token,
            Some(&self.session),
            PING,
        )
        .await
    }

    async fn assert_accepted(&self) -> TestResult {
        let response = self.ping().await?;
        assert_eq!(response.status(), StatusCode::OK);
        let _ = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        Ok(())
    }

    /// The body is exactly `body`: no registry path, provider record or
    /// parse error reaches the peer.
    async fn assert_refused(&self, status: StatusCode, body: &[u8]) -> TestResult {
        let response = self.ping().await?;
        assert_eq!(response.status(), status);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        assert_eq!(&bytes[..], body);
        let text = String::from_utf8_lossy(&bytes);
        for detail in [
            &*self.http.directory.path().to_string_lossy(),
            "enterprise-providers.json",
            "enterprise-login",
            ISSUER,
            "EOF",
            "line",
            "column",
        ] {
            assert!(!text.contains(detail), "refusal body disclosed {detail:?}");
        }
        assert_eq!(self.http.calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    async fn shutdown(self) -> TestResult {
        self.http.state.sessions.shutdown_all_active().await?;
        self.http.state.factory.shutdown_shared_upstream_owner()?;
        Ok(())
    }
}

#[tokio::test]
async fn static_session_credential_survives_provider_disable() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    write_record(
        &fixture.registry_path,
        provider_record(false, ISSUER, "https://issuer.enterprise.example/jwks"),
    )?;
    fixture.assert_accepted().await?;
    fixture.shutdown().await
}

#[tokio::test]
async fn session_credential_is_refused_after_the_registry_becomes_invalid() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    std::fs::write(&fixture.registry_path, b"{\"version\":")?;
    fixture
        .assert_refused(
            StatusCode::SERVICE_UNAVAILABLE,
            b"urn:chio:error:transport:provider-registry-invalid",
        )
        .await?;
    fixture.shutdown().await
}

#[tokio::test]
async fn session_credential_is_refused_after_the_registry_becomes_unreadable() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    std::fs::remove_file(&fixture.registry_path)?;
    fixture
        .assert_refused(
            StatusCode::SERVICE_UNAVAILABLE,
            b"urn:chio:error:transport:provider-registry-unreadable",
        )
        .await?;
    fixture.shutdown().await
}

#[tokio::test]
async fn static_session_credential_survives_provider_removal() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    write_providers(&fixture.registry_path, json!({}))?;
    fixture.assert_accepted().await?;
    fixture.shutdown().await
}

#[tokio::test]
async fn static_session_credential_survives_provider_issuer_change() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    write_record(
        &fixture.registry_path,
        provider_record(
            true,
            "https://rotated.enterprise.example",
            "https://issuer.enterprise.example/jwks",
        ),
    )?;
    fixture.assert_accepted().await?;
    fixture.shutdown().await
}

#[tokio::test]
async fn static_session_credential_survives_provider_key_change() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    write_record(
        &fixture.registry_path,
        provider_record(
            true,
            ISSUER,
            "https://issuer.enterprise.example/rotated-jwks",
        ),
    )?;
    fixture.assert_accepted().await?;
    fixture.shutdown().await
}

#[tokio::test]
async fn session_credential_is_accepted_while_the_registry_is_unchanged() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    fixture.assert_accepted().await?;
    write_record(&fixture.registry_path, enabled_record())?;
    fixture.assert_accepted().await?;
    fixture.shutdown().await
}

#[tokio::test]
async fn static_session_credential_survives_an_unrelated_provider_addition() -> TestResult {
    let fixture = RegistryFixture::admitted().await?;
    let mut other = enabled_record();
    other["provider_id"] = json!("unrelated-login");
    other["enabled"] = json!(false);
    write_providers(
        &fixture.registry_path,
        json!({"enterprise-login": enabled_record(), "unrelated-login": other}),
    )?;
    fixture.assert_accepted().await?;
    fixture.shutdown().await
}
