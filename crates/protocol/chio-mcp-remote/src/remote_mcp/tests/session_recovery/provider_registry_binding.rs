use super::super::enterprise_provider_freshness::{
    authenticate, jwt_verifier, signed_token, write_oversized_registry, write_registry, ISSUER,
};
use super::cursor_seed::{ready_factory_session, ReadOnlyTransport};
use super::*;
use chio_control_plane::enterprise_federation::EnterpriseProviderRegistry;

#[tokio::test]
async fn static_bearer_resume_ignores_provider_record_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    registry_scope_case(false).await
}

#[tokio::test]
async fn enterprise_resume_binds_only_its_provider_record() -> Result<(), Box<dyn std::error::Error>>
{
    registry_scope_case(true).await
}

async fn registry_scope_case(enterprise: bool) -> Result<(), Box<dyn std::error::Error>> {
    let temp = chio_test_support::private_tempdir()?;
    let directory = temp.path();
    let path = directory.join("sessions.sqlite3");
    let registry_path = directory.join("enterprise-providers.json");
    write_registry(&registry_path, true);
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )?;
    config.test_transport = Some(Arc::new(ReadOnlyTransport));
    config.session_db_path = Some(path.clone());
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(directory));
    config.enterprise_providers_file = Some(registry_path.clone());
    configure_signed_manifest(&mut config, directory);
    let auth = if enterprise {
        let keypair = Keypair::generate();
        config.auth_token = None;
        config.auth_jwt_public_key = Some(keypair.public_key().to_hex());
        config.auth_jwt_issuer = Some(ISSUER.to_string());
        config.auth_jwt_audience = Some("chio-mcp".to_string());
        authenticate(&jwt_verifier(&config), &signed_token(&keypair))
            .map_err(|response| format!("bearer admission failed: {}", response.status()))?
    } else {
        SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:provider-registry",
            sha256_hex(b"provider-registry-agent"),
            None,
        )
    };
    let factory = RemoteSessionFactory::new(config)?;
    let keyring = factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let fresh = factory.spawn_session(auth)?;
    ready_factory_session(&fresh).await?;
    let record = sign_test_resume_record(fresh.resume_record()?.ok_or("fresh record")?, &keyring);

    let Some(RestoredSession::Serve(unchanged)) = factory.restore_session(&record)? else {
        return Err("a session under an unchanged provider registry was not restorable".into());
    };

    let mut registry: serde_json::Value = serde_json::from_slice(&std::fs::read(&registry_path)?)?;
    let mut unrelated = registry["providers"]["enterprise-login"].clone();
    unrelated["provider_id"] = json!("unrelated-login");
    unrelated["enabled"] = json!(false);
    registry["providers"]["unrelated-login"] = unrelated;
    std::fs::write(&registry_path, serde_json::to_vec(&registry)?)?;
    let Some(RestoredSession::Serve(unrelated_change)) = factory.restore_session(&record)? else {
        return Err("an unrelated provider change invalidated the session".into());
    };
    unrelated_change.shutdown_upstream_transport()?;

    write_registry(&registry_path, false);
    if enterprise {
        assert!(
            factory.restore_session(&record)?.is_none(),
            "the session resumed after its own provider was disabled"
        );
    } else {
        let Some(RestoredSession::Serve(provider_change)) = factory.restore_session(&record)?
        else {
            return Err("a provider change invalidated a static-bearer session".into());
        };
        provider_change.shutdown_upstream_transport()?;
    }

    write_registry(&registry_path, true);
    let Some(RestoredSession::Serve(restored)) = factory.restore_session(&record)? else {
        return Err("a session under the restored provider registry was not restorable".into());
    };

    write_oversized_registry(&registry_path);
    let oversized = factory
        .restore_session(&record)
        .err()
        .ok_or("an oversized provider registry resumed a session")?;
    assert_eq!(oversized.to_string(), "urn:chio:error:cli:json");
    let Some(EnterpriseProviderRegistryRefusal::Oversized(CliError::SignedJson(
        chio_core::canonical::UntrustedJsonError::TooLarge { bytes, bound },
    ))) = EnterpriseProviderRegistryRefusal::find(&oversized)
    else {
        return Err(format!("expected an oversized registry refusal, got {oversized:?}").into());
    };
    assert_eq!(*bound, 16 * 1024 * 1024);
    assert_eq!(*bytes, bound + 1);

    std::fs::remove_file(&registry_path)?;
    let expected = EnterpriseProviderRegistry::load(&registry_path)
        .err()
        .ok_or("a missing provider registry loaded")?;
    let unreadable = factory
        .restore_session(&record)
        .err()
        .ok_or("an unreadable provider registry resumed a session")?;
    assert_eq!(unreadable.to_string(), "urn:chio:error:cli:io");
    let Some(EnterpriseProviderRegistryRefusal::Unreadable(cause)) =
        EnterpriseProviderRegistryRefusal::find(&unreadable)
    else {
        return Err(format!("expected an unreadable registry refusal, got {unreadable:?}").into());
    };
    assert_eq!(cause.to_string(), expected.to_string());

    drop((fresh, unchanged, restored, factory));
    Ok(())
}
