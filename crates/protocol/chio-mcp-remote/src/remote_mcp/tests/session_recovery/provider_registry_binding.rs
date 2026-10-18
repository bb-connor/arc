//! Resume reads the enterprise provider registry at restore time and refuses
//! a session admitted under a registry that has since changed.
use super::super::enterprise_provider_freshness::{write_oversized_registry, write_registry};
use super::cursor_seed::{ready_factory_session, ReadOnlyTransport};
use super::*;
use chio_control_plane::enterprise_federation::EnterpriseProviderRegistry;

#[tokio::test]
async fn resume_refuses_a_session_once_the_provider_registry_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, path) = private_test_session_database("provider-registry-binding");
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
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    config.enterprise_providers_file = Some(registry_path.clone());
    configure_signed_manifest(&mut config, &directory);
    let factory = RemoteSessionFactory::new(config)?;
    let keyring = factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let fresh = factory.spawn_session(SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:provider-registry",
        sha256_hex(b"provider-registry-agent"),
        None,
    ))?;
    ready_factory_session(&fresh).await?;
    let record = sign_test_resume_record(fresh.resume_record()?.ok_or("fresh record")?, &keyring);

    let Some(RestoredSession::Serve(unchanged)) = factory.restore_session(&record)? else {
        return Err("a session under an unchanged provider registry was not restorable".into());
    };

    write_registry(&registry_path, false);
    assert!(
        factory.restore_session(&record)?.is_none(),
        "a session admitted under an enabled provider resumed after the provider was disabled"
    );

    write_registry(&registry_path, true);
    let Some(RestoredSession::Serve(restored)) = factory.restore_session(&record)? else {
        return Err("a session under the restored provider registry was not restorable".into());
    };

    write_oversized_registry(&registry_path);
    let oversized = factory
        .restore_session(&record)
        .err()
        .ok_or("an oversized provider registry resumed a session")?;
    let CliError::SignedJson(chio_core::canonical::UntrustedJsonError::TooLarge { bytes, bound }) =
        &oversized
    else {
        return Err(format!("expected an oversized registry error, got {oversized:?}").into());
    };
    assert_eq!(*bound, 16 * 1024 * 1024);
    assert_eq!(*bytes, bound + 1);
    assert_eq!(
        oversized.to_string(),
        "urn:chio:error:attest:signed-json-too-large"
    );

    std::fs::remove_file(&registry_path)?;
    let expected = EnterpriseProviderRegistry::load(&registry_path)
        .err()
        .ok_or("a missing provider registry loaded")?;
    let unreadable = factory
        .restore_session(&record)
        .err()
        .ok_or("an unreadable provider registry resumed a session")?;
    assert!(
        matches!(
            EnterpriseProviderRegistryRefusal::from(unreadable),
            EnterpriseProviderRegistryRefusal::Unreadable(ref cause)
                if cause.to_string() == expected.to_string()
        ),
        "expected the unreadable registry cause {expected}"
    );

    drop((fresh, unchanged, restored, factory));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
