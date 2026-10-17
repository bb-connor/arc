//! Enterprise provider upsert and delete each load the providers file, change
//! it and write it back. One that starts while another sits between its read
//! and its write must be refused, so no committed change is lost.

use super::*;
use crate::enterprise_federation::{EnterpriseProviderRecord, EnterpriseProviderRegistry};

fn provider(provider_id: &str) -> Result<EnterpriseProviderRecord, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(serde_json::json!({
        "provider_id": provider_id,
        "kind": "oidc_jwks",
        "enabled": true,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": "jwks:enterprise-login",
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_issuers": ["https://issuer.enterprise.example"],
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": ["org-789"]
        },
        "issuer": "https://issuer.enterprise.example",
        "jwks_url": "https://issuer.enterprise.example/jwks",
        "tenant_id": "tenant-123",
        "organization_id": "org-789",
        "subject_mapping": {
            "principal_source": "sub",
            "tenant_id_field": "tid",
            "organization_id_field": "org_id",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    }))?)
}

/// A FIFO is only a deterministic read pause in this witness, never the
/// supported registry storage format. The bytes and mutation handlers are real.
#[tokio::test(flavor = "current_thread")]
async fn an_unrelated_provider_upsert_cannot_restore_a_deleted_provider() -> TestResult {
    use std::io::Write;
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("enterprise-providers.json");
    let mut initial = EnterpriseProviderRegistry::default();
    initial.upsert(provider("removed")?);
    let bytes = serde_json::to_vec(&initial)?;
    let added = provider("unrelated")?;
    let mut state = metrics_state("service-secret");
    state.config.enterprise_providers_file = Some(path.clone());
    let result = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&path)
        .status()?;
    assert!(
        result.success(),
        "could not create deterministic read pause"
    );
    let (opened_tx, opened_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fifo = path.clone();
    let supplied = bytes.clone();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).open(fifo)?;
        file.write_all(&supplied)?;
        let _ = opened_tx.send(());
        let _ = release_rx.recv_timeout(HANG_GUARD);
        Ok(())
    });
    let upsert = tokio::task::spawn_blocking({
        let state = state.clone();
        let added = added.clone();
        let runtime = tokio::runtime::Handle::current();
        move || {
            runtime.block_on(handle_upsert_enterprise_provider(
                State(state),
                AxumPath("unrelated".to_string()),
                bearer("service-secret").test_unwrap(),
                Json(added),
            ))
        }
    });
    tokio::task::spawn_blocking(move || opened_rx.recv_timeout(HANG_GUARD)).await??;
    std::fs::remove_file(&path)?;
    std::fs::write(&path, &bytes)?;
    let deletion = handle_delete_enterprise_provider(
        State(state.clone()),
        AxumPath("removed".to_string()),
        bearer("service-secret")?,
    )
    .await;
    let (status, text) = status_and_text(deletion).await?;
    release_tx.send(())?;
    let response = tokio::time::timeout(HANG_GUARD, upsert).await??;
    assert_eq!(response.status(), StatusCode::OK);
    writer.join().map_err(|_| "FIFO writer panicked")??;
    if status == StatusCode::OK {
        assert!(
            !EnterpriseProviderRegistry::load(&path)?
                .providers
                .contains_key("removed"),
            "an unrelated provider upsert restored a committed provider deletion"
        );
    }
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text)?,
        serde_json::json!({"error": CliError::from(RegistryUpdateError::Busy).to_string()})
    );

    let response = handle_delete_enterprise_provider(
        State(state),
        AxumPath("removed".to_string()),
        bearer("service-secret")?,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let reopened = EnterpriseProviderRegistry::load(&path)?;
    assert!(!reopened.providers.contains_key("removed"));
    assert!(reopened.providers.contains_key("unrelated"));
    Ok(())
}
