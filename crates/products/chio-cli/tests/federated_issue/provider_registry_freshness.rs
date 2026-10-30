//! A running trust-control service reads enterprise provider records from the
//! registry file each federated issuance reads, so an operator mutation governs
//! the next issuance without a restart.

use super::super::*;
use chio_control_plane::enterprise_federation::load_enterprise_provider_registry;

#[test]
fn federated_issue_refuses_a_provider_record_disabled_after_startup() {
    if skip_when_loopback_bind_denied(
        "federated_issue_refuses_a_provider_record_disabled_after_startup",
    ) {
        return;
    }

    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-disabled-after-startup",
        "org-789",
        "org-789",
        &["eng", "ops"],
        &["operator"],
        Some("enterprise-login"),
        Some(vec![enterprise_provider_record(
            "enterprise-login",
            true,
            "org-789",
        )]),
    );
    let disabled = Client::new()
        .put(format!(
            "{}/v1/federation/providers/enterprise-login",
            harness.base_url
        ))
        .bearer_auth(&harness.service_token)
        .json(&enterprise_provider_record(
            "enterprise-login",
            false,
            "org-789",
        ))
        .send()
        .expect("disable enterprise provider");
    assert_eq!(disabled.status(), reqwest::StatusCode::OK);

    let output = run_enterprise_federated_issue(&harness);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a provider disabled after startup still admitted: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("enterprise-provider lane requires a validated provider record"),
        "stderr={stderr}"
    );
    assert!(
        stderr
            .contains("enterprise-provider lane is active but provider_record_id is not validated"),
        "stderr={stderr}"
    );
}

#[test]
fn federated_issue_refuses_a_provider_registry_corrupted_after_startup() {
    if skip_when_loopback_bind_denied(
        "federated_issue_refuses_a_provider_registry_corrupted_after_startup",
    ) {
        return;
    }

    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-corrupted-after-startup",
        "org-789",
        "org-789",
        &["eng", "ops"],
        &["operator"],
        Some("enterprise-login"),
        Some(vec![enterprise_provider_record(
            "enterprise-login",
            true,
            "org-789",
        )]),
    );
    let providers_path = harness
        .challenge_path
        .with_file_name("enterprise-providers.json");
    fs::write(&providers_path, b"{\"version\":").expect("corrupt enterprise provider registry");
    let expected = load_enterprise_provider_registry(&providers_path)
        .expect_err("a truncated registry loaded")
        .to_string();

    let output = run_enterprise_federated_issue(&harness);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a corrupted provider registry still admitted: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(&expected),
        "expected={expected}\nstderr={stderr}"
    );
}
