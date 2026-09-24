use super::super::registration::registration_quotas;
use super::*;
use crate::ipc_client::{BrokerIpcClientConfig, BrokerPeerIdentity};
use chio_kernel::budget_store::{BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile};
use chio_kernel::supplemental_admission::SupplementalAdmissionParticipant;

fn ipc_config() -> BrokerIpcClientConfig {
    BrokerIpcClientConfig {
        socket_path: std::env::temp_dir().join("kernel-registration.sock"),
        tenant_scope: "tenant-a".into(),
        timeout_ms: 1000,
        expected_peer: BrokerPeerIdentity {
            process_id: 100,
            user_id: 1000,
            group_id: 1000,
        },
        trusted_receipt_signer: Keypair::from_seed(&[35; 32]).public_key(),
    }
}

#[test]
fn registration_generation_binds_transport_tenant_signers_domain_and_verifier() -> TestResult {
    let (verifier, _, _) = fixture()?;
    let signer = Arc::new(Ed25519Backend::new(Keypair::from_seed(&[34; 32])));
    let original = BrokerAdmissionParticipant::new(
        ipc_config(),
        signer.clone(),
        "domain-a".into(),
        &verifier,
    )?;
    assert!(original.requires_registration("broker-tools", "execute"));
    assert!(!original.requires_registration("broker-tools", "other-tool"));
    assert!(!original.requires_registration("other-server", "execute"));
    for change in 0..10 {
        let mut config = ipc_config();
        let mut selected_signer = signer.clone();
        let mut domain = "domain-a";
        let mut verifier_config = verifier.config.clone();
        match change {
            0 => config.socket_path.set_file_name("rebound.sock"),
            1 => config.tenant_scope = "tenant-b".into(),
            2 => config.timeout_ms += 1,
            3 => config.expected_peer.process_id += 1,
            4 => config.expected_peer.user_id += 1,
            5 => config.expected_peer.group_id += 1,
            6 => config.trusted_receipt_signer = Keypair::from_seed(&[36; 32]).public_key(),
            7 => selected_signer = Arc::new(Ed25519Backend::new(Keypair::from_seed(&[37; 32]))),
            8 => domain = "domain-b",
            _ => verifier_config.audience = "other-broker".into(),
        }
        let selected_verifier = BrokerQuotaVerifier::new(verifier_config, Arc::new(Clock(100)))?;
        let changed = BrokerAdmissionParticipant::new(
            config,
            selected_signer,
            domain.into(),
            &selected_verifier,
        )?;
        assert_ne!(changed.binding(), original.binding(), "selection {change}");
    }
    Ok(())
}

#[test]
fn registration_quota_aliases_preserve_all_owners_and_reject_collisions() -> TestResult {
    let (_, request, _) = fixture()?;
    let quotas = vec![
        BudgetInvocationQuota {
            key: BudgetQuotaKey::grant("parent-cap", 0),
            max_invocations: 4,
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::AggregateFamilyInvocation,
                owner_id: "family".into(),
                grant_index: None,
            },
            max_invocations: 3,
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::SupplementalBrokerCapabilityExecution,
                owner_id: "verified-broker-owner".into(),
                grant_index: None,
            },
            max_invocations: 1,
        },
    ];
    let projected = registration_quotas(&quotas, &request)?;
    assert_eq!(projected.len(), 3);
    assert!(projected
        .iter()
        .any(|quota| quota.key_id == "broker-quota" && quota.maximum_executions == 1));
    let mut changed = quotas.clone();
    changed[0].key.grant_index = Some(1);
    assert_ne!(registration_quotas(&changed, &request)?, projected);
    changed = quotas.clone();
    changed[1].key.owner_id = "other-family".into();
    assert_ne!(registration_quotas(&changed, &request)?, projected);
    for change in 0..5 {
        let mut changed = quotas.clone();
        match change {
            0 => {
                changed.pop();
            }
            1 => changed.push(changed[2].clone()),
            2 => changed[2].max_invocations = 2,
            3 => changed[0].key.owner_id = "other-parent".into(),
            _ => changed.push(changed[1].clone()),
        }
        assert!(registration_quotas(&changed, &request).is_err());
    }
    let mut collision = request;
    collision.capability.body.broker_quota_key_id = projected
        .iter()
        .find(|quota| quota.key_id != "broker-quota")
        .ok_or("kernel quota alias")?
        .key_id
        .clone();
    assert!(registration_quotas(&quotas, &collision).is_err());
    Ok(())
}
