use super::*;
use crate::ipc_client::{BrokerIpcClientConfig, BrokerPeerIdentity};
use chio_kernel::supplemental_admission::SupplementalAdmissionParticipant;

fn configs() -> TestResult<Vec<BrokerRouteConfig>> {
    let (verifier, _, _) = fixture()?;
    let first = BrokerRouteConfig {
        quota: verifier.config,
        ipc: BrokerIpcClientConfig {
            socket_path: std::env::temp_dir().join("chio-route-first.sock"),
            tenant_scope: "route-tenant".into(),
            timeout_ms: 1000,
            expected_peer: BrokerPeerIdentity {
                process_id: 100,
                user_id: 1000,
                group_id: 1000,
            },
            trusted_receipt_signer: Keypair::from_seed(&[35; 32]).public_key(),
        },
        authority_signer: Arc::new(Ed25519Backend::new(Keypair::from_seed(&[34; 32]))),
        revocation_authority_domain: "route-revocations".into(),
    };
    let mut second = first.clone();
    second.quota.server_id = "model".into();
    second.quota.tool_name = "infer".into();
    second.quota.audience = "model-broker".into();
    second
        .ipc
        .socket_path
        .set_file_name("chio-route-second.sock");
    second.ipc.expected_peer.process_id = 101;
    Ok(vec![first, second])
}

#[test]
fn route_set_binds_all_members_without_order_dependence() -> TestResult {
    let original = BrokerRouteSet::new(configs()?, Arc::new(Clock(100)))?;
    let mut reversed = configs()?;
    reversed.reverse();
    let reversed = BrokerRouteSet::new(reversed, Arc::new(Clock(100)))?;
    assert_eq!(original.verifier_binding(), reversed.verifier_binding());
    assert_eq!(
        original.participant_binding(),
        reversed.participant_binding()
    );
    for (server, tool) in [("broker-tools", "execute"), ("model", "infer")] {
        assert!(original.requires_registration(server, tool));
        assert!(original.requires_registration(server, "undeclared-tool"));
        assert_eq!(
            original.participant(server, tool)?.binding(),
            original.participant_binding()
        );
    }
    assert!(!original.requires_registration("uninstalled", "infer"));
    assert!(matches!(
        original.participant("broker-tools", "infer"),
        Err(BrokerError::AuthorizationDenied(_))
    ));
    for case in 0..5 {
        let mut changed = configs()?;
        match case {
            0 => changed[1].quota.provider_adapter_version += 1,
            1 => changed[1].ipc.expected_peer.process_id += 1,
            2 => changed[1].ipc.trusted_receipt_signer = Keypair::from_seed(&[36; 32]).public_key(),
            3 => changed[1].revocation_authority_domain = "changed-domain".into(),
            _ => {
                changed.pop();
            }
        }
        let changed = BrokerRouteSet::new(changed, Arc::new(Clock(100)))?;
        assert_ne!(
            original.participant_binding(),
            changed.participant_binding()
        );
    }
    Ok(())
}

#[test]
fn route_set_rejects_ambiguous_and_unbounded_composition() -> TestResult {
    for case in 0..5 {
        let mut selected = configs()?;
        match case {
            0 => selected.clear(),
            1 => selected[1].quota.server_id = selected[0].quota.server_id.clone(),
            2 => selected[1].quota.audience = selected[0].quota.audience.clone(),
            3 => selected[1].ipc.socket_path = selected[0].ipc.socket_path.clone(),
            _ => selected = vec![selected[0].clone(); MAX_BROKER_ROUTES + 1],
        }
        assert!(matches!(
            BrokerRouteSet::new(selected, Arc::new(Clock(100))),
            Err(BrokerError::AuthorizationDenied(_))
        ));
    }
    Ok(())
}

#[test]
fn route_set_verifies_each_audience_and_rejects_cross_route_authority() -> TestResult {
    let routes = BrokerRouteSet::new(configs()?, Arc::new(Clock(100)))?;
    let (_, mut request, mut context) = fixture()?;
    context.verifier_binding = routes.verifier_binding().clone();
    let original = canonical(&request)?;
    assert_eq!(
        routes.verify(&original, &context)?.normalized_destination,
        context.normalized_destination
    );
    context.normalized_destination = String::from_utf8(canonical(
        &serde_json::json!({"server_id":"model", "tool_name":"infer"}),
    )?)?;
    assert_eq!(
        routes.verify(&original, &context).err(),
        Some(SupplementalQuotaVerifierError::new(
            rejected().diagnostic_code()
        ))
    );
    let mut body = request.capability.body.clone();
    body.audience = "model-broker".into();
    request.capability = issue_capability(
        body,
        &Ed25519Backend::new(Keypair::from_seed(&[31; 32])),
        true,
    )?;
    request.proof = issue_request_proof(
        &request.capability,
        &request.request,
        "second-route-proof".into(),
        100,
        &Keypair::from_seed(&[32; 32]),
    )?;
    let bytes = canonical(&request)?;
    context.arguments_hash = hex::encode(Sha256::digest(&bytes));
    let verified = routes.verify(&bytes, &context)?;
    assert_eq!(
        verified.normalized_destination,
        context.normalized_destination
    );
    assert_eq!(
        verified.request_binding_hash,
        supplemental_request_binding_hash(&context)?
    );
    let mut changed = configs()?;
    changed[0].quota.provider_adapter_version += 1;
    let changed = BrokerRouteSet::new(changed, Arc::new(Clock(100)))?;
    assert_eq!(
        changed.verify(&bytes, &context).err(),
        Some(SupplementalQuotaVerifierError::new(
            rejected().diagnostic_code()
        ))
    );
    Ok(())
}
