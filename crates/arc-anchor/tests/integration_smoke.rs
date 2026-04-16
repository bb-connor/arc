#![cfg(feature = "web3")]

use arc_anchor::{
    build_anchor_discovery_artifact_with_runtime, AnchorDiscoveryChain,
    AnchorDiscoveryFreshnessStatus, AnchorDiscoveryServiceEndpoint, AnchorEmergencyControls,
    AnchorEmergencyMode, AnchorLaneHealthStatus, AnchorLaneKind, AnchorLaneRuntimeStatus,
    AnchorRuntimeReport, AnchorServiceConfig, ARC_ANCHOR_DISCOVERY_SCHEMA,
};
use arc_core::crypto::Keypair;
use arc_core::web3::{
    SignedWeb3IdentityBinding, Web3IdentityBindingCertificate, Web3KeyBindingPurpose,
    ARC_KEY_BINDING_CERTIFICATE_SCHEMA,
};

#[test]
fn anchor_public_types_capture_discovery_shape() {
    let endpoint = AnchorDiscoveryServiceEndpoint {
        chains: vec![AnchorDiscoveryChain {
            chain_id: "eip155:8453".to_string(),
            contract_address: "0xabc".to_string(),
            operator_address: "0xdef".to_string(),
            publisher_address: "0xdef".to_string(),
            requires_delegate_authorization: false,
        }],
        bitcoin_anchor_method: Some("opentimestamps".to_string()),
        ots_calendars: vec!["https://calendar.example".to_string()],
        solana_cluster: Some("devnet".to_string()),
        publication_policy: None,
        chain_runtime: Vec::new(),
        current_freshness: None,
    };

    assert_eq!(endpoint.chains.len(), 1);
    assert_eq!(endpoint.chains[0].chain_id, "eip155:8453");
    assert_eq!(AnchorLaneKind::BitcoinOts, AnchorLaneKind::BitcoinOts);
    assert_eq!(ARC_ANCHOR_DISCOVERY_SCHEMA, "arc.anchor-discovery.v1");
}

#[test]
fn anchor_discovery_reports_publication_policy_and_current_freshness_state() {
    let keypair = Keypair::generate();
    let certificate = Web3IdentityBindingCertificate {
        schema: ARC_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        arc_identity: "did:arc:operator-1".to_string(),
        arc_public_key: keypair.public_key(),
        chain_scope: vec!["eip155:8453".to_string()],
        purpose: vec![Web3KeyBindingPurpose::Anchor],
        settlement_address: "0xdef".to_string(),
        issued_at: 1_775_100_000,
        expires_at: 1_775_200_000,
        nonce: "bind-001".to_string(),
    };
    let signature = keypair
        .sign_canonical(&certificate)
        .expect("binding signature")
        .0;
    let binding = SignedWeb3IdentityBinding {
        certificate,
        signature,
    };
    let config = AnchorServiceConfig {
        evm_targets: vec![arc_anchor::EvmAnchorTarget {
            chain_id: "eip155:8453".to_string(),
            rpc_url: "https://rpc.example".to_string(),
            contract_address: "0xabc".to_string(),
            operator_address: "0xdef".to_string(),
            publisher_address: "0xfeed".to_string(),
        }],
        ots_calendars: vec!["https://calendar.example".to_string()],
        solana_cluster: Some("devnet".to_string()),
    };
    let report = AnchorRuntimeReport {
        schema: "arc.anchor-runtime-report.v1".to_string(),
        generated_at: 1_775_137_800,
        controls: AnchorEmergencyControls::normal(1_775_137_700),
        lanes: vec![AnchorLaneRuntimeStatus {
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            status: AnchorLaneHealthStatus::Lagging,
            latest_checkpoint_seq: 42,
            indexed_checkpoint_seq: 41,
            reorg_depth: 0,
            last_published_at: Some(1_775_137_760),
            next_action: Some("publish checkpoint 42".to_string()),
            note: Some("one checkpoint behind registry".to_string()),
        }],
        indexers: Vec::new(),
        incidents: Vec::new(),
    };

    let artifact = build_anchor_discovery_artifact_with_runtime(&config, &binding, &report, 120)
        .expect("discovery artifact");

    let endpoint = artifact.service.service_endpoint;
    let policy = endpoint.publication_policy.expect("publication policy");
    assert_eq!(policy.primary_lane, AnchorLaneKind::EvmPrimary);
    assert!(policy.secondary_lanes.contains(&AnchorLaneKind::BitcoinOts));
    assert!(policy.secondary_lanes.contains(&AnchorLaneKind::SolanaMemo));
    assert!(policy.requires_trust_anchor_binding);
    assert!(policy.requires_witness_or_immutable_anchor_reference);
    assert!(policy.delegate_publication_allowed);
    assert_eq!(policy.emergency_mode, AnchorEmergencyMode::Normal);

    let freshness = endpoint.current_freshness.expect("freshness state");
    assert_eq!(freshness.status, AnchorDiscoveryFreshnessStatus::Lagging);
    assert_eq!(freshness.latest_checkpoint_seq, 42);
    assert_eq!(freshness.indexed_checkpoint_seq, 41);
    assert_eq!(freshness.last_published_at, Some(1_775_137_760));
    assert_eq!(freshness.publication_age_secs, Some(40));

    assert_eq!(endpoint.chain_runtime.len(), 1);
    assert_eq!(endpoint.chain_runtime[0].chain_id, "eip155:8453");
    assert_eq!(
        endpoint.chain_runtime[0].status,
        AnchorDiscoveryFreshnessStatus::Lagging
    );
    assert!(!endpoint.chain_runtime[0].has_active_conflict);
    assert!(endpoint.chain_runtime[0].incident_codes.is_empty());
}
