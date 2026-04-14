#![cfg(feature = "web3")]

use arc_anchor::{
    AnchorDiscoveryChain, AnchorDiscoveryServiceEndpoint, AnchorLaneKind,
    ARC_ANCHOR_DISCOVERY_SCHEMA,
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
    };

    assert_eq!(endpoint.chains.len(), 1);
    assert_eq!(endpoint.chains[0].chain_id, "eip155:8453");
    assert_eq!(AnchorLaneKind::BitcoinOts, AnchorLaneKind::BitcoinOts);
    assert_eq!(ARC_ANCHOR_DISCOVERY_SCHEMA, "arc.anchor-discovery.v1");
}
