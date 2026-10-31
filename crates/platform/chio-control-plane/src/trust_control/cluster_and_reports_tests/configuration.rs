use super::*;

#[test]
fn build_cluster_state_validates_inputs_and_normalizes_peers() {
    let mut invalid = base_config();
    crate::trust_control::caller_credentials::tests::set_test_peers_with_secret(
        &mut invalid,
        "token",
        "http://127.0.0.1:3200",
        &["http://127.0.0.1:3300"],
    );
    invalid.authority_seed_path = Some(unique_temp_path("authority", "seed"));

    let error = build_cluster_state(&invalid, invalid.listen, chio_test_support::clock::clock())
        .test_unwrap_err();
    assert!(error
        .to_string()
        .contains("--authority-db instead of --authority-seed-file"));

    assert!(build_cluster_state(
        &base_config(),
        "127.0.0.1:0".parse().test_unwrap(),
        chio_test_support::clock::clock()
    )
    .test_unwrap()
    .is_none());

    let mut standalone_advertised = base_config();
    standalone_advertised.advertise_url = Some("http://127.0.0.1:3200/".to_string());
    assert!(build_cluster_state(
        &standalone_advertised,
        standalone_advertised.listen,
        chio_test_support::clock::clock()
    )
    .test_unwrap()
    .is_none());

    let mut config = base_config();
    crate::trust_control::caller_credentials::tests::set_test_peers(
        &mut config,
        "http://127.0.0.1:3200/",
        &["http://127.0.0.1:3200/", " http://127.0.0.1:3300/ "],
    );

    let cluster = build_cluster_state(&config, config.listen, chio_test_support::clock::clock())
        .test_unwrap()
        .test_unwrap();
    let guard = cluster.lock().test_unwrap();
    assert_eq!(guard.self_url, "http://127.0.0.1:3200");
    assert_eq!(guard.peers.len(), 1);
    assert!(guard.peers.contains_key("http://127.0.0.1:3300"));
}

#[test]
fn cluster_peer_url_validation_refuses_link_local_and_metadata_literals() {
    use chio_egress_contract::HttpEgressError;
    let host = |value: &str| value.to_string();
    for (peer_url, expected) in [
        (
            "https://169.254.169.254:3300",
            HttpEgressError::LinkLocalDenied {
                host: host("169.254.169.254"),
            },
        ),
        (
            "https://[fe80::1]:3300",
            HttpEgressError::LinkLocalDenied {
                host: host("fe80::1"),
            },
        ),
        (
            "https://100.100.100.200",
            HttpEgressError::ReservedAddressDenied {
                host: host("100.100.100.200"),
            },
        ),
        (
            "https://[fd00:ec2::254]",
            HttpEgressError::ReservedAddressDenied {
                host: host("fd00:ec2::254"),
            },
        ),
    ] {
        let error = normalize_cluster_config_url(peer_url).test_unwrap_err();
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut refusal = None;
        while let Some(current) = source {
            if let Some(found) = current.downcast_ref::<HttpEgressError>() {
                refusal = Some(found.clone());
                break;
            }
            source = current.source();
        }
        assert_eq!(refusal, Some(expected), "{peer_url}");
    }

    let normalized = normalize_cluster_config_url(" http://127.0.0.1:3300/ ").test_unwrap();
    assert_eq!(normalized, "http://127.0.0.1:3300");
}

#[test]
fn cluster_peer_url_validation_rejects_ambient_authority_material() {
    for peer_url in [
        "https://user:pass@control.example.test:443",
        "http://127.0.0.1:3300?token=secret",
        "http://127.0.0.1:3300#fragment",
    ] {
        let error = normalize_cluster_config_url(peer_url).test_unwrap_err();
        assert!(
            error.to_string().contains("cluster URL"),
            "unexpected error for peer URL `{peer_url}`: {error}",
        );
    }
}
