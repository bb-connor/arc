use super::*;

#[test]
fn build_cluster_state_validates_inputs_and_normalizes_peers() {
    let mut invalid = base_config();
    invalid.advertise_url = Some("http://127.0.0.1:3200".to_string());
    invalid.peer_urls = vec!["http://127.0.0.1:3300".to_string()];
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
    standalone_advertised.allow_local_peer_urls = false;
    standalone_advertised.advertise_url = Some("http://127.0.0.1:3200/".to_string());
    assert!(build_cluster_state(
        &standalone_advertised,
        standalone_advertised.listen,
        chio_test_support::clock::clock()
    )
    .test_unwrap()
    .is_none());

    let mut config = base_config();
    config.advertise_url = Some("http://127.0.0.1:3200/".to_string());
    config.peer_urls = vec![
        "http://127.0.0.1:3200/".to_string(),
        " http://127.0.0.1:3300/ ".to_string(),
        "http://127.0.0.1:3300".to_string(),
    ];

    let cluster = build_cluster_state(&config, config.listen, chio_test_support::clock::clock())
        .test_unwrap()
        .test_unwrap();
    let guard = cluster.lock().test_unwrap();
    assert_eq!(guard.self_url, "http://127.0.0.1:3200");
    assert_eq!(guard.peers.len(), 1);
    assert!(guard.peers.contains_key("http://127.0.0.1:3300"));
}

#[test]
fn cluster_peer_url_validation_rejects_local_networks_by_default() {
    let error = normalize_cluster_config_url("http://127.0.0.1:3300", false).test_unwrap_err();
    assert!(error.to_string().contains("--allow-local-peer-urls"));

    let normalized = normalize_cluster_config_url(" http://127.0.0.1:3300/ ", true).test_unwrap();
    assert_eq!(normalized, "http://127.0.0.1:3300");
}

#[test]
fn cluster_peer_url_validation_rejects_ambient_authority_material() {
    for peer_url in [
        "https://user:pass@control.example.test:443",
        "http://127.0.0.1:3300?token=secret",
        "http://127.0.0.1:3300#fragment",
    ] {
        let error = normalize_cluster_config_url(peer_url, true).test_unwrap_err();
        assert!(
            error.to_string().contains("cluster URL"),
            "unexpected error for peer URL `{peer_url}`: {error}",
        );
    }
}
