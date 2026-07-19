    fn assert_clustered_authority_build_rejects_custody(authority_db_path: &std::path::Path) {
        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.to_path_buf());

        let error = build_cluster_state(&config, config.listen).test_unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shared authority write and selector protocol"),
            "unexpected clustered authority error: {error}"
        );
    }

    #[test]
    fn persisted_authority_fence_loader_seeds_known_leader_term() {
        let authority_db_path = unique_temp_path("cluster-authority-fence", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .test_unwrap();
        let peers = HashMap::from([(
            "http://node-b".to_string(),
            PeerSyncState::default(),
        )]);

        let (term, leader_url) = load_persisted_authority_fence(
            &authority_db_path,
            "http://node-a",
            &peers,
        )
        .test_unwrap();

        assert_eq!(term, 7);
        assert_eq!(leader_url.as_deref(), Some("http://node-b"));
        assert_clustered_authority_build_rejects_custody(&authority_db_path);

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn persisted_authority_fence_loader_discards_unknown_leader() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-unknown-leader", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-z"), 7)
            .test_unwrap();
        let peers = HashMap::from([(
            "http://node-b".to_string(),
            PeerSyncState::default(),
        )]);

        let (term, leader_url) = load_persisted_authority_fence(
            &authority_db_path,
            "http://node-a",
            &peers,
        )
        .test_unwrap();

        assert_eq!(term, 7);
        assert!(leader_url.is_none(), "unknown persisted leader survived");
        assert_clustered_authority_build_rejects_custody(&authority_db_path);

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn persisted_authority_fence_loader_discards_non_current_generation() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-stale-generation", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .test_unwrap();
        let rotated = authority.rotate().test_unwrap();
        let refreshed_fence = authority.cluster_fence().test_unwrap();
        assert_eq!(refreshed_fence.authority_generation, rotated.generation);
        rusqlite::Connection::open(&authority_db_path)
            .test_unwrap()
            .execute(
                "UPDATE authority_cluster_fence SET authority_generation = 1 WHERE singleton_id = 1",
                [],
            )
            .test_unwrap();
        let peers = HashMap::from([(
            "http://node-b".to_string(),
            PeerSyncState::default(),
        )]);

        let (term, leader_url) = load_persisted_authority_fence(
            &authority_db_path,
            "http://node-a",
            &peers,
        )
        .test_unwrap();

        assert_eq!(term, 0);
        assert!(leader_url.is_none());
        assert_clustered_authority_build_rejects_custody(&authority_db_path);

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn apply_cluster_snapshot_fails_when_authority_fence_persistence_fails() {
        let authority_db_path = unique_temp_path("cluster-authority-fence-dir", "d");
        std::fs::create_dir_all(&authority_db_path).test_unwrap();

        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let mut target_state =
            state_with_cluster("http://node-b", &["http://node-a"], None, None, None);
        target_state.config.authority_db_path = Some(authority_db_path.clone());

        for state in [&source_state, &target_state] {
            let cluster = state.cluster.as_ref().test_unwrap();
            let mut guard = cluster.lock().test_unwrap();
            for peer in guard.peers.values_mut() {
                peer.health = PeerHealth::Healthy;
                peer.last_contact_at = Some(unix_timestamp_now());
            }
        }

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        let term_before = cluster_consensus_view(&target_state)
            .test_unwrap()
            .election_term;
        let error =
            apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap_err();
        let error_text = error.to_string();
        assert!(
            error_text.contains("directory") || error_text.contains("open database file"),
            "unexpected error: {error_text}"
        );
        assert_eq!(
            cluster_consensus_view(&target_state)
                .test_unwrap()
                .election_term,
            term_before
        );

        let _ = std::fs::remove_dir_all(authority_db_path);
    }
