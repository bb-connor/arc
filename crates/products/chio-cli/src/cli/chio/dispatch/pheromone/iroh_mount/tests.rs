    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chio_core_types::canonical_json_bytes;
    use chio_core_types::sha256_hex;
    use chio_core_types::Keypair;
    use chio_federation::pheromone_gossip::PheromoneGossipBatch;
    use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
    use chio_federation_transport_iroh::identity::transport_endorsement_preimage;
    use chio_federation_transport_iroh::identity::TransportDirectoryBundleBody;
    use chio_federation_transport_iroh::identity::TransportDirectoryDocument;
    use chio_federation_transport_iroh::identity::TransportDirectoryEntry;
    use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
    use chio_federation_transport_iroh::lanes::pheromone::deliver_batch_over_iroh;
    use chio_federation_transport_iroh::lanes::pheromone::MAX_PHEROMONE_BATCH_BYTES;
    use chio_pheromone_relay::PeerDirectoryDocument;
    use chio_pheromone_relay::PeerDirectoryEntry;
    use chio_pheromone_relay::PheromoneRelayError;
    use chio_pheromone_relay::RelayRole;
    use chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_SCHEMA;
    use chio_pheromone_runtime::PheromoneReceiveReport;
    use iroh::EndpointAddr;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    const NOW: u64 = 2_000_000;

    fn endpoint_from_seed(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// A verified single-entry directory admitting `kernel_id` at the transport
    /// endpoint derived from `transport_seed` (mirrors the crate fixture).
    fn verified_directory(kernel_id: &str, transport_seed: u8) -> Arc<VerifiedDirectory> {
        let passport = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let transport = endpoint_from_seed(transport_seed);
        let entry = TransportDirectoryEntry {
            kernel_id: kernel_id.to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement: passport
                .sign(&transport_endorsement_preimage(kernel_id, &transport)),
            revocation_signers: Vec::new(),
            removed: false,
        };
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:relay".to_string(),
            peers: vec![entry],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version: 1,
            previous_version_sha256: None,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let trust = TransportDirectoryBundleTrust {
            issuers: vec![TrustedTransportDirectoryIssuer {
                issuer: "did:chio:issuer".to_string(),
                key_id: "issuer-key-1".to_string(),
                public_key: issuer.public_key(),
            }],
            version_floor: 0,
            expected_previous_version_sha256: None,
            now_unix_ms: NOW,
        };
        Arc::new(
            bundle
                .verify_bundle(&trust)
                .expect("fixture bundle verifies"),
        )
    }

    /// A receiver double: the loopback 403 test never reaches it (the gate rejects
    /// the unbound dialer at handshake), so it fails closed if ever invoked.
    #[derive(Debug)]
    struct RejectingReceiver;

    #[async_trait::async_trait]
    impl RelayBatchReceiver for RejectingReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
            Err(PheromoneRelayError::Json(
                "test receiver never accepts".to_string(),
            ))
        }
    }

    /// A receiver double that records whether it was ever consulted, so the
    /// out-of-scope test can PROVE the inbound scope gate short-circuits BEFORE
    /// `receive_batch` (an out-of-scope sender must never reach the receiver).
    #[derive(Debug)]
    struct TripwireReceiver {
        called: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RelayBatchReceiver for TripwireReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
            self.called.store(true, Ordering::SeqCst);
            Err(PheromoneRelayError::Json(
                "receiver must not be reached for an out-of-scope sender".to_string(),
            ))
        }
    }

    /// A minimal issuer-independent peer directory admitting `kernel_id` with the
    /// given `relay_role` (the field `enforce_peer_batch_directory_scope` gates the
    /// inbound submit authorization on). Subscribed to `treaty:test` so an Origin/Hub
    /// entry passes the treaty check too.
    fn peer_directory_admitting(kernel_id: &str, role: RelayRole) -> PeerDirectory {
        let passport = Keypair::from_seed(&[7u8; 32]);
        let document = PeerDirectoryDocument {
            schema: PHEROMONE_PEER_DIRECTORY_SCHEMA.to_string(),
            local_kernel_id: "did:chio:relay".to_string(),
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
            peers: vec![PeerDirectoryEntry {
                kernel_id: kernel_id.to_string(),
                public_key: passport.public_key(),
                endpoint: "https://peer.example/relay".to_string(),
                treaty_subscriptions: vec!["treaty:test".to_string()],
                relay_role: role,
                allowed_subject_class_namespaces: Vec::new(),
                accepted_ladder_refs: Vec::new(),
                max_batch_frames: 128,
                max_catchup_frames: 128,
                max_catchup_bytes: 1_048_576,
            }],
        };
        PeerDirectory::from_document(document, NOW).expect("peer directory builds")
    }

    fn loopback_config(lanes: Vec<IrohLane>) -> IrohMountConfig {
        IrohMountConfig {
            relay_mode: RelayMode::Disabled,
            bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            lanes,
            max_idle_timeout: RECOMMENDED_MAX_IDLE_TIMEOUT,
        }
    }

    fn empty_batch() -> PheromoneGossipBatch {
        PheromoneGossipBatch {
            schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
            recipient_kernel_id: "did:chio:relay".to_string(),
            treaty_id: "treaty:test".to_string(),
            frames: Vec::new(),
            flushed_at_unix_ms: NOW,
        }
    }

    #[test]
    fn disabled_loads_no_inputs_and_touches_nothing() {
        // The opt-in-default-off guarantee: with iroh disabled, load returns None
        // before any file access (the bogus paths are never read) and constructs
        // nothing, so the serve path is byte-for-byte unchanged.
        let inputs = load_iroh_serve_inputs(
            false,
            Some(Path::new("/nonexistent/directory.json")),
            None,
            Some(Path::new("/nonexistent/issuers.json")),
            Some(Path::new("/nonexistent/key.json")),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("disabled load never errors");
        assert!(inputs.is_none(), "disabled iroh must construct nothing");
    }

    #[test]
    fn enable_without_transport_directory_fails_closed() {
        let error = match load_iroh_serve_inputs(
            true,
            None,
            None,
            Some(Path::new("/nonexistent/issuers.json")),
            Some(Path::new("/nonexistent/key.json")),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        ) {
            Ok(_) => panic!("missing transport directory must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("iroh-transport-directory"));
    }

    #[test]
    fn invalid_transport_directory_bundle_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        // A bundle that is not even the right schema: verification must reject it.
        std::fs::write(&bundle_path, "{\"schema\":\"totally.wrong\"}").unwrap();
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(
            &key_path,
            "{\"seedHex\":\"".to_string() + &"11".repeat(32) + "\"}",
        )
        .unwrap();

        let error = match load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        ) {
            Ok(_) => panic!("an invalid/tampered directory bundle must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("directory bundle"),
            "unexpected error: {error}"
        );
    }

    /// The local kernel id (`localKernelId`) the signed-bundle fixtures own; the
    /// local-transport-key binding check resolves THIS id.
    const LOCAL_KERNEL_ID: &str = "did:chio:relay";
    /// The transport seed the fixtures endorse for [`LOCAL_KERNEL_ID`]. Its
    /// `EndpointId` MUST equal the public of the seed the test key files carry
    /// (`0x11` bytes, i.e. `"11".repeat(32)`), so a matching key passes the check.
    const LOCAL_TRANSPORT_SEED: u8 = 0x11;

    /// The seedHex the test transport-key files carry, matching `transport_seed`.
    /// A file carrying this seed loads to a `SecretKey` whose public is
    /// `endpoint_from_seed(transport_seed)`.
    fn transport_key_json(transport_seed: u8) -> String {
        let seed_hex = hex::encode([transport_seed; 32]);
        format!("{{\"seedHex\":\"{seed_hex}\"}}")
    }

    /// A well-formed, non-removed directory entry binding `kernel_id` to the
    /// transport `EndpointId` derived from `transport_seed`, self-endorsed by a
    /// per-kernel passport.
    fn directory_entry(
        kernel_id: &str,
        passport_seed: u8,
        transport_seed: u8,
    ) -> TransportDirectoryEntry {
        let passport = Keypair::from_seed(&[passport_seed; 32]);
        let transport = endpoint_from_seed(transport_seed);
        TransportDirectoryEntry {
            kernel_id: kernel_id.to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement: passport
                .sign(&transport_endorsement_preimage(kernel_id, &transport)),
            revocation_signers: Vec::new(),
            removed: false,
        }
    }

    /// The local relay's OWN transport binding (`LOCAL_KERNEL_ID -> transport seed`).
    /// The local-transport-key binding check verifies the loaded `--iroh-transport-key`
    /// against exactly this entry's `EndpointId`.
    fn local_relay_entry(transport_seed: u8) -> TransportDirectoryEntry {
        directory_entry(LOCAL_KERNEL_ID, 8, transport_seed)
    }

    /// Build and serialize a signed transport-directory bundle over `peers` at
    /// `version`, chaining onto `previous_version_sha256`. Returns the bundle JSON
    /// plus the issuer keypair whose public key the trusted-issuers file must pin.
    fn build_signed_bundle_json(
        peers: Vec<TransportDirectoryEntry>,
        version: u64,
        previous_version_sha256: Option<String>,
    ) -> (String, Keypair) {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers,
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        (serde_json::to_string(&bundle).unwrap(), issuer)
    }

    /// Build a signed bundle whose directory carries BOTH the local relay's own
    /// binding (`LOCAL_KERNEL_ID` at [`LOCAL_TRANSPORT_SEED`], so the default test
    /// key file matches) AND a peer `kernel_id` at `transport_seed`. This keeps the
    /// local-transport-key binding check satisfied by default.
    fn signed_bundle_json(
        kernel_id: &str,
        transport_seed: u8,
        version: u64,
        previous_version_sha256: Option<String>,
    ) -> (String, Keypair) {
        build_signed_bundle_json(
            vec![
                local_relay_entry(LOCAL_TRANSPORT_SEED),
                directory_entry(kernel_id, 7, transport_seed),
            ],
            version,
            previous_version_sha256,
        )
    }

    /// Build a signed successor whose directory DECLARES `local_kernel_id` as its owner
    /// while STILL binding the local relay's own transport endpoint. Used to prove the
    /// reloader rejects a successor that reassigns this node's declared local identity even
    /// though the endpoint binding survives (the startup path would reject the same bundle).
    fn signed_bundle_with_local_kernel_id(
        local_kernel_id: &str,
        version: u64,
        previous_version_sha256: Option<String>,
    ) -> String {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: local_kernel_id.to_string(),
            peers: vec![
                local_relay_entry(LOCAL_TRANSPORT_SEED),
                directory_entry("did:chio:bob", 7, 24),
            ],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        serde_json::to_string(&bundle).unwrap()
    }

    /// Overwrite the trusted-issuers file at `path` to pin a SINGLE issuer identity/key
    /// that is NOT the one the test bundles are signed with (issuer seed 240,
    /// `did:chio:issuer#issuer-key-1`), modeling operators rotating the signing issuer out
    /// of the trust set on a running relay.
    fn write_rotated_trusted_issuers(path: &std::path::Path) {
        let other_issuer = Keypair::from_seed(&[241u8; 32]);
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer-2",
                "keyId": "issuer-key-2",
                "publicKey": other_issuer.public_key(),
            }],
        });
        std::fs::write(path, serde_json::to_string(&issuers).unwrap()).unwrap();
    }

    /// Write a signed, verifiable transport-directory bundle (peer did:chio:bob at
    /// transport seed 24, optionally tombstoned) plus its trusted-issuers file to
    /// `dir`. Returns (bundle_path, issuers_path, expires_at, body_sha256). The body
    /// hash is the full-document canonical sha256 the gate reports, so a successor
    /// can chain onto it. Bundles carry expires_at = NOW + 1.
    fn write_test_bundle(
        dir: &std::path::Path,
        version: u64,
        removed: bool,
        previous_version_sha256: Option<String>,
    ) -> (PathBuf, PathBuf, u64, String) {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let mut peer = directory_entry("did:chio:bob", 7, 24);
        peer.removed = removed;
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers: vec![local_relay_entry(LOCAL_TRANSPORT_SEED), peer],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let expires_at = NOW + 1;
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: expires_at,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let body_hash = sha256_hex(&canonical_json_bytes(&bundle).unwrap());
        let bundle_path = dir.join(format!("bundle-{version}.json"));
        std::fs::write(&bundle_path, serde_json::to_string(&bundle).unwrap()).unwrap();
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        (bundle_path, issuers_path, expires_at, body_hash)
    }

    #[test]
    fn reload_expiry_is_checked_before_the_unchanged_fast_path() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // In-window, same version on disk => Unchanged (the fast path fires).
        let now_in_window = expires_at - 1;
        assert!(matches!(
            reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::Unchanged
        ));

        // Same (unchanged) version on disk but now PAST expiry must NOT short-circuit
        // to Unchanged; with no strictly-newer in-window successor it fails closed as
        // ExpiredWhileRunning.
        let now_expired = expires_at + 1;
        assert!(matches!(
            reload_verified_directory(&config, now_expired, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::ExpiredWhileRunning
        ));
    }

    #[test]
    fn reload_rejects_unchanged_bundle_when_signing_issuer_leaves_trust_roots() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path.clone(),
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Baseline: while the signing issuer is still trusted, the unchanged in-window
        // bundle takes the fast path.
        assert!(matches!(
            reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::Unchanged
        ));

        // Rotate the trust set so the bundle's signing issuer is no longer pinned. The
        // on-disk bundle is byte-unchanged, but a restart would now reject it (unknown
        // issuer); the unchanged fast path must fail closed identically rather than keep
        // admitting under a signer the federation no longer trusts.
        write_rotated_trusted_issuers(&issuers_path);
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::TrustRootsChanged),
            "an unchanged bundle whose signing issuer left the trust roots must fail closed, \
             got {outcome:?}"
        );
    }

    #[test]
    fn reload_fails_closed_when_trusted_issuers_becomes_empty() {
        // Removing every trusted issuer on a running relay must trust no signer and admit
        // nothing, in lockstep with startup rejecting the same empty configuration. It must
        // NOT fold into the transient keep-last-good read-error path, which would keep the
        // previous signer active until expiry.
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path.clone(),
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Baseline: with the issuer still pinned, the unchanged in-window bundle is Unchanged.
        assert!(matches!(
            reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::Unchanged
        ));

        // Empty the trusted-issuer set while the on-disk bundle stays byte-unchanged.
        std::fs::write(&issuers_path, r#"{"issuers":[]}"#).unwrap();
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::TrustRootsEmpty),
            "an empty trusted-issuer set must fail closed, got {outcome:?}"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and last-good is
        // preserved so a successor under a restored issuer can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: body_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "an empty issuer set fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "an empty issuer set raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved so a restored issuer can self-heal"
        );
    }

    #[test]
    fn reload_denies_same_version_bundle_whose_body_was_replaced() {
        // A same-version bundle whose canonical body differs from the loaded one (the file
        // was replaced without a version bump) must fail closed, not take the unchanged fast
        // path. Reporting it Unchanged would keep the loaded directory admitting peers the
        // replacement dropped. Here v1 is overwritten in place by a different v1 that
        // tombstones the peer, still signed by the trusted issuer so it verifies but hashes
        // differently.
        let dir = tempfile::tempdir().unwrap();
        let (_original_path, _original_issuers, expires_at, loaded_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Overwrite bundle-1.json in place with a different v1 (peer tombstoned).
        let (bundle_path, issuers_path, _expires, replaced_hash) =
            write_test_bundle(dir.path(), 1, true, None);
        assert_ne!(
            loaded_hash, replaced_hash,
            "the replacement body must differ so the hash gate can catch it"
        );
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the loaded directory is the ORIGINAL v1 (loaded_hash); the on-disk
        // file is now a different v1, so the fast path fails closed rather than Unchanged.
        let outcome =
            reload_verified_directory(&config, now_in_window, 1, expires_at, &loaded_hash)
                .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::CurrentBodyReplaced),
            "a same-version bundle whose body was replaced must fail closed, got {outcome:?}"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and last-good is
        // preserved so a properly versioned successor can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: loaded_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a replaced same-version body fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a replaced same-version body raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved so a properly versioned successor can self-heal"
        );
    }

    #[test]
    fn reload_rejects_successor_that_reassigns_local_kernel_id() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, genesis_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // A strictly-newer, validly-signed, in-window successor that STILL binds this node's
        // transport endpoint but DECLARES a different local kernel as the directory owner.
        // The startup path (`build_iroh_router`) rejects such a bundle because its declared
        // local kernel id no longer matches the relay's, so the live reloader must fail closed
        // to deny-all rather than swap it in under a changed identity binding.
        let successor =
            signed_bundle_with_local_kernel_id("did:chio:usurper", 2, Some(genesis_hash.clone()));
        std::fs::write(&bundle_path, successor).unwrap();

        let now_in_window = expires_at - 1;
        let outcome =
            reload_verified_directory(&config, now_in_window, 1, expires_at, &genesis_hash)
                .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::LocalBindingRevoked(_)),
            "a successor reassigning this node's declared local kernel id must fail closed, \
             got {outcome:?}"
        );
    }

    #[test]
    fn directory_reload_swaps_in_successor_and_evicts_tombstoned_peer() {
        let dir = tempfile::tempdir().unwrap();
        // Genesis version 1 (peer live); its full-document hash is the chain pin.
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Version 2 on disk tombstones the peer, chaining onto v1's hash.
        let (bundle_path, issuers_path, expires_at, _v2_hash) =
            write_test_bundle(dir.path(), 2, true, Some(v1_hash.clone()));
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        let now_in_window = expires_at - 1;
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        let verified = match outcome {
            ReloadOutcome::Updated(verified) => verified,
            _ => panic!("expected Updated for a strictly-newer in-window successor"),
        };
        // Apply it through the gate and assert the tombstoned peer no longer admits.
        let gate = DirectoryGate::new(std::sync::Arc::new(verified));
        assert_eq!(gate.current_version(), 2);
        assert_eq!(gate.resolve(&endpoint_from_seed(24)), None);
    }

    /// Write a signed successor bundle (version `version`, chaining onto
    /// `previous_version_sha256`) that binds the LOCAL node at `local_transport_seed`
    /// (pass a seed != [`LOCAL_TRANSPORT_SEED`] to ROTATE this node's binding, so the
    /// successor no longer endorses the currently-bound endpoint). The peer entry is
    /// left live. Returns (bundle_path, issuers_path, expires_at).
    fn write_local_rotated_bundle(
        dir: &std::path::Path,
        version: u64,
        local_transport_seed: u8,
        previous_version_sha256: Option<String>,
    ) -> (PathBuf, PathBuf, u64) {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers: vec![
                local_relay_entry(local_transport_seed),
                directory_entry("did:chio:bob", 7, 24),
            ],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let expires_at = NOW + 1;
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: expires_at,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let bundle_path = dir.join(format!("bundle-{version}.json"));
        std::fs::write(&bundle_path, serde_json::to_string(&bundle).unwrap()).unwrap();
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        (bundle_path, issuers_path, expires_at)
    }

    #[test]
    fn directory_reload_fails_closed_when_successor_rotates_local_binding() {
        // Local-binding recheck (SECURITY). A strictly-newer, in-window, validly-signed
        // successor that ROTATES this node's local transport endpoint (or tombstones it)
        // no longer endorses the endpoint this node is bound to. Swapping it in would
        // leave the already-bound endpoint serving iroh ingress under the old key for
        // peers admitted in the new directory. The reloader must fail closed to
        // LocalBindingRevoked (deny-all), never Updated.
        //
        // The successor rotates the LOCAL entry from LOCAL_TRANSPORT_SEED (0x11) to a
        // DIFFERENT seed (0x22); the reloader's config pins the currently-bound endpoint
        // (endpoint_from_seed(LOCAL_TRANSPORT_SEED)). Without the recheck the successor
        // verifies and returns Updated, admitting under a revoked local identity; the
        // recheck instead denies the bound endpoint and returns LocalBindingRevoked.
        let dir = tempfile::tempdir().unwrap();
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Version 2 rotates the LOCAL node's transport endpoint to seed 0x22, chaining
        // onto v1's hash. The peer stays live, so only the local binding changed.
        let (bundle_path, issuers_path, expires_at) =
            write_local_rotated_bundle(dir.path(), 2, 0x22, Some(v1_hash.clone()));
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            // The endpoint this node is actually bound to (the OLD seed 0x11), which the
            // rotated successor no longer endorses.
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        let now_in_window = expires_at - 1;
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::LocalBindingRevoked(_)),
            "a successor that no longer binds this node's local endpoint fails closed, never Updated"
        );
    }

    /// Write a signed successor whose directory ROTATES the local node to
    /// `local_transport_seed` AND REASSIGNS a peer (`did:chio:bob`) to
    /// `peer_transport_seed`. Passing `peer_transport_seed == LOCAL_TRANSPORT_SEED` hands
    /// this node's currently-bound endpoint to a DIFFERENT kernel id, the exact case a
    /// bare `authorize(endpoint).is_some()` recheck would wrongly admit. Returns
    /// (bundle_path, issuers_path, expires_at).
    fn write_local_reassigned_bundle(
        dir: &std::path::Path,
        version: u64,
        local_transport_seed: u8,
        peer_transport_seed: u8,
        previous_version_sha256: Option<String>,
    ) -> (PathBuf, PathBuf, u64) {
        let (bundle_json, issuer) = build_signed_bundle_json(
            vec![
                directory_entry(LOCAL_KERNEL_ID, 8, local_transport_seed),
                directory_entry("did:chio:bob", 7, peer_transport_seed),
            ],
            version,
            previous_version_sha256,
        );
        let bundle_path = dir.join(format!("bundle-{version}.json"));
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        (bundle_path, issuers_path, NOW + 1)
    }

    #[test]
    fn directory_reload_fails_closed_when_successor_reassigns_bound_endpoint() {
        // Local-binding recheck (SECURITY, deeper than the rotation case). A
        // strictly-newer, in-window, validly-signed successor that REASSIGNS this node's
        // bound transport endpoint to a DIFFERENT kernel id still `authorize`s the endpoint
        // (it resolves to the OTHER kernel), so a recheck that only asks "does the endpoint
        // resolve to some kernel?" would wrongly swap it in - leaving the relay serving iroh
        // ingress under the OLD secret for an identity the successor now assigns elsewhere.
        // The recheck must mirror STARTUP: require the successor to bind THIS kernel id to
        // THIS endpoint.
        //
        // v2 rotates the LOCAL node to seed 0x22 AND reassigns the peer to
        // LOCAL_TRANSPORT_SEED (0x11 = this node's bound endpoint). An
        // `authorize(endpoint).is_none()` recheck would see authorize(0x11) == Some(bob)
        // (not None) and swap it in, admitting under a reassigned local endpoint. The
        // `resolve_transport_endpoint(local_kernel_id) == endpoint` recheck instead
        // resolves LOCAL_KERNEL_ID to 0x22 != 0x11 and returns LocalBindingRevoked.
        let dir = tempfile::tempdir().unwrap();
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let (bundle_path, issuers_path, expires_at) = write_local_reassigned_bundle(
            dir.path(),
            2,
            0x22,
            LOCAL_TRANSPORT_SEED,
            Some(v1_hash.clone()),
        );
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::LocalBindingRevoked(_)),
            "a successor that reassigns this node's bound endpoint to another kernel fails closed"
        );
    }

    /// Write a trusted-issuers file at `dir/issuers.json` pinning `min_version`
    /// (camelCase on the wire) with the standard issuer key. Returns its path.
    fn write_issuers_with_min_version(dir: &std::path::Path, min_version: u64) -> PathBuf {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
            "minVersion": min_version,
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        issuers_path
    }

    #[test]
    fn directory_reload_denies_newer_successor_below_raised_min_version() {
        // A staged successor that is NEWER than the running directory but STILL BELOW a
        // minVersion operators raised above it must fail closed to deny-all, exactly as
        // the unchanged path and a restart would. It must NOT surface as a transient verify
        // error that keeps the stale, now below-floor directory admitting until expiry. The
        // successor is still verified and CAPTURED so the last-good chain advances onto it,
        // letting a later at-or-above-floor bundle (which chains onto this successor)
        // self-heal.
        let dir = tempfile::tempdir().unwrap();
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let (bundle_path, _v2_issuers, expires_at, v2_hash) =
            write_test_bundle(dir.path(), 2, false, Some(v1_hash.clone()));
        // Pin minVersion = 10 AFTER the bundles are written; the on-disk successor (v2) is
        // newer than the running v1 but still below the floor.
        let issuers_path = write_issuers_with_min_version(dir.path(), 10);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the newer-but-still-below-floor successor fails closed and is
        // captured for chain advancement rather than returning a transient verify error.
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::BelowMinVersionFloor(Some(_))),
            "a newer successor below the raised minVersion must fail closed, got {outcome:?}"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and the chain advances
        // onto the below-floor successor so a later at-or-above-floor bundle can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a newer-but-below-floor successor fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a below-min-version successor raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 2,
            "the chain advances onto the below-floor successor so a later bundle can chain on"
        );
        assert_eq!(
            state.body_sha256, v2_hash,
            "the chain pin advances to the below-floor successor's hash"
        );
    }

    #[test]
    fn directory_reload_denies_unchanged_directory_below_raised_min_version() {
        // Raising minVersion above the running version must fail the running directory
        // closed on the next reload even when the on-disk bundle is unchanged (same
        // version): the unchanged fast path must not short-circuit to Unchanged before
        // honoring the minVersion floor a restart would enforce via transport_bundle_trust.
        // A version-1 directory whose issuers now pin minVersion 5 is below the floor, so
        // the reload fails closed to BelowMinVersionFloor and the gate flips to deny-all.
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, _issuers, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Raise minVersion to 5 while the running (and on-disk) version stays 1.
        let issuers_path = write_issuers_with_min_version(dir.path(), 5);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the unchanged (v1 == on-disk) directory below the raised floor
        // fails closed rather than short-circuiting to Unchanged.
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::BelowMinVersionFloor(None)),
            "an unchanged directory below a raised minVersion must fail closed, not Unchanged"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and last-good is
        // preserved so a successor at or above the floor can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: body_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a below-min-version directory fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a below-min-version directory raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved so a successor at/above the floor can self-heal"
        );
    }

    #[test]
    fn directory_reload_self_heals_across_below_floor_successors() {
        // When operators raise minVersion above an intermediate successor, that successor is
        // denied admission but its hash must still advance the chain, so a later
        // at-or-above-floor bundle - which chains onto it - self-heals instead of being
        // stranded in deny-all against a dropped chain. minVersion is 3 here: v2 is below the
        // floor (deny-all, chain advances to v2), then v3 at the floor chains onto v2 and
        // restores admission without a restart.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = write_issuers_with_min_version(dir.path(), 3);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // v1 binds this node; the reloader's last-good starts here.
        let v1_hash = write_local_binding_bundle_at(&bundle_path, 1, LOCAL_TRANSPORT_SEED, None);
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: NOW + 1,
        };

        // v2 is a valid successor (chains onto v1) but below the raised floor: deny-all, and
        // the chain advances onto v2 so v3 can chain onto it.
        let v2_hash =
            write_local_binding_bundle_at(&bundle_path, 2, LOCAL_TRANSPORT_SEED, Some(v1_hash));
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a below-floor successor fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a below-floor successor raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 2,
            "the chain advances onto the below-floor successor"
        );
        assert_eq!(
            state.body_sha256, v2_hash,
            "the chain pin advances to the below-floor successor's hash"
        );

        // v3 at the floor chains onto v2; self-heal must restore admission without a restart.
        let _v3_hash =
            write_local_binding_bundle_at(&bundle_path, 3, LOCAL_TRANSPORT_SEED, Some(v2_hash));
        alive.store(true, Ordering::SeqCst);
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            3,
            "an at-floor successor chained onto the below-floor one self-heals admission"
        );
        assert_eq!(
            state.version, 3,
            "last-good advances to the recovered successor"
        );
    }

    #[test]
    fn directory_reload_fails_closed_when_below_floor_running_directory_has_an_invalid_successor() {
        // Operators raised minVersion above the running directory, so a restart would reject
        // it. An on-disk successor at or above the floor that FAILS verification (partially
        // written or bad) must not mask that: the reloader must fail closed to deny-all
        // rather than keep the below-floor directory admitting until expiry.
        let dir = tempfile::tempdir().unwrap();
        // v1 is the running directory; its hash is the chain pin.
        let (_v1_path, _v1_issuers, expires_at, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // An on-disk v3 at or above the raised floor but that does NOT chain onto v1 (a
        // bad/partial successor), so it fails verification.
        let (bundle_path, _v3_issuers, _v3_expires, _v3_hash) =
            write_test_bundle(dir.path(), 3, false, Some("00".repeat(32)));
        // Raise minVersion to 3: the running v1 is below the floor, the on-disk v3 is at it.
        let issuers_path = write_issuers_with_min_version(dir.path(), 3);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the invalid at-floor successor does not mask the below-floor running
        // directory; the reload fails closed rather than returning a transient verify error.
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::BelowMinVersionFloor(None)),
            "a below-floor running directory with an invalid successor must fail closed, got \
             {outcome:?}"
        );

        // Step-level: the gate flips to deny-all and the alarm is raised.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a below-floor directory with a bad successor fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "the fail-closed alarm is raised"
        );
    }

    /// Like [`write_test_bundle`] but with an explicit validity window, so a test can
    /// publish a still-in-window successor AFTER the running bundle has lapsed. Writes to
    /// `path` and returns the full-document body hash (the successor's chain pin).
    fn write_test_bundle_windowed(
        path: &std::path::Path,
        version: u64,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        previous_version_sha256: Option<String>,
    ) -> String {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers: vec![
                local_relay_entry(LOCAL_TRANSPORT_SEED),
                directory_entry("did:chio:bob", 7, 24),
            ],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms,
            expires_at_unix_ms,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let body_hash = sha256_hex(&canonical_json_bytes(&bundle).unwrap());
        std::fs::write(path, serde_json::to_string(&bundle).unwrap()).unwrap();
        body_hash
    }

    #[test]
    fn directory_reloader_self_heals_after_expiry_lapse() {
        // After an expiry lapses the gate to deny-all, a valid in-window successor must
        // be able to swap back in WITHOUT a restart. The reloader keeps the
        // last-good version + hash chain SEPARATELY from the admission gate, so the deny-all
        // sentinel (version 0, empty predecessor hash) never becomes the chain the successor
        // must verify against.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = write_issuers_with_min_version(dir.path(), 0);
        // v1: in-window early, expires at NOW + 1.
        let v1_hash = write_test_bundle_windowed(&bundle_path, 1, NOW - 1, NOW + 1, None);

        let gate = DirectoryGate::new(std::sync::Arc::new(
            chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
        ));
        let alive = AtomicBool::new(true);
        // The reloader's preserved last-good, pinned to the running v1.
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: NOW + 1,
        };
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // Tick 1: now is PAST v1's expiry with no successor on disk -> fail closed to
        // deny-all, but last-good (v1) is PRESERVED.
        let now_expired = NOW + 2;
        directory_reload_step(&gate, &config, now_expired, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "expiry lapses the gate to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "expiry raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved across the deny-all lapse"
        );

        // Publish a valid in-window v2 successor (chained onto v1, issued after v1 lapsed).
        let _v2_hash =
            write_test_bundle_windowed(&bundle_path, 2, NOW + 1, NOW + 100, Some(v1_hash.clone()));

        // Counterfactual: had the reloader re-derived last-good FROM THE GATE, the
        // deny-all sentinel (version 0, empty hash) would be the predecessor and the same
        // successor would NOT swap in.
        let denied = reload_verified_directory(&config, now_expired, 0, 0, "")
            .expect("reload runs against the deny-all sentinel");
        assert!(
            !matches!(denied, ReloadOutcome::Updated(_)),
            "a successor chained onto last-good cannot recover from the deny-all sentinel"
        );

        // Tick 2: the same successor verified against the PRESERVED last-good chain
        // self-heals admission back to v2.
        directory_reload_step(&gate, &config, now_expired, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            2,
            "a valid successor self-heals admission after an expiry lapse"
        );
        assert_eq!(
            state.version, 2,
            "last-good advances to the recovered successor"
        );
    }

    /// Write a signed successor to a FIXED `path` (so successive versions overwrite one
    /// bundle the reloader re-reads), binding the LOCAL node at `local_transport_seed`
    /// (pass [`LOCAL_TRANSPORT_SEED`] to REBIND this node, any other seed to ROTATE it
    /// away), peer `did:chio:bob` live, chaining onto `previous_version_sha256`. Returns
    /// the full-document body hash (the successor's chain pin).
    fn write_local_binding_bundle_at(
        path: &std::path::Path,
        version: u64,
        local_transport_seed: u8,
        previous_version_sha256: Option<String>,
    ) -> String {
        let (bundle_json, _issuer) = build_signed_bundle_json(
            vec![
                local_relay_entry(local_transport_seed),
                directory_entry("did:chio:bob", 7, 24),
            ],
            version,
            previous_version_sha256,
        );
        std::fs::write(path, &bundle_json).unwrap();
        let bundle: TransportDirectoryBundleDocument = serde_json::from_str(&bundle_json).unwrap();
        sha256_hex(&canonical_json_bytes(&bundle).unwrap())
    }

    #[test]
    fn directory_reload_advances_chain_after_local_binding_revoked() {
        // When a valid v2 successor rotates or tombstones this node (LocalBindingRevoked
        // -> deny-all), the reload chain must advance to v2 so a later v3 that rebinds this
        // node - chaining onto v2, the canonical successor - can self-heal admission,
        // rather than staying pinned to v1 and rejecting the correctly-chained v3 forever.
        // Here v2 revokes the local binding (the chain must advance to v2), then v3 chained
        // onto v2 rebinds this node and restores admission through the gate.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = write_issuers_with_min_version(dir.path(), 0);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // v1 binds this node (0x11); the reloader's last-good starts here.
        let v1_hash = write_local_binding_bundle_at(&bundle_path, 1, LOCAL_TRANSPORT_SEED, None);
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: NOW + 1,
        };

        // v2 ROTATES this node away (LOCAL -> 0x22), chaining onto v1 -> LocalBindingRevoked.
        let v2_hash = write_local_binding_bundle_at(&bundle_path, 2, 0x22, Some(v1_hash.clone()));
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a revoked local binding fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a revoked local binding raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 2,
            "the chain advances to the revoking successor so a rebind can self-heal"
        );
        assert_eq!(
            state.body_sha256, v2_hash,
            "the chain pin advances to the revoking successor's hash"
        );

        // v3 REBINDS this node (LOCAL -> 0x11), chaining onto v2. Self-heal must restore
        // admission without a restart.
        let _v3_hash =
            write_local_binding_bundle_at(&bundle_path, 3, LOCAL_TRANSPORT_SEED, Some(v2_hash));
        alive.store(true, Ordering::SeqCst);
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            3,
            "a rebinding successor chained onto the revoker self-heals admission"
        );
        assert_eq!(
            state.version, 3,
            "last-good advances to the recovered successor"
        );
    }

    #[test]
    fn reloader_wakes_at_expiry_before_the_fixed_interval() {
        // The reloader must re-check expiry at the deadline, not wait the full fixed
        // interval. With a 60s interval, a bundle that expires just after a poll would
        // otherwise keep admitting for almost a minute (the gate's decide() is not itself
        // time-aware). next_reload_delay caps the wake at the expiry deadline: in-window
        // with expiry sooner than the interval it wakes at expiry, not 60s.
        let interval = Duration::from_secs(60);
        assert_eq!(
            next_reload_delay(interval, 1_000, 1_005),
            Duration::from_millis(5),
            "wake at the expiry deadline when it precedes the next fixed poll"
        );
        // Expiry farther off than the interval -> the fixed interval caps the wake.
        assert_eq!(
            next_reload_delay(interval, 1_000, 1_000 + 120_000),
            interval,
            "the fixed interval caps the wake when expiry is far off"
        );
        // Deny-all sentinel (gate expiry 0, admitting nothing) -> the fixed interval
        // governs the poll for a successor; never a zero-delay busy-loop.
        assert_eq!(
            next_reload_delay(interval, 2_000, 0),
            interval,
            "a deny-all gate polls on the fixed interval, not a busy-loop"
        );
    }

    #[test]
    fn reloader_rechecks_immediately_when_a_live_directory_expires_mid_cycle() {
        // A LIVE directory (positive expiry) whose deadline elapsed between the reload step
        // and this delay computation is still admitting through the gate, so it must be
        // rechecked IMMEDIATELY to flip it closed at the deadline, not admit for another
        // full interval. This is the distinction between "still-admitting-but-just-expired"
        // and the "already-deny-all" sentinel, which polls on the interval.
        let interval = Duration::from_secs(60);
        assert_eq!(
            next_reload_delay(interval, 2_000, 1_000),
            Duration::ZERO,
            "a live directory whose expiry already passed rechecks immediately"
        );
        // Expiry exactly at `now` is already past (decide uses `expires_at <= now`), so a
        // live directory at that boundary also rechecks immediately.
        assert_eq!(
            next_reload_delay(interval, 1_000, 1_000),
            Duration::ZERO,
            "a live directory whose expiry equals now rechecks immediately"
        );
    }

    #[test]
    fn watchdog_flips_gauge_and_alarms_on_death() {
        // A liveness probe reporting dead flips the router-alive gauge to 0 (the
        // testable per-tick step the spawned watchdog loops over).
        chio_federation_transport_iroh::metrics::set_router_alive(true);
        let dead = true;
        note_router_liveness(!dead); // alive = false
        assert_eq!(chio_federation_transport_iroh::metrics::router_alive(), 0);
        // A live probe restores the gauge.
        note_router_liveness(true);
        assert_eq!(chio_federation_transport_iroh::metrics::router_alive(), 1);
    }

    #[test]
    fn directory_reload_rejects_rollback_and_keeps_last_good() {
        let dir = tempfile::tempdir().unwrap();
        // On-disk bundle is version 1; the running directory is already at version 3.
        let (bundle_path, issuers_path, expires_at, _hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;
        let error =
            reload_verified_directory(&config, now_in_window, 3, expires_at, "current-hash")
                .expect_err("an in-window rollback is rejected");
        assert!(matches!(
            error,
            DirectoryReloadError::Rollback {
                found: 1,
                current: 3
            }
        ));
    }

    #[test]
    fn successor_bundle_accepted_with_rotation_state_supplied() {
        // A ROTATED successor bundle (version 5, chaining onto a predecessor hash)
        // is REJECTED at genesis defaults (floor 0, no predecessor) but ACCEPTED
        // once the rotation-state pin supplies the floor + expected predecessor
        // hash, so a durable directory rotation is loadable at startup.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");
        let state_path = dir.path().join("state.json");

        let predecessor = "predecessor-bundle-sha256".to_string();
        let (bundle_json, issuer) =
            signed_bundle_json("did:chio:bob", 24, 5, Some(predecessor.clone()));
        std::fs::write(&bundle_path, &bundle_json).unwrap();

        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(
            &key_path,
            "{\"seedHex\":\"".to_string() + &"11".repeat(32) + "\"}",
        )
        .unwrap();

        // Without the rotation state, the successor is rejected fail-closed: its
        // previousVersionSha256 cannot chain onto the genesis default of None.
        let rejected = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        );
        assert!(
            rejected.is_err(),
            "a rotated successor bundle must be rejected without the rotation-state pin"
        );

        // With the floor + predecessor hash supplied, the successor is accepted.
        let state = serde_json::json!({
            "versionFloor": 4,
            "expectedPreviousVersionSha256": predecessor,
        });
        std::fs::write(&state_path, serde_json::to_string(&state).unwrap()).unwrap();

        let inputs = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            Some(&state_path),
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("successor bundle accepted with the rotation-state pin")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            inputs.directory.version(),
            5,
            "the accepted directory must be the rotated successor (version 5)"
        );
    }

    #[test]
    fn bundle_below_trusted_issuer_min_version_is_rejected_without_state_file() {
        // The shared --trusted-issuers file sets minVersion (the SAME floor the HTTP
        // peer-directory loader enforces). With NO explicit transport-directory-state
        // pin, that minVersion must be the rollback floor, so a below-floor bundle is
        // rejected fail-closed rather than promoted against a hardcoded floor of 0.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        // A genesis-shaped bundle at version 3 (no predecessor to chain onto).
        let (below_json, issuer) = signed_bundle_json("did:chio:bob", 24, 3, None);
        std::fs::write(&bundle_path, &below_json).unwrap();

        // Pin minVersion = 5 in the trusted-issuers file (camelCase on the wire).
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
            "minVersion": 5,
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(
            &key_path,
            "{\"seedHex\":\"".to_string() + &"11".repeat(32) + "\"}",
        )
        .unwrap();

        // No state file: the floor comes from minVersion (5), so version 3 is rejected.
        let rejected = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        );
        assert!(
            rejected.is_err(),
            "a bundle below the trusted-issuer minVersion must be rejected even without a state file"
        );

        // A genesis-shaped bundle above the floor (version 6, no predecessor) loads.
        let (above_json, _issuer) = signed_bundle_json("did:chio:bob", 24, 6, None);
        std::fs::write(&bundle_path, &above_json).unwrap();
        let inputs = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("a bundle above the minVersion floor loads")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            inputs.directory.version(),
            6,
            "the accepted directory must be the above-floor bundle"
        );

        // Boundary: minVersion is INCLUSIVE, so a bundle EXACTLY at minVersion (5)
        // must be accepted (the exclusive `version_floor` maps to minVersion - 1).
        let (at_floor_json, _issuer) = signed_bundle_json("did:chio:bob", 24, 5, None);
        std::fs::write(&bundle_path, &at_floor_json).unwrap();
        let at_floor = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("a bundle exactly at the minVersion floor loads")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            at_floor.directory.version(),
            5,
            "a bundle at minVersion must be accepted (inclusive floor)"
        );

        // Boundary: one BELOW minVersion (4) must still be rejected fail-closed.
        let (below_floor_json, _issuer) = signed_bundle_json("did:chio:bob", 24, 4, None);
        std::fs::write(&bundle_path, &below_floor_json).unwrap();
        let below_floor = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        );
        assert!(
            below_floor.is_err(),
            "a bundle one below minVersion must be rejected"
        );
    }

    include!("tests/transport.rs");
