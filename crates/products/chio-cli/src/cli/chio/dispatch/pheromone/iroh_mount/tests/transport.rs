    #[test]
    fn matching_local_transport_key_binding_loads() {
        // The directory endorses LOCAL_TRANSPORT_SEED for the local kernel id, and the
        // key file carries that SAME seed: the local-transport-key binding check passes
        // and startup produces serve inputs whose transport key is the endorsed endpoint.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        let (bundle_json, issuer) = signed_bundle_json("did:chio:bob", 24, 6, None);
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(&key_path, transport_key_json(LOCAL_TRANSPORT_SEED)).unwrap();

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
        .expect("a matching local transport key must load")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            inputs.transport_key.public(),
            endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            "the loaded transport key must be the directory-endorsed local endpoint"
        );
    }

    #[test]
    fn local_transport_key_mismatch_fails_closed() {
        // The directory endorses LOCAL_TRANSPORT_SEED for the local kernel id, but the
        // key file carries a DIFFERENT seed: the endpoint would authenticate as an
        // EndpointId no peer endorses, so startup must fail closed BEFORE returning
        // serve inputs (peers enforcing the same directory would reject/bypass it).
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        let (bundle_json, issuer) = signed_bundle_json("did:chio:bob", 24, 6, None);
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        // A key whose public endpoint (seed 0x22) is NOT the endorsed local one
        // (LOCAL_TRANSPORT_SEED, 0x11).
        std::fs::write(&key_path, transport_key_json(0x22)).unwrap();

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
            Ok(_) => {
                panic!("a transport key that is not the endorsed local binding must fail closed")
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("does not match the")
                && error.to_string().contains("transport endpoint"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn local_kernel_without_directory_binding_fails_closed() {
        // The directory admits a peer but binds NO transport endpoint for the local
        // kernel id, so there is nothing this node can authenticate as. Fail closed.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        // Only a peer entry (no LOCAL_KERNEL_ID binding) in the directory.
        let (bundle_json, issuer) =
            build_signed_bundle_json(vec![directory_entry("did:chio:bob", 7, 24)], 6, None);
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(&key_path, transport_key_json(LOCAL_TRANSPORT_SEED)).unwrap();

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
            Ok(_) => panic!("a directory with no local binding must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("no non-removed transport endpoint"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn revocation_and_bilateral_lanes_are_rejected_fail_closed() {
        assert!(parse_iroh_lanes("revocation").is_err());
        assert!(parse_iroh_lanes("bilateral").is_err());
        assert!(parse_iroh_lanes("pheromone,bilateral").is_err());
        assert!(parse_iroh_lanes("").is_err());
        assert_eq!(
            parse_iroh_lanes("pheromone").unwrap(),
            vec![IrohLane::Pheromone]
        );
    }

    async fn bind_dialer(seed: u8) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .relay_mode(RelayMode::Disabled)
            // Single-family loopback bind (mirrors the production bind sites): clear the
            // default 0.0.0.0 + [::] transports before binding the one loopback address.
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("loopback bind address parses")
            .bind()
            .await
            .expect("dialer endpoint binds on loopback")
    }

    fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
        let socket = endpoint
            .bound_sockets()
            .into_iter()
            .next()
            .expect("endpoint bound a socket");
        EndpointAddr::new(endpoint.id()).with_ip_addr(socket)
    }

    #[tokio::test]
    async fn build_iroh_router_succeeds_and_403s_unadmitted_over_loopback() {
        let dialer_seed = 24u8;
        let unbound_seed = 99u8;
        // The directory admits only the endpoint derived from dialer_seed.
        let directory = verified_directory("did:chio:bob", dialer_seed);
        let inputs = IrohServeInputs {
            directory,
            // The acceptor's own transport key is unrelated to the admitted set.
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // Matches the relay's own local id (peer_directory below), so the
            // relay/transport identity binding guard passes.
            transport_local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            config: loopback_config(vec![IrohLane::Pheromone]),
        };
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RejectingReceiver);
        let peer_directory = peer_directory_admitting("did:chio:bob", RelayRole::Origin);

        let mount = build_iroh_router(
            inputs,
            receiver,
            store,
            peer_directory,
            MAX_PHEROMONE_BATCH_BYTES,
        )
        .await
        .expect("mount builder succeeds with a valid directory + gate");
        assert_eq!(mount.enabled_lanes, vec!["pheromone"]);
        // DEPLOYABILITY: the mount returns the ACTUAL bound socket(s). Binding on
        // loopback port 0, the OS must have assigned a concrete, non-zero port the
        // operator can log + hand to peers.
        assert!(
            !mount.bound_sockets.is_empty(),
            "mount must report at least one bound socket"
        );
        assert!(
            mount.bound_sockets.iter().all(|socket| socket.port() != 0),
            "an ephemeral bind must resolve to a concrete non-zero port: {:?}",
            mount.bound_sockets
        );
        // SECURITY: the config binds a single IPv4 loopback address. `clear_ip_transports`
        // before `bind_addr` must have removed BOTH default IP transports (0.0.0.0 AND
        // [::]), so the endpoint binds ONLY the operator-intended family - no stray IPv6
        // wildcard socket exposing the lane on an unintended interface.
        assert!(
            mount
                .bound_sockets
                .iter()
                .all(std::net::SocketAddr::is_ipv4),
            "a single-family (IPv4 loopback) bind must NOT open any IPv6 socket: {:?}",
            mount.bound_sockets
        );
        let acceptor_addr = direct_addr(mount.router.endpoint());

        // An unadmitted (unbound) endpoint is rejected at the admission gate (403 at
        // after_handshake) BEFORE any handler runs: the delivery must error.
        let unbound = bind_dialer(unbound_seed).await;
        let batch = empty_batch();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&unbound, acceptor_addr, &batch),
        )
        .await
        .expect("dial resolves before timeout");
        assert!(
            result.is_err(),
            "an unadmitted endpoint must be 403'd at the gate, got {result:?}"
        );

        mount.router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn iroh_ingress_rejects_out_of_scope_sender_before_the_receiver() {
        // The transport gate ADMITS the dialer endpoint (it resolves to did:chio:bob),
        // so the batch reaches the handler; but the peer directory lists did:chio:bob
        // as a Receiver (NOT an Origin/Hub), so it is not authorized to SUBMIT inbound
        // batches. enforce_peer_batch_directory_scope must reject the batch on the iroh
        // ingress path BEFORE receive_batch - exactly as the HTTP handle_batch_relay
        // would - and the TripwireReceiver proves the batch never reached the receiver.
        let dialer_seed = 24u8;
        let directory = verified_directory("did:chio:bob", dialer_seed);
        let inputs = IrohServeInputs {
            directory,
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // Matches the relay's own local id (peer_directory below), so the
            // relay/transport identity binding guard passes.
            transport_local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            config: loopback_config(vec![IrohLane::Pheromone]),
        };
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let called = Arc::new(AtomicBool::new(false));
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(TripwireReceiver {
            called: called.clone(),
        });
        // Admitted at the transport endpoint, but only a Receiver in the peer
        // directory: NOT authorized to submit inbound batches.
        let peer_directory = peer_directory_admitting("did:chio:bob", RelayRole::Receiver);

        let mount = build_iroh_router(
            inputs,
            receiver,
            store,
            peer_directory,
            MAX_PHEROMONE_BATCH_BYTES,
        )
        .await
        .expect("mount builder succeeds");
        let acceptor_addr = direct_addr(mount.router.endpoint());

        let dialer = bind_dialer(dialer_seed).await;
        let batch = empty_batch();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("dial resolves before timeout");
        assert!(
            result.is_err(),
            "an out-of-scope (non-Origin/Hub) sender's batch must be rejected on the iroh path, got {result:?}"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "the inbound scope gate must reject BEFORE the receiver is ever consulted"
        );

        mount.router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn build_iroh_router_rejects_relay_vs_transport_local_id_mismatch() {
        // The transport directory's own localKernelId is the identity the iroh endpoint
        // authenticates AS. It MUST equal the relay's configured local identity
        // (peer_directory.local_kernel_id()), which the relay's receiver verifies every
        // inbound batch against. When they differ, the endpoint authenticates as a
        // DIFFERENT kernel than the receiver expects, so valid deliveries would be
        // rejected/dead-lettered while startup silently "succeeds". The build must fail
        // closed BEFORE binding the endpoint.
        let directory = verified_directory("did:chio:bob", 24);
        let inputs = IrohServeInputs {
            directory,
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // A transport-directory local id that is NOT the relay's own (peer_directory
            // below is "did:chio:relay").
            transport_local_kernel_id: "did:chio:someone-else".to_string(),
            config: loopback_config(vec![IrohLane::Pheromone]),
        };
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RejectingReceiver);
        // The relay's local identity is "did:chio:relay".
        let peer_directory = peer_directory_admitting("did:chio:bob", RelayRole::Origin);

        let error = match build_iroh_router(
            inputs,
            receiver,
            store,
            peer_directory,
            MAX_PHEROMONE_BATCH_BYTES,
        )
        .await
        {
            Ok(_) => {
                panic!(
                    "a transport-directory local id that is not the relay's own must fail closed"
                )
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("does not match the relay")
                && error.to_string().contains("local kernel id"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn tick_outbound_endpoint_uses_ephemeral_port_not_the_serving_bind_addr() {
        // A durable relay-serve process holds the stable --iroh-bind-addr for inbound
        // reachability. The tick is OUTBOUND-ONLY: it must NOT reuse that addr:port, or
        // a second process would fail to bind the already-in-use UDP port. Occupy a
        // loopback port (standing in for a running serve), configure the tick with that
        // SAME addr:port, and prove the outbound endpoint binds a DISTINCT ephemeral port.
        let serve = bind_dialer(200).await;
        let serve_socket = serve
            .bound_sockets()
            .into_iter()
            .next()
            .expect("serve endpoint bound a socket");
        let serve_port = serve_socket.port();
        assert_ne!(serve_port, 0, "the occupied serve port must be concrete");

        let directory = verified_directory("did:chio:bob", 24);
        let mut config = loopback_config(vec![IrohLane::Pheromone]);
        // Reuse the EXACT stable serving addr:port the running serve already holds.
        config.bind_addr = serve_socket;
        let inputs = IrohServeInputs {
            directory,
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // Must equal the relay local id passed to build_iroh_outbound_endpoint below
            // (the tick path now enforces the same relay/transport identity binding).
            transport_local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            config,
        };

        let (endpoint, _directory) = build_iroh_outbound_endpoint(inputs, LOCAL_KERNEL_ID)
            .await
            .expect("the outbound tick endpoint must bind despite the serve addr being in use");
        let bound = endpoint.bound_sockets();
        assert!(
            !bound.is_empty(),
            "the outbound endpoint must bind a socket"
        );
        assert!(
            bound.iter().all(|socket| socket.port() != serve_port),
            "the outbound tick endpoint must NOT reuse the serving port {serve_port}, got {bound:?}"
        );
        assert!(
            bound.iter().all(|socket| socket.port() != 0),
            "the ephemeral bind must resolve to a concrete non-zero port: {bound:?}"
        );
        // SECURITY: the configured bind addr is IPv4 loopback, so `clear_ip_transports`
        // before `bind_addr` must have dropped the default [::] transport too - the
        // outbound tick socket lives on ONLY the intended family, never an IPv6 wildcard.
        assert!(
            bound.iter().all(std::net::SocketAddr::is_ipv4),
            "the outbound tick bind must be single-family (IPv4), got {bound:?}"
        );

        endpoint.close().await;
        drop(serve);
    }
