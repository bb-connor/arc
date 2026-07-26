    fn resign_event(
        mut event: UnverifiedSecurityEvent,
        body: SecurityEventBody,
        signer: &Keypair,
    ) -> UnverifiedSecurityEvent {
        let canonical_body = canonical_json_bytes(&body)
            .unwrap_or_else(|error| panic!("canonical rebound event body: {error}"));
        let signed = SignedSecurityEvent::sign_with_backend(
            body.clone(),
            &Ed25519Backend::new(signer.clone()),
        )
        .unwrap_or_else(|error| panic!("sign rebound event: {error}"));
        let source_evidence = canonical_json_bytes(&signed)
            .unwrap_or_else(|error| panic!("canonical rebound event envelope: {error}"));
        event.tenant_id = body.tenant_id;
        event.event_id = body.event_id;
        event.producer_id = body.producer_id;
        event.event_time_unix_ms = body.event_time_unix_ms;
        event.received_at_unix_ms = body.ingest_time_unix_ms;
        event.canonical_body = CanonicalBody::new(canonical_body.clone())
            .unwrap_or_else(|error| panic!("rebound event body: {error}"));
        event.body_hash = Digest32::new(*chio_core::sha256(&canonical_body).as_bytes());
        event.source_evidence = CanonicalBody::new(source_evidence)
            .unwrap_or_else(|error| panic!("rebound event envelope: {error}"));
        event
    }

    fn security_event_row_count(connection: &Connection, table: &str) -> u64 {
        let query = match table {
            "security_verified_events" => "SELECT COUNT(*) FROM security_verified_events",
            "security_correlation_ingress" => {
                "SELECT COUNT(*) FROM security_correlation_ingress"
            },
            "security_correlation_events" => "SELECT COUNT(*) FROM security_correlation_events",
            "security_advisory_events" => "SELECT COUNT(*) FROM security_advisory_events",
            _ => panic!("unsupported security event table: {table}"),
        };
        let count: i64 = connection
            .query_row(query, [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("count {table}: {error}"));
        checked_sqlite_count(count, table)
    }

    fn assert_no_security_event_rows(connection: &Connection, mutation: &str) {
        for table in [
            "security_verified_events",
            "security_correlation_ingress",
            "security_correlation_events",
            "security_advisory_events",
        ] {
            assert_eq!(
                security_event_row_count(connection, table),
                0,
                "{mutation} reached {table}"
            );
        }
    }

    fn current_ingress_event(trusted: &Keypair) -> UnverifiedSecurityEvent {
        signed_event_kind_at(
            "event-ingress-mutation",
            SecurityEventKind::TripwireObservation,
            99_900,
            100_000,
            trusted,
        )
    }

    fn assert_ingress_mutation_rejected<F>(
        mutation: &str,
        expected_error: PortErrorKind,
        build_mutation: F,
    ) where
        F: FnOnce(&Keypair, &Keypair, &Keypair) -> UnverifiedSecurityEvent,
    {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create verifier ingress directory: {error}"));
        let database_path = directory
            .path()
            .join(format!("verifier-ingress-{mutation}.sqlite3"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(&database_path)
                .unwrap_or_else(|error| panic!("open verifier ingress store: {error}")),
        );
        let trusted = Keypair::from_seed(&[101_u8; 32]);
        let receipt_signer = Keypair::from_seed(&[102_u8; 32]);
        let untrusted = Keypair::from_seed(&[103_u8; 32]);
        let ingress = VerifiedSecurityEventIngress::new(
            Arc::new(verifier_with_receipts(
                &trusted,
                &receipt_signer,
                Arc::new(FixedClock(100_000)),
            )),
            Arc::clone(&store),
        )
        .unwrap_or_else(|error| panic!("construct verifier ingress: {error}"));

        let event = build_mutation(&trusted, &receipt_signer, &untrusted);
        let connection = Connection::open(&database_path)
            .unwrap_or_else(|error| panic!("inspect verifier ingress store: {error}"));
        let error = rejected(
            ingress.verify_and_append(&event),
            &format!("{mutation} event entered verified ingress"),
        );
        assert_eq!(error.kind(), expected_error, "{mutation} error kind");
        assert_no_security_event_rows(&connection, mutation);

        assert_eq!(
            ingress
                .verify_and_append(&current_ingress_event(&trusted))
                .unwrap_or_else(|error| panic!("valid event ingress failed: {error}")),
            EventAppend::Inserted
        );
        assert_eq!(
            security_event_row_count(&connection, "security_verified_events"),
            1
        );
        assert_eq!(
            security_event_row_count(&connection, "security_correlation_ingress"),
            1
        );
        assert_eq!(
            security_event_row_count(&connection, "security_correlation_events"),
            0
        );
        assert_eq!(
            security_event_row_count(&connection, "security_advisory_events"),
            0
        );
    }

    #[test]
    fn verifier_ingress_rejects_forged_event_without_persistence() {
        assert_ingress_mutation_rejected(
            "forged",
            PortErrorKind::IntegrityFailure,
            |trusted, _receipt_signer, untrusted| {
                let event = current_ingress_event(trusted);
                let signed: SignedSecurityEvent =
                    serde_json::from_slice(event.source_evidence.as_bytes())
                        .unwrap_or_else(|error| panic!("decode forged event body: {error}"));
                resign_event(event, signed.body().clone(), untrusted)
            },
        );
    }

    #[test]
    fn verifier_ingress_rejects_unsigned_event_without_persistence() {
        assert_ingress_mutation_rejected(
            "unsigned",
            PortErrorKind::InvalidData,
            |trusted, _receipt_signer, _untrusted| {
                let mut event = current_ingress_event(trusted);
                event.source_evidence = event.canonical_body.clone();
                event
            },
        );
    }

    #[test]
    fn verifier_ingress_rejects_untrusted_producer_event_without_persistence() {
        assert_ingress_mutation_rejected(
            "untrusted-producer",
            PortErrorKind::IntegrityFailure,
            |trusted, _receipt_signer, untrusted| {
                let event = current_ingress_event(trusted);
                let signed: SignedSecurityEvent =
                    serde_json::from_slice(event.source_evidence.as_bytes())
                        .unwrap_or_else(|error| panic!("decode untrusted event body: {error}"));
                let mut body = signed.body().clone();
                body.producer_id = ProducerId::new("untrusted-detector")
                    .unwrap_or_else(|error| panic!("untrusted producer id: {error}"));
                body.producer_key_id = record("untrusted-detector-key");
                resign_event(event, body, untrusted)
            },
        );
    }

    #[test]
    fn verifier_ingress_rejects_cross_tenant_event_without_persistence() {
        assert_ingress_mutation_rejected(
            "cross-tenant",
            PortErrorKind::IntegrityFailure,
            |trusted, _receipt_signer, _untrusted| {
                let event = current_ingress_event(trusted);
                let signed: SignedSecurityEvent =
                    serde_json::from_slice(event.source_evidence.as_bytes())
                        .unwrap_or_else(|error| panic!("decode cross-tenant event body: {error}"));
                let mut body = signed.body().clone();
                body.tenant_id = TenantId::new("other-tenant")
                    .unwrap_or_else(|error| panic!("cross-tenant id: {error}"));
                resign_event(event, body, trusted)
            },
        );
    }

    #[test]
    fn verifier_ingress_rejects_stale_event_without_persistence() {
        assert_ingress_mutation_rejected(
            "stale",
            PortErrorKind::InvalidData,
            |trusted, _receipt_signer, _untrusted| {
                signed_event_kind_at(
                    "event-ingress-stale",
                    SecurityEventKind::TripwireObservation,
                    39_999,
                    40_000,
                    trusted,
                )
            },
        );
    }

    #[test]
    fn verifier_ingress_rejects_future_dated_event_without_persistence() {
        assert_ingress_mutation_rejected(
            "future",
            PortErrorKind::InvalidData,
            |trusted, _receipt_signer, _untrusted| {
                signed_event_kind_at(
                    "event-ingress-future",
                    SecurityEventKind::TripwireObservation,
                    101_001,
                    101_001,
                    trusted,
                )
            },
        );
    }

    #[test]
    fn verifier_ingress_rejects_invalid_receipt_event_without_persistence() {
        assert_ingress_mutation_rejected(
            "invalid-receipt",
            PortErrorKind::IntegrityFailure,
            |_trusted, receipt_signer, _untrusted| {
                receipt_event(
                    receipt_signer,
                    ToolOrigin::HostExecutedProviderReported,
                    99_900,
                    100_000,
                )
            },
        );
    }
