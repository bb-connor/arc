use super::*;


    #[test]
    fn corrupt_tripwire_signature_cannot_enter_verified_persistence_or_correlation() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create security event directory: {error}"));
        let database_path = directory.path().join("tripwire-events.sqlite3");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&database_path)
                .unwrap_or_else(|error| panic!("open security event store: {error}")),
        );
        let keypair = Keypair::from_seed(&[74_u8; 32]);
        let ingress =
            VerifiedSecurityEventIngress::new(Arc::new(verifier(&keypair)), Arc::clone(&store))
                .unwrap_or_else(|error| panic!("construct verified ingress: {error}"));
        let mut corrupted = signed_event(&keypair);
        let signed: SignedSecurityEvent =
            serde_json::from_slice(corrupted.source_evidence.as_bytes())
                .unwrap_or_else(|error| panic!("decode signed event: {error}"));
        let wrong_key = Keypair::from_seed(&[75_u8; 32]);
        let wrong_signature = wrong_key.sign(
            &signed
                .signing_bytes()
                .unwrap_or_else(|error| panic!("security event signing bytes: {error}")),
        );
        let mut envelope = serde_json::to_value(&signed)
            .unwrap_or_else(|error| panic!("encode signed event: {error}"));
        envelope["signature"] = serde_json::to_value(wrong_signature)
            .unwrap_or_else(|error| panic!("encode corrupt signature: {error}"));
        let corrupt_envelope: SignedSecurityEvent = serde_json::from_value(envelope)
            .unwrap_or_else(|error| panic!("decode corrupt envelope: {error}"));
        corrupted.source_evidence = CanonicalBody::new(
            canonical_json_bytes(&corrupt_envelope)
                .unwrap_or_else(|error| panic!("canonical corrupt envelope: {error}")),
        )
        .unwrap_or_else(|error| panic!("bound corrupt envelope: {error}"));

        assert!(ingress.verify_and_append(&corrupted).is_err());

        let connection = Connection::open(&database_path)
            .unwrap_or_else(|error| panic!("inspect security event store: {error}"));
        let verified_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM security_verified_events", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("count verified events: {error}"));
        let verified_count = checked_sqlite_count(verified_count, "verified event count");
        let correlation_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM security_correlation_events",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("count correlated events: {error}"));
        let correlation_count = checked_sqlite_count(correlation_count, "correlation event count");
        assert_eq!(verified_count, 0);
        assert_eq!(correlation_count, 0);

        assert_eq!(
            ingress
                .verify_and_append(&signed_event(&keypair))
                .unwrap_or_else(|error| panic!("ingest valid signed event: {error}")),
            EventAppend::Inserted
        );
        let verified_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM security_verified_events", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("recount verified events: {error}"));
        let verified_count = checked_sqlite_count(verified_count, "verified event recount");
        assert_eq!(verified_count, 1);
    }
