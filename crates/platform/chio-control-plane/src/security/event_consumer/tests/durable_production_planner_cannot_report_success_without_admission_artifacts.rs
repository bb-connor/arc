use super::*;


    #[test]
    fn durable_production_planner_cannot_report_success_without_admission_artifacts() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("missing-admission.sqlite"))
                .unwrap_or_else(|error| panic!("admission store: {error}")),
        );
        let coordinator = Arc::new(ArtifactEnforcingCoordinator::default());
        let planner = DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&store)
                as Arc<dyn chio_security_types::ports::AttestedFindingBatchStore>,
            store as Arc<dyn AttestedFindingResponseOutboxStore>,
            Arc::new(TestFindingAuthority::new(std::slice::from_ref(
                &authoritative_finding(),
            ))),
            Arc::new(MissingArtifactResponsePolicy),
            Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
            Arc::new(FixedClock(10_002)),
        )
        .unwrap_or_else(|error| panic!("durable planner: {error}"));
        let finding = authoritative_finding();
        let expected = build_attested_finding_batch_publication(std::slice::from_ref(&finding))
            .unwrap_or_else(|error| panic!("expected publication: {error}"));
        let error = rejected(
            planner.publish_attested_batch(std::slice::from_ref(&finding)),
            "missing capability and approval artifacts must fail closed",
        );
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::IntegrityFailure
        );
        let replay_error = rejected(
            planner.publish_attested_batch(std::slice::from_ref(&finding)),
            "a durable terminal response failure must replay as failure",
        );
        assert_eq!(replay_error.code(), error.code());
        assert!(!coordinator.effects_applied.load(Ordering::Acquire));
        assert_eq!(
            planner
                .load_published_attested_batch(&AttestedFindingBatchKey {
                    tenant_id: expected.body.tenant_id.clone(),
                    batch_id: expected.body.batch_id.clone(),
                })
                .unwrap_or_else(|error| panic!("dry-run batch: {error}")),
            expected
        );
    }
