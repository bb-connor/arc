use super::*;


    #[test]
    fn durable_production_planner_reloads_the_exact_batch_after_restart() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("durable-planner.sqlite");
        let findings = reverse_lexicographic_findings();
        let expected = build_attested_finding_batch_publication(&findings)
            .unwrap_or_else(|error| panic!("expected publication: {error}"));
        let policy = Arc::new(RecordingResponsePolicy);
        let coordinator = Arc::new(RecordingResponseCoordinator::default());
        {
            let store = Arc::new(
                SqliteSecurityStateStore::open(&path)
                    .unwrap_or_else(|error| panic!("open durable planner store: {error}")),
            );
            let planner = DurableAttestedFindingBatchPlanner::new(
                Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
                store as Arc<dyn AttestedFindingResponseOutboxStore>,
                Arc::new(TestFindingAuthority::new(&findings)),
                Arc::clone(&policy) as Arc<dyn AttestedFindingResponsePolicyPlanner>,
                Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
                Arc::new(FixedClock(10_002)),
            )
            .unwrap_or_else(|error| panic!("durable planner: {error}"));
            planner
                .publish_attested_batch(&findings)
                .unwrap_or_else(|error| panic!("publish batch: {error}"));
            planner
                .publish_attested_batch(&findings)
                .unwrap_or_else(|error| panic!("retry batch: {error}"));
        }
        let reopened_store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("reopen durable planner store: {error}")),
        );
        let reopened = DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&reopened_store) as Arc<dyn AttestedFindingBatchStore>,
            reopened_store as Arc<dyn AttestedFindingResponseOutboxStore>,
            Arc::new(TestFindingAuthority::new(&findings)),
            Arc::clone(&policy) as Arc<dyn AttestedFindingResponsePolicyPlanner>,
            Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
            Arc::new(FixedClock(10_002)),
        )
        .unwrap_or_else(|error| panic!("reopened durable planner: {error}"));
        assert_eq!(
            reopened
                .load_published_attested_batch(&AttestedFindingBatchKey {
                    tenant_id: expected.body.tenant_id.clone(),
                    batch_id: expected.body.batch_id.clone(),
                })
                .unwrap_or_else(|error| panic!("reload publication: {error}")),
            expected
        );
        let executions = coordinator
            .executions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(executions.len(), 2);
    }
