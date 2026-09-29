use super::*;


    #[test]
    fn planner_api_accepts_only_authoritative_signed_finding_evidence() {
        fn assert_planner_contract<T: AttestedFindingBatchPlanner>() {}
        assert_planner_contract::<RecordingPlanner>();
    }
