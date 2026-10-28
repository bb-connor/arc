use chio_core_types::canonical::UntrustedJsonError;
use chio_quarantine::{GroupingKey, RuleError, RuleLimits, TemporalRule};

fn parse(input: &str) -> Result<TemporalRule, RuleError> {
    TemporalRule::parse_json(input.as_bytes(), &RuleLimits::default())
}

#[test]
fn valid_two_stage_and_multi_stage_rules_preserve_order_and_canonical_version() {
    let two_stage = parse(
        r#"{
          "rule_id":"credential-egress",
          "policy_version":"policy-v7",
          "group_by":"session_id",
          "max_groups":64,
          "max_partial_matches_per_group":16,
          "allow_event_reuse":false,
          "stages":[
            {"name":"credential","event_kind":"credential_access","minimum_severity":"medium"},
            {"name":"egress","event_kind":"egress_attempt","minimum_severity":"high","after":"credential","within_ms":30000}
          ]
        }"#,
    )
    .unwrap_or_else(|error| panic!("valid two-stage rule rejected: {error}"));

    assert_eq!(two_stage.group_by(), GroupingKey::SessionId);
    assert_eq!(two_stage.stages()[0].name().as_str(), "credential");
    assert_eq!(two_stage.stages()[1].name().as_str(), "egress");

    let canonical = two_stage
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("canonical rule serialization failed: {error}"));
    let reparsed = TemporalRule::parse_json(&canonical, &RuleLimits::default())
        .unwrap_or_else(|error| panic!("canonical rule rejected: {error}"));
    let reparsed_bytes = reparsed
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("canonical rule reserialization failed: {error}"));
    assert_eq!(canonical, reparsed_bytes);
    assert_eq!(two_stage.version_hash(), reparsed.version_hash());

    let multi_stage = parse(
        r#"{
          "rule_id":"three-stage",
          "policy_version":"policy-v7",
          "group_by":"lineage_seed",
          "max_groups":8,
          "max_partial_matches_per_group":8,
          "allow_event_reuse":false,
          "stages":[
            {"name":"first","event_kind":"tripwire_observation","minimum_severity":"low"},
            {"name":"second","event_kind":"tool_invocation","minimum_severity":"medium","after":"first","within_ms":1000},
            {"name":"third","event_kind":"flow_denial","minimum_severity":"high","after":"second","within_ms":2000}
          ]
        }"#,
    )
    .unwrap_or_else(|error| panic!("valid multi-stage rule rejected: {error}"));
    let names: Vec<&str> = multi_stage
        .stages()
        .iter()
        .map(|stage| stage.name().as_str())
        .collect();
    assert_eq!(names, vec!["first", "second", "third"]);
}

type RefusalCase = (&'static str, &'static str, fn(&RuleError) -> bool);

#[test]
fn invalid_stage_graph_timing_fields_kinds_and_cardinality_reject_at_load_time() {
    let invalid: [RefusalCase; 19] = [
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[]}"#,
            "EmptyStages",
            |error| matches!(error, RuleError::EmptyStages),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"missing","within_ms":1}]}"#,
            "InvalidPredecessor",
            |error| matches!(error, RuleError::InvalidPredecessor),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low","after":"b","within_ms":1},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":1}]}"#,
            "InvalidFirstStageTiming",
            |error| matches!(error, RuleError::InvalidFirstStageTiming),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"b","within_ms":1}]}"#,
            "InvalidPredecessor",
            |error| matches!(error, RuleError::InvalidPredecessor),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a"}]}"#,
            "MissingWindow",
            |error| matches!(error, RuleError::MissingWindow),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":0}]}"#,
            "InvalidWindow",
            |error| matches!(error, RuleError::InvalidWindow),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":-1}]}"#,
            "Parse(UntrustedJsonError::Decode(_))",
            |error| matches!(error, RuleError::Parse(UntrustedJsonError::Decode(_))),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":18446744073709551616}]}"#,
            "Parse(UntrustedJsonError::SignedInput(_))",
            |error| matches!(error, RuleError::Parse(UntrustedJsonError::SignedInput(_))),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":86400001}]}"#,
            "InvalidWindow",
            |error| matches!(error, RuleError::InvalidWindow),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low","regex":".*"}]}"#,
            "Parse(UntrustedJsonError::Decode(_))",
            |error| matches!(error, RuleError::Parse(UntrustedJsonError::Decode(_))),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"a","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":1}]}"#,
            "DuplicateStage",
            |error| matches!(error, RuleError::DuplicateStage),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"not_a_kind","minimum_severity":"low"}]}"#,
            "Parse(UntrustedJsonError::Decode(_))",
            |error| matches!(error, RuleError::Parse(UntrustedJsonError::Decode(_))),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":0,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
            "InvalidGroupBound",
            |error| matches!(error, RuleError::InvalidGroupBound),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1025,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
            "InvalidGroupBound",
            |error| matches!(error, RuleError::InvalidGroupBound),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"unbounded_field","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
            "Parse(UntrustedJsonError::Decode(_))",
            |error| matches!(error, RuleError::Parse(UntrustedJsonError::Decode(_))),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1024,"max_partial_matches_per_group":1024,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":1}]}"#,
            "StateEstimateExceeded",
            |error| matches!(error, RuleError::StateEstimateExceeded),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"unexpected":true,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
            "Parse(UntrustedJsonError::Decode(_))",
            |error| matches!(error, RuleError::Parse(UntrustedJsonError::Decode(_))),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":0,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
            "InvalidPartialBound",
            |error| matches!(error, RuleError::InvalidPartialBound),
        ),
        (
            r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","within_ms":1}]}"#,
            "MissingPredecessor",
            |error| matches!(error, RuleError::MissingPredecessor),
        ),
    ];

    for (document, expected, refused_by) in invalid {
        match parse(document) {
            Err(error) => assert!(
                refused_by(&error),
                "expected {expected}, got {error:?} for {document}"
            ),
            Ok(_) => panic!("invalid rule loaded: {document}"),
        }
    }
}

const TWO_STAGE: &str = r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":4294967295,"max_partial_matches_per_group":4294967295,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":1}]}"#;

fn limits(max_stages: usize, max_groups: u32, max_state_entries: u64) -> RuleLimits {
    RuleLimits::new(max_stages, 86_400_000, max_groups, max_state_entries)
        .unwrap_or_else(|error| panic!("valid limits rejected: {error}"))
}

#[test]
fn stage_count_above_the_configured_limit_is_refused() {
    let refused = TemporalRule::parse_json(TWO_STAGE.as_bytes(), &limits(1, u32::MAX, u64::MAX));
    assert!(
        matches!(refused, Err(RuleError::TooManyStages)),
        "{refused:?}"
    );
}

#[test]
fn state_estimate_overflow_is_refused_before_the_limit_comparison() {
    let refused = TemporalRule::parse_json(TWO_STAGE.as_bytes(), &limits(32, u32::MAX, u64::MAX));
    assert!(
        matches!(refused, Err(RuleError::StateEstimateOverflow)),
        "{refused:?}"
    );
}

#[test]
fn zero_rule_limits_are_refused() {
    for (max_stages, max_window_ms, max_groups, max_state_entries) in
        [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)]
    {
        let refused = RuleLimits::new(max_stages, max_window_ms, max_groups, max_state_entries);
        assert!(
            matches!(refused, Err(RuleError::InvalidLimits)),
            "{refused:?}"
        );
    }
}
