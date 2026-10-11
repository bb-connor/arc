use chio_quarantine::{GroupingKey, RuleLimits, TemporalRule};

fn parse(input: &str) -> Result<TemporalRule, chio_quarantine::RuleError> {
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

#[test]
fn invalid_stage_graph_timing_fields_kinds_and_cardinality_reject_at_load_time() {
    let invalid = [
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"missing","within_ms":1}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low","after":"b","within_ms":1},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":1}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"b","within_ms":1}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a"}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":0}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":-1}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":18446744073709551616}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":86400001}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low","regex":".*"}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"a","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":1}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"not_a_kind","minimum_severity":"low"}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":0,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1025,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"unbounded_field","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1024,"max_partial_matches_per_group":1024,"allow_event_reuse":false,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"},{"name":"b","event_kind":"egress_attempt","minimum_severity":"low","after":"a","within_ms":1}]}"#,
        r#"{"rule_id":"r","policy_version":"p","group_by":"session_id","max_groups":1,"max_partial_matches_per_group":1,"allow_event_reuse":false,"unexpected":true,"stages":[{"name":"a","event_kind":"credential_access","minimum_severity":"low"}]}"#,
    ];

    for document in invalid {
        assert!(parse(document).is_err(), "invalid rule loaded: {document}");
    }
}
