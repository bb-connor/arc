use super::*;

#[test]
fn load_hushspec_policy_identity_tracks_threat_intel_pattern_db_bytes() {
    let policy_dir = std::env::temp_dir().join(format!(
        "chio-hushspec-asset-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_millis()
    ));
    std::fs::create_dir_all(&policy_dir).test_unwrap();
    let pattern_db = policy_dir.join("pattern-db.json");
    let policy_path = policy_dir.join("policy.yaml");

    std::fs::write(&pattern_db, sample_threat_intel_pattern_db("first")).test_unwrap();
    std::fs::write(
        &policy_path,
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - read_file
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "pattern-db.json"
"#,
    )
    .test_unwrap();

    let first = load_policy(&policy_path).test_unwrap();
    std::fs::write(&pattern_db, sample_threat_intel_pattern_db("second")).test_unwrap();
    let second = load_policy(&policy_path).test_unwrap();

    assert_ne!(first.identity.source_hash, second.identity.source_hash);
    assert_ne!(first.identity.runtime_hash, second.identity.runtime_hash);

    let _ = std::fs::remove_dir_all(policy_dir);
}

#[test]
fn load_hushspec_policy_refuses_a_non_regular_threat_intel_pattern_db() {
    let policy_dir =
        std::env::temp_dir().join(format!("chio-hushspec-asset-dir-{}", std::process::id()));
    std::fs::create_dir_all(policy_dir.join("pattern-db.json")).test_unwrap();
    let policy_path = policy_dir.join("policy.yaml");
    std::fs::write(
        &policy_path,
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - read_file
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "pattern-db.json"
"#,
    )
    .test_unwrap();

    let error = load_policy(&policy_path).test_unwrap_err().to_string();
    let _ = std::fs::remove_dir_all(&policy_dir);

    assert!(
        error.contains("guard input must be a regular file"),
        "unexpected refusal: {error}"
    );
}

#[test]
fn load_hushspec_policy_refuses_an_oversized_threat_intel_pattern_db() {
    let policy_dir =
        std::env::temp_dir().join(format!("chio-hushspec-asset-big-{}", std::process::id()));
    std::fs::create_dir_all(&policy_dir).test_unwrap();
    let pattern_db = std::fs::File::create(policy_dir.join("pattern-db.json")).test_unwrap();
    pattern_db
        .set_len(chio_guards::embedding_anomaly::MAX_PATTERN_BYTES as u64 + 1)
        .test_unwrap();
    let policy_path = policy_dir.join("policy.yaml");
    std::fs::write(
        &policy_path,
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - read_file
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "pattern-db.json"
"#,
    )
    .test_unwrap();

    let error = load_policy(&policy_path).test_unwrap_err().to_string();
    let _ = std::fs::remove_dir_all(&policy_dir);

    assert!(
        error.contains("guard input exceeds byte limit"),
        "unexpected refusal: {error}"
    );
}
