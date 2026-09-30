use super::*;
use std::error::Error;

#[test]
fn selected_formats_never_fall_back_after_ambiguous_json() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("policy.json");
    std::fs::write(
        &json,
        br#"{"rule":{"private-marker":1,"private-marker":2}}"#,
    )
    .unwrap();
    let error = config::load::<serde_json::Value>(&json).unwrap_err();
    assert!(error.source().is_some());
    assert!(!error.to_string().contains("private-marker"));
    std::fs::write(&json, b"rule: allow").unwrap();
    assert!(config::load::<serde_json::Value>(&json).is_err());
    let yaml = dir.path().join("policy.yaml");
    std::fs::write(&yaml, "rule:\n  action: allow\n  action: deny\n").unwrap();
    assert!(config::load::<serde_json::Value>(&yaml).is_err());
    std::fs::write(&yaml, "rule: allow\n---\nrule: deny\n").unwrap();
    assert!(config::load::<serde_json::Value>(&yaml).is_err());
    std::fs::write(&yaml, "count: 18446744073709551615\nrule: allow\n").unwrap();
    assert_eq!(
        config::load::<serde_json::Value>(&yaml).unwrap()["count"].as_u64(),
        Some(u64::MAX)
    );
}

#[test]
fn enums_are_literals_and_not_json_fragments() {
    #[derive(Debug, serde::Deserialize, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum Rule {
        Allow,
    }
    assert_eq!(literal::<Rule>("allow").unwrap(), Rule::Allow);
    assert!(literal::<Rule>(r"\u0061llow").is_err());
    assert!(literal::<Rule>("allow\" ").is_err());
}

#[test]
fn streams_reject_the_first_byte_over_the_bound() {
    let error = read_stream(std::io::Cursor::new(b"1234"), 3).unwrap_err();
    assert!(matches!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<UntrustedJsonError>(),
        Some(UntrustedJsonError::TooLarge { bytes: 4, bound: 3 })
    ));
    assert_eq!(
        read_stream(std::io::Cursor::new(b"123"), 3).unwrap(),
        b"123"
    );
}

#[test]
fn yaml_expansion_and_depth_have_shared_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let mut document = format!("base: &base {}\nexpanded:\n", "x".repeat(32_768));
    for _ in 0..600 {
        document.push_str("  - *base\n");
    }
    std::fs::write(&path, document).unwrap();
    assert!(config::load::<serde_json::Value>(&path).is_err());
    std::fs::write(&path, format!("x: {}0{}", "[".repeat(80), "]".repeat(80))).unwrap();
    assert!(config::load::<serde_json::Value>(&path).is_err());
}

#[test]
fn snapshots_reject_collisions_amplification_and_preserve_captured_bytes() {
    for paths in [vec!["a", "a"], vec!["a", "a/b"], vec!["a/b", "a"]] {
        let error =
            snapshot::Snapshot::from_entries(paths.into_iter().map(|p| (p, b"x".as_slice())))
                .err()
                .unwrap();
        assert!(error.to_string().contains("collision"));
    }
    let paths: Vec<_> = (0..100)
        .map(|i| {
            format!(
                "{i}/{}/file",
                (0..50).map(|d| d.to_string()).collect::<Vec<_>>().join("/")
            )
        })
        .collect();
    let error =
        snapshot::Snapshot::from_entries(paths.iter().map(|p| (p.as_str(), b"x".as_slice())))
            .err()
            .unwrap();
    assert!(error.to_string().contains("entry limit"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    std::fs::write(&path, b"original verified input").unwrap();
    let captured = snapshot::Snapshot::capture(dir.path()).unwrap();
    std::fs::write(path, b"substituted later input").unwrap();
    assert_eq!(
        std::fs::read(captured.path().join("manifest.json")).unwrap(),
        b"original verified input"
    );
}

#[test]
fn collection_limits_charge_retained_bytes_entries_and_depth() {
    let mut budget = collection::Budget::default();
    budget.charge(collection::MAX_BYTES).unwrap();
    assert!(budget
        .charge(1)
        .unwrap_err()
        .to_string()
        .contains("byte limit"));
    let mut budget = collection::Budget::default();
    for _ in 0..collection::MAX_ENTRIES {
        budget.enter(0).unwrap();
    }
    assert!(budget
        .enter(0)
        .unwrap_err()
        .to_string()
        .contains("entry limit"));
    assert!(collection::Budget::default()
        .enter(collection::MAX_DEPTH + 1)
        .unwrap_err()
        .to_string()
        .contains("depth"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact");
    std::fs::write(&path, b"1234").unwrap();
    let mut budget = collection::Budget::default();
    budget.charge(collection::MAX_BYTES - 3).unwrap();
    assert!(budget.read(&path).is_err());
}

#[cfg(unix)]
#[test]
fn collection_rejects_symlinks_and_nonregular_files() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("artifact");
    std::fs::write(&file, b"{}").unwrap();
    std::os::unix::fs::symlink(&file, dir.path().join("alias")).unwrap();
    assert!(collection::paths(dir.path())
        .unwrap_err()
        .to_string()
        .contains("regular files"));
    assert!(read(dir.path()).is_err());
    assert!(read(dir.path().join("alias")).is_err());
}

#[cfg(unix)]
#[test]
fn signing_custody_is_existing_private_bounded_and_not_aliased() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seed");
    assert!(crate::load_existing_authority_keypair(&path).is_err());
    assert!(!path.exists());
    let signer = chio_core::Keypair::from_seed(&[51; 32]);
    std::fs::write(&path, signer.seed_hex()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        crate::load_existing_authority_keypair(&path)
            .unwrap()
            .public_key(),
        signer.public_key()
    );
    assert!(chio_control_plane::read_private_signing_custody(&path, 63).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(crate::load_existing_authority_keypair(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.path().join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(crate::load_existing_authority_keypair(&path).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(crate::load_existing_authority_keypair(&alias).is_err());
}
