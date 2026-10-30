use super::*;
use crate::CliError;
use std::error::Error;

fn causes(error: &dyn Error) -> String {
    let mut chain = vec![error.to_string()];
    let mut source = error.source();
    while let Some(cause) = source {
        chain.push(cause.to_string());
        source = cause.source();
    }
    chain.join(" <- ")
}

fn assert_registry(error: CliError, code: &str, message: &str) {
    assert!(matches!(error, CliError::Chio(_)), "{error:?}");
    let text = error.to_string();
    assert!(
        text.starts_with(&format!("{code} [cli:error]: {message} (")),
        "{text}"
    );
}

fn assert_signed_input(error: CliError) {
    assert!(
        matches!(
            error,
            CliError::SignedJson(UntrustedJsonError::SignedInput(_))
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "urn:chio:error:attest:signed-json-invalid-input"
    );
}

fn assert_yaml_cause(error: CliError, cause: &str) {
    assert!(matches!(error, CliError::RegisteredSource(_)), "{error:?}");
    let chain = causes(&error);
    assert!(chain.starts_with("urn:chio:error:cli:yaml <- "), "{chain}");
    assert!(chain.contains(cause), "{chain}");
}

fn assert_io_message(error: CliError, message: &str) {
    assert_registry(error, "urn:chio:error:cli:io", message);
}

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
    assert_signed_input(config::load::<serde_json::Value>(&json).unwrap_err());
    let yaml = dir.path().join("policy.yaml");
    std::fs::write(&yaml, "rule:\n  action: allow\n  action: deny\n").unwrap();
    assert_yaml_cause(
        config::load::<serde_json::Value>(&yaml).unwrap_err(),
        "duplicate configuration key",
    );
    std::fs::write(&yaml, "rule: allow\n---\nrule: deny\n").unwrap();
    assert_registry(
        config::load::<serde_json::Value>(&yaml).unwrap_err(),
        "urn:chio:error:cli:other",
        "configuration must contain one document",
    );
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
    let escaped = format!("{}u0061llow", '\\');
    assert_eq!(
        literal::<Rule>(&escaped).unwrap_err().to_string(),
        format!("unknown variant `{escaped}`, expected `allow`")
    );
    assert_eq!(
        literal::<Rule>("allow\" ").unwrap_err().to_string(),
        "unknown variant `allow\" `, expected `allow`"
    );
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
    assert_yaml_cause(
        config::load::<serde_json::Value>(&path).unwrap_err(),
        "configuration expanded string limit",
    );
    std::fs::write(&path, format!("x: {}0{}", "[".repeat(80), "]".repeat(80))).unwrap();
    assert_yaml_cause(
        config::load::<serde_json::Value>(&path).unwrap_err(),
        "configuration nesting limit",
    );
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
    let error = budget.read(&path).unwrap_err();
    let CliError::Io(io) = &error else {
        panic!("{error:?}");
    };
    assert!(matches!(
        io.get_ref().unwrap().downcast_ref::<UntrustedJsonError>(),
        Some(UntrustedJsonError::TooLarge { bytes: 4, bound: 3 })
    ));
    assert_eq!(
        budget.read(&path).unwrap_err().to_string(),
        "urn:chio:error:cli:other [cli:error]: artifact collection byte budget exhausted (Preserve the original message and migrate the call site to a specific registry code when touched.)"
    );
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
    let directory = read(dir.path()).unwrap_err();
    assert_eq!(directory.to_string(), "input must be a regular file");
    assert_eq!(directory.kind(), std::io::ErrorKind::Other);
    let alias = read(dir.path().join("alias")).unwrap_err();
    assert_eq!(alias.raw_os_error(), Some(libc::ELOOP));
}

#[cfg(unix)]
#[test]
fn signing_custody_is_existing_private_bounded_and_not_aliased() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seed");
    let missing = crate::load_existing_authority_keypair(&path).err().unwrap();
    assert!(
        matches!(&missing, CliError::Io(io) if io.kind() == std::io::ErrorKind::NotFound),
        "{missing:?}"
    );
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
    assert_io_message(
        CliError::from(chio_secure_ipc::seed_custody::read_private_file(&path, 63).unwrap_err()),
        "authority seed exceeds its byte limit",
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_io_message(
        crate::load_existing_authority_keypair(&path).err().unwrap(),
        "authority seed must be singly linked with mode 0600 or stricter",
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.path().join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert_io_message(
        crate::load_existing_authority_keypair(&path).err().unwrap(),
        "authority seed must be singly linked with mode 0600 or stricter",
    );
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert_io_message(
        crate::load_existing_authority_keypair(&alias)
            .err()
            .unwrap(),
        "authority seed must be a regular file",
    );
}

#[test]
fn operator_policy_accepts_producer_numbers_in_json_and_yaml(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let policy = chio_kernel::UnderwritingDecisionPolicy {
        reduce_ceiling_factor: 0.5,
        ..Default::default()
    };
    let document = serde_json::to_string(&policy)?.replace("0.5", "0.50");
    let json = dir.path().join("policy.json");
    std::fs::write(&json, document)?;
    let actual = crate::load_underwriting_decision_policy(&json)?;
    assert_eq!(actual, policy);
    let yaml = dir.path().join("policy.yaml");
    std::fs::write(&yaml, yaml_serde::to_string(&policy)?)?;
    assert_eq!(crate::load_underwriting_decision_policy(&yaml)?, policy);
    Ok(())
}

#[test]
fn unsigned_runtime_attestation_evidence_accepts_operator_numbers(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let json = directory.path().join("evidence.json");
    let yaml = directory.path().join("evidence.yaml");
    for (number, yaml_number) in [("0.50", "0.5"), ("1e-05", "0.00001")] {
        let body = format!(
            r#"{{"schema":"test.evidence.v1","verifier":"test","tier":"basic","issued_at":1,"expires_at":2,"evidence_sha256":"{}","claims":{{"measurement":{number}}}}}"#,
            "a".repeat(64)
        );
        std::fs::write(&json, &body)?;
        std::fs::write(&yaml, format!("schema: test.evidence.v1\nverifier: test\ntier: basic\nissued_at: 1\nexpires_at: 2\nevidence_sha256: {}\nclaims:\n  measurement: {yaml_number}\n", "a".repeat(64)))?;
        // The separate signed-appraisal route still rejects the original
        // numeric spelling, before attempting any typed appraisal projection.
        assert!(matches!(
            crate::load_signed_runtime_attestation_appraisal_result(&json),
            Err(crate::CliError::SignedJson(
                UntrustedJsonError::SignedInput(_)
            ))
        ));
        let from_json = crate::load_runtime_attestation_evidence(&json)?;
        let from_yaml = crate::load_runtime_attestation_evidence(&yaml)?;
        assert_eq!(from_json, from_yaml);
        std::fs::write(
            &json,
            body.replace(
                &format!("\"measurement\":{number}"),
                "\"measurement\":1,\"measurement\":2",
            ),
        )?;
        assert_signed_input(crate::load_runtime_attestation_evidence(&json).unwrap_err());
    }
    Ok(())
}
