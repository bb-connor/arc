use super::*;
use chio_manifest::ToolManifest;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn record(policy: &Path) -> Result<Record, CliError> {
    let key = Keypair::generate().public_key().to_hex();
    let config = crate::input::project(json!({
        "schema": super::super::state::SCHEMA,
        "policy": "policy.yaml",
        "servers": [{
            "id": "server", "command": ["/bin/true"],
            "launch_policy": policy, "launch_policy_signer": key
        }],
        "limits": {"max_processes": 2, "max_depth": 1, "max_calls": 4}
    }))?;
    Ok(Record {
        config,
        source_policy_hash: "0".repeat(64),
        runtime_policy_hash: "0".repeat(64),
        manifests: vec![ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_owned(),
            server_id: "server".to_owned(),
            name: "server".to_owned(),
            description: None,
            version: "1".to_owned(),
            tools: Vec::new(),
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: key,
        }],
        abi: chio_process::PROCESS_ABI.to_owned(),
        written_by: None,
    })
}

#[test]
fn launch_policy_fifo_is_refused_without_blocking() -> TestResult {
    super::super::artifact_reader_tests::fifo_refusal(|path, _| routes(&record(path)?).map(|_| ()))
}

#[test]
fn launch_policy_regular_control_and_bound() -> TestResult {
    let directory = tempfile::tempdir()?;
    let artifact = directory.path().join("launch.json");
    std::fs::write(&artifact, b"{}")?;
    let record = record(&artifact)?;
    let original = routes(&record)?;
    assert_eq!(original.len(), 1);
    std::fs::write(&artifact, b"{\"changed\":true}")?;
    let changed = routes(&record)?;
    assert_ne!(
        original["server"].protocol_target,
        changed["server"].protocol_target
    );
    let bound = crate::input::MAX_DOCUMENT_BYTES;
    std::fs::File::create(&artifact)?.set_len(bound as u64 + 1)?;
    let Err(CliError::Io(failure)) = routes(&record) else {
        return Err("expected bounded launch policy refusal".into());
    };
    assert_eq!(failure.kind(), std::io::ErrorKind::Other);
    assert!(matches!(
        failure.get_ref().and_then(|source| source.downcast_ref::<chio_core::canonical::UntrustedJsonError>()),
        Some(chio_core::canonical::UntrustedJsonError::TooLarge { bytes, bound: actual })
            if *bytes == bound + 1 && *actual == bound
    ));
    Ok(())
}
