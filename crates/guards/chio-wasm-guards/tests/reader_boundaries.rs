use chio_wasm_guards::{
    blocklist::GuardDigestBlocklist,
    manifest::{load_manifest, load_signature_sidecar},
    BlocklistError, WasmGuardError,
};

#[test]
fn blocklist_requires_explicit_valid_canonical_digests() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("blocklist.json");
    let blocklist = GuardDigestBlocklist::from_path(&path);
    let digest = format!("sha256:{}", "a".repeat(64));
    for bad in [
        "{}",
        r#"{"digests":[],"digests":[]}"#,
        r#"{"digests":[],"ignored":true}"#,
    ] {
        std::fs::write(&path, bad)?;
        assert!(matches!(
            blocklist.is_blocklisted(&digest),
            Err(BlocklistError::Input(_))
        ));
    }
    std::fs::write(&path, r#"{"digests":["invalid"]}"#)?;
    assert!(matches!(
        blocklist.is_blocklisted(&digest),
        Err(BlocklistError::InvalidDigest { .. })
    ));
    std::fs::write(&path, format!(r#"{{"digests":["{digest}"]}}"#))?;
    assert!(blocklist.is_blocklisted(&digest)?);
    Ok(())
}

#[test]
fn original_yaml_duplicate_config_and_json_sidecar_extensions_reject(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let wasm = dir.path().join("guard.wasm");
    let wasm = wasm.to_str().ok_or("UTF-8 path")?;
    let manifest = "name: test\nversion: \"1\"\nabi_version: \"1\"\nwit_world: chio:guard/guard@0.2.0\nwasm_path: guard.wasm\nwasm_sha256: hash\nconfig:\n  token: first\n";
    std::fs::write(dir.path().join("guard-manifest.yaml"), manifest)?;
    assert_eq!(
        load_manifest(wasm)?.config.get("token").map(String::as_str),
        Some("first")
    );
    std::fs::write(
        dir.path().join("guard-manifest.yaml"),
        format!("{manifest}  token: second\n"),
    )?;
    let error = match load_manifest(wasm) {
        Err(error) => error,
        Ok(_) => return Err("duplicate YAML accepted".into()),
    };
    assert!(matches!(error, WasmGuardError::ManifestYaml(_)));
    assert!(!format!("{error:?} {error}").contains("second"));
    std::fs::write(format!("{wasm}.sig"), r#"{"ignored":{"x":1,"x":2}}"#)?;
    assert!(matches!(
        load_signature_sidecar(wasm),
        Err(WasmGuardError::Input(_))
    ));
    Ok(())
}

#[test]
fn sparse_oversized_sidecar_rejects_before_reading() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let wasm = dir.path().join("guard.wasm");
    let wasm = wasm.to_str().ok_or("UTF-8 path")?;
    std::fs::File::create(format!("{wasm}.sig"))?.set_len(64 * 1024 * 1024)?;
    assert!(
        matches!(load_signature_sidecar(wasm), Err(WasmGuardError::InputFile { source: error, .. }) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn sidecar_symlink_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let wasm = dir.path().join("guard.wasm");
    let wasm = wasm.to_str().ok_or("UTF-8 path")?;
    let target = dir.path().join("target");
    std::fs::write(&target, "{}")?;
    std::os::unix::fs::symlink(&target, format!("{wasm}.sig"))?;
    assert!(
        matches!(load_signature_sidecar(wasm), Err(WasmGuardError::InputFile { source: error, .. }) if error.raw_os_error() == Some(libc::ELOOP))
    );
    Ok(())
}
