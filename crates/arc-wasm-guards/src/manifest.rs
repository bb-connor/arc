//! Guard manifest parsing, SHA-256 verification, and ABI version gating.
//!
//! Each WASM guard is shipped alongside a `guard-manifest.yaml` that declares
//! its name, version, ABI version, WASM binary path, expected SHA-256 hash,
//! and optional configuration. The functions in this module load and validate
//! the manifest before the guard is instantiated.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::WasmGuardError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ABI versions supported by this version of the WASM guard runtime.
pub const SUPPORTED_ABI_VERSIONS: &[&str] = &["1"];

/// Well-known filename for the guard manifest.
pub const MANIFEST_FILENAME: &str = "guard-manifest.yaml";

// ---------------------------------------------------------------------------
// GuardManifest
// ---------------------------------------------------------------------------

/// Parsed representation of a `guard-manifest.yaml` file.
///
/// The manifest lives in the same directory as the `.wasm` binary and carries
/// integrity and versioning metadata that the loader verifies before
/// instantiation.
#[derive(Debug, Clone, Deserialize)]
pub struct GuardManifest {
    /// Human-readable guard name (e.g. "pii-scanner").
    pub name: String,
    /// Semantic version of the guard (e.g. "1.0.0").
    pub version: String,
    /// ABI version the guard was compiled against (must be in
    /// [`SUPPORTED_ABI_VERSIONS`]).
    pub abi_version: String,
    /// Relative or absolute path to the `.wasm` binary.
    pub wasm_path: String,
    /// Hex-encoded SHA-256 digest of the `.wasm` binary.
    pub wasm_sha256: String,
    /// Optional guard-specific configuration key-value pairs.
    #[serde(default)]
    pub config: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Load and parse a `guard-manifest.yaml` from the parent directory of the
/// given WASM file path.
///
/// For example, if `wasm_path` is `/opt/guards/pii/pii.wasm`, this function
/// reads `/opt/guards/pii/guard-manifest.yaml`.
pub fn load_manifest(wasm_path: &str) -> Result<GuardManifest, WasmGuardError> {
    let wasm = Path::new(wasm_path);
    let parent = wasm
        .parent()
        .ok_or_else(|| WasmGuardError::ManifestLoad {
            path: wasm_path.to_string(),
            reason: "wasm path has no parent directory".to_string(),
        })?;

    let manifest_path = parent.join(MANIFEST_FILENAME);
    let contents =
        std::fs::read_to_string(&manifest_path).map_err(|e| WasmGuardError::ManifestLoad {
            path: manifest_path.display().to_string(),
            reason: e.to_string(),
        })?;

    serde_yml::from_str::<GuardManifest>(&contents)
        .map_err(|e| WasmGuardError::ManifestParse(e.to_string()))
}

/// Verify that the SHA-256 digest of `wasm_bytes` matches the
/// hex-encoded `expected_hex` string from the manifest.
pub fn verify_wasm_hash(wasm_bytes: &[u8], expected_hex: &str) -> Result<(), WasmGuardError> {
    let mut hasher = Sha256::new();
    hasher.update(wasm_bytes);
    let actual_hex = hex::encode(hasher.finalize());

    if actual_hex != expected_hex {
        return Err(WasmGuardError::HashMismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }
    Ok(())
}

/// Verify that the given ABI version string is in [`SUPPORTED_ABI_VERSIONS`].
pub fn verify_abi_version(version: &str) -> Result<(), WasmGuardError> {
    if SUPPORTED_ABI_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err(WasmGuardError::UnsupportedAbiVersion {
            version: version.to_string(),
            supported: SUPPORTED_ABI_VERSIONS.join(", "),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -- Deserialization tests ------------------------------------------------

    #[test]
    fn manifest_deserializes_from_valid_yaml() {
        let yaml = r#"
name: pii-scanner
version: "1.0.0"
abi_version: "1"
wasm_path: pii.wasm
wasm_sha256: abc123
config:
  threshold: "0.8"
  mode: strict
"#;
        let manifest: GuardManifest = serde_yml::from_str(yaml).unwrap();
        assert_eq!(manifest.name, "pii-scanner");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.abi_version, "1");
        assert_eq!(manifest.wasm_path, "pii.wasm");
        assert_eq!(manifest.wasm_sha256, "abc123");
        assert_eq!(manifest.config.len(), 2);
        assert_eq!(manifest.config.get("threshold").unwrap(), "0.8");
        assert_eq!(manifest.config.get("mode").unwrap(), "strict");
    }

    #[test]
    fn manifest_deserializes_with_empty_config() {
        let yaml = r#"
name: simple-guard
version: "0.1.0"
abi_version: "1"
wasm_path: simple.wasm
wasm_sha256: deadbeef
"#;
        let manifest: GuardManifest = serde_yml::from_str(yaml).unwrap();
        assert_eq!(manifest.name, "simple-guard");
        assert!(manifest.config.is_empty(), "config should default to empty HashMap");
    }

    #[test]
    fn manifest_rejects_missing_required_fields() {
        // Missing name
        let yaml = r#"
version: "1.0.0"
abi_version: "1"
wasm_sha256: abc123
wasm_path: foo.wasm
"#;
        let result = serde_yml::from_str::<GuardManifest>(yaml);
        assert!(result.is_err(), "should reject YAML missing 'name'");

        // Missing abi_version
        let yaml = r#"
name: test
version: "1.0.0"
wasm_sha256: abc123
wasm_path: foo.wasm
"#;
        let result = serde_yml::from_str::<GuardManifest>(yaml);
        assert!(result.is_err(), "should reject YAML missing 'abi_version'");

        // Missing wasm_sha256
        let yaml = r#"
name: test
version: "1.0.0"
abi_version: "1"
wasm_path: foo.wasm
"#;
        let result = serde_yml::from_str::<GuardManifest>(yaml);
        assert!(result.is_err(), "should reject YAML missing 'wasm_sha256'");
    }

    // -- verify_wasm_hash tests -----------------------------------------------

    #[test]
    fn verify_wasm_hash_accepts_matching_digest() {
        let data = b"hello wasm module";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected = hex::encode(hasher.finalize());

        assert!(verify_wasm_hash(data, &expected).is_ok());
    }

    #[test]
    fn verify_wasm_hash_rejects_mismatching_digest() {
        let data = b"hello wasm module";
        let result = verify_wasm_hash(data, "0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::HashMismatch { expected, actual } => {
                assert_eq!(expected, "0000000000000000000000000000000000000000000000000000000000000000");
                assert!(!actual.is_empty());
                assert_ne!(actual, expected);
            }
            other => panic!("expected HashMismatch, got: {other:?}"),
        }
    }

    // -- verify_abi_version tests ---------------------------------------------

    #[test]
    fn verify_abi_version_accepts_supported_version() {
        assert!(verify_abi_version("1").is_ok());
    }

    #[test]
    fn verify_abi_version_rejects_unsupported_version() {
        let result = verify_abi_version("99");
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::UnsupportedAbiVersion { version, supported } => {
                assert_eq!(version, "99");
                assert_eq!(supported, "1");
            }
            other => panic!("expected UnsupportedAbiVersion, got: {other:?}"),
        }
    }

    // -- load_manifest tests --------------------------------------------------

    #[test]
    fn load_manifest_reads_adjacent_yaml() {
        let dir = std::env::temp_dir().join("arc_manifest_test_load");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let manifest_content = r#"
name: test-guard
version: "0.1.0"
abi_version: "1"
wasm_path: test.wasm
wasm_sha256: abcdef0123456789
config:
  key: value
"#;
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let mut f = std::fs::File::create(&manifest_path).unwrap();
        f.write_all(manifest_content.as_bytes()).unwrap();

        let wasm_path = dir.join("test.wasm");
        let manifest = load_manifest(wasm_path.to_str().unwrap()).unwrap();
        assert_eq!(manifest.name, "test-guard");
        assert_eq!(manifest.abi_version, "1");
        assert_eq!(manifest.config.get("key").unwrap(), "value");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_manifest_returns_error_when_file_missing() {
        let result = load_manifest("/nonexistent/path/guard.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::ManifestLoad { path, reason } => {
                assert!(path.contains("guard-manifest.yaml"), "path should contain manifest filename, got: {path}");
                assert!(!reason.is_empty());
            }
            other => panic!("expected ManifestLoad, got: {other:?}"),
        }
    }

    // -- Error display tests --------------------------------------------------

    #[test]
    fn error_display_manifest_parse() {
        let err = WasmGuardError::ManifestParse("bad yaml".to_string());
        assert_eq!(err.to_string(), "failed to parse guard manifest: bad yaml");
    }

    #[test]
    fn error_display_hash_mismatch() {
        let err = WasmGuardError::HashMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert_eq!(err.to_string(), "wasm hash mismatch: expected aaa, got bbb");
    }

    #[test]
    fn error_display_unsupported_abi() {
        let err = WasmGuardError::UnsupportedAbiVersion {
            version: "99".to_string(),
            supported: "1".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "unsupported abi_version \"99\" (supported: 1)"
        );
    }

    #[test]
    fn error_display_manifest_load() {
        let err = WasmGuardError::ManifestLoad {
            path: "/foo/bar".to_string(),
            reason: "not found".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to load guard manifest for /foo/bar: not found"
        );
    }
}
