//! Configuration loading from file paths and raw strings.

use std::fs;
use std::path::Path;

use crate::interpolation::interpolate;
use crate::schema::ArcConfig;
use crate::validation::validate;
use crate::ConfigError;

/// Load and validate an `ArcConfig` from a file path.
///
/// Steps:
/// 1. Read the file contents.
/// 2. Interpolate environment variables.
/// 3. Deserialize from YAML.
/// 4. Run post-deserialization validation.
pub fn load_from_file(path: &Path) -> Result<ArcConfig, ConfigError> {
    let raw = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    load_from_str(&raw)
}

/// Load and validate an `ArcConfig` from a YAML string.
///
/// Useful for testing and for configs embedded in other formats.
pub fn load_from_str(yaml: &str) -> Result<ArcConfig, ConfigError> {
    let interpolated = interpolate(yaml)?;
    let config: ArcConfig =
        serde_yml::from_str(&interpolated).map_err(|e| ConfigError::Parse(e.to_string()))?;
    validate(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::Write as _;

    fn minimal_yaml() -> &'static str {
        r#"
kernel:
  signing_key: "generate"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#
    }

    #[test]
    fn load_minimal_yaml() {
        let config =
            load_from_str(minimal_yaml()).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.signing_key, "generate");
        assert_eq!(config.adapters.len(), 1);
        assert_eq!(config.adapters[0].id, "petstore");
        // Defaults applied
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
        assert_eq!(config.receipts.checkpoint_interval, 100);
        assert_eq!(config.receipts.retention_days, 90);
    }

    #[test]
    fn load_full_yaml() {
        let yaml = r#"
kernel:
  signing_key: "deadbeef"
  receipt_store: "sqlite:///tmp/test.db"
  log_level: "debug"

adapters:
  - id: "petstore"
    protocol: "openapi"
    upstream: "http://localhost:8000"
    spec: "./petstore.yaml"
    auth:
      type: "bearer"
      header: "Authorization"

edges:
  - id: "mcp-bridge"
    protocol: "mcp"
    expose_from: "petstore"

receipts:
  store: "sqlite:///tmp/receipts.db"
  checkpoint_interval: 50
  retention_days: 30

logging:
  level: "debug"
  format: "text"
"#;
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.signing_key, "deadbeef");
        assert_eq!(config.kernel.log_level, "debug");
        assert_eq!(config.adapters[0].id, "petstore");
        assert_eq!(config.edges.len(), 1);
        assert_eq!(config.edges[0].expose_from, "petstore");
        assert_eq!(config.receipts.checkpoint_interval, 50);
        assert_eq!(config.logging.format, "text");
    }

    #[test]
    fn interpolation_in_yaml() {
        env::set_var("ARC_TEST_KEY", "my-secret-key");
        let yaml = r#"
kernel:
  signing_key: "${ARC_TEST_KEY}"

adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.signing_key, "my-secret-key");
        env::remove_var("ARC_TEST_KEY");
    }

    #[test]
    fn interpolation_with_default() {
        env::remove_var("ARC_TEST_LOG_LEVEL");
        let yaml = r#"
kernel:
  signing_key: "generate"
  log_level: "${ARC_TEST_LOG_LEVEL:-warn}"

adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let config = load_from_str(yaml).unwrap_or_else(|e| panic!("load should work: {e}"));
        assert_eq!(config.kernel.log_level, "warn");
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = r#"
kernel:
  signing_key: "generate"
  mystery: true

adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let err = load_from_str(yaml).unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "should be parse error: {err}"
        );
    }

    #[test]
    fn missing_kernel_rejected() {
        let yaml = r#"
adapters:
  - id: "test"
    protocol: "openapi"
    upstream: "http://localhost:8000"
"#;
        let err = load_from_str(yaml).unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "should be parse error: {err}"
        );
    }

    #[test]
    fn load_from_file_works() {
        let dir = std::env::temp_dir().join("arc_config_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_arc.yaml");
        {
            let mut f =
                fs::File::create(&path).unwrap_or_else(|e| panic!("create file failed: {e}"));
            f.write_all(minimal_yaml().as_bytes())
                .unwrap_or_else(|e| panic!("write failed: {e}"));
        }
        let config =
            load_from_file(&path).unwrap_or_else(|e| panic!("load from file should work: {e}"));
        assert_eq!(config.kernel.signing_key, "generate");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_from_nonexistent_file() {
        let path = Path::new("/tmp/arc_config_nonexistent_12345.yaml");
        let err = load_from_file(path).unwrap_err();
        assert!(
            matches!(err, ConfigError::Io(_)),
            "should be IO error: {err}"
        );
    }

    #[test]
    fn validation_error_from_loader() {
        // Valid YAML but no adapters -- validation should reject.
        let yaml = r#"
kernel:
  signing_key: "generate"
"#;
        let err = load_from_str(yaml).unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "should be validation error: {err}"
        );
    }
}
