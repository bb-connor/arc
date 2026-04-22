//! OpenAPI spec auto-discovery and loading.

use crate::error::ProtectError;

/// Load an OpenAPI spec from a file path or URL.
pub fn load_spec_from_file(path: &str) -> Result<String, ProtectError> {
    std::fs::read_to_string(path)
        .map_err(|e| ProtectError::SpecLoad(format!("cannot read {path}: {e}")))
}

/// Try to discover the OpenAPI spec from the upstream server.
///
/// Probes well-known paths (`/openapi.json`, `/openapi.yaml`,
/// `/swagger.json`, `/api-docs`) in order, returning the first
/// non-empty successful response.
pub async fn discover_spec(upstream: &str) -> Result<String, ProtectError> {
    let client = reqwest::Client::new();
    let well_known_paths = [
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/api-docs",
    ];

    for path in &well_known_paths {
        let url = format!("{}{}", upstream.trim_end_matches('/'), path);
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(body) if !body.is_empty() => return Ok(body),
                _ => continue,
            },
            _ => continue,
        }
    }

    Err(ProtectError::SpecLoad(
        "could not auto-discover OpenAPI spec from upstream; use --spec to provide one".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_spec_from_existing_file() -> Result<(), Box<dyn std::error::Error>> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("chio-api-protect-test-{suffix}"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("spec.json");
        std::fs::write(&path, r#"{"openapi":"3.1.0"}"#)?;
        let spec = load_spec_from_file(&path.to_string_lossy())?;
        assert!(spec.contains("3.1.0"));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn load_spec_from_missing_file_fails() {
        let result = load_spec_from_file("/nonexistent/path/openapi.json");
        assert!(result.is_err());
    }
}
