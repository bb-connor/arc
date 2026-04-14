//! OpenAPI spec auto-discovery and loading.

use crate::error::ProtectError;

/// Load an OpenAPI spec from a file path or URL.
pub fn load_spec_from_file(path: &str) -> Result<String, ProtectError> {
    std::fs::read_to_string(path).map_err(|e| {
        ProtectError::SpecLoad(format!("cannot read {path}: {e}"))
    })
}

/// Try to discover the OpenAPI spec from the upstream server.
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
            Ok(resp) if resp.status().is_success() => {
                match resp.text().await {
                    Ok(body) if !body.is_empty() => return Ok(body),
                    _ => continue,
                }
            }
            _ => continue,
        }
    }

    Err(ProtectError::SpecLoad(
        "could not auto-discover OpenAPI spec from upstream; use --spec to provide one".to_string(),
    ))
}
