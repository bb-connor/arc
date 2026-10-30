use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chio_core_types::enterprise_provider::EnterpriseProviderRegistry;
use serde::{Deserialize, Serialize};

use crate::passport_verifier::RegistryTransactionError;
use crate::CliError;

pub const CERTIFICATION_DISCOVERY_NETWORK_VERSION: &str = "chio.certify.discovery-network.v1";

/// Reads the enterprise provider registry through the bounded signed-input
/// reader and revalidates every record.
pub fn load_enterprise_provider_registry(
    path: &Path,
) -> Result<EnterpriseProviderRegistry, CliError> {
    let bytes = crate::signed_input::read_bounded(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read enterprise provider registry {}: {error}",
            path.display()
        ))
    })?;
    let registry: EnterpriseProviderRegistry = crate::signed_input::decode(&bytes)?;
    registry
        .revalidated()
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

/// Updates the latest registry under its stable writer lock, returning the
/// outcome only after durable bounded persistence. A missing file starts
/// empty.
pub fn update_enterprise_provider_registry<R, E>(
    path: &Path,
    change: impl FnOnce(&mut EnterpriseProviderRegistry) -> Result<R, E>,
) -> Result<R, RegistryTransactionError<E>> {
    crate::signed_input::update_bounded_registry(
        path,
        |path| {
            if path.exists() {
                load_enterprise_provider_registry(path)
            } else {
                Ok(EnterpriseProviderRegistry::default())
            }
        },
        crate::signed_input::MAX_SIGNED_FILE_BYTES,
        change,
    )
}

#[cfg(test)]
pub(crate) fn save_enterprise_provider_registry(
    registry: &EnterpriseProviderRegistry,
    path: &Path,
) -> Result<(), CliError> {
    let registry = registry
        .clone()
        .revalidated()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    crate::signed_input::write_bounded_json(path, &registry)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDiscoveryOperator {
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_token: Option<String>,
    #[serde(default)]
    pub allow_publish: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDiscoveryNetwork {
    pub version: String,
    #[serde(default)]
    pub operators: BTreeMap<String, CertificationDiscoveryOperator>,
}

impl Default for CertificationDiscoveryNetwork {
    fn default() -> Self {
        Self {
            version: CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string(),
            operators: BTreeMap::new(),
        }
    }
}

impl CertificationDiscoveryOperator {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        require_non_empty(&self.operator_id, "operator_id", &mut errors);
        require_non_empty(&self.registry_url, "registry_url", &mut errors);

        if !(is_blank(Some(&self.registry_url))
            || self.registry_url.starts_with("http://")
            || self.registry_url.starts_with("https://"))
        {
            errors.push("registry_url must start with http:// or https://".to_string());
        }

        errors
    }

    pub fn normalized_registry_url(&self) -> String {
        self.registry_url.trim().trim_end_matches('/').to_string()
    }

    pub fn is_valid(&self) -> bool {
        self.validation_errors.is_empty()
    }
}

impl CertificationDiscoveryNetwork {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let bytes = fs::read(path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read certification discovery network {}: {error}",
                path.display()
            ))
        })?;
        let network = chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed::<Self>())
            .map_err(CliError::from)?;
        network.with_revalidated_records()
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        let network = self.clone().with_revalidated_records()?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::cli_io_error(format!(
                        "failed to create certification discovery network directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let serialized = serde_json::to_vec_pretty(&network).map_err(|error| {
            CliError::cli_json_error(format!(
                "failed to serialize certification discovery network {}: {error}",
                path.display()
            ))
        })?;
        fs::write(path, serialized).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write certification discovery network {}: {error}",
                path.display()
            ))
        })
    }

    pub fn validated_operator(&self, operator_id: &str) -> Option<&CertificationDiscoveryOperator> {
        self.operators
            .get(operator_id)
            .filter(|operator| operator.is_valid())
    }

    pub fn validated_operators(&self) -> impl Iterator<Item = &CertificationDiscoveryOperator> {
        self.operators
            .values()
            .filter(|operator| operator.is_valid())
    }

    pub fn upsert(&mut self, mut operator: CertificationDiscoveryOperator) {
        operator.registry_url = operator.normalized_registry_url();
        operator.validation_errors = operator.validate();
        self.version = CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string();
        self.operators
            .insert(operator.operator_id.clone(), operator);
    }

    fn with_revalidated_records(mut self) -> Result<Self, CliError> {
        if self.version != CERTIFICATION_DISCOVERY_NETWORK_VERSION {
            return Err(CliError::cli_other_error(format!(
                "unsupported certification discovery network version `{}`",
                self.version
            )));
        }
        self.version = CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string();

        let mut normalized = BTreeMap::new();
        for (_, mut operator) in self.operators {
            operator.registry_url = operator.normalized_registry_url();
            operator.validation_errors = operator.validate();
            normalized.insert(operator.operator_id.clone(), operator);
        }
        self.operators = normalized;
        Ok(self)
    }
}

fn require_non_empty(value: &str, field: &str, errors: &mut Vec<String>) {
    if is_blank(Some(value)) {
        errors.push(format!("{field} is required"));
    }
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core_types::enterprise_provider::{
        EnterpriseProviderRecord, EnterpriseProviderRegistry, ENTERPRISE_PROVIDER_REGISTRY_VERSION,
    };

    use crate::CliError;

    use super::{
        load_enterprise_provider_registry, save_enterprise_provider_registry,
        CertificationDiscoveryNetwork, CertificationDiscoveryOperator,
        CERTIFICATION_DISCOVERY_NETWORK_VERSION,
    };

    /// An `oidc_jwks` record that fails validation: it names no issuer.
    fn invalid_oidc_record() -> EnterpriseProviderRecord {
        serde_json::from_value(serde_json::json!({
            "provider_id": "oidc", "kind": "oidc_jwks", "enabled": true,
            "provenance": { "configured_from": "manual", "trust_material_ref": "jwks:primary" },
            "jwks_url": "https://issuer.example/jwks",
            "subject_mapping": { "principal_source": "sub" }
        }))
        .test_unwrap()
    }

    fn temp_registry_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("chio-enterprise-provider-registry-{nonce}.json"))
    }

    fn temp_discovery_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("chio-certify-discovery-network-{nonce}.json"))
    }

    fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected_code);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    fn assert_signed_input_error(error: &CliError) {
        let CliError::SignedJson(source) = error else {
            panic!("expected a typed signed-input error, got {error:?}");
        };
        assert!(matches!(
            source,
            chio_core::canonical::UntrustedJsonError::SignedInput(_)
        ));
        assert!(std::error::Error::source(source).is_some());
        assert_eq!(
            source.code(),
            "urn:chio:error:attest:signed-json-invalid-input"
        );
    }

    use chio_test_support::prelude::*;

    fn must_err<T: std::fmt::Debug>(result: Result<T, CliError>, context: &str) -> CliError {
        match result {
            Ok(value) => panic!("{context}: expected error, got {value:?}"),
            Err(error) => error,
        }
    }

    fn write_test_file(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
        if let Err(error) = fs::write(path, bytes) {
            panic!("failed to write {}: {error}", path.display());
        }
    }

    fn discovery_operator(operator_id: &str) -> CertificationDiscoveryOperator {
        CertificationDiscoveryOperator {
            operator_id: operator_id.to_string(),
            operator_name: Some(format!("Operator {operator_id}")),
            registry_url: format!("https://{operator_id}.example.com/"),
            control_token: Some(format!("token-{operator_id}")),
            allow_publish: true,
            trust_labels: vec!["public".to_string()],
            validation_errors: Vec::new(),
        }
    }

    #[test]
    fn enterprise_provider_registry_round_trips_validation_state() {
        let path = temp_registry_path();
        let mut registry = EnterpriseProviderRegistry {
            version: ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string(),
            providers: BTreeMap::new(),
        };
        let invalid_record = invalid_oidc_record();
        registry.upsert(invalid_record.clone());

        save_enterprise_provider_registry(&registry, &path).test_unwrap();
        let loaded = load_enterprise_provider_registry(&path).test_unwrap();

        assert_eq!(loaded.version, ENTERPRISE_PROVIDER_REGISTRY_VERSION);
        assert_eq!(
            loaded.providers.get("oidc").test_unwrap().validation_errors,
            invalid_record.validate()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn enterprise_provider_registry_local_failures_preserve_typed_domains() {
        let missing_path = temp_registry_path();
        let missing_error = must_err(
            load_enterprise_provider_registry(&missing_path),
            "missing registry should fail closed",
        );
        assert_registry_error(&missing_error, "urn:chio:error:cli:io", "cli");

        let invalid_json_path = temp_registry_path();
        write_test_file(&invalid_json_path, b"{not-json");
        let json_error = must_err(
            load_enterprise_provider_registry(&invalid_json_path),
            "invalid registry JSON should fail closed",
        );
        assert_signed_input_error(&json_error);
        let _ = fs::remove_file(invalid_json_path);

        let unsupported_version_path = temp_registry_path();
        write_test_file(
            &unsupported_version_path,
            r#"{"version":"unsupported","providers":{}}"#,
        );
        let version_error = must_err(
            load_enterprise_provider_registry(&unsupported_version_path),
            "unsupported registry version should fail closed",
        );
        assert_registry_error(&version_error, "urn:chio:error:cli:other", "cli");
        let _ = fs::remove_file(unsupported_version_path);
    }

    #[test]
    fn certification_discovery_network_round_trips_validation_state() {
        let path = temp_discovery_path();
        let mut network = CertificationDiscoveryNetwork {
            version: CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string(),
            operators: BTreeMap::new(),
        };
        let mut invalid = discovery_operator("west");
        invalid.registry_url = "west.example.com".to_string();
        network.upsert(invalid.clone());

        network.save(&path).test_unwrap();
        let loaded = CertificationDiscoveryNetwork::load(&path).test_unwrap();

        assert_eq!(loaded.version, CERTIFICATION_DISCOVERY_NETWORK_VERSION);
        assert_eq!(
            loaded.operators.get("west").test_unwrap().validation_errors,
            invalid.validate()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn certification_discovery_network_local_failures_preserve_typed_domains() {
        let invalid_json_path = temp_discovery_path();
        write_test_file(&invalid_json_path, b"{not-json");
        let json_error = must_err(
            CertificationDiscoveryNetwork::load(&invalid_json_path),
            "invalid discovery JSON should fail closed",
        );
        assert_signed_input_error(&json_error);
        let _ = fs::remove_file(invalid_json_path);

        let unsupported_version_path = temp_discovery_path();
        write_test_file(
            &unsupported_version_path,
            r#"{"version":"unsupported","operators":{}}"#,
        );
        let version_error = must_err(
            CertificationDiscoveryNetwork::load(&unsupported_version_path),
            "unsupported discovery version should fail closed",
        );
        assert_registry_error(&version_error, "urn:chio:error:cli:other", "cli");
        let _ = fs::remove_file(unsupported_version_path);
    }

    #[test]
    fn certification_discovery_network_normalizes_registry_urls() {
        let mut network = CertificationDiscoveryNetwork::default();
        network.upsert(discovery_operator("east"));

        assert_eq!(
            network
                .validated_operator("east")
                .test_unwrap()
                .registry_url,
            "https://east.example.com"
        );
    }
}
