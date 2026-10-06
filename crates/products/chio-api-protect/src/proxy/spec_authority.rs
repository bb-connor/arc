//! Operator provenance for policy-relaxing OpenAPI extensions.

use super::{ProtectConfig, ProtectError};
use std::io::Read;

pub(super) struct LoadedSpec {
    content: String,
    pinned: bool,
}

impl LoadedSpec {
    pub(super) fn content(&self) -> &str {
        &self.content
    }

    pub(super) fn policy_hash(&self, allow_anonymous_reads: bool) -> Result<String, ProtectError> {
        self.policy_hash_with_guard_profile(
            allow_anonymous_reads,
            &chio_guards::default_runtime_guard_profile_identity()?,
        )
    }

    fn policy_hash_with_guard_profile(
        &self,
        allow_anonymous_reads: bool,
        guard_profile_identity: &str,
    ) -> Result<String, ProtectError> {
        let bytes = chio_core_types::canonical::canonical_json_bytes(&(
            "chio-api-protect-local-policy-v2",
            chio_core_types::sha256_hex(self.content.as_bytes()),
            self.pinned,
            allow_anonymous_reads,
            guard_profile_identity,
        ))?;
        Ok(chio_core_types::sha256_hex(&bytes))
    }

    pub(super) fn is_pinned(&self) -> bool {
        self.pinned
    }
}

pub(super) fn validate_source(config: &ProtectConfig) -> Result<(), ProtectError> {
    if config.spec_content.is_some() && config.spec_path.is_some() {
        return Err(ProtectError::Config(
            "spec content and path are mutually exclusive".into(),
        ));
    }
    if let Some(pin) = &config.spec_sha256 {
        if config.spec_path.is_none() || config.spec_content.is_some() {
            return Err(ProtectError::Config(
                "spec SHA-256 requires a local spec path".into(),
            ));
        }
        if pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ProtectError::Config(
                "spec SHA-256 must contain exactly 64 hexadecimal digits".into(),
            ));
        }
    }
    Ok(())
}

pub(super) async fn load(config: &ProtectConfig) -> Result<LoadedSpec, ProtectError> {
    validate_source(config)?;
    let content = match (&config.spec_content, &config.spec_path) {
        (Some(content), None) => content.clone(),
        (None, Some(path)) => {
            let file = std::fs::File::open(path)?;
            let mut content = String::new();
            // Hash and parse the same bounded read. A replacement of the pathname
            // cannot substitute bytes after provenance has been established.
            file.take(chio_openapi::MAX_OPENAPI_BYTES as u64 + 1)
                .read_to_string(&mut content)?;
            content
        }
        (None, None) => crate::spec_discovery::discover_spec(&config.upstream).await?,
        (Some(_), Some(_)) => return Err(ProtectError::Config("ambiguous spec source".into())),
    };
    if content.len() > chio_openapi::MAX_OPENAPI_BYTES {
        return Err(chio_core_types::canonical::UntrustedJsonError::TooLarge {
            bytes: content.len(),
            bound: chio_openapi::MAX_OPENAPI_BYTES,
        }
        .into());
    }
    let pinned = if let Some(pin) = &config.spec_sha256 {
        if !chio_core_types::sha256_hex(content.as_bytes()).eq_ignore_ascii_case(pin) {
            return Err(ProtectError::Config(
                "local spec SHA-256 does not match the operator pin".into(),
            ));
        }
        true
    } else {
        false
    };
    Ok(LoadedSpec { content, pinned })
}

#[cfg(test)]
mod product_guard_tests {
    use super::*;

    #[test]
    fn product_default_guards_authority_identity_binds_spec_and_profile() -> Result<(), ProtectError>
    {
        let spec = LoadedSpec {
            content: "openapi: 3.0.3".into(),
            pinned: true,
        };
        let baseline = spec.policy_hash(false)?;
        assert_eq!(baseline.len(), 64);
        let changed_profile = chio_core_types::sha256_hex(b"changed-default-profile");
        assert_ne!(
            baseline,
            spec.policy_hash_with_guard_profile(false, &changed_profile)?
        );
        assert_ne!(spec.policy_hash(false)?, spec.policy_hash(true)?);
        let unpinned = LoadedSpec {
            content: spec.content.clone(),
            pinned: false,
        };
        assert_ne!(spec.policy_hash(false)?, unpinned.policy_hash(false)?);
        let other_spec = LoadedSpec {
            content: "openapi: 3.1.0".into(),
            pinned: true,
        };
        assert_ne!(spec.policy_hash(false)?, other_spec.policy_hash(false)?);
        Ok(())
    }
}
