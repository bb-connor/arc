use alloc::format;
use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_json_bytes, canonical_json_bytes_from_str};
use crate::crypto::Signature;
use crate::error::{Error, Result};

pub const CAPABILITY_SECURITY_BINDING_SCHEMA: &str = "chio.capability-security-binding.v1";

/// Signed workload and session identity carried by a directly issued
/// capability. The binding is serialized inside a first-party caveat, so it is
/// covered by the capability signature without changing the legacy token body
/// used by existing issuers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilitySecurityBinding {
    pub schema: String,
    pub tenant_id: String,
    pub lineage_id: String,
    pub session_id: String,
    pub principal_id: String,
    pub isolation_epoch_id: String,
    pub context_generation: u64,
    pub workload_id: String,
    pub server_id: String,
    pub workload_signer_public_key: String,
}

impl CapabilitySecurityBinding {
    pub fn validate(&self) -> Result<()> {
        if self.schema != CAPABILITY_SECURITY_BINDING_SCHEMA {
            return Err(Error::AttenuationViolation {
                reason: "capability security binding schema mismatch".to_string(),
            });
        }
        for (label, value) in [
            ("tenant", self.tenant_id.as_str()),
            ("lineage", self.lineage_id.as_str()),
            ("session", self.session_id.as_str()),
            ("principal", self.principal_id.as_str()),
            ("isolation epoch", self.isolation_epoch_id.as_str()),
            ("workload", self.workload_id.as_str()),
            ("server", self.server_id.as_str()),
            (
                "workload signer public key",
                self.workload_signer_public_key.as_str(),
            ),
        ] {
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
                return Err(Error::AttenuationViolation {
                    reason: format!("capability security binding {label} is invalid"),
                });
            }
        }
        if self.context_generation == 0 {
            return Err(Error::AttenuationViolation {
                reason: "capability security binding context generation is zero".to_string(),
            });
        }
        crate::crypto::PublicKey::from_hex(&self.workload_signer_public_key).map_err(|_| {
            Error::AttenuationViolation {
                reason: "capability security binding workload signer public key is invalid"
                    .to_string(),
            }
        })?;
        Ok(())
    }
}

/// First-party caveat attached to a attenuated capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Caveat {
    pub kind: CaveatKind,
    pub predicate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Signature>,
}

/// Built-in first-party caveat kinds. Third-party discharges are deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaveatKind {
    RestrictTool,
    BindSession,
    RestrictAudience,
    RestrictGeo,
    RestrictTimeWindow,
    BindSecurityContext,
}

impl Caveat {
    pub fn bind_security_context(binding: &CapabilitySecurityBinding) -> Result<Self> {
        binding.validate()?;
        let predicate = String::from_utf8(canonical_json_bytes(binding)?).map_err(|_| {
            Error::AttenuationViolation {
                reason: "capability security binding is not canonical UTF-8".to_string(),
            }
        })?;
        Ok(Self {
            kind: CaveatKind::BindSecurityContext,
            predicate,
            sig: None,
        })
    }

    pub fn security_binding(&self) -> Result<Option<CapabilitySecurityBinding>> {
        if self.kind != CaveatKind::BindSecurityContext {
            return Ok(None);
        }
        if self.sig.is_some() {
            return Err(Error::AttenuationViolation {
                reason: "capability security binding caveat must not carry a detached signature"
                    .to_string(),
            });
        }
        let canonical = canonical_json_bytes_from_str(&self.predicate)?;
        if canonical.as_slice() != self.predicate.as_bytes() {
            return Err(Error::AttenuationViolation {
                reason: "capability security binding predicate is not canonical JSON".to_string(),
            });
        }
        let binding: CapabilitySecurityBinding = serde_json::from_slice(&canonical)?;
        binding.validate()?;
        Ok(Some(binding))
    }
}

/// Per-grant subset relation recorded in an attenuation witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantSubsetRelation {
    pub grant_kind: String,
    pub child_index: u32,
    pub parent_index: u32,
    pub subset: bool,
}
