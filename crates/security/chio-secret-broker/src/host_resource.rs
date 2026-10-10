//! Fixed host projections for credential-mediated resource operations.
//!
//! These envelopes are not credentials. A resource must accept them only on its
//! authenticated broker channel, with a credential dedicated to its fixed route.
//! The host constructs the caller binding from the original process capability
//! inside durable preparation; worker-supplied metadata is never authority.

use chio_core_types::{canonical::UntrustedJsonText, canonical_json_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{validate_digest, validate_identifier, BrokerError, Result};

const SCHEMA: &str = "chio.host-resource-invocation.v1";
const MAX_BYTES: usize = 131_072;

/// Operator-selected identity of one resource operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostResourceRoute {
    pub resource: String,
    pub tenant: String,
    pub operation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    route: HostResourceRoute,
    caller_capability_sha256: String,
    arguments: Value,
}

/// Application arguments and caller projection decoded on the authenticated
/// host channel. Possession of this value does not authorize another channel.
pub struct HostResourceInvocation {
    pub caller_capability_sha256: String,
    pub arguments: Value,
}

impl HostResourceRoute {
    pub fn validate(&self) -> Result<()> {
        for (value, label) in [
            (&self.resource, "resource"),
            (&self.tenant, "resource tenant"),
            (&self.operation, "resource operation"),
        ] {
            validate_identifier(value, label, 128)?;
        }
        Ok(())
    }

    /// Called only by trusted host preparation with its own caller digest.
    pub fn encode(&self, arguments: &Value, caller: &str) -> Result<Vec<u8>> {
        self.validate()?;
        validate_digest(caller, "resource caller")?;
        validate_arguments(arguments)?;
        let bytes = canonical_json_bytes(&Envelope {
            schema: SCHEMA.into(),
            route: self.clone(),
            caller_capability_sha256: caller.into(),
            arguments: arguments.clone(),
        })
        .map_err(|_| BrokerError::InvalidRequest("resource payload encoding failed".into()))?;
        if bytes.len() > MAX_BYTES {
            return Err(BrokerError::InvalidRequest(
                "resource payload is oversized".into(),
            ));
        }
        Ok(bytes)
    }

    /// Decode only after channel authentication. Pins the entire route, rejects
    /// duplicate fields throughout the document and bounds bytes before parsing.
    pub fn decode(&self, bytes: &[u8]) -> Result<HostResourceInvocation> {
        self.validate()?;
        let envelope: Envelope =
            UntrustedJsonText::from_wire(bytes, MAX_BYTES)?.decode_document()?;
        if envelope.schema != SCHEMA || envelope.route != *self {
            return Err(BrokerError::AuthorizationDenied(
                "resource route differs".into(),
            ));
        }
        validate_digest(&envelope.caller_capability_sha256, "resource caller")?;
        validate_arguments(&envelope.arguments)?;
        Ok(HostResourceInvocation {
            caller_capability_sha256: envelope.caller_capability_sha256,
            arguments: envelope.arguments,
        })
    }
}

fn validate_arguments(arguments: &Value) -> Result<()> {
    let object = arguments.as_object().ok_or_else(|| {
        BrokerError::InvalidRequest("resource arguments must be an object".into())
    })?;
    if ["_meta", "route", "caller_capability_sha256"]
        .iter()
        .any(|field| object.contains_key(*field))
    {
        return Err(BrokerError::InvalidRequest(
            "worker supplied reserved resource metadata".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::canonical::UntrustedJsonError;
    use serde_json::json;

    fn route() -> HostResourceRoute {
        HostResourceRoute {
            resource: "postgres-jobs".into(),
            tenant: "one".into(),
            operation: "complete".into(),
        }
    }

    #[test]
    fn resource_v1_wire_shape_is_stable() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let wire = concat!(
            "{\"arguments\":{\"result\":{\"p95\":12.5}},",
            "\"caller_capability_sha256\":",
            "\"abababababababababababababababababababababababababababababababab\",",
            "\"route\":{\"operation\":\"complete\",\"resource\":\"postgres-jobs\",\"tenant\":\"one\"},",
            "\"schema\":\"chio.host-resource-invocation.v1\"}"
        );
        let invocation = route().decode(wire.as_bytes())?;
        assert_eq!(invocation.caller_capability_sha256, "ab".repeat(32));
        assert_eq!(invocation.arguments, json!({"result": {"p95": 12.5}}));
        assert_eq!(
            route().encode(&invocation.arguments, &invocation.caller_capability_sha256)?,
            wire.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn refuses_cross_route_and_ambiguous_envelopes(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let route = route();
        let bytes = route.encode(&json!({"result": {"p95": 12.5}}), &"ab".repeat(32))?;
        let invocation = route.decode(&bytes)?;
        assert_eq!(invocation.arguments, json!({"result": {"p95": 12.5}}));
        for field in ["resource", "tenant", "operation"] {
            let mut changed: Value = serde_json::from_slice(&bytes)?;
            changed["route"][field] = json!("other");
            assert!(matches!(
                route.decode(&serde_json::to_vec(&changed)?),
                Err(BrokerError::AuthorizationDenied(_))
            ));
        }
        let original = String::from_utf8(bytes)?;
        assert!(matches!(
            route.decode(original.replacen('{', "{\"extra\":1,", 1).as_bytes()),
            Err(BrokerError::UntrustedInput(UntrustedJsonError::Decode(_)))
        ));
        for changed in [
            original.replace("\"p95\":12.5", "\"p95\":12.5,\"p95\":9"),
            original.replacen("\"schema\":", "\"schema\":\"other\",\"schema\":", 1),
        ] {
            assert!(matches!(
                route.decode(changed.as_bytes()),
                Err(BrokerError::UntrustedInput(
                    UntrustedJsonError::SignedInput(_)
                ))
            ));
        }
        assert!(matches!(
            route.decode(&vec![b' '; MAX_BYTES + 1]),
            Err(BrokerError::UntrustedInput(
                UntrustedJsonError::TooLarge { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn refuses_oversized_payloads_and_worker_identity_projection() {
        let route = route();
        let caller = "ab".repeat(32);
        assert!(matches!(
            route.encode(&json!({"text": "x".repeat(MAX_BYTES)}), &caller),
            Err(BrokerError::InvalidRequest(_))
        ));
        assert!(matches!(
            route.encode(&json!({"_meta": {"caller": "forged"}}), &caller),
            Err(BrokerError::InvalidRequest(_))
        ));
        assert!(matches!(
            route.encode(&json!({}), "bad-digest"),
            Err(BrokerError::InvalidRequest(_))
        ));
    }
}
