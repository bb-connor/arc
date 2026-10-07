//! Complete existing process identity derivation, shared by invoke/finalize.
use crate::{digest, ProcessError, ProcessRoute, ProcessRuntime, ProcessSecurityProfile};
use chio_kernel::ToolCallRequest;

pub(crate) struct ProcessCallBinding {
    pub(crate) request_hash: String,
    pub(crate) binding_hash: String,
}
impl ProcessRuntime {
    pub(crate) fn derive_call_binding(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
        known_outcome_only: bool,
    ) -> Result<ProcessCallBinding, ProcessError> {
        let mut binding = request.clone();
        binding.request_id = self.request_id(process_id, operation_key)?;
        let request_hash = digest(&binding)?;
        let binding_hash = complete_binding(
            &request_hash,
            known_outcome_only,
            self.routes.get(&request.server_id),
            self.security_profile.as_ref(),
        )?;
        Ok(ProcessCallBinding {
            request_hash,
            binding_hash,
        })
    }
}

pub(crate) fn complete_binding(
    request_hash: &str,
    known_outcome_only: bool,
    route: Option<&ProcessRoute>,
    profile: Option<&ProcessSecurityProfile>,
) -> Result<String, ProcessError> {
    let recovery_binding = if known_outcome_only {
        digest(&("chio.process.known-outcome-only.v1", &request_hash))?
    } else {
        request_hash.to_owned()
    };
    let binding_hash = match route {
        Some(route) => digest(&("chio.process.host-route.v1", &recovery_binding, route))?,
        None => recovery_binding,
    };
    let binding_hash = match profile {
        Some(profile) => digest(&("chio.process.security-context.v1", binding_hash, profile))?,
        None => binding_hash,
    };
    Ok(binding_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_all_legacy_mode_route_and_profile_bytes_match_the_fixed_reference(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../spec/vectors/recovery/v1/legacy-process-binding.json"
        ))?;
        let request: ToolCallRequest = serde_json::from_value(fixture["request"].clone())?;
        assert_eq!(serde_json::to_value(&request)?, fixture["request"]);
        let route = ProcessRoute::new("bridge-a", "provider-a", "route-a")?;
        let profile: ProcessSecurityProfile = serde_json::from_value(fixture["profile"].clone())?;
        for case in fixture["cases"].as_array().ok_or("cases")? {
            let request_hash = digest(&request)?;
            let binding = complete_binding(
                &request_hash,
                case["known_outcome_only"].as_bool().ok_or("mode")?,
                case["with_route"]
                    .as_bool()
                    .ok_or("route")?
                    .then_some(&route),
                case["with_profile"]
                    .as_bool()
                    .ok_or("profile")?
                    .then_some(&profile),
            )?;
            assert_eq!(Some(request_hash.as_str()), case["request_hash"].as_str());
            assert_eq!(Some(binding.as_str()), case["binding_hash"].as_str());
        }
        Ok(())
    }
}
