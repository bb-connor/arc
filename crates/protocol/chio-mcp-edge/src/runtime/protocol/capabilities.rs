use super::*;

pub(in crate::runtime) fn select_capability_for_request(
    capabilities: &[CapabilityToken],
    tool_name: &str,
    server_id: &str,
    arguments: &Value,
    model_metadata: Option<&ModelMetadata>,
) -> Result<Option<CapabilityToken>, chio_kernel::KernelError> {
    select_matching_capability(capabilities, |capability| {
        chio_kernel::capability_matches_request_with_model_metadata(
            capability,
            tool_name,
            server_id,
            arguments,
            model_metadata,
        )
    })
}

pub(in crate::runtime) fn select_capability_for_resource(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Result<Option<CapabilityToken>, chio_kernel::KernelError> {
    select_matching_capability(capabilities, |capability| {
        chio_kernel::capability_matches_resource_request(capability, uri)
    })
}

pub(in crate::runtime) fn select_capability_for_resource_subscription(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Result<Option<CapabilityToken>, chio_kernel::KernelError> {
    select_matching_capability(capabilities, |capability| {
        chio_kernel::capability_matches_resource_subscription(capability, uri)
    })
}

pub(in crate::runtime) fn select_capability_for_prompt(
    capabilities: &[CapabilityToken],
    prompt_name: &str,
) -> Result<Option<CapabilityToken>, chio_kernel::KernelError> {
    select_matching_capability(capabilities, |capability| {
        chio_kernel::capability_matches_prompt_request(capability, prompt_name)
    })
}

pub(in crate::runtime) fn select_capability_for_resource_pattern(
    capabilities: &[CapabilityToken],
    pattern: &str,
) -> Result<Option<CapabilityToken>, chio_kernel::KernelError> {
    select_matching_capability(capabilities, |capability| {
        chio_kernel::capability_matches_resource_pattern(capability, pattern)
    })
}

fn select_matching_capability(
    capabilities: &[CapabilityToken],
    mut matches: impl FnMut(&CapabilityToken) -> Result<bool, chio_kernel::KernelError>,
) -> Result<Option<CapabilityToken>, chio_kernel::KernelError> {
    for capability in capabilities {
        if matches(capability)? {
            return Ok(Some(capability.clone()));
        }
    }
    Ok(None)
}

pub(in crate::runtime) fn tool_is_authorized(
    capabilities: &[CapabilityToken],
    binding: &ExposedToolBinding,
) -> bool {
    capabilities.iter().any(|capability| {
        capability.scope.grants.iter().any(|grant| {
            matches_server(&grant.server_id, &binding.server_id)
                && matches_name(&grant.tool_name, &binding.tool_name)
                && grant.operations.contains(&Operation::Invoke)
        })
    })
}

pub(in crate::runtime) fn matches_server(pattern: &str, server_id: &str) -> bool {
    pattern == "*" || pattern == server_id
}

pub(in crate::runtime) fn matches_name(pattern: &str, tool_name: &str) -> bool {
    pattern == "*" || pattern == tool_name
}
