use super::*;

pub(crate) fn resolve_agent_subject(
    configured_key: Option<&str>,
    capabilities: &[policy::DefaultCapability],
) -> Result<chio_core::PublicKey, CliError> {
    if let Some(key) = configured_key {
        return Ok(chio_core::PublicKey::from_hex(key)?);
    }
    if capabilities.iter().any(|capability| {
        capability
            .scope
            .grants
            .iter()
            .any(|grant| grant.dpop_required == Some(true))
    }) {
        return Err(CliError::cli_other_error(
            "proof-required policy needs --agent-public-key bound to the caller's signing key"
                .to_owned(),
        ));
    }
    Ok(Keypair::generate().public_key())
}
