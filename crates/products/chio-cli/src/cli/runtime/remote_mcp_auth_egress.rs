use super::CliError;

pub(crate) fn remote_mcp_auth_egress_contract(
    server_id: &str,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_jwt_provider_profile: Option<chio_core_types::enterprise_provider::JwtProviderProfile>,
    auth_jwt_issuer: Option<&str>,
    auth_jwks_uri: Option<&str>,
) -> Result<Option<chio_egress_contract::HttpEgressContract>, CliError> {
    let mut urls = Vec::new();
    urls.extend(auth_jwt_discovery_url);
    urls.extend(auth_introspection_url);
    urls.extend(auth_jwks_uri);
    if auth_jwt_provider_profile.is_some() || auth_jwt_discovery_url.is_some() {
        urls.extend(auth_jwt_issuer);
    }
    if urls.is_empty() {
        return Ok(None);
    }

    let mut allowed_schemes = std::collections::BTreeSet::new();
    let mut allowed_authority_set = std::collections::BTreeSet::new();
    let mut deny_loopback = true;
    let mut deny_link_local = true;
    let mut private_network_allowances = std::collections::BTreeSet::new();

    for raw_url in urls {
        let parsed = url::Url::parse(raw_url).map_err(|error| {
            CliError::cli_other_error(format!(
                "remote MCP auth egress URL `{raw_url}` is invalid: {error}"
            ))
        })?;
        allowed_schemes.insert(parsed.scheme().to_ascii_lowercase());
        allowed_authority_set.insert(cli_normalized_url_authority(&parsed)?);
        private_network_allowances
            .extend(chio_egress_contract::PrivateNetworkAllowance::for_ipv6_ula_literal(&parsed));

        if let Some(host) = parsed.host() {
            match host {
                url::Host::Domain(domain) => {
                    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                    if matches!(normalized.as_str(), "localhost" | "localhost.localdomain") {
                        deny_loopback = false;
                    }
                }
                url::Host::Ipv4(address) => {
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if address.is_link_local() {
                        deny_link_local = false;
                    }
                }
                url::Host::Ipv6(address) => {
                    if let Some(mapped) = address.to_ipv4_mapped() {
                        if mapped.is_loopback() {
                            deny_loopback = false;
                        }
                        if mapped.is_link_local() {
                            deny_link_local = false;
                        }
                    }
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if is_cli_ipv6_unicast_link_local(&address) {
                        deny_link_local = false;
                    }
                }
            }
        }
    }

    let contract = chio_egress_contract::HttpEgressContract {
        tenant_egress_namespace: format!("remote-mcp-auth:{server_id}"),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback,
        deny_link_local,
        max_redirect_chain: 3,
        max_response_bytes: 1024 * 1024,
        private_network_allowances,
    };
    contract.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress contract is invalid: {error}"
        ))
    })?;
    Ok(Some(contract))
}

fn cli_normalized_url_authority(url: &url::Url) -> Result<String, CliError> {
    let host = url.host_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress URL `{url}` is missing an authority"
        ))
    })?;
    let host = match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(url::Host::Domain(_)) => host.trim_end_matches('.').to_ascii_lowercase(),
        _ => host.to_ascii_lowercase(),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn is_cli_ipv6_unicast_link_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::super::runtime_local_error_domain_tests::assert_registry_error;
    use super::*;

    #[test]
    fn remote_mcp_auth_contract_is_derived_from_external_auth_urls() {
        let contract = remote_mcp_auth_egress_contract(
            "edge-a",
            Some("https://id.example.com/.well-known/openid-configuration"),
            Some("https://auth.example.com/oauth2/introspect"),
            None,
            Some("https://issuer.example.com/oauth2/default"),
            Some("https://keys.example.com/jwks.json"),
        )
        .expect("contract builds")
        .expect("external auth creates contract");

        assert_eq!(contract.tenant_egress_namespace, "remote-mcp-auth:edge-a");
        assert!(contract.allowed_schemes.contains("https"));
        assert!(contract.allowed_authority_set.contains("id.example.com"));
        assert!(contract.allowed_authority_set.contains("auth.example.com"));
        assert!(contract
            .allowed_authority_set
            .contains("issuer.example.com"));
        assert!(contract.allowed_authority_set.contains("keys.example.com"));
        assert!(contract.deny_loopback);
    }

    #[test]
    fn remote_mcp_auth_contract_permits_explicit_loopback_auth_url() {
        let contract = remote_mcp_auth_egress_contract(
            "edge-local",
            None,
            Some("http://127.0.0.1:18080/introspect"),
            None,
            None,
            None,
        )
        .expect("contract builds")
        .expect("loopback auth creates contract");

        assert!(contract.allowed_schemes.contains("http"));
        assert!(contract.allowed_authority_set.contains("127.0.0.1:18080"));
        assert!(!contract.deny_loopback);
    }

    #[test]
    fn remote_mcp_auth_contract_pins_a_unique_local_auth_url() {
        let introspection = "https://[fd12:3456:789a::7]:8443/introspect";
        let contract = remote_mcp_auth_egress_contract(
            "edge-ula",
            None,
            Some(introspection),
            None,
            None,
            Some("https://keys.example.com/jwks.json"),
        )
        .expect("contract builds")
        .expect("auth URLs create a contract");

        let pins: Vec<_> = contract
            .private_network_allowances
            .iter()
            .map(|pin| (pin.host.as_str(), pin.port, pin.cidr.to_string()))
            .collect();
        assert_eq!(
            pins,
            vec![(
                "fd12:3456:789a::7",
                8443,
                "fd12:3456:789a::7/128".to_string()
            )]
        );
        assert!(contract.enforce_url(introspection, 0).is_ok());
    }

    #[test]
    fn remote_mcp_auth_contract_refuses_a_unique_local_metadata_url() {
        let error = remote_mcp_auth_egress_contract(
            "edge-ula",
            None,
            Some("https://[fd00:ec2::254]:8443/introspect"),
            None,
            None,
            None,
        )
        .expect_err("metadata range");
        assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
        assert!(
            error
                .to_string()
                .contains("includes the reserved range fd00:ec2::/32"),
            "{error}"
        );
    }

    #[test]
    fn remote_mcp_auth_contract_refuses_one_unique_local_endpoint_under_both_schemes() {
        let error = remote_mcp_auth_egress_contract(
            "edge-ula",
            None,
            Some("https://[fd12:3456:789a::7]:8443/introspect"),
            None,
            None,
            Some("http://[fd12:3456:789a::7]:8443/jwks.json"),
        )
        .expect_err("both schemes");
        assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
        assert!(
            error
                .to_string()
                .contains("allowance for fd12:3456:789a::7:8443 names both http and https"),
            "{error}"
        );
    }
}
