use std::collections::BTreeSet;
use std::net::IpAddr;

use chio_core::canonical::UntrustedJsonText;
use chio_egress_contract::{
    BlockingContractAgent, BlockingContractRequest, HttpEgressContract, HttpEgressError,
};

use super::client::path_with_encoded_param;
use super::*;

const PUBLIC_REGISTRY: &str = "public registry";
const PUBLIC_CERTIFICATION_REGISTRY: &str = "public certification registry";
const MAX_PUBLIC_REGISTRY_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

pub fn resolve_public_certification(
    registry_url: &str,
    tool_server_id: &str,
) -> Result<CertificationResolutionResponse, CliError> {
    let path = path_with_encoded_param(
        PUBLIC_CERTIFICATION_RESOLVE_PATH,
        "tool_server_id",
        tool_server_id,
    );
    registry_get_json(PUBLIC_CERTIFICATION_REGISTRY, registry_url, &path, "")
}

pub fn resolve_public_certification_metadata(
    registry_url: &str,
) -> Result<CertificationPublicMetadata, CliError> {
    registry_get_json(
        PUBLIC_CERTIFICATION_REGISTRY,
        registry_url,
        PUBLIC_CERTIFICATION_METADATA_PATH,
        "",
    )
}

pub fn resolve_public_generic_namespace(
    registry_url: &str,
) -> Result<SignedGenericNamespace, CliError> {
    registry_get_json(
        PUBLIC_REGISTRY,
        registry_url,
        PUBLIC_GENERIC_NAMESPACE_PATH,
        "",
    )
}

pub fn search_public_generic_listings(
    registry_url: &str,
    query: &GenericListingQuery,
) -> Result<GenericListingReport, CliError> {
    let query = encode_registry_query(PUBLIC_REGISTRY, query)?;
    registry_get_json(
        PUBLIC_REGISTRY,
        registry_url,
        PUBLIC_GENERIC_LISTINGS_PATH,
        &query,
    )
}

pub fn search_public_certifications(
    registry_url: &str,
    query: &CertificationPublicSearchQuery,
) -> Result<CertificationPublicSearchResponse, CliError> {
    let query = encode_registry_query(PUBLIC_CERTIFICATION_REGISTRY, query)?;
    registry_get_json(
        PUBLIC_CERTIFICATION_REGISTRY,
        registry_url,
        PUBLIC_CERTIFICATION_SEARCH_PATH,
        &query,
    )
}

pub fn resolve_public_certification_transparency(
    registry_url: &str,
    query: &CertificationTransparencyQuery,
) -> Result<CertificationTransparencyResponse, CliError> {
    let query = encode_registry_query(PUBLIC_CERTIFICATION_REGISTRY, query)?;
    registry_get_json(
        PUBLIC_CERTIFICATION_REGISTRY,
        registry_url,
        PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
        &query,
    )
}

fn encode_registry_query<Q: Serialize>(label: &str, query: &Q) -> Result<String, CliError> {
    serde_urlencoded::to_string(query).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode {label} query: {error}"))
    })
}

/// One GET to the operator-configured registry authority: that scheme and
/// authority only, plaintext `http` only to a loopback host, no redirects,
/// and a bounded body.
fn registry_get_json<T: for<'de> Deserialize<'de>>(
    label: &str,
    registry_url: &str,
    path: &str,
    query: &str,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{label} URL must not be empty"
        )));
    }
    let url = if query.is_empty() {
        format!("{endpoint}{path}")
    } else {
        format!("{endpoint}{path}?{query}")
    };
    let response = registry_contract(endpoint)
        .and_then(|contract| {
            BlockingContractAgent::new(&contract, CONTROL_HTTP_TIMEOUT, CONTROL_HTTP_TIMEOUT)
        })
        .and_then(|agent| agent.get(&url))
        .and_then(BlockingContractRequest::call)
        .map_err(|error| {
            CliError::cli_other_error(format!("{label} egress to {endpoint} failed: {error}"))
        })?;
    if !(200..300).contains(&response.status()) {
        return Err(CliError::cli_other_error(format!(
            "{label} {endpoint} returned HTTP status {}",
            response.status()
        )));
    }
    UntrustedJsonText::from_wire(
        response.body(),
        usize::try_from(MAX_PUBLIC_REGISTRY_RESPONSE_BYTES).unwrap_or(usize::MAX),
    )
    .and_then(|document| document.decode_signed())
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse {label} response from {endpoint}: {error}"
        ))
    })
}

fn registry_contract(endpoint: &str) -> Result<HttpEgressContract, HttpEgressError> {
    let parsed = url::Url::parse(endpoint)
        .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or(HttpEgressError::MissingAuthority)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let loopback_http = parsed.scheme() == "http"
        && (host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback()));
    let scheme = if loopback_http { "http" } else { "https" };
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let contract = HttpEgressContract {
        tenant_egress_namespace: "public-registry".to_owned(),
        allowed_schemes: BTreeSet::from([scheme.to_owned()]),
        allowed_authority_set: BTreeSet::from([authority]),
        deny_loopback: !loopback_http,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: MAX_PUBLIC_REGISTRY_RESPONSE_BYTES,
        private_network_allowances: Default::default(),
    };
    contract.enforce_url(endpoint, 0)?;
    Ok(contract)
}

#[cfg(test)]
#[path = "public_registry_tests.rs"]
mod tests;
