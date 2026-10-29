//! Requests to an operator-named finding venue, each under a contract for
//! that endpoint's own authority: no redirects, a response ceiling, and only
//! the private endpoints the operator allows.
use crate::CliError;
use chio_egress_contract::{
    BlockingContractAgent, BlockingContractResponse, EgressAllowanceSet, EndpointSource,
    HttpEgressContract, HttpEgressError,
};
use std::time::Duration;

const VENUE_PHASE_TIMEOUT: Duration = Duration::from_secs(30);
const VENUE_DEADLINE: Duration = Duration::from_secs(60);

fn venue_agent(
    endpoint: &str,
    max_response_bytes: usize,
    allowances: &EgressAllowanceSet,
) -> Result<BlockingContractAgent, HttpEgressError> {
    let contract = HttpEgressContract::single_endpoint(
        EndpointSource::Operator,
        "finding-venue",
        endpoint,
        max_response_bytes as u64,
        allowances,
    )?;
    BlockingContractAgent::new(&contract, VENUE_PHASE_TIMEOUT, VENUE_DEADLINE)
}

pub(super) fn venue_get(
    endpoint: &str,
    max_response_bytes: usize,
    allowances: &EgressAllowanceSet,
) -> Result<BlockingContractResponse, HttpEgressError> {
    venue_agent(endpoint, max_response_bytes, allowances)?
        .get(endpoint)?
        .call()
}

pub(super) fn venue_post(
    endpoint: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    max_response_bytes: usize,
    allowances: &EgressAllowanceSet,
) -> Result<BlockingContractResponse, HttpEgressError> {
    let mut request = venue_agent(endpoint, max_response_bytes, allowances)?.post(endpoint)?;
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.send_bytes(body)
}

pub(super) fn venue_failure(error: HttpEgressError, label: &str) -> CliError {
    match error {
        HttpEgressError::ResponseTooLarge { max, .. } => {
            CliError::transport_shape_error(format!("{label} exceeds the {max} byte bound"))
        }
        error => CliError::transport_error(format!("transport request failed: {error}")),
    }
}

pub(super) fn venue_text(body: &[u8], label: &str) -> Result<String, CliError> {
    String::from_utf8(body.to_vec())
        .map_err(|_| CliError::transport_shape_error(format!("{label} is not UTF-8")))
}

pub(super) fn is_success(response: &BlockingContractResponse) -> bool {
    (200..300).contains(&response.status())
}
