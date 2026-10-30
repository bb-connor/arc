//! The private network allowances a payment rail may dial.

use std::collections::BTreeSet;

use chio_egress_contract::{
    private_network_allowance_digest, EgressAllowanceSet, PrivateNetworkAllowance,
    EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST,
};
use url::{Host, Url};

use super::PaymentError;

/// The allowances that pin one rail's own `host:port`, and their digest. The
/// digest is journaled with every payment so recovery refuses a rail whose
/// allowance changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PaymentRailEgress {
    allowances: BTreeSet<PrivateNetworkAllowance>,
    digest: String,
}

impl Default for PaymentRailEgress {
    fn default() -> Self {
        Self {
            allowances: BTreeSet::new(),
            digest: EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST.to_owned(),
        }
    }
}

impl PaymentRailEgress {
    /// Keep only the allowances for the rail URL's host and port; entries for
    /// other destinations are not this rail's.
    pub(crate) fn for_rail(
        base_url: &str,
        allowances: &EgressAllowanceSet,
    ) -> Result<Self, PaymentError> {
        let invalid_url = || PaymentError::RailError("payment rail URL is invalid".to_owned());
        let parsed = Url::parse(base_url).map_err(|_| invalid_url())?;
        let host = match parsed.host().ok_or_else(invalid_url)? {
            Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address
                .to_ipv4_mapped()
                .map_or_else(|| address.to_string(), |mapped| mapped.to_string()),
        };
        let port = parsed.port_or_known_default().ok_or_else(invalid_url)?;
        let allowances = allowances.for_endpoint(&host, port);
        let digest = private_network_allowance_digest(&allowances).map_err(|_| {
            PaymentError::RailError("payment rail egress allowance is invalid".to_owned())
        })?;
        Ok(Self { allowances, digest })
    }

    pub(crate) fn allowances(&self) -> &BTreeSet<PrivateNetworkAllowance> {
        &self.allowances
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test fixtures assert on constructed values and fail the test on a bad fixture."
)]
#[path = "rail_egress_tests.rs"]
mod tests;
