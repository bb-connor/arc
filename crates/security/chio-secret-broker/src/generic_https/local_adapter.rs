//! Operator-installed HTTPS identity for a privileged loopback adapter.
//!
//! This is a fixed endpoint with ordinary TLS validation plus an exact leaf
//! certificate pin. Caller bytes cannot select a resolver, trust store or
//! private-network exception. Public provider traffic uses `production()`.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalHttpsAdapterConfig {
    pub server_name: String,
    pub address: IpAddr,
    pub port: u16,
    pub certificate_der: Vec<u8>,
}

impl LocalHttpsAdapterConfig {
    pub fn validate(&self) -> Result<()> {
        let destination = crate::protocol::BrokerDestination {
            scheme: BrokerScheme::Https,
            normalized_host: self.server_name.clone(),
            explicit_port: self.port,
            exact_path_and_query: "/".into(),
            method: "POST".into(),
        };
        destination.validate(false)?;
        if !self.address.is_loopback()
            || self.server_name.parse::<IpAddr>().is_ok()
            || self.certificate_der.is_empty()
            || self.certificate_der.len() > 16_384
        {
            return Err(BrokerError::InvalidRequest(
                "local adapter requires a DNS TLS name, loopback address and bounded certificate"
                    .into(),
            ));
        }
        Ok(())
    }
}

struct FixedAdapterResolver {
    host: String,
    port: u16,
    address: IpAddr,
}

impl DestinationResolver for FixedAdapterResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        if host != self.host || port != self.port {
            return Err(BrokerError::AuthorizationDenied(
                "request differs from the installed local adapter".into(),
            ));
        }
        Ok(vec![self.address])
    }
}

impl GenericHttpsExecutor {
    /// Install one host-owned adapter. There is no DNS, system-root fallback,
    /// proxy, redirect or transport injection on this route.
    pub fn for_local_adapter(config: &LocalHttpsAdapterConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            resolver: Arc::new(FixedAdapterResolver {
                host: config.server_name.clone(),
                port: config.port,
                address: config.address,
            }),
            transport: Arc::new(RustlsPinnedHttpsTransport::for_local_adapter(
                &config.certificate_der,
            )?),
            network_policy: NetworkPolicy {
                allow_loopback_test: false,
                allow_exact_address: Some(config.address),
            },
            exact_destination: Some((config.server_name.clone(), config.port)),
        })
    }
}
