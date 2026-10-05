//! Host-owned PostgreSQL transport. Confined tools receive only broker IPC.
use std::{collections::BTreeSet, io::Write, path::PathBuf, time::Duration};

use chio_core_types::{canonical::UntrustedJsonText, canonical_json_bytes};
use chio_finding_market_store_postgres::{HostedTenantId, PostgresFindingMarketStore};
use chio_secret_broker::{
    host_https::{HostHttpsServer, HttpsEndpoint, JsonAdapter},
    host_resource::HostResourceRoute,
    BrokerError,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Task,
    Complete,
    Renew,
    Assign,
    Release,
    Inspect,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Complete => "complete",
            Self::Renew => "renew",
            Self::Assign => "assign",
            Self::Release => "release",
            Self::Inspect => "inspect",
        }
    }

    fn mode(self) -> &'static str {
        match self {
            Self::Task | Self::Complete | Self::Renew => "worker",
            Self::Assign | Self::Release | Self::Inspect => "operator",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    operation: Operation,
    bind: std::net::SocketAddr,
    certificate_der: Vec<u8>,
    private_key_file: PathBuf,
    bearer_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    tenant: String,
    timeout_ms: u64,
    endpoints: Vec<Endpoint>,
    #[serde(default)]
    claim_response_loss_directory: Option<PathBuf>,
}

fn refused() -> BrokerError {
    BrokerError::AuthorizationDenied("PostgreSQL resource configuration or request refused".into())
}

fn unavailable() -> BrokerError {
    BrokerError::Upstream("PostgreSQL outcome unavailable; automatic retry forbidden".into())
}

struct Adapter {
    store: PostgresFindingMarketStore,
    tenant: HostedTenantId,
    operation: Operation,
    route: HostResourceRoute,
    runtime: tokio::runtime::Handle,
    timeout_ms: u64,
    fault: Option<std::sync::Arc<super::fault::ClaimResponseLoss>>,
}

impl JsonAdapter for Adapter {
    fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    fn execute_json(&self, bytes: &[u8]) -> chio_secret_broker::Result<Vec<u8>> {
        // HostHttpsServer authenticates the route's dedicated bearer first.
        // No worker-selected metadata is copied into the authority projection.
        let invocation = self.route.decode(bytes)?;
        let params = json!({
            "name": self.operation.name(),
            "arguments": invocation.arguments,
            "_meta": {"chioCallerCapabilitySha256": invocation.caller_capability_sha256}
        });
        let result = self.runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(self.timeout_ms),
                super::resource::invoke(&self.store, &self.tenant, self.operation.mode(), &params),
            )
            .await
        });
        // A timeout can occur after commit. Closing the exchange preserves the
        // broker's uncertain outcome rather than advertising a safe retry.
        let value = result
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        if self.operation == Operation::Assign {
            if let Some(fault) = &self.fault {
                fault.after_commit(&params, &value)?;
            }
        }
        canonical_json_bytes(&value).map_err(|_| unavailable())
    }
}

/// Bind every fixed endpoint before advertising readiness. The database pool
/// retains its production worker-role and verified TLS configuration.
pub fn serve(
    path: &std::path::Path,
    store: PostgresFindingMarketStore,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut input = Vec::new();
    std::fs::File::open(path)?
        .take(131_073)
        .read_to_end(&mut input)?;
    let config: Config = UntrustedJsonText::from_wire(&input, 131_072)?.decode_document()?;
    if config.schema != "chio.postgres-job-resource.v1"
        || !(1..=20_000).contains(&config.timeout_ms)
        || config.endpoints.is_empty()
        || config.endpoints.len() > 6
    {
        return Err(refused().into());
    }
    let tenant = HostedTenantId::new(config.tenant.clone())?;
    let fault = config
        .claim_response_loss_directory
        .map(super::fault::ClaimResponseLoss::new)
        .transpose()?
        .map(std::sync::Arc::new);
    let mut operations = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    let mut servers = Vec::new();
    for endpoint in config.endpoints {
        if !operations.insert(endpoint.operation)
            || !credentials.insert(std::fs::canonicalize(&endpoint.bearer_file)?)
        {
            return Err(refused().into());
        }
        let route = HostResourceRoute {
            resource: "postgres-jobs".into(),
            tenant: config.tenant.clone(),
            operation: endpoint.operation.name().into(),
        };
        route.validate()?;
        let server = HostHttpsServer::bind(
            HttpsEndpoint {
                bind: endpoint.bind,
                certificate_der: endpoint.certificate_der,
                private_key_file: endpoint.private_key_file,
                bearer_file: endpoint.bearer_file,
            },
            Adapter {
                store: store.clone(),
                tenant: tenant.clone(),
                operation: endpoint.operation,
                route,
                runtime: tokio::runtime::Handle::current(),
                timeout_ms: config.timeout_ms,
                fault: fault.clone(),
            },
        )?;
        if servers
            .iter()
            .any(|other| server.shares_credential_with(other))
        {
            return Err(refused().into());
        }
        servers.push(server);
    }
    let (failed, failure) = std::sync::mpsc::sync_channel(servers.len());
    for server in servers {
        let failed = failed.clone();
        std::thread::Builder::new()
            .name("postgres-resource".into())
            .spawn(move || {
                let result = server.serve();
                let _ = failed.send(result);
            })?;
    }
    drop(failed);
    println!("{}", json!({"ready": true, "resource": "postgres-jobs"}));
    std::io::stdout().flush()?;
    failure.recv()??;
    Err(unavailable().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_six_existing_operations_are_enabled() -> Result<(), Box<dyn std::error::Error>> {
        for name in ["task", "complete", "renew", "assign", "release", "inspect"] {
            let operation: Operation = serde_json::from_value(json!(name))?;
            assert_eq!(operation.name(), name);
        }
        for name in ["query", "sql", "migrate", "seed", "execute", "delete"] {
            assert!(serde_json::from_value::<Operation>(json!(name)).is_err());
        }
        Ok(())
    }
}
