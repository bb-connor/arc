//! Trusted host transport for the PostgreSQL lease adapter.

use std::{path::Path, time::Duration};

use chio_core_types::{canonical::UntrustedJsonText, canonical_json_bytes};
use chio_finding_market_store_postgres::{HostedTenantId, PostgresFindingMarketStore};
use chio_secret_broker::{
    host_https::{private_bytes, HostHttpsServer, HttpsEndpoint, JsonAdapter},
    BrokerError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::runtime::Runtime;

#[path = "qualification_fault.rs"]
mod qualification_fault;

const REQUEST_LIMIT: usize = 131_072;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Worker,
    Operator,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Operator => "operator",
        }
    }

    fn permits(self, tool: &str) -> bool {
        matches!(
            (self, tool),
            (Self::Worker, "task" | "complete" | "renew")
                | (Self::Operator, "assign" | "release" | "inspect")
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    endpoint: HttpsEndpoint,
    tenant: String,
    role: Role,
    /// Explicit qualification cut point, never enabled by a tool request.
    qualification_fault_directory: Option<std::path::PathBuf>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Caller {
    #[serde(rename = "chioCallerCapabilitySha256")]
    capability_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Call {
    name: String,
    arguments: Value,
    #[serde(rename = "_meta")]
    caller: Caller,
}

fn denied() -> BrokerError {
    BrokerError::AuthorizationDenied("PostgreSQL adapter request refused".into())
}

fn unavailable() -> BrokerError {
    BrokerError::Upstream("PostgreSQL outcome unavailable; automatic retry forbidden".into())
}

fn decode_request(bytes: &[u8], role: Role) -> chio_secret_broker::Result<Value> {
    let call: Call = UntrustedJsonText::from_wire(bytes, REQUEST_LIMIT)
        .and_then(|text| text.decode_signed())
        .map_err(|_| denied())?;
    let digest = call.caller.capability_sha256.as_bytes();
    if !role.permits(&call.name)
        || !call.arguments.is_object()
        || digest.len() != 64
        || !digest
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(denied());
    }
    serde_json::to_value(call).map_err(|_| denied())
}

struct Adapter {
    runtime: Runtime,
    store: PostgresFindingMarketStore,
    tenant: HostedTenantId,
    role: Role,
    fault: Option<qualification_fault::ClaimResponseLoss>,
}

impl JsonAdapter for Adapter {
    fn timeout_ms(&self) -> u64 {
        // The qualification cut point also has a bounded wait for host SIGKILL.
        if self.fault.is_some() {
            45_000
        } else {
            15_000
        }
    }

    fn execute_json(&self, bytes: &[u8]) -> chio_secret_broker::Result<Vec<u8>> {
        let request = decode_request(bytes, self.role)?;
        let delivery = self
            .fault
            .as_ref()
            .map(|fault| fault.before(&request))
            .transpose()?;
        let value = self.runtime.block_on(async {
            tokio::time::timeout(
                OPERATION_TIMEOUT,
                super::resource::invoke(&self.store, &self.tenant, self.role.as_str(), &request),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())
        })?;
        let response = json!({"content":[{"type":"text","text":value.to_string()}],
            "structuredContent":value,"isError":false});
        if let (Some(fault), Some(delivery)) = (&self.fault, delivery) {
            fault.after(delivery, &response)?;
        }
        canonical_json_bytes(&response).map_err(|_| unavailable())
    }
}

pub fn serve(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = private_bytes(path, 65_536)?;
    let config: Config = UntrustedJsonText::from_wire(&bytes, 65_536)?.decode_signed()?;
    if config.schema != "chio.postgres-job-https-adapter.v1"
        || (config.qualification_fault_directory.is_some()
            && !matches!(config.role, Role::Operator))
    {
        return Err(denied().into());
    }
    let tenant = HostedTenantId::new(config.tenant)?;
    let fault = config
        .qualification_fault_directory
        .map(qualification_fault::ClaimResponseLoss::new)
        .transpose()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let store = runtime.block_on(PostgresFindingMarketStore::connect_worker(
        &super::database_config()?,
    ))?;
    let server = HostHttpsServer::bind(
        config.endpoint,
        Adapter {
            runtime,
            store,
            tenant,
            role: config.role,
            fault,
        },
    )?;
    println!("CHIO_POSTGRES_ADAPTER_READY");
    server.serve()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_bound_caller_and_installed_role_reach_the_resource(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let valid = json!({"name":"task","arguments":{"job_id":"job"},
            "_meta":{"chioCallerCapabilitySha256":"a".repeat(64)}});
        assert_eq!(
            decode_request(&serde_json::to_vec(&valid)?, Role::Worker)?,
            valid
        );
        for (key, value) in [
            ("name", json!("assign")),
            ("tenant", json!("other")),
            ("_meta", json!({"chioCallerCapabilitySha256":"invalid"})),
            ("arguments", json!(null)),
        ] {
            let mut changed = valid.clone();
            changed[key] = value;
            assert!(decode_request(&serde_json::to_vec(&changed)?, Role::Worker).is_err());
        }
        let mut operator = valid.clone();
        operator["name"] = json!("inspect");
        assert!(decode_request(&serde_json::to_vec(&operator)?, Role::Worker).is_err());
        assert!(decode_request(&serde_json::to_vec(&operator)?, Role::Operator).is_ok());
        Ok(())
    }

    #[test]
    fn ambiguous_and_oversized_json_is_rejected_before_dispatch() {
        assert!(decode_request(br#"{"name":"task","name":"assign"}"#, Role::Worker).is_err());
        assert!(decode_request(&vec![b' '; 131_073], Role::Worker).is_err());
    }
}
