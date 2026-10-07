use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chio_core_types::capability::attenuation::validate_attenuation;
use chio_core_types::capability::scope::ChioScope;
use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_runtime_core::outcome_continuation::{OutcomeEffectArguments, OutcomeEffectRequest};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use super::model::{hash, outcome, Delivery, OwnerConfig, Reply, Rpc};
use crate::{Gate, Result, NOW};

const MAX_INPUT: u64 = 1024 * 1024;

fn read<T: DeserializeOwned>(reader: impl Read) -> Result<T> {
    let mut bytes = Vec::new();
    reader.take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err("graph input exceeds one MiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn checkpoint(selected: &str, phase: &str) {
    if selected == phase {
        println!("GRAPH_CHECKPOINT {phase}");
        let _ = std::io::stdout().flush();
        loop {
            std::thread::park();
        }
    }
}

struct Receiver {
    config: OwnerConfig,
    key: Keypair,
    directory: PathBuf,
    gate: Option<Gate>,
    fault: String,
}

impl Receiver {
    fn status(&self, arguments: Value) -> Result<Value> {
        if let (Some(gate), Some(rule)) = (&self.gate, &self.config.rule) {
            let (state, result) = gate.status(rule)?;
            return Ok(json!({"state":state,"result":result}));
        }
        let digest = arguments["artifactSha256"]
            .as_str()
            .ok_or("artifact digest absent")?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid artifact digest".into());
        }
        let path = self.directory.join(format!("verified-{digest}.json"));
        match std::fs::File::open(path) {
            Ok(file) => Ok(json!({"state":"completed","result":read::<Value>(file)?})),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(json!({"state":"waiting","result":null}))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn verify(&self, artifact: Value) -> Result<Value> {
        let candidate: ChioScope = serde_json::from_value(artifact.clone())?;
        validate_attenuation(&self.config.contract, &candidate)?;
        validate_attenuation(&candidate, &self.config.contract)?;
        let successor = self
            .config
            .successor
            .as_ref()
            .ok_or("verifier has no successor")?;
        let result = serde_json::to_value(Delivery {
            evidence: outcome(successor, &artifact, &self.key)?,
            artifact,
        })?;
        let digest = hash(&result["artifact"])?;
        let path = self.directory.join(format!("verified-{digest}.json"));
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
        file.write_all(&canonical_json_bytes(&result)?)?;
        file.as_file().sync_all()?;
        if let Err(error) = file.persist_noclobber(&path) {
            if error.error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.error.into());
            }
            if read::<Value>(std::fs::File::open(path)?)? != result {
                return Err("immutable verification result conflicts".into());
            }
        }
        #[cfg(unix)]
        std::fs::File::open(&self.directory)?.sync_all()?;
        checkpoint(&self.fault, "after_complete");
        Ok(result)
    }

    fn apply(&self, arguments: Value) -> Result<Value> {
        let delivery: Delivery = serde_json::from_value(arguments)?;
        let gate = self.gate.as_ref().ok_or("effect gate missing")?;
        let rule = self.config.rule.as_ref().ok_or("effect rule missing")?;
        let request = OutcomeEffectRequest {
            arguments: OutcomeEffectArguments {
                artifact_sha256: hash(&delivery.artifact)?,
                resource: rule.resource.clone(),
            },
            evidence: delivery.evidence,
        };
        let prepared = gate.prepare(&request, self.server_id(), "apply", NOW)?;
        checkpoint(&self.fault, "before_claim");
        let permit = gate.claim(&prepared, self.server_id(), "apply", NOW)?;
        checkpoint(&self.fault, "after_claim");
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.join("effects.log"))?;
        writeln!(log, "{}", request.arguments.artifact_sha256)?;
        log.sync_all()?;
        let mut approved = std::fs::File::create(self.directory.join("approved.scope.json"))?;
        approved.write_all(&canonical_json_bytes(&delivery.artifact)?)?;
        approved.sync_all()?;
        #[cfg(unix)]
        std::fs::File::open(&self.directory)?.sync_all()?;
        checkpoint(&self.fault, "after_effect");
        let result = if let Some(successor) = &self.config.successor {
            serde_json::to_value(Delivery {
                evidence: outcome(successor, &delivery.artifact, &self.key)?,
                artifact: delivery.artifact,
            })?
        } else {
            json!({"artifact":delivery.artifact,"artifactSha256":request.arguments.artifact_sha256,"completed":true})
        };
        // Outbound evidence becomes retrievable only with this completed
        // result. A claimed slot never exposes a success continuation.
        gate.complete(permit, &result)?;
        checkpoint(&self.fault, "after_complete");
        Ok(result)
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for Receiver {
    fn server_id(&self) -> &str {
        &self.config.role
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "status".into(),
            if self.config.role == "verifier" {
                "verify"
            } else {
                "apply"
            }
            .into(),
        ]
    }

    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let result = match (self.config.role.as_str(), tool) {
            (_, "status") => self.status(arguments),
            ("verifier", "verify") => self.verify(arguments),
            ("publisher" | "archive", "apply") => self.apply(arguments),
            _ => Err("receiver operation unavailable".into()),
        };
        result.map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

pub fn worker(directory: &Path, fault: &str) -> Result<()> {
    if !matches!(
        fault,
        "none" | "before_claim" | "after_claim" | "after_effect" | "after_complete"
    ) {
        return Err("unsupported graph fault phase".into());
    }
    let config: OwnerConfig = read(std::fs::File::open(directory.join("owner.json"))?)?;
    let key = Keypair::from_seed_hex(&std::fs::read_to_string(directory.join("key.seed"))?)?;
    let rpc: Rpc = read(std::io::stdin().lock())?;
    let gate = config
        .rule
        .as_ref()
        .map(|rule| Gate::open(&config.backend, directory, rule))
        .transpose()?;
    let mut kernel = crate::workload::configured_kernel(directory, key.clone())?;
    let role = config.role.clone();
    kernel.register_tool_server(Box::new(Receiver {
        config,
        key: key.clone(),
        directory: directory.into(),
        gate,
        fault: fault.into(),
    }));
    // This public test ingress issues an exact-operation capability under the
    // receiver's key. The courier never receives that key or chooses its scope.
    let id = Keypair::generate().public_key().to_hex();
    let response =
        crate::workload::invoke_authorized(&kernel, &key, &role, &rpc.tool, rpc.arguments, &id)?;
    let output = match response.output {
        Some(chio_kernel::ToolCallOutput::Value(value)) => Some(value),
        _ => None,
    };
    let reply = Reply {
        allowed: response.verdict == Verdict::Allow,
        output,
        receipt: response.receipt,
    };
    println!("{}", serde_json::to_string(&reply)?);
    Ok(())
}
