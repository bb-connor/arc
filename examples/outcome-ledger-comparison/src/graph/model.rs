use std::path::{Path, PathBuf};

use chio_core_types::capability::scope::ChioScope;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::body::ChioReceipt;
use chio_runtime_core::outcome_continuation::{
    ArtifactOutcome, OutcomeEffectRule, OutcomeEffectSlot, SignedArtifactOutcome,
    ARTIFACT_OUTCOME_SCHEMA,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{scope, Gate, Result, NOW};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfig {
    pub backend: String,
    pub role: String,
    pub contract: ChioScope,
    pub rule: Option<OutcomeEffectRule>,
    pub successor: Option<OutcomeEffectRule>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub artifact: Value,
    pub evidence: SignedArtifactOutcome,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rpc {
    pub tool: String,
    pub arguments: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub allowed: bool,
    pub output: Option<Value>,
    pub receipt: ChioReceipt,
}

/// Public endpoint information held by the untrusted courier. It contains no
/// receiver key or mutation API for owner rules and durable state.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub directory: PathBuf,
    pub key: PublicKey,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJob {
    pub endpoints: [Endpoint; 3],
    pub artifact: Value,
}

pub fn hash(value: &impl Serialize) -> Result<String> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

pub fn outcome(
    rule: &OutcomeEffectRule,
    artifact: &Value,
    key: &Keypair,
) -> Result<SignedArtifactOutcome> {
    Ok(SignedArtifactOutcome::sign(
        ArtifactOutcome {
            schema: ARTIFACT_OUTCOME_SCHEMA.into(),
            slot: rule.slot.clone(),
            predecessor_step_id: rule.predecessor_step_id.clone(),
            contract_sha256: rule.contract_sha256.clone(),
            artifact_sha256: hash(artifact)?,
            passed: true,
            verified_at_unix_ms: NOW,
        },
        key,
    )?)
}

fn rule(
    receiver: &Keypair,
    verifier: &Keypair,
    step: &str,
    predecessor: &str,
    contract: String,
) -> OutcomeEffectRule {
    OutcomeEffectRule {
        slot: OutcomeEffectSlot {
            receiver_id: receiver.public_key().to_hex(),
            workflow_id: "reviewed-scope-distribution".into(),
            step_id: step.into(),
        },
        predecessor_step_id: predecessor.into(),
        verifier_key: verifier.public_key(),
        contract_sha256: contract,
        server_id: step.into(),
        tool_name: "apply".into(),
        resource: format!("{step}/approved-scopes"),
        valid_from_unix_ms: NOW - 1000,
        valid_until_unix_ms: NOW + 1000,
    }
}

pub fn provision(root: &Path, backend: &str) -> Result<[Endpoint; 3]> {
    let keys = [
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    ];
    let contract = scope("source-checkout", "read");
    let publisher = rule(
        &keys[1],
        &keys[0],
        "publisher",
        "verifier",
        hash(&contract)?,
    );
    let archive = rule(
        &keys[2],
        &keys[1],
        "archive",
        "publisher",
        hash(&json!({"publicationRule":publisher,"requiredState":"completed"}))?,
    );
    let configs = [
        OwnerConfig {
            backend: backend.into(),
            role: "verifier".into(),
            contract: contract.clone(),
            rule: None,
            successor: Some(publisher.clone()),
        },
        OwnerConfig {
            backend: backend.into(),
            role: "publisher".into(),
            contract: contract.clone(),
            rule: Some(publisher),
            successor: Some(archive.clone()),
        },
        OwnerConfig {
            backend: backend.into(),
            role: "archive".into(),
            contract,
            rule: Some(archive),
            successor: None,
        },
    ];
    let mut endpoints = Vec::new();
    for (config, key) in configs.iter().zip(keys) {
        let directory = root.join(&config.role);
        std::fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::write(
            directory.join("owner.json"),
            serde_json::to_vec_pretty(config)?,
        )?;
        std::fs::write(directory.join("key.seed"), key.seed_hex())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                directory.join("key.seed"),
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        if let Some(rule) = &config.rule {
            drop(Gate::open(backend, &directory, rule)?);
        }
        endpoints.push(Endpoint {
            directory,
            key: key.public_key(),
            role: config.role.clone(),
            socket: None,
        });
    }
    endpoints
        .try_into()
        .map_err(|_| "expected three receiver endpoints".into())
}
