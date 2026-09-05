use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use chio_control_plane::prepare_private_directory;
use chio_core_types::capability::attenuation::{
    compute_attenuation_witness, delegate, scope_hash, AttenuationProof,
};
use chio_core_types::capability::scope::{ChioScope, Operation};
use chio_core_types::capability::token::{
    CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody,
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::ScopeAttenuation;
use chio_manifest::ToolManifest;
use chio_process::worker::WorkerService;
use chio_process::{ProcessRuntime, ProcessState};
use serde_json::json;

use super::state::{error, kernel, write_secret, Child, Config, Host, Lease, Record};
use crate::CliError;

fn select_scope(
    parent: &ChioScope,
    child: &Child,
    manifests: &[ToolManifest],
) -> Result<ChioScope, CliError> {
    let mut grants = Vec::new();
    for route in &child.tools {
        if !manifests.iter().any(|server| {
            server.server_id == route.server_id
                && server.tools.iter().any(|tool| tool.name == route.tool_name)
        }) {
            return Err(error(
                "child route does not exist in the host tool definitions",
            ));
        }
        let selected: Vec<_> = parent
            .grants
            .iter()
            .filter(|grant| {
                (grant.server_id == route.server_id || grant.server_id == "*")
                    && (grant.tool_name == route.tool_name || grant.tool_name == "*")
                    && grant.operations.contains(&Operation::Invoke)
            })
            .collect();
        if selected.is_empty() {
            return Err(error("child tool route exceeds its parent's scope"));
        }
        for grant in selected {
            let mut grant = grant.clone();
            grant.server_id = route.server_id.clone();
            grant.tool_name = route.tool_name.clone();
            grants.push(grant);
        }
    }
    Ok(ChioScope {
        grants,
        ..Default::default()
    })
}

pub(super) fn child_capability(
    parent: &CapabilityToken,
    parent_key: &Keypair,
    child: &Child,
    subject: &Keypair,
    issuer: &Keypair,
    manifests: &[ToolManifest],
) -> Result<CapabilityToken, CliError> {
    let scope = select_scope(&parent.scope, child, manifests)?;
    let delegation = delegate(
        parent,
        &scope,
        parent_key,
        &subject.public_key(),
        ScopeAttenuation {
            budget_share_bps: Some(child.budget_share_bps),
            ..Default::default()
        },
        parent.issued_at,
        *uuid::Uuid::new_v4().as_bytes(),
    )
    .map_err(error)?;
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: uuid::Uuid::new_v4().to_string(),
                issuer: parent.issuer.clone(),
                subject: subject.public_key(),
                issued_at: parent.issued_at,
                expires_at: parent.expires_at,
                delegation_chain: delegation.complete_chain(),
                aggregate_invocation_budget: parent.aggregate_invocation_budget.clone(),
                scope: scope.clone(),
            },
            caveats: parent.caveats.clone(),
            scope_attenuations: parent.scope_attenuations.clone().unwrap_or_default(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent.scope).map_err(error)?,
                child_scope_hash: scope_hash(&scope).map_err(error)?,
                normalized_subset_proof: compute_attenuation_witness(&parent.scope, &scope)
                    .map_err(error)?,
            },
            budget_share_bps: Some(child.budget_share_bps),
        },
        issuer,
    )
    .map_err(error)
}

pub(super) fn init(config: &Path, state: &Path) -> Result<(), CliError> {
    let config = Config::load(config)?;
    let policy = chio_control_plane::policy::load_policy(&config.policy)?;
    if config.limits.max_depth > policy.kernel.delegation_depth_limit {
        return Err(error(
            "process tree depth exceeds the policy delegation limit",
        ));
    }
    let identity = policy.identity.clone();
    let defaults = policy.default_capabilities.clone();
    let lease = Lease::acquire(state, true)?;
    let (kernel, issuer) = kernel(lease.directory.path(), policy)?;
    let (servers, manifests) = super::serving::connect(&config, &kernel, lease.directory.path())?;
    let root_key = Keypair::generate();
    let root = kernel
        .issue_capability(
            &root_key.public_key(),
            defaults[0].scope.clone(),
            defaults[0].ttl,
        )
        .map_err(error)?;
    for template in &config.spawn_templates {
        select_scope(
            &root.scope,
            &Child {
                id: template.id.clone(),
                parent: "root".to_owned(),
                tools: template.tools.clone(),
                budget_share_bps: template.max_budget_share_bps,
            },
            &manifests,
        )?;
    }
    // Validate and sign the initial topology before creating process rows.
    let mut identities = BTreeMap::from([("root".to_owned(), (root.clone(), root_key))]);
    for child in &config.children {
        let (parent, parent_key) = identities
            .get(&child.parent)
            .ok_or_else(|| error("missing parent"))?;
        let subject = Keypair::generate();
        let capability =
            child_capability(parent, parent_key, child, &subject, &issuer, &manifests)?;
        identities.insert(child.id.clone(), (capability, subject));
    }
    let runtime = ProcessRuntime::open(lease.directory.path().join("process.db"), Arc::new(kernel))
        .map_err(error)?;
    runtime
        .create_root("root", &root, config.limits)
        .map_err(error)?;
    for child in &config.children {
        let (capability, _) = identities
            .get(&child.id)
            .ok_or_else(|| error("missing child capability"))?;
        runtime
            .spawn(&child.parent, &child.id, capability)
            .map_err(error)?;
    }
    if !config.spawn_templates.is_empty() {
        let keys: Vec<_> = identities
            .iter()
            .map(|(id, (_, key))| (id.clone(), key))
            .collect();
        runtime.registry().provision_signers(&keys).map_err(error)?;
    }
    let record = Record {
        config,
        source_policy_hash: identity.source_hash,
        runtime_policy_hash: identity.runtime_hash,
        manifests,
    };
    let encoded = canonical_json_bytes(&record).map_err(error)?;
    if encoded.len() as u64 > super::state::MAX_CONFIG_BYTES {
        return Err(error("configuration and tool definitions exceed one MiB"));
    }
    write_secret(
        &lease.directory,
        std::ffi::OsStr::new("host.json"),
        &encoded,
    )?;
    lease.directory.validate_path_identity()?;
    drop(servers);
    println!(
        "{}",
        json!({"initialized": true, "processes": identities.len(), "kernel_key": issuer.public_key().to_hex()})
    );
    Ok(())
}

pub(super) fn credential(
    state: &Path,
    process: &str,
    socket: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let host = Host::open(state, false)?;
    let process = host.runtime.process(process).map_err(error)?;
    if process.state != ProcessState::Running {
        return Err(error("cannot issue credentials for a cancelled process"));
    }
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = prepare_private_directory(parent)?;
    use std::os::unix::fs::PermissionsExt;
    if std::fs::metadata(directory.path())?.permissions().mode() & 0o077 != 0 {
        return Err(error(
            "connection descriptor directory must be private (0700)",
        ));
    }
    let name = out
        .file_name()
        .ok_or_else(|| error("missing descriptor filename"))?;
    if directory.path().join(name).symlink_metadata().is_ok() {
        return Err(error("connection descriptor already exists"));
    }
    let socket_parent = socket
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let socket_path = std::fs::canonicalize(socket_parent)?.join(
        socket
            .file_name()
            .ok_or_else(|| error("missing socket filename"))?,
    );
    let descriptor = connection(&host, &process.id, &socket_path)?;
    write_secret(
        &directory,
        name,
        &canonical_json_bytes(&descriptor).map_err(error)?,
    )?;
    directory.validate_path_identity()?;
    println!(
        "{}",
        json!({"issued": true, "process_id": process.id, "expires_at": process.capability.expires_at})
    );
    Ok(())
}

pub(super) fn connection(
    host: &Host,
    process_id: &str,
    socket_path: &Path,
) -> Result<serde_json::Value, CliError> {
    let process = host.runtime.process(process_id).map_err(error)?;
    if process.state != ProcessState::Running {
        return Err(error("cannot issue credentials for a cancelled process"));
    }
    let mut tools = Vec::new();
    let mut aliases = BTreeSet::new();
    for server in &host.record.manifests {
        for tool in &server.tools {
            if !process.capability.scope.grants.iter().any(|grant| {
                (grant.server_id == server.server_id || grant.server_id == "*")
                    && (grant.tool_name == tool.name || grant.tool_name == "*")
                    && grant.operations.contains(&Operation::Invoke)
            }) {
                continue;
            }
            let candidate = format!("{}__{}", server.server_id, tool.name);
            let alias = if candidate.len() <= 64
                && candidate
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                candidate
            } else {
                format!("tool_{}", &sha256_hex(candidate.as_bytes())[..24])
            };
            if !aliases.insert(alias.clone()) {
                return Err(error("model tool alias collision"));
            }
            tools.push(
                json!({"name": alias, "server_id": server.server_id, "tool_name": tool.name,
                "description": tool.description, "input_schema": tool.input_schema}),
            );
        }
    }
    let credential = WorkerService::new(host.runtime.clone())
        .issue_credential(&process.id, process.capability.expires_at)
        .map_err(error)?;
    Ok(
        json!({"schema": "chio.process.connection.v1", "protocol": chio_process::worker::PROTOCOL,
        "process_id": process.id, "socket_path": socket_path, "credential": credential.expose_secret(),
        "expires_at": process.capability.expires_at, "kernel_key": host.kernel.public_key().to_hex(), "tools": tools}),
    )
}
