//! `chio trust config check`: validate a trust-control access configuration
//! and print what it grants, never a secret or secret digest.

use std::path::Path;

use chio_control_plane::trust_control::caller_credentials::{
    AccessConfigDocument, CredentialEntry, CredentialKind, CredentialSecret, TenantAuthority,
    TrustAccessConfig,
};
use chio_control_plane::trust_control::credential_roles::CredentialRole;
use serde::Serialize;
use serde_json::json;

use crate::trust_access_file::load_trust_access;
use crate::CliError;

pub(crate) fn cmd_trust_config_check(
    access_config: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let access = load_trust_access(access_config)?;
    let config = access.config();
    let credentials: Vec<_> = access
        .credentials()
        .summaries()
        .map(|(id, kind, scopes, tenant_authority)| {
            json!({
                "id": id,
                "kind": kind,
                "tenantAuthority": tenant_authority,
                "scopes": scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    let peers: Vec<_> = access
        .peers()
        .iter()
        .map(|peer| {
            json!({
                "nodeId": peer.node_id,
                "internalUrl": peer.internal_url,
                "publicKey": peer.public_key.to_hex(),
                "scopes": peer.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    let identity = access.peers().identity().map(|identity| {
        json!({
            "nodeId": identity.node_id,
            "nodePublicKey": access.node_keypair().map(|key| key.public_key().to_hex()),
        })
    });
    let report = json!({
        "deployment": config.deployment(),
        "internalListen": config.internal_listen().to_string(),
        "credentials": credentials,
        "cluster": identity,
        "peers": peers,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("deployment:      {}", config.deployment());
    println!("internal listen: {}", config.internal_listen());
    for credential in report["credentials"].as_array().into_iter().flatten() {
        println!(
            "credential {} ({}, tenant authority {}): {}",
            credential["id"].as_str().unwrap_or_default(),
            credential["kind"].as_str().unwrap_or_default(),
            credential["tenantAuthority"],
            credential["scopes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|scope| scope.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if let Some(identity) = access.peers().identity() {
        println!("cluster node:    {}", identity.node_id);
    }
    for peer in access.peers().iter() {
        println!(
            "peer {} via {}: {}",
            peer.node_id,
            peer.internal_url,
            peer.scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    Ok(())
}

pub(crate) struct CredentialEntryArgs<'a> {
    pub(crate) id: &'a str,
    pub(crate) role: Option<&'a str>,
    pub(crate) kind: Option<CredentialKind>,
    pub(crate) deployment: &'a str,
    pub(crate) secret_file: Option<&'a Path>,
    pub(crate) secret_env: Option<&'a str>,
    pub(crate) scopes: &'a [String],
    pub(crate) tenant: Option<&'a str>,
}

/// The entry's kind and scopes: a role preset widened by each `--scope` not
/// already in it, or, without a role, `--kind` and exactly the `--scope`s.
fn kind_and_scopes(
    args: &CredentialEntryArgs<'_>,
) -> Result<(CredentialKind, Vec<String>), CliError> {
    let Some(name) = args.role else {
        let kind = args
            .kind
            .ok_or_else(|| CliError::cli_other_error("pass --role or --kind".to_owned()))?;
        return Ok((kind, args.scopes.to_vec()));
    };
    let role = CredentialRole::parse(name).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "unknown credential role \"{name}\"; expected one of {}",
            CredentialRole::ALL
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    if role.requires_tenant() && args.tenant.is_none() {
        return Err(CliError::cli_other_error(format!(
            "role {} requires --tenant",
            role.as_str()
        )));
    }
    let mut scopes: Vec<String> = role
        .scopes()
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    for extra in args.scopes {
        if scopes.contains(extra) {
            return Err(CliError::cli_other_error(format!(
                "scope \"{extra}\" is already in role {}",
                role.as_str()
            )));
        }
        scopes.push(extra.clone());
    }
    Ok((role.kind(), scopes))
}

fn read_secret(args: &CredentialEntryArgs<'_>) -> Result<CredentialSecret, CliError> {
    let mut secret = match (args.secret_file, args.secret_env) {
        (Some(path), None) => {
            let bytes = chio_control_plane::read_private_signing_custody(path, 4096)?;
            String::from_utf8(bytes.to_vec()).map_err(|_| {
                CliError::cli_other_error("credential secret is not valid UTF-8".to_owned())
            })?
        }
        (None, Some(name)) => std::env::var(name).map_err(|_| {
            CliError::cli_other_error(format!("environment variable {name} is not set"))
        })?,
        _ => {
            return Err(CliError::cli_other_error(
                "pass exactly one of --secret-file or --secret-env".to_owned(),
            ))
        }
    };
    if secret.ends_with('\n') {
        secret.pop();
    }
    CredentialSecret::parse(secret).map_err(|error| CliError::cli_other_error(error.to_string()))
}

#[derive(Serialize)]
struct CredentialsTable<'a> {
    credentials: &'a [CredentialEntry],
}

/// Print one `[[credentials]]` entry after validating it as the sole
/// credential of an access configuration.
pub(crate) fn cmd_trust_config_credential(args: &CredentialEntryArgs<'_>) -> Result<(), CliError> {
    let (kind, scopes) = kind_and_scopes(args)?;
    let secret = read_secret(args)?;
    let tenant_authority = args.tenant.map_or(TenantAuthority::Deployment, |tenant| {
        TenantAuthority::Tenant(tenant.to_owned())
    });
    let entry = CredentialEntry::new(
        args.id.to_owned(),
        kind,
        &secret,
        scopes,
        args.deployment.to_owned(),
        tenant_authority,
    );
    TrustAccessConfig::from_document(AccessConfigDocument::unclustered(
        args.deployment.to_owned(),
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        vec![entry.clone()],
    ))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let table = toml::to_string(&CredentialsTable {
        credentials: std::slice::from_ref(&entry),
    })
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    print!("{table}");
    Ok(())
}
