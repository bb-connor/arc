//! `chio trust config check`: validate a trust-control access configuration
//! and print what it grants, never a secret or secret digest.

use std::path::Path;

use chio_control_plane::trust_control::caller_credentials::{
    CredentialKind, TenantAuthority, TrustAccess, TrustAccessConfig,
};
use chio_control_plane::trust_control::credential_roles::CredentialRole;
use chio_egress_contract::{private_network_allowance_digest, EgressAllowanceSet};
use serde_json::json;

use crate::CliError;

pub(crate) fn cmd_trust_config_check(
    access_config: &Path,
    egress: &EgressAllowanceSet,
    json_output: bool,
) -> Result<(), CliError> {
    let access = TrustAccess::load(access_config)?;
    let config = access.config();
    let credentials: Vec<_> = access
        .credentials()
        .summaries()
        .map(|(id, kind, scopes, tenant_authority)| {
            json!({
                "id": id,
                "kind": match kind {
                    CredentialKind::Caller => "caller",
                    CredentialKind::Deployment => "deployment",
                },
                "tenantAuthority": match tenant_authority {
                    TenantAuthority::Deployment => json!("deployment"),
                    TenantAuthority::Tenant(tenant) => json!({ "tenant": tenant }),
                },
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
    let egress_digest = private_network_allowance_digest(egress.entries())
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let report = json!({
        "deployment": config.deployment,
        "internalListen": config.internal_listen.to_string(),
        "credentials": credentials,
        "cluster": identity,
        "peers": peers,
        "egressAllowanceDigest": egress_digest,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("deployment:      {}", config.deployment);
    println!("internal listen: {}", config.internal_listen);
    println!("egress allowances: {egress_digest}");
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
    pub(crate) kind: Option<&'a str>,
    pub(crate) deployment: &'a str,
    pub(crate) secret_file: Option<&'a Path>,
    pub(crate) secret_env: Option<&'a str>,
    pub(crate) scopes: &'a [String],
    pub(crate) tenant: Option<&'a str>,
}

/// The entry's kind and scopes: a role preset widened by each `--scope` not
/// already in it, or, without a role, `--kind` and exactly the `--scope`s.
fn kind_and_scopes(args: &CredentialEntryArgs<'_>) -> Result<(String, Vec<String>), CliError> {
    let Some(name) = args.role else {
        let kind = args
            .kind
            .ok_or_else(|| CliError::cli_other_error("pass --role or --kind".to_owned()))?;
        return Ok((kind.to_owned(), args.scopes.to_vec()));
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
    let kind = match role.kind() {
        CredentialKind::Caller => "caller",
        CredentialKind::Deployment => "deployment",
    };
    Ok((kind.to_owned(), scopes))
}

fn read_secret(args: &CredentialEntryArgs<'_>) -> Result<String, CliError> {
    let secret = match (args.secret_file, args.secret_env) {
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
    let secret = secret.strip_suffix('\n').unwrap_or(&secret).to_owned();
    if secret.is_empty() || secret.chars().any(char::is_control) || secret.trim() != secret {
        return Err(CliError::cli_other_error(
            "credential secret must be non-empty without padding or control characters".to_owned(),
        ));
    }
    Ok(secret)
}

/// Print one validated `[[credentials]]` entry. The entry is parsed back as a
/// complete access configuration before it is printed.
pub(crate) fn cmd_trust_config_credential(args: &CredentialEntryArgs<'_>) -> Result<(), CliError> {
    let (kind, scopes) = kind_and_scopes(args)?;
    let secret = read_secret(args)?;
    let tenant_authority = match args.tenant {
        None => "\"deployment\"".to_owned(),
        Some(tenant) => format!("{{ tenant = {} }}", toml_string(tenant)),
    };
    let entry = format!(
        "[[credentials]]\nid = {}\nkind = {}\nsecret_sha256 = \"{}\"\nscopes = [{}]\ndeployment = {}\ntenant_authority = {tenant_authority}\n",
        toml_string(args.id),
        toml_string(&kind),
        chio_core::sha256_hex(secret.as_bytes()),
        scopes
            .iter()
            .map(|scope| toml_string(scope))
            .collect::<Vec<_>>()
            .join(", "),
        toml_string(args.deployment),
    );
    let document = format!(
        "deployment = {}\ninternal_listen = \"127.0.0.1:0\"\n{entry}",
        toml_string(args.deployment)
    );
    TrustAccessConfig::from_toml_str(&document)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    print!("{entry}");
    Ok(())
}

fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
