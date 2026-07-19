use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::capabilities::{
    build_default_capabilities_from_scope, build_runtime_default_capabilities,
};
use super::guards::{build_guard_pipeline, build_post_invocation_pipeline};
use super::issuance::{
    materialize_reputation_issuance_policy, materialize_runtime_assurance_policy,
};
use super::types::{
    ChioPolicy, KernelPolicyConfig, LoadedPolicy, PolicyAssetDigest, PolicyError, PolicyFormat,
    PolicyIdentity,
};
use super::util::{
    hash_bytes, hash_json_value, runtime_hash_for_chio_yaml, runtime_hash_for_hushspec,
};

/// Load a policy from a YAML file.
///
/// Auto-detects whether the file is a HushSpec policy (contains `hushspec:`
/// top-level key) or a Chio YAML policy. HushSpec inputs are resolved,
/// validated, compiled, and kept alive as runtime state rather than being
/// reduced to an empty fallback policy shell.
pub fn load_policy(path: &Path) -> Result<LoadedPolicy, PolicyError> {
    load_policy_with_optional_approver_directory(path, None, None)
}

/// Load policy with an authenticated approver-directory authority.
pub fn load_policy_with_approver_directory(
    path: &Path,
    directory: &chio_policy::AuthenticatedApproverDirectorySnapshot,
) -> Result<LoadedPolicy, PolicyError> {
    load_policy_with_optional_approver_directory(path, Some(directory), None)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedApproverDirectoryDocument {
    version: u64,
    approver_ids: Vec<String>,
}

/// Load a product runtime policy with explicit threshold trust authorities.
///
/// The directory and proposal authority are one closed configuration: either
/// both are absent for a non-threshold policy, or both must be present for a
/// threshold policy. This prevents policy compilation from silently selecting
/// the kernel signer as the proposal trust root.
pub fn load_policy_for_runtime(
    path: &Path,
    approver_directory_path: Option<&Path>,
    threshold_proposal_authority: Option<&chio_core::PublicKey>,
) -> Result<LoadedPolicy, PolicyError> {
    let (directory, proposal_authority) = match (
        approver_directory_path,
        threshold_proposal_authority,
    ) {
        (None, None) => return load_policy(path),
        (Some(_), None) | (None, Some(_)) => {
            return Err(PolicyError::Invalid(
                "threshold approval runtime configuration requires both an authenticated approver directory and a proposal-authority public key"
                    .to_string(),
            ));
        }
        (Some(directory_path), Some(proposal_authority)) => {
            let contents = std::fs::read_to_string(directory_path)?;
            let document: AuthenticatedApproverDirectoryDocument = serde_yml::from_str(&contents)?;
            let directory =
                chio_policy::AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(
                    document.version,
                    document.approver_ids,
                )?;
            (directory, proposal_authority)
        }
    };
    let loaded = load_policy_with_optional_approver_directory(
        path,
        Some(&directory),
        Some(proposal_authority),
    )?;
    if loaded.threshold_approval_resolver.is_none() {
        return Err(PolicyError::Invalid(
            "threshold approval authorities were configured for a policy without a threshold approval requirement"
                .to_string(),
        ));
    }
    Ok(loaded)
}

fn load_policy_with_optional_approver_directory(
    path: &Path,
    directory: Option<&chio_policy::AuthenticatedApproverDirectorySnapshot>,
    threshold_proposal_authority: Option<&chio_core::PublicKey>,
) -> Result<LoadedPolicy, PolicyError> {
    let contents = std::fs::read_to_string(path)?;
    let source_hash = hash_bytes(contents.as_bytes());

    if chio_policy::is_hushspec_format(&contents) {
        return load_hushspec_policy(path, source_hash, directory, threshold_proposal_authority);
    }

    let policy: ChioPolicy = serde_yml::from_str(&contents)?;
    let default_capabilities = build_runtime_default_capabilities(&policy)?;
    let (active_defense_rules, active_defense_assets) =
        load_active_defense_rules(path, &policy.active_defense.rule_files)?;
    let source_hash =
        source_hash_with_assets(PolicyFormat::ChioYaml, &source_hash, &active_defense_assets)?;
    let base_runtime_hash = runtime_hash_for_chio_yaml(&policy, &default_capabilities)?;
    let runtime_hash = runtime_hash_with_assets(
        PolicyFormat::ChioYaml,
        &base_runtime_hash,
        &active_defense_assets,
    )?;

    Ok(LoadedPolicy {
        format: PolicyFormat::ChioYaml,
        identity: PolicyIdentity {
            source_hash,
            runtime_hash,
        },
        kernel: policy.kernel.clone(),
        default_capabilities,
        guard_pipeline: build_guard_pipeline(&policy.guards)?,
        post_invocation_pipeline: build_post_invocation_pipeline(&policy.guards)?,
        issuance_policy: None,
        runtime_assurance_policy: None,
        threshold_approval_resolver: None,
        threshold_approval_policy_authority: None,
        active_defense: policy.active_defense,
        active_defense_rules,
    })
}

/// Load a HushSpec policy and compile it into the runtime policy materialization.
fn load_hushspec_policy(
    path: &Path,
    source_hash: String,
    directory: Option<&chio_policy::AuthenticatedApproverDirectorySnapshot>,
    threshold_proposal_authority: Option<&chio_core::PublicKey>,
) -> Result<LoadedPolicy, PolicyError> {
    let spec = chio_policy::resolve_from_path(path)?;
    let validation = chio_policy::validate(&spec);
    if !validation.is_valid() {
        let messages: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return Err(PolicyError::Invalid(format!(
            "HushSpec validation failed: {}",
            messages.join("; ")
        )));
    }

    let source_dir = path.parent();
    let auxiliary_assets = hushspec_auxiliary_asset_digests(&spec, source_dir)?;
    let source_hash = hushspec_source_hash_with_assets(&source_hash, &auxiliary_assets)?;
    let mut compiled = match directory {
        Some(directory) => chio_policy::compile_policy_with_source_and_approver_directory(
            &spec,
            Some(path),
            directory,
        )?,
        None => chio_policy::compile_policy_with_source(&spec, Some(path))?,
    };
    let kernel = KernelPolicyConfig::default();
    let default_capabilities =
        build_default_capabilities_from_scope(&compiled.default_scope, kernel.max_capability_ttl);
    let issuance_policy = materialize_reputation_issuance_policy(&spec)?;
    let runtime_assurance_policy = materialize_runtime_assurance_policy(&spec)?;
    let threshold_requirement = compiled
        .threshold_approval
        .as_ref()
        .and_then(chio_policy::ThresholdApprovalResolverSnapshot::requirement);
    let runtime_hash = runtime_hash_for_hushspec(
        &kernel,
        &default_capabilities,
        &spec,
        &auxiliary_assets,
        threshold_requirement.as_ref(),
        threshold_proposal_authority,
    )?;
    let threshold_approval_resolver = compiled
        .threshold_approval
        .take()
        .map(|snapshot| {
            snapshot
                .with_policy_hash(runtime_hash.clone())
                .map(chio_policy::ThresholdApprovalResolver::new)
        })
        .transpose()?;

    Ok(LoadedPolicy {
        format: PolicyFormat::HushSpec,
        identity: PolicyIdentity {
            source_hash,
            runtime_hash,
        },
        kernel,
        default_capabilities,
        guard_pipeline: compiled.guards,
        post_invocation_pipeline: compiled.post_invocation,
        issuance_policy,
        runtime_assurance_policy,
        threshold_approval_resolver,
        threshold_approval_policy_authority: threshold_proposal_authority.cloned(),
        active_defense: super::types::ActiveDefensePolicyConfig::default(),
        active_defense_rules: Vec::new(),
    })
}

fn load_active_defense_rules(
    policy_path: &Path,
    rule_files: &[PathBuf],
) -> Result<(Vec<chio_quarantine::TemporalRule>, Vec<PolicyAssetDigest>), PolicyError> {
    let source_dir = policy_path.parent();
    let limits = chio_quarantine::RuleLimits::default();
    let mut loaded = Vec::with_capacity(rule_files.len());
    let mut assets = Vec::with_capacity(rule_files.len());
    for configured in rule_files {
        let configured_text = configured.to_string_lossy();
        if configured_text.trim().is_empty() || configured_text.contains('\0') {
            return Err(PolicyError::Invalid(
                "active-defense rule path is invalid".to_string(),
            ));
        }
        let resolved = resolve_policy_asset_path(&configured_text, source_dir);
        let bytes = std::fs::read(&resolved).map_err(|error| {
            PolicyError::Invalid(format!(
                "failed to read active-defense rule '{}': {error}",
                resolved.display()
            ))
        })?;
        let rule = chio_quarantine::TemporalRule::parse_json(&bytes, &limits).map_err(|error| {
            PolicyError::Invalid(format!(
                "active-defense rule '{}' is invalid: {error}",
                resolved.display()
            ))
        })?;
        let identity_path = std::fs::canonicalize(&resolved)
            .unwrap_or_else(|_| resolved.clone())
            .display()
            .to_string();
        assets.push(PolicyAssetDigest {
            field: "active_defense.rule_files",
            path: identity_path,
            sha256: hash_bytes(&bytes),
        });
        loaded.push(rule);
    }
    loaded.sort_by(|left, right| {
        (left.policy_version(), left.rule_id()).cmp(&(right.policy_version(), right.rule_id()))
    });
    if loaded.windows(2).any(|pair| {
        pair[0].policy_version() == pair[1].policy_version()
            && pair[0].rule_id() == pair[1].rule_id()
    }) {
        return Err(PolicyError::Invalid(
            "active-defense rules contain a duplicate policy-version and rule-id binding"
                .to_string(),
        ));
    }
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((loaded, assets))
}

fn hushspec_auxiliary_asset_digests(
    spec: &chio_policy::HushSpec,
    source_dir: Option<&Path>,
) -> Result<Vec<PolicyAssetDigest>, PolicyError> {
    let mut assets = Vec::new();
    let Some(threat_intel) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.detection.as_ref())
        .and_then(|detection| detection.threat_intel.as_ref())
    else {
        return Ok(assets);
    };
    if !threat_intel.enabled.unwrap_or(true) {
        return Ok(assets);
    }
    let Some(pattern_db) = threat_intel.pattern_db.as_deref() else {
        return Ok(assets);
    };

    let resolved_path = resolve_policy_asset_path(pattern_db, source_dir);
    let bytes = std::fs::read(&resolved_path).map_err(|error| {
        PolicyError::Invalid(format!(
            "failed to read HushSpec auxiliary asset detection.threat_intel.pattern_db '{}' (resolved to '{}'): {error}",
            pattern_db,
            resolved_path.display()
        ))
    })?;
    let identity_path = std::fs::canonicalize(&resolved_path)
        .unwrap_or_else(|_| resolved_path.clone())
        .display()
        .to_string();
    assets.push(PolicyAssetDigest {
        field: "extensions.detection.threat_intel.pattern_db",
        path: identity_path,
        sha256: hash_bytes(&bytes),
    });
    Ok(assets)
}

fn resolve_policy_asset_path(path: &str, source_dir: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return candidate;
    }

    match source_dir {
        Some(dir) => dir.join(candidate),
        None => candidate,
    }
}

fn hushspec_source_hash_with_assets(
    source_hash: &str,
    auxiliary_assets: &[PolicyAssetDigest],
) -> Result<String, PolicyError> {
    source_hash_with_assets(PolicyFormat::HushSpec, source_hash, auxiliary_assets)
}

fn source_hash_with_assets(
    format: PolicyFormat,
    source_hash: &str,
    auxiliary_assets: &[PolicyAssetDigest],
) -> Result<String, PolicyError> {
    if auxiliary_assets.is_empty() {
        return Ok(source_hash.to_string());
    }
    hash_json_value(&serde_json::json!({
        "format": format.as_str(),
        "source_hash": source_hash,
        "auxiliary_assets": auxiliary_assets,
    }))
}

fn runtime_hash_with_assets(
    format: PolicyFormat,
    runtime_hash: &str,
    auxiliary_assets: &[PolicyAssetDigest],
) -> Result<String, PolicyError> {
    if auxiliary_assets.is_empty() {
        return Ok(runtime_hash.to_string());
    }
    hash_json_value(&serde_json::json!({
        "format": format.as_str(),
        "runtime_hash": runtime_hash,
        "auxiliary_assets": auxiliary_assets,
    }))
}

/// Parse a policy from a YAML string.
pub fn parse_policy(yaml: &str) -> Result<ChioPolicy, PolicyError> {
    let policy: ChioPolicy = serde_yml::from_str(yaml)?;
    Ok(policy)
}
