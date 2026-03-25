use std::fs;
use std::path::Path;

use crate::enterprise_federation::{EnterpriseProviderRecord, EnterpriseProviderRegistry};
use crate::policy::{load_policy, DefaultCapability};
use crate::{
    certify, load_or_create_authority_keypair, require_control_token, trust_control, CliError,
};

fn require_enterprise_providers_file(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::Other(
            "provider admin requires --enterprise-providers-file when --control-url is not set"
                .to_string(),
        )
    })
}

fn require_certification_registry_file(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::Other(
            "certification registry commands require --certification-registry-file when --control-url is not set"
                .to_string(),
        )
    })
}

fn load_enterprise_provider_registry_local(
    path: &Path,
) -> Result<EnterpriseProviderRegistry, CliError> {
    if path.exists() {
        EnterpriseProviderRegistry::load(path)
    } else {
        Ok(EnterpriseProviderRegistry::default())
    }
}

pub(crate) fn load_admission_policy(
    path: &Path,
) -> Result<Option<pact_policy::HushSpec>, CliError> {
    let contents = fs::read_to_string(path)?;
    if pact_policy::is_hushspec_format(&contents) {
        return pact_policy::resolve_from_path(path)
            .map(Some)
            .map_err(|error| CliError::Other(error.to_string()));
    }
    Ok(None)
}

pub(crate) fn cmd_trust_provider_list(
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_enterprise_providers()?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let registry = load_enterprise_provider_registry_local(path)?;
        trust_control::EnterpriseProviderListResponse {
            configured: true,
            count: registry.providers.len(),
            providers: registry.providers.into_values().collect(),
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("providers: {}", response.count);
        for provider in response.providers {
            println!(
                "- {} [{}] enabled={} valid={}",
                provider.provider_id,
                serde_json::to_string(&provider.kind).unwrap_or_default(),
                provider.enabled,
                provider.validation_errors.is_empty()
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_provider_get(
    provider_id: &str,
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let provider = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.get_enterprise_provider(provider_id)?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let registry = load_enterprise_provider_registry_local(path)?;
        registry
            .providers
            .get(provider_id)
            .cloned()
            .ok_or_else(|| {
                CliError::Other(format!("enterprise provider `{provider_id}` was not found"))
            })?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&provider)?);
    } else {
        println!("provider_id: {}", provider.provider_id);
        println!(
            "kind:        {}",
            serde_json::to_string(&provider.kind).unwrap_or_default()
        );
        println!("enabled:     {}", provider.enabled);
        println!(
            "validated:   {}",
            if provider.validation_errors.is_empty() {
                "true"
            } else {
                "false"
            }
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_provider_upsert(
    input_path: &Path,
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let provider: EnterpriseProviderRecord = serde_json::from_slice(&fs::read(input_path)?)?;
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .upsert_enterprise_provider(&provider.provider_id, &provider)?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let mut registry = load_enterprise_provider_registry_local(path)?;
        registry.upsert(provider.clone());
        registry.save(path)?;
        registry
            .providers
            .get(&provider.provider_id)
            .cloned()
            .ok_or_else(|| {
                CliError::Other("provider upsert did not persist the requested record".to_string())
            })?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("provider upserted: {}", response.provider_id);
    }

    Ok(())
}

pub(crate) fn cmd_trust_provider_delete(
    provider_id: &str,
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.delete_enterprise_provider(provider_id)?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let mut registry = load_enterprise_provider_registry_local(path)?;
        let deleted = registry.remove(provider_id);
        registry.save(path)?;
        trust_control::EnterpriseProviderDeleteResponse {
            provider_id: provider_id.to_string(),
            deleted,
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("provider_deleted: {}", response.deleted);
        println!("provider_id:      {}", response.provider_id);
    }

    Ok(())
}

pub(crate) fn cmd_certify_registry_publish(
    input_path: &Path,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let artifact: certify::SignedCertificationCheck =
            serde_json::from_slice(&fs::read(input_path)?)?;
        let entry = trust_control::build_client(url, token)?.publish_certification(&artifact)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&entry)?);
        } else {
            println!("published certification artifact");
            println!("artifact_id:     {}", entry.artifact_id);
            println!("tool_server_id:  {}", entry.tool_server_id);
            println!("verdict:         {}", entry.verdict.label());
            println!("status:          {}", entry.status.label());
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_publish_local(input_path, path, json_output)
    }
}

pub(crate) fn cmd_certify_registry_list(
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.list_certifications()?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&response)?);
        } else {
            println!("certifications: {}", response.count);
            for artifact in response.artifacts {
                println!(
                    "- {} server={} verdict={} status={}",
                    artifact.artifact_id,
                    artifact.tool_server_id,
                    artifact.verdict.label(),
                    artifact.status.label()
                );
            }
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_list_local(path, json_output)
    }
}

pub(crate) fn cmd_certify_registry_get(
    artifact_id: &str,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let entry = trust_control::build_client(url, token)?.get_certification(artifact_id)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&entry)?);
        } else {
            println!("certification artifact");
            println!("artifact_id:     {}", entry.artifact_id);
            println!("tool_server_id:  {}", entry.tool_server_id);
            println!("verdict:         {}", entry.verdict.label());
            println!("status:          {}", entry.status.label());
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_get_local(artifact_id, path, json_output)
    }
}

pub(crate) fn cmd_certify_registry_resolve(
    tool_server_id: &str,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response =
            trust_control::build_client(url, token)?.resolve_certification(tool_server_id)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&response)?);
        } else {
            println!("tool_server_id: {}", response.tool_server_id);
            let state = match response.state {
                certify::CertificationResolutionState::Active => "active",
                certify::CertificationResolutionState::Superseded => "superseded",
                certify::CertificationResolutionState::Revoked => "revoked",
                certify::CertificationResolutionState::NotFound => "not-found",
            };
            println!("state:          {state}");
            println!("total_entries:  {}", response.total_entries);
            if let Some(current) = response.current {
                println!("artifact_id:    {}", current.artifact_id);
                println!("verdict:        {}", current.verdict.label());
                println!("status:         {}", current.status.label());
            }
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_resolve_local(tool_server_id, path, json_output)
    }
}

pub(crate) fn cmd_certify_registry_revoke(
    artifact_id: &str,
    certification_registry_file: Option<&Path>,
    reason: Option<&str>,
    revoked_at: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let entry = trust_control::build_client(url, token)?.revoke_certification(
            artifact_id,
            &certify::CertificationRevocationRequest {
                reason: reason.map(str::to_string),
                revoked_at,
            },
        )?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&entry)?);
        } else {
            println!("revoked certification artifact");
            println!("artifact_id:     {}", entry.artifact_id);
            println!("tool_server_id:  {}", entry.tool_server_id);
            println!("status:          {}", entry.status.label());
            if let Some(revoked_at) = entry.revoked_at {
                println!("revoked_at:      {revoked_at}");
            }
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_revoke_local(
            artifact_id,
            path,
            reason,
            revoked_at,
            json_output,
        )
    }
}

pub(crate) fn cmd_trust_federated_issue(
    presentation_response_path: &Path,
    challenge_path: &Path,
    capability_policy_path: &Path,
    enterprise_identity_path: Option<&Path>,
    delegation_policy_path: Option<&Path>,
    upstream_capability_id: Option<&str>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let control_url = control_url.ok_or_else(|| {
        CliError::Other(
            "federated issuance requires --control-url so the trust-control service enforces verifier and issuance policy centrally"
                .to_string(),
        )
    })?;
    let token = require_control_token(control_token)?;
    let presentation: pact_credentials::PassportPresentationResponse =
        serde_json::from_slice(&fs::read(presentation_response_path)?)?;
    let expected_challenge: pact_credentials::PassportPresentationChallenge =
        serde_json::from_slice(&fs::read(challenge_path)?)?;
    let capability = load_single_default_capability(capability_policy_path)?;
    let admission_policy = load_admission_policy(capability_policy_path)?;
    let enterprise_identity = enterprise_identity_path
        .map(|path| {
            serde_json::from_slice::<pact_core::EnterpriseIdentityContext>(&fs::read(path)?)
                .map_err(CliError::from)
        })
        .transpose()?;
    let delegation_policy = delegation_policy_path
        .map(|path| {
            serde_json::from_slice::<trust_control::FederatedDelegationPolicyDocument>(&fs::read(
                path,
            )?)
            .map_err(CliError::from)
        })
        .transpose()?;

    let response = trust_control::build_client(control_url, token)?.federated_issue(
        &trust_control::FederatedIssueRequest {
            presentation,
            expected_challenge,
            capability,
            admission_policy,
            enterprise_identity,
            delegation_policy,
            upstream_capability_id: upstream_capability_id.map(str::to_string),
        },
    )?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("federated capability issued");
        println!("subject:             {}", response.subject);
        println!("subject_public_key:  {}", response.subject_public_key);
        println!("verifier:            {}", response.verification.verifier);
        println!("nonce:               {}", response.verification.nonce);
        println!("presentation_accepted: {}", response.verification.accepted);
        println!("capability_id:       {}", response.capability.id);
        println!(
            "issuer:              {}",
            response.capability.issuer.to_hex()
        );
        println!("expires_at:          {}", response.capability.expires_at);
        if let Some(audit) = response.enterprise_audit.as_ref() {
            println!("enterprise_provider: {}", audit.provider_id);
            if let Some(profile) = audit.matched_origin_profile.as_deref() {
                println!("origin_profile:      {profile}");
            }
        }
        if let Some(anchor_id) = response.delegation_anchor_capability_id.as_deref() {
            println!("delegation_anchor:   {anchor_id}");
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_federated_delegation_policy_create(
    output_path: &Path,
    signing_seed_file: &Path,
    issuer: &str,
    partner: &str,
    verifier: &str,
    capability_policy_path: &Path,
    expires_at: u64,
    purpose: Option<&str>,
    parent_capability_id: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let capability = load_single_default_capability(capability_policy_path)?;
    let keypair = load_or_create_authority_keypair(signing_seed_file)?;
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let body = trust_control::FederatedDelegationPolicyBody {
        schema: "pact.federated-delegation-policy.v1".to_string(),
        issuer: issuer.to_string(),
        partner: partner.to_string(),
        verifier: verifier.to_string(),
        signer_public_key: keypair.public_key(),
        created_at,
        expires_at,
        ttl_seconds: capability.ttl,
        scope: capability.scope,
        purpose: purpose.map(str::to_string),
        parent_capability_id: parent_capability_id.map(str::to_string),
    };
    let (signature, _) = keypair.sign_canonical(&body)?;
    let policy = trust_control::FederatedDelegationPolicyDocument { body, signature };
    trust_control::verify_federated_delegation_policy(&policy)?;
    fs::write(output_path, serde_json::to_vec_pretty(&policy)?)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&policy)?);
    } else {
        println!("federated delegation policy created");
        println!("output:              {}", output_path.display());
        println!("issuer:              {}", policy.body.issuer);
        println!("partner:             {}", policy.body.partner);
        println!("verifier:            {}", policy.body.verifier);
        println!(
            "signer_public_key:   {}",
            policy.body.signer_public_key.to_hex()
        );
        println!("ttl_seconds:         {}", policy.body.ttl_seconds);
        println!("expires_at:          {}", policy.body.expires_at);
        if let Some(parent_capability_id) = policy.body.parent_capability_id.as_deref() {
            println!("parent_capability_id: {parent_capability_id}");
        }
    }

    Ok(())
}

fn load_single_default_capability(path: &Path) -> Result<DefaultCapability, CliError> {
    let loaded = load_policy(path)?;
    match loaded.default_capabilities.as_slice() {
        [capability] => Ok(capability.clone()),
        [] => Err(CliError::Other(
            "federated issuance requires a capability policy with exactly one default capability"
                .to_string(),
        )),
        _ => Err(CliError::Other(
            "federated issuance currently supports exactly one default capability per request"
                .to_string(),
        )),
    }
}
