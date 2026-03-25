use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::{Keypair, PublicKey};
use pact_credentials::{
    build_agent_passport, create_passport_presentation_challenge_with_reference,
    create_signed_passport_verifier_policy, ensure_signed_passport_verifier_policy_active,
    evaluate_agent_passport, issue_reputation_credential, present_agent_passport,
    respond_to_passport_presentation_challenge, verify_agent_passport,
    verify_passport_presentation_response_with_policy, verify_signed_passport_verifier_policy,
    AgentPassport, AttestationWindow, PactCredentialEvidence, PassportPresentationChallenge,
    PassportPresentationOptions, PassportPresentationResponse, PassportVerifierPolicy,
    PassportVerifierPolicyReference, SignedPassportVerifierPolicy,
};
use pact_did::DidPact;
use pact_kernel::{EvidenceExportQuery, SqliteReceiptStore};
use pact_reputation::{compute_local_scorecard, ReputationConfig};

use crate::issuance::build_local_reputation_corpus;
use crate::passport_verifier::{PassportVerifierChallengeStore, VerifierPolicyRegistry};
use crate::trust_control::{
    CreatePassportChallengeRequest, VerifierPolicyListResponse, VerifyPassportChallengeRequest,
};
use crate::{load_or_create_authority_keypair, CliError};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn ensure_parent_dir(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn require_verifier_policy_registry_path(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::Other(
            "verifier policy commands require --verifier-policies-file <path> when not using --control-url"
                .to_string(),
        )
    })
}

fn load_verifier_policy_registry_for_admin(
    path: &Path,
) -> Result<VerifierPolicyRegistry, CliError> {
    if path.exists() {
        VerifierPolicyRegistry::load(path)
    } else {
        Ok(VerifierPolicyRegistry::default())
    }
}

fn load_signed_passport_verifier_policy(
    path: &Path,
) -> Result<SignedPassportVerifierPolicy, CliError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn load_existing_keypair(path: &Path) -> Result<Keypair, CliError> {
    let seed_hex = fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CliError::Other(format!("required seed file not found: {}", path.display()))
        } else {
            CliError::Io(error)
        }
    })?;
    Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

fn validity_seconds(validity_days: u32) -> u64 {
    u64::from(validity_days) * 86_400
}

fn require_receipt_db(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::Other(
            "passport creation requires --receipt-db so the local attestation corpus can be assembled"
                .to_string(),
        )
    })
}

fn build_attestation_evidence(
    store: &SqliteReceiptStore,
    subject_key: &str,
    since: Option<u64>,
    until: Option<u64>,
    receipt_log_urls: &[String],
    require_checkpoints: bool,
) -> Result<PactCredentialEvidence, CliError> {
    let bundle = store.build_evidence_export_bundle(&EvidenceExportQuery {
        capability_id: None,
        agent_subject: Some(subject_key.to_string()),
        since,
        until,
    })?;

    if bundle.tool_receipts.is_empty() {
        return Err(CliError::Other(format!(
            "no receipts found for subject {subject_key} in the selected window"
        )));
    }
    if require_checkpoints && !bundle.uncheckpointed_receipts.is_empty() {
        return Err(CliError::Other(format!(
            "passport creation requires checkpoint coverage, but {} selected receipt(s) are uncheckpointed",
            bundle.uncheckpointed_receipts.len()
        )));
    }

    Ok(PactCredentialEvidence {
        query: AttestationWindow {
            since,
            until: until.unwrap_or_else(unix_now),
        },
        receipt_count: bundle.tool_receipts.len(),
        receipt_ids: bundle
            .tool_receipts
            .into_iter()
            .map(|record| record.receipt.id)
            .collect(),
        checkpoint_roots: bundle
            .checkpoints
            .into_iter()
            .map(|checkpoint| checkpoint.body.merkle_root.to_string())
            .collect(),
        receipt_log_urls: receipt_log_urls.to_vec(),
        lineage_records: bundle.capability_lineage.len(),
        uncheckpointed_receipts: bundle.uncheckpointed_receipts.len(),
    })
}

pub(crate) fn cmd_passport_create(
    subject_public_key: &str,
    output: &Path,
    signing_seed_file: &Path,
    validity_days: u32,
    since: Option<u64>,
    until: Option<u64>,
    receipt_log_urls: &[String],
    require_checkpoints: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let subject_public_key = PublicKey::from_hex(subject_public_key)?;
    let subject_key = subject_public_key.to_hex();
    let now = unix_now();
    let attestation_until = until.unwrap_or(now);
    let corpus = build_local_reputation_corpus(
        &subject_key,
        receipt_db_path,
        budget_db_path,
        since,
        Some(attestation_until),
    )?;
    if corpus.receipts.is_empty() {
        return Err(CliError::Other(format!(
            "no receipts found for subject {subject_key} in the selected window"
        )));
    }

    let scorecard = compute_local_scorecard(
        &subject_key,
        attestation_until,
        &corpus,
        &ReputationConfig::default(),
    );
    let store = SqliteReceiptStore::open(require_receipt_db(receipt_db_path)?)?;
    let evidence = build_attestation_evidence(
        &store,
        &subject_key,
        since,
        Some(attestation_until),
        receipt_log_urls,
        require_checkpoints,
    )?;
    let signing_key = load_or_create_authority_keypair(signing_seed_file)?;
    let credential = issue_reputation_credential(
        &signing_key,
        scorecard,
        evidence,
        now,
        now + validity_seconds(validity_days),
    )?;
    let subject_did = DidPact::from_public_key(subject_public_key);
    let passport = build_agent_passport(&subject_did.to_string(), vec![credential])?;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&passport)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "subject": passport.subject,
                "credentialCount": passport.credentials.len(),
                "merkleRootCount": passport.merkle_roots.len(),
                "validUntil": passport.valid_until,
            }))?
        );
    } else {
        println!("wrote passport to {}", output.display());
        println!("subject:          {}", passport.subject);
        println!("credential_count: {}", passport.credentials.len());
        println!("merkle_roots:     {}", passport.merkle_roots.len());
        println!("valid_until:      {}", passport.valid_until);
    }
    Ok(())
}

pub(crate) fn cmd_passport_verify(
    input: &Path,
    at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let verification = verify_agent_passport(&passport, at.unwrap_or_else(unix_now))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&verification)?);
    } else {
        println!("passport verified");
        println!("subject:          {}", verification.subject);
        if let Some(issuer) = verification.issuer.as_deref() {
            println!("issuer:           {issuer}");
        } else {
            println!("issuers:          {}", verification.issuers.join(", "));
        }
        println!("issuer_count:     {}", verification.issuer_count);
        println!("credential_count: {}", verification.credential_count);
        println!("merkle_roots:     {}", verification.merkle_root_count);
        println!("valid_until:      {}", verification.valid_until);
    }
    Ok(())
}

pub(crate) fn cmd_passport_evaluate(
    input: &Path,
    policy_path: &Path,
    at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let policy = load_passport_verifier_policy(policy_path)?;
    let evaluation = evaluate_agent_passport(&passport, at.unwrap_or_else(unix_now), &policy)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&evaluation)?);
    } else {
        println!("passport evaluated");
        println!("subject:             {}", evaluation.verification.subject);
        if let Some(issuer) = evaluation.verification.issuer.as_deref() {
            println!("issuer:              {issuer}");
        } else {
            println!(
                "issuers:             {}",
                evaluation.verification.issuers.join(", ")
            );
        }
        println!(
            "issuer_count:        {}",
            evaluation.verification.issuer_count
        );
        println!("accepted:            {}", evaluation.accepted);
        println!(
            "matched_credentials: {}",
            evaluation.matched_credential_indexes.len()
        );
        if !evaluation.matched_issuers.is_empty() {
            println!(
                "matched_issuers:     {}",
                evaluation.matched_issuers.join(", ")
            );
        }
        println!(
            "credential_count:    {}",
            evaluation.verification.credential_count
        );
        println!(
            "valid_until:         {}",
            evaluation.verification.valid_until
        );
        if !evaluation.accepted {
            println!("rejections:");
            for result in &evaluation.credential_results {
                if result.accepted {
                    continue;
                }
                println!("  credential {} ({}):", result.index, result.issuer);
                for reason in &result.reasons {
                    println!("    - {}", reason);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_present(
    input: &Path,
    output: &Path,
    issuers: &[String],
    max_credentials: Option<usize>,
    json_output: bool,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    verify_agent_passport(&passport, unix_now())?;

    let presented = present_agent_passport(
        &passport,
        &PassportPresentationOptions {
            issuer_allowlist: issuers.iter().cloned().collect::<BTreeSet<_>>(),
            max_credentials,
        },
    )?;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&presented)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "subject": presented.subject,
                "credentialCount": presented.credentials.len(),
                "merkleRootCount": presented.merkle_roots.len(),
            }))?
        );
    } else {
        println!("wrote presented passport to {}", output.display());
        println!("subject:          {}", presented.subject);
        println!("credential_count: {}", presented.credentials.len());
        println!("merkle_roots:     {}", presented.merkle_roots.len());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_passport_policy_create(
    output: &Path,
    policy_id: &str,
    verifier: &str,
    signing_seed_file: &Path,
    policy_path: &Path,
    expires_at: u64,
    verifier_policies_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let now = unix_now();
    let keypair = load_or_create_authority_keypair(signing_seed_file)?;
    let policy = load_passport_verifier_policy(policy_path)?;
    let document = create_signed_passport_verifier_policy(
        &keypair, policy_id, verifier, now, expires_at, policy,
    )?;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&document)?)?;

    let registration = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?
            .upsert_verifier_policy(policy_id, &document)?;
        Some(url.to_string())
    } else if let Some(path) = verifier_policies_file {
        let mut registry = load_verifier_policy_registry_for_admin(path)?;
        registry.upsert(document.clone())?;
        registry.save(path)?;
        Some(path.display().to_string())
    } else {
        None
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        println!("verifier policy created");
        println!("output:            {}", output.display());
        println!("policy_id:         {}", document.body.policy_id);
        println!("verifier:          {}", document.body.verifier);
        println!(
            "signer_public_key: {}",
            document.body.signer_public_key.to_hex()
        );
        println!("created_at:        {}", document.body.created_at);
        println!("expires_at:        {}", document.body.expires_at);
        if let Some(registration) = registration.as_deref() {
            println!("registered_in:     {registration}");
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_verify(
    input: &Path,
    at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let document = load_signed_passport_verifier_policy(input)?;
    verify_signed_passport_verifier_policy(&document)
        .map_err(|error| CliError::Other(error.to_string()))?;
    ensure_signed_passport_verifier_policy_active(&document, at.unwrap_or_else(unix_now))
        .map_err(|error| CliError::Other(error.to_string()))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        println!("verifier policy verified");
        println!("policy_id:         {}", document.body.policy_id);
        println!("verifier:          {}", document.body.verifier);
        println!(
            "signer_public_key: {}",
            document.body.signer_public_key.to_hex()
        );
        println!("created_at:        {}", document.body.created_at);
        println!("expires_at:        {}", document.body.expires_at);
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_list(
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?.list_verifier_policies()?
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let registry = load_verifier_policy_registry_for_admin(path)?;
        VerifierPolicyListResponse {
            configured: true,
            count: registry.policies.len(),
            policies: registry.policies.into_values().collect(),
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("configured: {}", response.configured);
        println!("count:      {}", response.count);
        for document in response.policies {
            println!(
                "- {} ({}) expires_at={}",
                document.body.policy_id, document.body.verifier, document.body.expires_at
            );
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_get(
    policy_id: &str,
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let document = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?.get_verifier_policy(policy_id)?
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let registry = load_verifier_policy_registry_for_admin(path)?;
        registry.get(policy_id).cloned().ok_or_else(|| {
            CliError::Other(format!("verifier policy `{policy_id}` was not found"))
        })?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        println!("policy_id:         {}", document.body.policy_id);
        println!("verifier:          {}", document.body.verifier);
        println!(
            "signer_public_key: {}",
            document.body.signer_public_key.to_hex()
        );
        println!("created_at:        {}", document.body.created_at);
        println!("expires_at:        {}", document.body.expires_at);
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_upsert(
    input: &Path,
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let document = load_signed_passport_verifier_policy(input)?;
    verify_signed_passport_verifier_policy(&document)
        .map_err(|error| CliError::Other(error.to_string()))?;
    let saved = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?
            .upsert_verifier_policy(&document.body.policy_id, &document)?
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let mut registry = load_verifier_policy_registry_for_admin(path)?;
        registry.upsert(document.clone())?;
        registry.save(path)?;
        document
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&saved)?);
    } else {
        println!("verifier policy upserted");
        println!("policy_id:  {}", saved.body.policy_id);
        println!("verifier:   {}", saved.body.verifier);
        println!("expires_at: {}", saved.body.expires_at);
    }
    Ok(())
}

pub(crate) fn cmd_passport_policy_delete(
    policy_id: &str,
    json_output: bool,
    verifier_policies_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (deleted, configured) = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        let response =
            crate::trust_control::build_client(url, token)?.delete_verifier_policy(policy_id)?;
        (response.deleted, true)
    } else {
        let path = require_verifier_policy_registry_path(verifier_policies_file)?;
        let mut registry = load_verifier_policy_registry_for_admin(path)?;
        let deleted = registry.remove(policy_id);
        registry.save(path)?;
        (deleted, true)
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "configured": configured,
                "policyId": policy_id,
                "deleted": deleted,
            }))?
        );
    } else {
        println!("configured: {configured}");
        println!("policy_id:  {policy_id}");
        println!("deleted:    {deleted}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_passport_challenge_create(
    output: &Path,
    verifier: &str,
    ttl_secs: u64,
    issuers: &[String],
    max_credentials: Option<usize>,
    policy_path: Option<&Path>,
    policy_id: Option<&str>,
    verifier_policies_file: Option<&Path>,
    verifier_challenge_db: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let now = unix_now();
    if policy_path.is_some() && policy_id.is_some() {
        return Err(CliError::Other(
            "challenge creation accepts either --policy or --policy-id, not both".to_string(),
        ));
    }
    let challenge = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?.create_passport_challenge(
            &CreatePassportChallengeRequest {
                verifier: verifier.to_string(),
                ttl_seconds: ttl_secs,
                issuers: issuers.to_vec(),
                max_credentials,
                policy_id: policy_id.map(str::to_string),
                policy: policy_path.map(load_passport_verifier_policy).transpose()?,
            },
        )?
    } else {
        let (policy_ref, policy, policy_verifier) = if let Some(policy_id) = policy_id {
            let path = require_verifier_policy_registry_path(verifier_policies_file)?;
            let registry = load_verifier_policy_registry_for_admin(path)?;
            let document = registry.active_policy(policy_id, now)?;
            (
                Some(PassportVerifierPolicyReference {
                    policy_id: document.body.policy_id.clone(),
                }),
                None,
                document.body.verifier.clone(),
            )
        } else {
            (
                None,
                policy_path.map(load_passport_verifier_policy).transpose()?,
                verifier.to_string(),
            )
        };
        if policy_ref.is_some() && policy_verifier != verifier {
            return Err(CliError::Other(
                "stored verifier policy verifier must match --verifier".to_string(),
            ));
        }
        let challenge = create_passport_presentation_challenge_with_reference(
            verifier,
            Some(Keypair::generate().public_key().to_hex()),
            Keypair::generate().public_key().to_hex(),
            now,
            now.saturating_add(ttl_secs),
            PassportPresentationOptions {
                issuer_allowlist: issuers.iter().cloned().collect::<BTreeSet<_>>(),
                max_credentials,
            },
            policy_ref,
            policy,
        )?;
        if let Some(path) = verifier_challenge_db {
            PassportVerifierChallengeStore::open(path)?.register(&challenge)?;
        }
        challenge
    };

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&challenge)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "verifier": challenge.verifier,
                "challengeId": challenge.challenge_id,
                "nonce": challenge.nonce,
                "expiresAt": challenge.expires_at,
                "policyId": challenge.policy_ref.as_ref().map(|reference| reference.policy_id.clone()),
                "policyEmbedded": challenge.policy.is_some(),
            }))?
        );
    } else {
        println!("wrote challenge to {}", output.display());
        println!("verifier:        {}", challenge.verifier);
        if let Some(challenge_id) = challenge.challenge_id.as_deref() {
            println!("challenge_id:    {challenge_id}");
        }
        println!("nonce:           {}", challenge.nonce);
        println!("expires_at:      {}", challenge.expires_at);
        if let Some(policy_id) = challenge
            .policy_ref
            .as_ref()
            .map(|reference| reference.policy_id.as_str())
        {
            println!("policy_id:       {policy_id}");
        }
        println!("policy_embedded: {}", challenge.policy.is_some());
    }
    Ok(())
}

pub(crate) fn cmd_passport_challenge_respond(
    input: &Path,
    challenge_path: &Path,
    holder_seed_file: &Path,
    output: &Path,
    at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let challenge: PassportPresentationChallenge =
        serde_json::from_slice(&fs::read(challenge_path)?)?;
    let holder_keypair = load_existing_keypair(holder_seed_file)?;
    let response = respond_to_passport_presentation_challenge(
        &holder_keypair,
        &passport,
        &challenge,
        at.unwrap_or_else(unix_now),
    )?;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&response)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "subject": response.passport.subject,
                "verifier": response.challenge.verifier,
                "nonce": response.challenge.nonce,
                "credentialCount": response.passport.credentials.len(),
            }))?
        );
    } else {
        println!("wrote challenge response to {}", output.display());
        println!("subject:          {}", response.passport.subject);
        println!("verifier:         {}", response.challenge.verifier);
        println!("nonce:            {}", response.challenge.nonce);
        println!("credential_count: {}", response.passport.credentials.len());
    }
    Ok(())
}

pub(crate) fn cmd_passport_challenge_verify(
    input: &Path,
    challenge_path: Option<&Path>,
    verifier_policies_file: Option<&Path>,
    verifier_challenge_db: Option<&Path>,
    at: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response: PassportPresentationResponse = serde_json::from_slice(&fs::read(input)?)?;
    let expected_challenge = challenge_path
        .map(|path| -> Result<PassportPresentationChallenge, CliError> {
            Ok(serde_json::from_slice(&fs::read(path)?)?)
        })
        .transpose()?;
    let now = at.unwrap_or_else(unix_now);
    let verification = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?.verify_passport_challenge(
            &VerifyPassportChallengeRequest {
                presentation: response,
                expected_challenge,
            },
        )?
    } else {
        let challenge = expected_challenge.as_ref().unwrap_or(&response.challenge);
        let (resolved_policy, policy_source) =
            resolve_challenge_policy_local(challenge, verifier_policies_file, now)?;
        let mut verification = verify_passport_presentation_response_with_policy(
            &response,
            expected_challenge.as_ref(),
            now,
            resolved_policy.as_ref(),
            policy_source,
        )?;
        if let Some(path) = verifier_challenge_db {
            PassportVerifierChallengeStore::open(path)?.consume(challenge, now)?;
            verification.replay_state = Some("consumed".to_string());
        }
        verification
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&verification)?);
    } else {
        println!("presentation verified");
        println!("subject:              {}", verification.subject);
        println!("verifier:             {}", verification.verifier);
        if let Some(challenge_id) = verification.challenge_id.as_deref() {
            println!("challenge_id:         {challenge_id}");
        }
        println!("nonce:                {}", verification.nonce);
        println!("accepted:             {}", verification.accepted);
        println!("policy_evaluated:     {}", verification.policy_evaluated);
        if let Some(policy_source) = verification.policy_source.as_deref() {
            println!("policy_source:        {policy_source}");
        }
        if let Some(policy_id) = verification.policy_id.as_deref() {
            println!("policy_id:            {policy_id}");
        }
        println!("credential_count:     {}", verification.credential_count);
        println!("valid_until:          {}", verification.valid_until);
        println!(
            "challenge_expires_at: {}",
            verification.challenge_expires_at
        );
        if let Some(replay_state) = verification.replay_state.as_deref() {
            println!("replay_state:         {replay_state}");
        }
    }
    Ok(())
}

fn load_passport_verifier_policy(path: &Path) -> Result<PassportVerifierPolicy, CliError> {
    let contents = fs::read_to_string(path)?;
    let policy = if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        serde_yaml::from_str(&contents)?
    } else if let Ok(document) = serde_json::from_str::<SignedPassportVerifierPolicy>(&contents) {
        verify_signed_passport_verifier_policy(&document)
            .map_err(|error| CliError::Other(error.to_string()))?;
        document.body.policy
    } else {
        serde_json::from_str(&contents).or_else(|_| serde_yaml::from_str(&contents))?
    };
    Ok(policy)
}

fn resolve_challenge_policy_local(
    challenge: &PassportPresentationChallenge,
    verifier_policies_file: Option<&Path>,
    now: u64,
) -> Result<(Option<PassportVerifierPolicy>, Option<String>), CliError> {
    if let Some(policy) = challenge.policy.as_ref() {
        return Ok((Some(policy.clone()), Some("embedded".to_string())));
    }
    let Some(reference) = challenge.policy_ref.as_ref() else {
        return Ok((None, None));
    };
    let path = require_verifier_policy_registry_path(verifier_policies_file)?;
    let registry = load_verifier_policy_registry_for_admin(path)?;
    let document = registry.active_policy(&reference.policy_id, now)?;
    if document.body.verifier != challenge.verifier {
        return Err(CliError::Other(format!(
            "verifier policy `{}` is bound to verifier `{}` but challenge expects `{}`",
            document.body.policy_id, document.body.verifier, challenge.verifier
        )));
    }
    Ok((
        Some(document.body.policy.clone()),
        Some(format!("registry:{}", document.body.policy_id)),
    ))
}
