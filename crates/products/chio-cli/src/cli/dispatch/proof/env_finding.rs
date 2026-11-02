//! Cognition-market proof trust pinned by the deployment environment.

use std::path::Path;

use super::*;

const FINDING_VERIFIER_AUTHORITY_KEY_ENV: &str = "CHIO_FINDING_VERIFIER_AUTHORITY_KEY";
const FINDING_PURCHASE_AUTHORITY_KEY_ENV: &str = "CHIO_FINDING_PURCHASE_AUTHORITY_KEY";
const FINDING_PURCHASE_AUTHORITY_STATUS_PATH_ENV: &str =
    "CHIO_FINDING_PURCHASE_AUTHORITY_STATUS_PATH";
const FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY_ENV: &str =
    "CHIO_FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY";
const FINDING_PROFILE_GOVERNANCE_AUTHORITY_POLICY_PATH_ENV: &str =
    "CHIO_FINDING_PROFILE_GOVERNANCE_AUTHORITY_POLICY_PATH";
const FINDING_PROFILE_GOVERNANCE_AUTHORITY_STATUS_PATH_ENV: &str =
    "CHIO_FINDING_PROFILE_GOVERNANCE_AUTHORITY_STATUS_PATH";
const FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256_ENV: &str =
    "CHIO_FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256";
pub(super) const FINDING_VERIFIER_PROFILE_PATH_ENV: &str = "CHIO_FINDING_VERIFIER_PROFILE_PATH";
const FINDING_TRUST_ROOT_SNAPSHOT_SHA256_ENV: &str = "CHIO_FINDING_TRUST_ROOT_SNAPSHOT_SHA256";
const FINDING_RESOLVER_POLICY_SHA256_ENV: &str = "CHIO_FINDING_RESOLVER_POLICY_SHA256";
const FINDING_TRUSTED_TIME_INPUT_SHA256_ENV: &str = "CHIO_FINDING_TRUSTED_TIME_INPUT_SHA256";
pub(super) const FINDING_VERIFIER_AUTHORITY_STATUS_PATH_ENV: &str =
    "CHIO_FINDING_VERIFIER_AUTHORITY_STATUS_PATH";
pub(super) const FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH_ENV: &str =
    "CHIO_FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH";
const FINDING_VERIFIER_AUTHORITY_STATUS_CHECKED_AT_ENV: &str =
    "CHIO_FINDING_VERIFIER_AUTHORITY_STATUS_CHECKED_AT";
const FINDING_VERIFIER_AUTHORITY_STATUS_MAX_AGE_SECONDS_ENV: &str =
    "CHIO_FINDING_VERIFIER_AUTHORITY_STATUS_MAX_AGE_SECONDS";
pub(super) const FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV: &str =
    "CHIO_FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH";
const FINDING_STATUS_OPERATOR_AUTHORIZATION_SHA256_ENV: &str =
    "CHIO_FINDING_STATUS_OPERATOR_AUTHORIZATION_SHA256";
const FINDING_STATUS_OPERATOR_AUTHORITY_STATUS_PATH_ENV: &str =
    "CHIO_FINDING_STATUS_OPERATOR_AUTHORITY_STATUS_PATH";
const FINDING_STATUS_AUTHORITY_DATABASE_PATH_ENV: &str =
    "CHIO_FINDING_STATUS_AUTHORITY_DATABASE_PATH";
const FINDING_STATUS_AUTHORITY_LOCK_ROOT_ENV: &str = "CHIO_FINDING_STATUS_AUTHORITY_LOCK_ROOT";
const FINDING_STATUS_NOW_UNIX_SECONDS_ENV: &str = "CHIO_FINDING_STATUS_NOW_UNIX_SECONDS";
const FINDING_STATUS_MAX_AGE_SECONDS_ENV: &str = "CHIO_FINDING_STATUS_MAX_AGE_SECONDS";
const FINDING_STATUS_AUTHORIZATION_MAX_BYTES: usize = 64 * 1024;
const FINDING_VERIFIER_AUTHORITY_STATUS_MAX_BYTES: usize = 64 * 1024;
const FINDING_AUTHORITY_POLICY_MAX_BYTES: usize = 64 * 1024;
const FINDING_VERIFIER_PROFILE_MAX_BYTES: usize = 256 * 1024;

fn require_independent_profile_authorities(
    governance: &chio_core_types::PublicKey,
    verifier: &chio_core_types::PublicKey,
) -> Result<(), CliError> {
    if governance == verifier {
        return Err(verifier_context_invalid(format!(
            "{FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY_ENV} must differ from {FINDING_VERIFIER_AUTHORITY_KEY_ENV}"
        )));
    }
    Ok(())
}

fn validate_cli_finding_verifier_profile(
    profile: &chio_finding::FindingChallengeVerifierProfile,
) -> Result<(), CliError> {
    chio_finding_verifier::validate_supported_finding_verifier_profile(profile).map_err(|error| {
        verifier_feature_unsupported(format!(
            "{FINDING_VERIFIER_PROFILE_PATH_ENV} requires unsupported verifier behavior: {error}"
        ))
    })
}

pub(in super::super) fn cognition_market_proof_trust_from_env(
    trusted_passport_signer_keys: &[chio_core_types::PublicKey],
    trusted_checkpoint_signer_keys: &[chio_core_types::PublicKey],
    status_claim_selected: bool,
    purchase_claim_selected: bool,
) -> Result<chio_control_plane::transaction_passport::CognitionMarketProofTrust, CliError> {
    let governance_keys = required_public_keys_from_env(
        FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY_ENV,
        "Finding profile governance authority",
    )?;
    if governance_keys.len() != 1 {
        return Err(verifier_context_invalid(format!(
            "{FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY_ENV} must contain exactly one public key"
        )));
    }
    let profile_governance_authority = governance_keys.into_iter().next().ok_or_else(|| {
        verifier_context_invalid("Finding profile governance authority key is missing")
    })?;
    let profile_governance_authority_policy = finding_authority_policy_from_env(
        FINDING_PROFILE_GOVERNANCE_AUTHORITY_POLICY_PATH_ENV,
        "profile governance authority",
    )?;
    if profile_governance_authority_policy.key != profile_governance_authority {
        return Err(verifier_context_invalid(format!(
            "{FINDING_PROFILE_GOVERNANCE_AUTHORITY_POLICY_PATH_ENV} key does not match {FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY_ENV}"
        )));
    }
    let verifier_keys = required_public_keys_from_env(
        FINDING_VERIFIER_AUTHORITY_KEY_ENV,
        "Finding verifier authority",
    )?;
    if verifier_keys.len() != 1 {
        return Err(verifier_context_invalid(format!(
            "{FINDING_VERIFIER_AUTHORITY_KEY_ENV} must contain exactly one public key"
        )));
    }
    let finding_verifier_authority = verifier_keys
        .into_iter()
        .next()
        .ok_or_else(|| verifier_context_invalid("Finding verifier authority key is missing"))?;
    let purchase_keys = required_public_keys_from_env(
        FINDING_PURCHASE_AUTHORITY_KEY_ENV,
        "Finding purchase-record authority",
    )?;
    if purchase_keys.len() != 1 {
        return Err(verifier_context_invalid(format!(
            "{FINDING_PURCHASE_AUTHORITY_KEY_ENV} must contain exactly one public key"
        )));
    }
    let purchase_authority = purchase_keys.into_iter().next().ok_or_else(|| {
        verifier_context_invalid("Finding purchase-record authority key is missing")
    })?;
    require_independent_profile_authorities(
        &profile_governance_authority,
        &finding_verifier_authority,
    )?;
    let trusted_verifier_profile = finding_verifier_profile_from_env()?;
    chio_finding::verify_signed_profile(
        &trusted_verifier_profile,
        &profile_governance_authority_policy.key,
    )
    .map_err(|error| {
        verifier_context_invalid(format!(
            "{FINDING_VERIFIER_PROFILE_PATH_ENV} is not authorized by {FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY_ENV}: {error}"
        ))
    })?;
    validate_cli_finding_verifier_profile(&trusted_verifier_profile.body)?;
    if trusted_verifier_profile.body.verifier_report_signer.key != finding_verifier_authority {
        return Err(verifier_context_invalid(format!(
            "{FINDING_VERIFIER_PROFILE_PATH_ENV} signer key does not match {FINDING_VERIFIER_AUTHORITY_KEY_ENV}"
        )));
    }
    if trusted_verifier_profile.body.purchase_authority.key != purchase_authority {
        return Err(verifier_context_invalid(format!(
            "{FINDING_VERIFIER_PROFILE_PATH_ENV} purchase authority key does not match {FINDING_PURCHASE_AUTHORITY_KEY_ENV}"
        )));
    }
    let trusted_verifier_profile_envelope_sha256 =
        required_sha256_env(FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256_ENV)?;
    let trusted_trust_root_snapshot_sha256 =
        required_sha256_env(FINDING_TRUST_ROOT_SNAPSHOT_SHA256_ENV)?;
    let trusted_resolver_policy_sha256 = required_sha256_env(FINDING_RESOLVER_POLICY_SHA256_ENV)?;
    let trusted_time_input_sha256 = required_sha256_env(FINDING_TRUSTED_TIME_INPUT_SHA256_ENV)?;
    let status_authority = finding_authority_policy_from_env(
        FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH_ENV,
        "Finding authority-status signer",
    )?;
    require_independent_verifier_status_authority(
        &status_authority.key,
        &finding_verifier_authority,
    )?;
    if status_authority.key == profile_governance_authority {
        return Err(verifier_context_invalid(format!(
            "{FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH_ENV} key must differ from {FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY_ENV}"
        )));
    }
    let checked_at = required_positive_u64_env(FINDING_VERIFIER_AUTHORITY_STATUS_CHECKED_AT_ENV)?;
    let max_age_secs =
        required_positive_u64_env(FINDING_VERIFIER_AUTHORITY_STATUS_MAX_AGE_SECONDS_ENV)?;
    let profile_governance_authority_status = finding_authority_status_trust_from_env(
        FINDING_PROFILE_GOVERNANCE_AUTHORITY_STATUS_PATH_ENV,
        &profile_governance_authority,
        &status_authority,
        checked_at,
        max_age_secs,
    )?;
    let verifier_authority_status = finding_authority_status_trust_from_env(
        FINDING_VERIFIER_AUTHORITY_STATUS_PATH_ENV,
        &finding_verifier_authority,
        &status_authority,
        checked_at,
        max_age_secs,
    )?;
    let purchase_authority_status = purchase_claim_selected
        .then(|| {
            finding_authority_status_trust_from_env(
                FINDING_PURCHASE_AUTHORITY_STATUS_PATH_ENV,
                &purchase_authority,
                &status_authority,
                checked_at,
                max_age_secs,
            )
        })
        .transpose()?;
    let status_liveness_required = status_claim_selected
        || trusted_verifier_profile
            .body
            .required_facets
            .contains(&chio_finding::FindingFacetKind::StatusLiveness);
    let status = if status_liveness_required {
        Some(cognition_market_status_trust_from_env(
            &status_authority,
            &profile_governance_authority_policy.key,
            checked_at,
            max_age_secs,
        )?)
    } else {
        None
    };
    if status
        .as_ref()
        .is_some_and(|status| status.status_freshness.now != verifier_authority_status.checked_at)
    {
        return Err(verifier_context_invalid(format!(
            "{FINDING_STATUS_NOW_UNIX_SECONDS_ENV} must equal {FINDING_VERIFIER_AUTHORITY_STATUS_CHECKED_AT_ENV}"
        )));
    }
    Ok(
        chio_control_plane::transaction_passport::CognitionMarketProofTrust {
            trusted_passport_signer_keys: trusted_passport_signer_keys.to_vec(),
            trusted_checkpoint_signer_keys: trusted_checkpoint_signer_keys.to_vec(),
            profile_governance_authority: profile_governance_authority_policy,
            profile_governance_authority_status,
            finding_verifier_authority,
            purchase_authority,
            purchase_authority_status,
            trusted_verifier_profile_envelope_sha256,
            trusted_verifier_profile,
            trusted_trust_root_snapshot_sha256,
            trusted_resolver_policy_sha256,
            trusted_time_input_sha256,
            verifier_authority_status,
            status,
        },
    )
}

fn decode_pinned_context<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T, CliError> {
    crate::input::canonical_ijson(bytes).map_err(|source| {
        CliError::with_source(
            &chio_errors::_generated::error_codes::TRANSACTION_VERIFIER_CONTEXT_INVALID,
            source,
        )
    })
}

pub(super) fn finding_verifier_profile_from_env(
) -> Result<chio_finding::SignedFindingChallengeVerifierProfile, CliError> {
    let path = required_utf8_env(FINDING_VERIFIER_PROFILE_PATH_ENV)?;
    let bytes = crate::input::read_regular(Path::new(&path), FINDING_VERIFIER_PROFILE_MAX_BYTES)?;
    let profile = decode_pinned_context(&bytes)?;
    Ok(profile)
}

pub(super) fn finding_authority_status_trust_from_env(
    status_path_env: &'static str,
    subject_authority: &chio_core_types::PublicKey,
    status_authority: &chio_finding::FindingAuthorityKeyPolicy,
    checked_at: u64,
    max_age_secs: u64,
) -> Result<
    chio_control_plane::transaction_passport::CognitionMarketVerifierAuthorityStatusTrust,
    CliError,
> {
    let path = required_utf8_env(status_path_env)?;
    let bytes = crate::input::read_regular(
        Path::new(&path),
        FINDING_VERIFIER_AUTHORITY_STATUS_MAX_BYTES,
    )?;
    let signed_status: chio_finding::SignedFindingAuthorityStatus = decode_pinned_context(&bytes)?;
    chio_finding::verify_signed_authority_status(&signed_status, &status_authority.key).map_err(
        |error| {
            verifier_context_invalid(format!(
                "{status_path_env} is not authorized by {FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH_ENV}: {error}"
            ))
        },
    )?;
    if &signed_status.body.key != subject_authority {
        return Err(verifier_context_invalid(format!(
            "{status_path_env} key does not match its deployment-pinned authority"
        )));
    }
    Ok(
        chio_control_plane::transaction_passport::CognitionMarketVerifierAuthorityStatusTrust {
            signed_status,
            status_authority: status_authority.clone(),
            checked_at,
            max_age_secs,
        },
    )
}

pub(super) fn finding_authority_policy_from_env(
    policy_path_env: &'static str,
    subject: &'static str,
) -> Result<chio_finding::FindingAuthorityKeyPolicy, CliError> {
    let path = required_utf8_env(policy_path_env)?;
    let bytes = crate::input::read_regular(Path::new(&path), FINDING_AUTHORITY_POLICY_MAX_BYTES)?;
    let policy: chio_finding::FindingAuthorityKeyPolicy = decode_pinned_context(&bytes)?;
    policy.validate(subject).map_err(|error| {
        verifier_context_invalid(format!("{policy_path_env} is invalid: {error}"))
    })?;
    Ok(policy)
}

pub(super) fn require_independent_verifier_status_authority(
    status_authority: &chio_core_types::PublicKey,
    finding_verifier_authority: &chio_core_types::PublicKey,
) -> Result<(), CliError> {
    if status_authority == finding_verifier_authority {
        return Err(verifier_context_invalid(format!(
            "{FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH_ENV} key must differ from {FINDING_VERIFIER_AUTHORITY_KEY_ENV}"
        )));
    }
    Ok(())
}

pub(super) fn cognition_market_status_trust_from_env(
    status_authority: &chio_finding::FindingAuthorityKeyPolicy,
    governance_authority: &chio_core_types::PublicKey,
    checked_at: u64,
    max_age_secs: u64,
) -> Result<chio_control_plane::transaction_passport::CognitionMarketStatusTrust, CliError> {
    let authorization_path = required_utf8_env(FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV)?;
    let authorization_bytes = crate::input::read_regular(
        Path::new(&authorization_path),
        FINDING_STATUS_AUTHORIZATION_MAX_BYTES,
    )?;
    let signed_status_operator_authorization: chio_core_types::receipt::lineage::SignedExportEnvelope<
        chio_finding::FindingStatusOperatorAuthorization,
    > = decode_pinned_context(&authorization_bytes)?;
    signed_status_operator_authorization
        .body
        .validate()
        .map_err(|error| {
            verifier_context_invalid(format!(
                "Finding status operator authorization is invalid: {error}"
            ))
        })?;
    chio_finding::verify_pinned_envelope(
        &signed_status_operator_authorization,
        governance_authority,
        "status_operator_authorization",
    )
    .map_err(|error| {
        verifier_context_invalid(format!(
            "Finding status operator authorization envelope is invalid: {error}"
        ))
    })?;
    let status_operator_authorization_sha256 =
        required_sha256_env(FINDING_STATUS_OPERATOR_AUTHORIZATION_SHA256_ENV)?;
    let actual_authorization_sha256 = chio_core_types::crypto::sha256_hex(&authorization_bytes);
    if status_operator_authorization_sha256 != actual_authorization_sha256 {
        return Err(verifier_context_invalid(format!(
            "{FINDING_STATUS_OPERATOR_AUTHORIZATION_SHA256_ENV} does not match the signed authorization envelope"
        )));
    }
    let operator_authority_status = finding_authority_status_trust_from_env(
        FINDING_STATUS_OPERATOR_AUTHORITY_STATUS_PATH_ENV,
        &signed_status_operator_authorization.body.operator.key,
        status_authority,
        checked_at,
        max_age_secs,
    )?;
    let now = required_positive_u64_env(FINDING_STATUS_NOW_UNIX_SECONDS_ENV)?;
    let max_epoch_age_secs = required_positive_u64_env(FINDING_STATUS_MAX_AGE_SECONDS_ENV)?;
    let authority_database = required_utf8_env(FINDING_STATUS_AUTHORITY_DATABASE_PATH_ENV)?;
    let authority_lock_root = required_utf8_env(FINDING_STATUS_AUTHORITY_LOCK_ROOT_ENV)?;
    let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving(
        &authority_database,
        &authority_lock_root,
    )
    .map_err(|error| {
        CliError::cli_io_error(format!(
            "durable Finding status authority store could not be opened: {error}"
        ))
    })?;
    let status_store = authority.finding_status_store();
    Ok(
        chio_control_plane::transaction_passport::CognitionMarketStatusTrust {
            signed_status_operator_authorization,
            status_operator_authorization_sha256,
            operator_authority_status,
            status_freshness: chio_finding::FindingStatusFreshnessPolicy {
                now,
                max_epoch_age_secs,
            },
            status_store: Arc::new(status_store),
        },
    )
}

fn required_utf8_env(env_name: &str) -> Result<String, CliError> {
    match std::env::var(env_name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => Err(verifier_context_invalid(format!(
            "{env_name} must be non-empty"
        ))),
        Err(std::env::VarError::NotPresent) => Err(verifier_feature_unsupported(format!(
            "{env_name} must be set"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(verifier_context_invalid(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

fn required_positive_u64_env(env_name: &str) -> Result<u64, CliError> {
    let raw = required_utf8_env(env_name)?;
    raw.parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| verifier_context_invalid(format!("{env_name} must be a nonzero u64")))
}

fn required_sha256_env(env_name: &str) -> Result<String, CliError> {
    let value = required_utf8_env(env_name)?;
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(value)
    } else {
        Err(verifier_context_invalid(format!(
            "{env_name} must be a lowercase 64-character SHA-256 digest"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        require_independent_profile_authorities, require_independent_verifier_status_authority,
        validate_cli_finding_verifier_profile,
    };

    #[test]
    fn verifier_status_authority_must_differ_from_verifier_signer() {
        let signer = chio_core_types::Keypair::from_seed(&[113_u8; 32]).public_key();
        let error = match require_independent_verifier_status_authority(&signer, &signer) {
            Ok(()) => String::new(),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("must differ"), "unexpected error: {error}");
    }

    #[test]
    fn profile_governance_must_differ_from_verifier_signer() {
        let signer = chio_core_types::Keypair::from_seed(&[114_u8; 32]).public_key();
        let error = require_independent_profile_authorities(&signer, &signer)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains("must differ"), "unexpected error: {error}");
    }

    #[test]
    fn proof_environment_rejects_unsupported_required_profile_facets() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../fixtures/proof-room/finding/cognition-market-qualified-profile/deployment/verifier-profile.json",
        );
        let bytes = crate::input::read(path).unwrap_or_default();
        let mut profile: chio_finding::SignedFindingChallengeVerifierProfile =
            crate::input::json(&bytes).unwrap_or_else(|error| {
                panic!("parse qualified verifier profile fixture: {error}")
            });
        profile
            .body
            .required_facets
            .push(chio_finding::FindingFacetKind::IntentBinding);

        assert!(validate_cli_finding_verifier_profile(&profile.body).is_err());
    }
}
