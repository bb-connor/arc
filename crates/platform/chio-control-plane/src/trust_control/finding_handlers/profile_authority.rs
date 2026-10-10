use super::*;

pub(super) fn verify_profile_registration_authority(
    request: &FindingProfileRegistrationRequest,
    config: &FindingMarketConfig,
    now: u64,
) -> Result<(), String> {
    if !config.governance_root.covers(now) {
        return Err("profile governance authority is not live at registration".to_owned());
    }
    let governance_key = config
        .governance_root
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_profile(&request.profile, &governance_key).map_err(|error| error.to_string())?;
    if !config
        .governance_root
        .covers(request.profile.body.issued_at)
    {
        return Err("profile was issued outside the governance key validity window".to_owned());
    }
    if now < request.profile.body.issued_at || now >= request.profile.body.expires_at {
        return Err("verifier profile is not live at registration".to_owned());
    }

    verify_profile_governance_lifecycle(
        &request.profile,
        &request.governance_authority_status,
        config,
        now,
        "profile registration",
    )
}

pub(super) fn verify_profile_governance_lifecycle(
    profile: &SignedFindingChallengeVerifierProfile,
    authority_status: &SignedFindingAuthorityStatus,
    config: &FindingMarketConfig,
    now: u64,
    boundary: &'static str,
) -> Result<(), String> {
    if !config.governance_root.covers(now) {
        return Err(format!(
            "profile governance authority is not live at {boundary}"
        ));
    }
    let governance_key = config
        .governance_root
        .key()
        .map_err(|error| error.to_string())?;
    let status_key = config
        .authority_status
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_authority_status(authority_status, &status_key)
        .map_err(|error| error.to_string())?;
    let status = &authority_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return Err(format!("authority-status signer is not live at {boundary}"));
    }
    if status.status_ref != config.governance_root.revocation_status_ref
        || status.authority_id != config.governance_root.authority_id
        || status.key != governance_key
        || status.key_epoch != config.governance_root.key_epoch
    {
        return Err("governance authority status does not bind the deployment pin".to_owned());
    }
    if status.observed_at < profile.body.issued_at {
        return Err("governance authority status predates profile issuance".to_owned());
    }
    if status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return Err("governance authority status is not a fresh current reading".to_owned());
    }
    if status.revoked_from.is_some() {
        return Err(format!(
            "profile governance authority is revoked at {boundary}"
        ));
    }
    Ok(())
}
