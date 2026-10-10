use super::super::report_validation::{
    inspect_authority_state_blocking, load_authority_status_for_state,
};
use super::*;
use chio_fiscal::{FiscalDomain, FiscalResolution};
use chio_open_market::fiscal_adapter::{
    build_fiscal_open_market_fee_schedule_artifact, build_fiscal_open_market_penalty_artifact,
    evaluate_fiscal_open_market_penalty, materialize_fiscal_open_market_fee_schedule,
    FiscalLegacyFeeScheduleBinding, FiscalOpenMarketSchedule,
};

pub(crate) const AUTHORITY_NOT_CONFIGURED: &str = "trust-control authority is not configured";
pub(crate) const AUTHORITY_KEY_MALFORMED: &str =
    "trust-control authority published a malformed signing key";
pub(crate) const NO_TRUSTED_SIGNING_KEYS: &str =
    "trust-control authority did not publish any trusted signing keys";
pub(crate) const NO_SIGNING_HEAD: &str = "trust-control authority did not publish a signing head";
pub(crate) const SIGNER_NOT_ADMITTED_HEAD: &str =
    "local signing key is not the admitted live trust-control authority head";
pub(crate) const AUTHORITY_CHANGED_DURING_SIGNING: &str =
    "trust-control authority changed while the artifact was signed; the artifact was discarded";

/// Issuers that one admitted authority read trusts, with that read's head.
///
/// `trusted` is exactly the read's live issuer set and is never empty.
pub(crate) struct AdmittedAuthoritySigners {
    head: PublicKey,
    trusted: Vec<PublicKey>,
}

impl AdmittedAuthoritySigners {
    pub(crate) fn head(&self) -> &PublicKey {
        &self.head
    }

    pub(crate) fn trusted(&self) -> &[PublicKey] {
        &self.trusted
    }

    /// A signer is admitted only as this view's head and a live issuer.
    pub(crate) fn admits_signer(&self, signer: &PublicKey) -> bool {
        *signer == self.head && self.trusted.contains(signer)
    }
}

/// Trusted governance signers from the service's admitted authority view.
///
/// A stale, unconfirmed or expired view refuses with its own admission
/// response. A view without a usable issuer set refuses as unavailable.
pub(crate) fn admitted_authority_signers(
    state: &TrustServiceState,
) -> Result<AdmittedAuthoritySigners, Response> {
    let status = load_authority_status_for_state(state)?;
    admitted_signers_from_status(&status)
        .map_err(|reason| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, reason))
}

pub(crate) fn admitted_signers_from_status(
    status: &TrustAuthorityStatus,
) -> Result<AdmittedAuthoritySigners, &'static str> {
    if !status.configured {
        return Err(AUTHORITY_NOT_CONFIGURED);
    }
    let parse = |value: &str| PublicKey::from_hex(value).map_err(|_| AUTHORITY_KEY_MALFORMED);
    let mut trusted = status
        .trusted_public_keys
        .iter()
        .map(|value| parse(value))
        .collect::<Result<Vec<_>, _>>()?;
    let head = status.public_key.as_deref().map(parse).transpose()?;
    // A lifecycle projection lists exactly the live issuers. Its head may be a
    // successor that has not reached its activation instant.
    if status.issuer_state.is_none() {
        if let Some(head) = head.as_ref() {
            if !trusted.contains(head) {
                trusted.push(head.clone());
            }
        }
    }
    if trusted.is_empty() {
        return Err(NO_TRUSTED_SIGNING_KEYS);
    }
    let head = head.ok_or(NO_SIGNING_HEAD)?;
    Ok(AdmittedAuthoritySigners { head, trusted })
}

/// Signs only with the admitted live head, and returns the artifact only
/// while a fresh admitted read still names its signer as that head. An
/// artifact signed under a view that changed before return is discarded.
pub(crate) fn sign_with_admitted_authority<T>(
    state: &TrustServiceState,
    issue: impl FnOnce(&Keypair, &AdmittedAuthoritySigners) -> Result<T, CliError>,
    signer_of: impl FnOnce(&T) -> PublicKey,
) -> Result<T, Response> {
    let preflight = admitted_authority_signers(state)?;
    sign_with_admitted_signers(state, &preflight, issue, signer_of)
}

/// Signs under an already admitted `preflight` view; see
/// `sign_with_admitted_authority`.
pub(crate) fn sign_with_admitted_signers<T>(
    state: &TrustServiceState,
    preflight: &AdmittedAuthoritySigners,
    issue: impl FnOnce(&Keypair, &AdmittedAuthoritySigners) -> Result<T, CliError>,
    signer_of: impl FnOnce(&T) -> PublicKey,
) -> Result<T, Response> {
    let keypair =
        resolve_public_registry_signing_key(&state.config, &state.finding_challenge_clock)
            .map_err(rejected)?;
    let local_signer = keypair.public_key();
    if !preflight.admits_signer(&local_signer) {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            SIGNER_NOT_ADMITTED_HEAD,
        ));
    }
    let artifact = issue(&keypair, preflight).map_err(rejected)?;
    let current = admitted_authority_signers(state)?;
    let signer = signer_of(&artifact);
    if signer != local_signer || !current.admits_signer(&signer) {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            AUTHORITY_CHANGED_DURING_SIGNING,
        ));
    }
    Ok(artifact)
}

fn rejected(error: CliError) -> Response {
    plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
}

pub(crate) fn issue_signed_generic_trust_activation(
    state: &TrustServiceState,
    request: &GenericTrustActivationIssueRequest,
) -> Result<SignedGenericTrustActivation, Response> {
    sign_with_admitted_authority(
        state,
        |signer_keypair, _| {
            let local_operator = public_generic_registry_publisher(&state.config)?;
            let issued_at = request.requested_at.unwrap_or(now_unix_secs()?);
            let artifact = build_generic_trust_activation_artifact(
                &local_operator.operator_id,
                local_operator.operator_name.clone(),
                request,
                issued_at,
            )
            .map_err(CliError::cli_other_error)?;
            SignedGenericTrustActivation::sign(artifact, signer_keypair).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to sign trust activation artifact: {error}"
                ))
            })
        },
        |signed| signed.signer_key.clone(),
    )
}

pub(crate) fn evaluate_generic_trust_activation_request(
    state: &TrustServiceState,
    request: &GenericTrustActivationEvaluationRequest,
) -> Result<GenericTrustActivationEvaluation, Response> {
    let signers = admitted_authority_signers(state)?;
    evaluate_generic_trust_activation_with_signers(&signers, request).map_err(rejected)
}

pub(crate) fn evaluate_generic_trust_activation_with_signers(
    signers: &AdmittedAuthoritySigners,
    request: &GenericTrustActivationEvaluationRequest,
) -> Result<GenericTrustActivationEvaluation, CliError> {
    // Without an activation the admitted head stands in as the local signer.
    let trusted_local_operator_signer = match request.activation.as_ref() {
        Some(activation) => {
            ensure_signed_by_trusted_authority(
                "trust activation",
                &activation.signer_key,
                signers.trusted(),
            )?;
            &activation.signer_key
        }
        None => signers.head(),
    };
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_generic_trust_activation(request, now, trusted_local_operator_signer)
        .map_err(CliError::cli_other_error)
}

pub(crate) fn issue_signed_generic_governance_charter(
    state: &TrustServiceState,
    request: &GenericGovernanceCharterIssueRequest,
) -> Result<SignedGenericGovernanceCharter, Response> {
    sign_with_admitted_authority(
        state,
        |signer_keypair, _| {
            let local_operator = public_generic_registry_publisher(&state.config)?;
            let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
            let artifact = build_generic_governance_charter_artifact(
                &local_operator.operator_id,
                local_operator.operator_name.clone(),
                request,
                issued_at,
            )
            .map_err(CliError::cli_other_error)?;
            SignedGenericGovernanceCharter::sign(artifact, signer_keypair).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to sign governance charter artifact: {error}"
                ))
            })
        },
        |signed| signed.signer_key.clone(),
    )
}

pub(crate) fn issue_signed_generic_governance_case(
    state: &TrustServiceState,
    request: &GenericGovernanceCaseIssueRequest,
) -> Result<SignedGenericGovernanceCase, Response> {
    sign_with_admitted_authority(
        state,
        |signer_keypair, _| {
            let local_operator = public_generic_registry_publisher(&state.config)?;
            let issued_at = request.opened_at.unwrap_or(now_unix_secs()?);
            let artifact = build_generic_governance_case_artifact(
                &local_operator.operator_id,
                request,
                issued_at,
            )
            .map_err(CliError::cli_other_error)?;
            SignedGenericGovernanceCase::sign(artifact, signer_keypair).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to sign governance case artifact: {error}"
                ))
            })
        },
        |signed| signed.signer_key.clone(),
    )
}

pub fn evaluate_generic_governance_case_request(
    request: &GenericGovernanceCaseEvaluationRequest,
) -> Result<GenericGovernanceCaseEvaluation, CliError> {
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_generic_governance_case(request, now).map_err(CliError::cli_other_error)
}

/// An open-market fee schedule signed under the admitted authority. Signing
/// persists nothing; a governed schedule still has to be bound.
pub(crate) struct PreparedFeeSchedule {
    signed: SignedOpenMarketFeeSchedule,
    binding: Option<(Arc<TrustFiscalRuntime>, String)>,
}

impl PreparedFeeSchedule {
    /// The schedule itself when nothing has to be bound, which makes it final
    /// once signed.
    pub(crate) fn into_unbound(self) -> Result<SignedOpenMarketFeeSchedule, Self> {
        match self.binding {
            None => Ok(self.signed),
            Some(_) => Err(self),
        }
    }
}

pub(crate) fn prepare_open_market_fee_schedule(
    state: &TrustServiceState,
    request: &OpenMarketFeeScheduleIssueRequest,
) -> Result<PreparedFeeSchedule, Response> {
    let fiscal_runtime = state.fiscal_runtime.clone();
    let (signed, governed_schedule_id) = sign_with_admitted_authority(
        state,
        |signer_keypair, _| {
            let local_operator = public_generic_registry_publisher(&state.config)?;
            let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
            let (artifact, governed_schedule_id) = if let Some(runtime) = fiscal_runtime.as_deref()
            {
                runtime
                    .with_resolver(|resolver| {
                        match resolver.resolve::<FiscalOpenMarketSchedule>(
                            FiscalDomain::OpenMarketFeeAndBondSchedule,
                            None,
                        ) {
                            FiscalResolution::Governed { schedule_id, .. } => Ok((
                                materialize_fiscal_open_market_fee_schedule(resolver)
                                    .map_err(|error| error.to_string())?,
                                Some(schedule_id),
                            )),
                            FiscalResolution::Fallback(_) => Ok((
                                build_fiscal_open_market_fee_schedule_artifact(
                                    &local_operator.operator_id,
                                    local_operator.operator_name.clone(),
                                    request,
                                    issued_at,
                                    resolver,
                                )
                                .map_err(|error| error.to_string())?,
                                None,
                            )),
                            FiscalResolution::Denied(reason) => {
                                Err(format!("fiscal open-market economics denied: {reason:?}"))
                            }
                        }
                    })
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?
                    .map_err(CliError::cli_other_error)?
            } else {
                (
                    build_open_market_fee_schedule_artifact(
                        &local_operator.operator_id,
                        local_operator.operator_name.clone(),
                        request,
                        issued_at,
                    )
                    .map_err(CliError::cli_other_error)?,
                    None,
                )
            };
            let signed =
                SignedOpenMarketFeeSchedule::sign(artifact, signer_keypair).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to sign open-market fee schedule artifact: {error}"
                    ))
                })?;
            Ok((signed, governed_schedule_id))
        },
        |(signed, _)| signed.signer_key.clone(),
    )?;
    Ok(PreparedFeeSchedule {
        signed,
        binding: fiscal_runtime.zip(governed_schedule_id),
    })
}

/// Binds a governed fee schedule and returns it.
///
/// The final authority authorization is observed inside the fiscal binding
/// write transaction, immediately before it commits; that commit is the
/// durable binding point. The two live in separate databases, so they are
/// not atomic: an authority change after the observation does not undo or
/// refuse a binding that has committed, and nothing after the commit reports
/// a refusal. A refused observation rolls the binding back, so no binding
/// is ever persisted behind an authority refusal. Fiscal storage failures
/// stay distinct from that refusal.
pub(crate) fn bind_governed_fee_schedule(
    state: &TrustServiceState,
    prepared: PreparedFeeSchedule,
) -> Result<SignedOpenMarketFeeSchedule, Response> {
    let PreparedFeeSchedule { signed, binding } = prepared;
    let Some((runtime, schedule_id)) = binding else {
        return Ok(signed);
    };
    let authorization = runtime
        .bind_legacy_fee_schedule_admitted(&schedule_id, &signed, || {
            inspect_authority_state_blocking(state, |state| {
                if admitted_authority_signers(state)?.admits_signer(&signed.signer_key) {
                    Ok(())
                } else {
                    Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        AUTHORITY_CHANGED_DURING_SIGNING,
                    ))
                }
            })
        })
        .map_err(|error| rejected(CliError::cli_other_error(error.to_string())))?;
    authorization.map(|()| signed)
}

pub(crate) fn issue_signed_open_market_penalty(
    state: &TrustServiceState,
    request: &OpenMarketPenaltyIssueRequest,
) -> Result<SignedOpenMarketPenalty, Response> {
    let fiscal_runtime = state.fiscal_runtime.as_deref();
    sign_with_admitted_authority(
        state,
        |signer_keypair, signers| {
            let trusted_authority_signers = signers.trusted();
            ensure_open_market_issue_signed_by_trusted_authority(
                request,
                trusted_authority_signers,
            )?;
            let local_operator = public_generic_registry_publisher(&state.config)?;
            let issued_at = request.opened_at.unwrap_or(now_unix_secs()?);
            let artifact = if let Some(runtime) = fiscal_runtime {
                runtime
                    .with_resolver(|resolver| {
                        let binding = fiscal_binding(runtime, resolver)?;
                        build_fiscal_open_market_penalty_artifact(
                            &local_operator.operator_id,
                            request,
                            issued_at,
                            binding.as_ref(),
                            resolver,
                            trusted_authority_signers,
                        )
                        .map_err(|error| error.to_string())
                    })
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?
                    .map_err(CliError::cli_other_error)?
            } else {
                build_open_market_penalty_artifact_with_trusted_signers(
                    &local_operator.operator_id,
                    request,
                    issued_at,
                    trusted_authority_signers,
                )
                .map_err(CliError::cli_other_error)?
            };
            SignedOpenMarketPenalty::sign(artifact, signer_keypair).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to sign open-market penalty artifact: {error}"
                ))
            })
        },
        |signed| signed.signer_key.clone(),
    )
}

pub(crate) fn evaluate_open_market_penalty_request(
    state: &TrustServiceState,
    request: &OpenMarketPenaltyEvaluationRequest,
) -> Result<OpenMarketPenaltyEvaluation, Response> {
    let signers = admitted_authority_signers(state)?;
    evaluate_open_market_penalty_with_signers(&signers, request, state.fiscal_runtime.as_deref())
        .map_err(rejected)
}

pub(crate) fn evaluate_open_market_penalty_with_signers(
    signers: &AdmittedAuthoritySigners,
    request: &OpenMarketPenaltyEvaluationRequest,
    fiscal_runtime: Option<&TrustFiscalRuntime>,
) -> Result<OpenMarketPenaltyEvaluation, CliError> {
    let trusted_authority_signers = signers.trusted();
    ensure_open_market_evaluation_signed_by_trusted_authority(request, trusted_authority_signers)?;
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    if let Some(runtime) = fiscal_runtime {
        runtime
            .with_resolver(|resolver| {
                let binding = fiscal_binding(runtime, resolver)?;
                evaluate_fiscal_open_market_penalty(
                    request,
                    now,
                    binding.as_ref(),
                    resolver,
                    trusted_authority_signers,
                )
                .map_err(|error| error.to_string())
            })
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .map_err(CliError::cli_other_error)
    } else {
        evaluate_open_market_penalty_with_trusted_signers(request, now, trusted_authority_signers)
            .map_err(CliError::cli_other_error)
    }
}

fn fiscal_binding(
    runtime: &TrustFiscalRuntime,
    resolver: &chio_fiscal::FiscalResolver<'_>,
) -> Result<Option<FiscalLegacyFeeScheduleBinding>, String> {
    match resolver
        .resolve::<FiscalOpenMarketSchedule>(FiscalDomain::OpenMarketFeeAndBondSchedule, None)
    {
        FiscalResolution::Governed { schedule_id, .. } => runtime
            .legacy_fee_schedule_binding(&schedule_id)
            .map_err(|error| error.to_string()),
        FiscalResolution::Fallback(_) => Ok(None),
        FiscalResolution::Denied(reason) => {
            Err(format!("fiscal open-market economics denied: {reason:?}"))
        }
    }
}

fn ensure_open_market_issue_signed_by_trusted_authority(
    request: &OpenMarketPenaltyIssueRequest,
    trusted_authority_signers: &[PublicKey],
) -> Result<(), CliError> {
    ensure_signed_by_trusted_authority(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance charter",
        &request.charter.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance case",
        &request.case.signer_key,
        trusted_authority_signers,
    )?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_signed_by_trusted_authority(
            "trust activation",
            &activation.signer_key,
            trusted_authority_signers,
        )?;
    }
    Ok(())
}

fn ensure_open_market_evaluation_signed_by_trusted_authority(
    request: &OpenMarketPenaltyEvaluationRequest,
    trusted_authority_signers: &[PublicKey],
) -> Result<(), CliError> {
    ensure_signed_by_trusted_authority(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance charter",
        &request.charter.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance case",
        &request.case.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "open-market penalty",
        &request.penalty.signer_key,
        trusted_authority_signers,
    )?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_signed_by_trusted_authority(
            "trust activation",
            &activation.signer_key,
            trusted_authority_signers,
        )?;
    }
    if let Some(prior_penalty) = request.prior_penalty.as_ref() {
        ensure_signed_by_trusted_authority(
            "prior open-market penalty",
            &prior_penalty.signer_key,
            trusted_authority_signers,
        )?;
    }
    Ok(())
}

pub(crate) fn ensure_signed_by_trusted_authority(
    label: &str,
    signer_key: &PublicKey,
    trusted_authority_signers: &[PublicKey],
) -> Result<(), CliError> {
    if !trusted_authority_signers
        .iter()
        .any(|trusted_signer| trusted_signer == signer_key)
    {
        return Err(CliError::cli_other_error(format!(
            "{label} signer does not match a trusted trust-control authority signer"
        )));
    }
    Ok(())
}

pub(crate) fn evaluate_federation_policy_request(
    state: &TrustServiceState,
    request: &FederationAdmissionEvaluationRequest,
    now: u64,
) -> Result<FederationAdmissionEvaluationResponse, CliError> {
    let (_, registry) = load_federation_policy_registry_for_admin(&state.config)?;
    let record = registry.get(&request.policy_id).cloned().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "federation policy `{}` was not found",
            request.policy_id
        ))
    })?;
    verify_federation_admission_policy_record(&record)?;

    let policy = &record.policy.body;
    let proof_of_work_required = record.anti_sybil.proof_of_work_bits.is_some();
    let proof_of_work_verified = record
        .anti_sybil
        .proof_of_work_bits
        .map(|difficulty_bits| {
            request.proof_of_work_nonce.as_deref().is_some_and(|nonce| {
                verify_admission_proof_of_work(
                    &request.policy_id,
                    &request.subject_key,
                    nonce,
                    difficulty_bits,
                )
            })
        })
        .unwrap_or(true);
    let bond_backed_required = record.anti_sybil.bond_backed_only;
    let bond_backed_satisfied = !bond_backed_required
        || request.requested_admission_class == GenericTrustAdmissionClass::BondBacked;

    let mut response = FederationAdmissionEvaluationResponse {
        policy_id: request.policy_id.clone(),
        subject_key: request.subject_key.clone(),
        requested_admission_class: request.requested_admission_class,
        accepted: false,
        decision_reason: String::new(),
        proof_of_work_required,
        proof_of_work_verified,
        bond_backed_required,
        bond_backed_satisfied,
        minimum_reputation_score: record.minimum_reputation_score,
        observed_reputation_score: None,
        rate_limit: None,
    };

    if !policy
        .allowed_admission_classes
        .contains(&request.requested_admission_class)
    {
        response.decision_reason =
            "requested admission class is not allowed by the signed federation policy".to_string();
        return Ok(response);
    }

    if proof_of_work_required && !proof_of_work_verified {
        response.decision_reason =
            "proof-of-work nonce did not satisfy the configured federation policy difficulty"
                .to_string();
        return Ok(response);
    }

    if !bond_backed_satisfied {
        response.decision_reason =
            "federation policy requires bond_backed admission for permissionless entry".to_string();
        return Ok(response);
    }

    if let Some(minimum_score) = record.minimum_reputation_score {
        let read_context = chio_kernel::ReceiptReadContext::admin_service();
        let trusted_kernel_keys = trusted_kernel_keys_from_service_config(&state.config)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "trust service authority material is configured but could not be loaded for federation admission: {error}"
                ))
            })?
            .unwrap_or_default();
        let inspection = match state.receipt_store.as_deref() {
            Some(receipt_store) => crate::issuance::inspect_local_reputation_with_store(
                &request.subject_key,
                receipt_store,
                state.config.budget_db_path.as_deref(),
                None,
                None,
                state.config.issuance_policy.as_ref(),
                &trusted_kernel_keys,
                &read_context,
            ),
            None => crate::issuance::inspect_local_reputation_with_read_context(
                &request.subject_key,
                None,
                state.config.budget_db_path.as_deref(),
                None,
                None,
                state.config.issuance_policy.as_ref(),
                &trusted_kernel_keys,
                &read_context,
            ),
        }
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to inspect local reputation for federation admission: {error}"
            ))
        })?;
        response.observed_reputation_score = Some(inspection.effective_score);
        if inspection.effective_score < minimum_score {
            response.decision_reason = format!(
                "effective local reputation score {:.4} is below the federation threshold {:.4}",
                inspection.effective_score, minimum_score
            );
            return Ok(response);
        }
    }

    if let Some(limit) = record.anti_sybil.rate_limit.as_ref() {
        let mut limiter = state
            .federation_admission_rate_limiter
            .lock()
            .map_err(|_| {
                CliError::cli_other_error(
                    "federation admission rate limiter is poisoned".to_string(),
                )
            })?;
        let status = limiter.check_and_record(&request.policy_id, &request.subject_key, limit, now);
        let limited = status.retry_after_seconds.is_some();
        response.rate_limit = Some(status);
        if limited {
            response.decision_reason =
                "federation admission rate limit exceeded for the configured policy window"
                    .to_string();
            return Ok(response);
        }
    }

    response.accepted = true;
    response.decision_reason =
        "subject satisfied the configured federation reputation and anti-sybil controls"
            .to_string();
    Ok(response)
}
