use super::*;

pub fn issue_signed_liability_quote_request(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityQuoteRequestIssueRequest,
) -> Result<SignedLiabilityQuoteRequest, CliError> {
    let clock_now = unix_timestamp_now()?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request.provider_id.clone(),
            jurisdiction: request.jurisdiction.clone(),
            coverage_class: request.coverage_class,
            currency: request.requested_coverage_amount.currency.clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_quote_request_artifact(request, &resolution, issued_at)?;
    let signed = SignedLiabilityQuoteRequest::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability quote request artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_quote_request(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_quote_response(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityQuoteResponseIssueRequest,
) -> Result<SignedLiabilityQuoteResponse, CliError> {
    let clock_now = unix_timestamp_now()?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request.quote_request.body.provider_policy.coverage_class,
            currency: request.quote_request.body.provider_policy.currency.clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request.quote_request.body.quote_request_id,
            request
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_quote_response_artifact(request, issued_at)?;
    let signed = SignedLiabilityQuoteResponse::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability quote response artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_quote_response(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_placement(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityPlacementIssueRequest,
) -> Result<SignedLiabilityPlacement, CliError> {
    let clock_now = unix_timestamp_now()?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_placement_artifact(request, issued_at)?;
    let signed = SignedLiabilityPlacement::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability placement artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_placement(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_pricing_authority(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityPricingAuthorityIssueRequest,
) -> Result<SignedLiabilityPricingAuthority, CliError> {
    let clock_now = unix_timestamp_now()?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request.quote_request.body.provider_policy.coverage_class,
            currency: request.quote_request.body.provider_policy.currency.clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request.quote_request.body.quote_request_id,
            request
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_pricing_authority_artifact(request, issued_at)?;
    let signed = SignedLiabilityPricingAuthority::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability pricing authority artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_pricing_authority(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_bound_coverage(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityBoundCoverageIssueRequest,
) -> Result<SignedLiabilityBoundCoverage, CliError> {
    let clock_now = unix_timestamp_now()?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_bound_coverage_artifact(request, issued_at)?;
    let signed = SignedLiabilityBoundCoverage::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability bound coverage artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_bound_coverage(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_auto_bind(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityAutoBindIssueRequest,
) -> Result<SignedLiabilityAutoBindDecision, CliError> {
    let clock_now = unix_timestamp_now()?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    if request.authority.body.expires_at <= clock_now {
        return Err(CliError::cli_other_error(format!(
            "liability pricing authority `{}` is stale",
            request.authority.body.authority_id
        )));
    }
    let quoted_terms = request
        .quote_response
        .body
        .quoted_terms
        .as_ref()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "liability auto-bind requires a quoted quote response".to_string(),
            )
        })?;
    if quoted_terms.expires_at <= clock_now {
        return Err(CliError::cli_other_error(format!(
            "liability quote response `{}` is stale",
            request.quote_response.body.quote_response_id
        )));
    }
    if !request.authority.body.auto_bind_enabled {
        return Err(CliError::cli_other_error(format!(
            "liability pricing authority `{}` does not permit automatic binding",
            request.authority.body.authority_id
        )));
    }
    if request
        .quote_response
        .body
        .quote_request
        .body
        .quote_request_id
        != request.authority.body.quote_request.body.quote_request_id
    {
        return Err(CliError::cli_other_error(
            "liability auto-bind quote response must match the delegated pricing authority"
                .to_string(),
        ));
    }
    if quoted_terms.quoted_coverage_amount.units > request.authority.body.max_coverage_amount.units
    {
        return Err(CliError::cli_other_error(
            "liability auto-bind cannot be issued because quoted coverage exceeds pricing authority ceiling"
                .to_string(),
        ));
    }
    if quoted_terms.quoted_premium_amount.units > request.authority.body.max_premium_amount.units {
        return Err(CliError::cli_other_error(
            "liability auto-bind cannot be issued because quoted premium exceeds pricing authority ceiling"
                .to_string(),
        ));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let placement_request = LiabilityPlacementIssueRequest {
        quote_response: request.quote_response.clone(),
        selected_coverage_amount: quoted_terms.quoted_coverage_amount.clone(),
        selected_premium_amount: quoted_terms.quoted_premium_amount.clone(),
        effective_from: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_from,
        effective_until: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_until,
        placement_ref: request.placement_ref.clone(),
        notes: request.notes.clone(),
    };
    let placement_artifact = build_liability_placement_artifact(&placement_request, issued_at)?;
    let signed_placement =
        SignedLiabilityPlacement::sign(placement_artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability placement artifact: {error}"
            ))
        })?;
    let bound_request = LiabilityBoundCoverageIssueRequest {
        placement: signed_placement.clone(),
        policy_number: request.policy_number.clone(),
        carrier_reference: request.carrier_reference.clone(),
        bound_at: Some(issued_at),
        effective_from: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_from,
        effective_until: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_until,
        coverage_amount: quoted_terms.quoted_coverage_amount.clone(),
        premium_amount: quoted_terms.quoted_premium_amount.clone(),
    };
    let bound_artifact = build_liability_bound_coverage_artifact(&bound_request, issued_at)?;
    let signed_bound =
        SignedLiabilityBoundCoverage::sign(bound_artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability bound coverage artifact: {error}"
            ))
        })?;
    let decision_artifact = build_liability_auto_bind_decision_artifact(
        request,
        issued_at,
        signed_placement,
        signed_bound,
    )?;
    let signed =
        SignedLiabilityAutoBindDecision::sign(decision_artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability auto-bind decision artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_auto_bind_decision(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_market_workflows(
    receipt_store: &SqliteReceiptStore,
    query: &LiabilityMarketWorkflowQuery,
) -> Result<LiabilityMarketWorkflowReport, CliError> {
    receipt_store
        .query_liability_market_workflows(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn build_liability_provider_policy_reference(
    resolution: &LiabilityProviderResolutionReport,
) -> LiabilityProviderPolicyReference {
    LiabilityProviderPolicyReference {
        provider_id: resolution.provider.body.report.provider_id.clone(),
        provider_record_id: resolution.provider.body.provider_record_id.clone(),
        display_name: resolution.provider.body.report.display_name.clone(),
        jurisdiction: resolution.matched_policy.jurisdiction.clone(),
        coverage_class: resolution.query.coverage_class,
        currency: resolution.query.currency.clone(),
        required_evidence: resolution.matched_policy.required_evidence.clone(),
        max_coverage_amount: resolution.matched_policy.max_coverage_amount.clone(),
        claims_supported: resolution.matched_policy.claims_supported,
        quote_ttl_seconds: resolution.matched_policy.quote_ttl_seconds,
        bound_coverage_supported: resolution.support_boundary.bound_coverage_supported,
    }
}

fn build_liability_quote_request_artifact(
    request: &LiabilityQuoteRequestIssueRequest,
    resolution: &LiabilityProviderResolutionReport,
    issued_at: u64,
) -> Result<LiabilityQuoteRequestArtifact, CliError> {
    let artifact = LiabilityQuoteRequestArtifact {
        schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
        quote_request_id: format!(
            "lqqr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.provider_id,
                    &request.jurisdiction,
                    request.coverage_class,
                    &request.requested_coverage_amount,
                    request.requested_effective_from,
                    request.requested_effective_until,
                    &request.risk_package.body.subject_key,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        provider_policy: build_liability_provider_policy_reference(resolution),
        requested_coverage_amount: request.requested_coverage_amount.clone(),
        requested_effective_from: request.requested_effective_from,
        requested_effective_until: request.requested_effective_until,
        risk_package: request.risk_package.clone(),
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_quote_response_artifact(
    request: &LiabilityQuoteResponseIssueRequest,
    issued_at: u64,
) -> Result<LiabilityQuoteResponseArtifact, CliError> {
    let disposition = request.disposition.clone();
    let artifact = LiabilityQuoteResponseArtifact {
        schema: LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        quote_response_id: format!(
            "lqqs-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_request.body.quote_request_id,
                    &request.provider_quote_ref,
                    &disposition,
                    &request.supersedes_quote_response_id,
                    &request.quoted_terms,
                    &request.decline_reason,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        quote_request: request.quote_request.clone(),
        provider_quote_ref: request.provider_quote_ref.clone(),
        disposition,
        supersedes_quote_response_id: request.supersedes_quote_response_id.clone(),
        quoted_terms: request.quoted_terms.clone(),
        decline_reason: request.decline_reason.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_pricing_authority_artifact(
    request: &LiabilityPricingAuthorityIssueRequest,
    issued_at: u64,
) -> Result<LiabilityPricingAuthorityArtifact, CliError> {
    let artifact = LiabilityPricingAuthorityArtifact {
        schema: LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA.to_string(),
        authority_id: format!(
            "lqpa-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_request.body.quote_request_id,
                    &request.facility.body.facility_id,
                    &request.underwriting_decision.body.decision_id,
                    &request.envelope,
                    &request.max_coverage_amount,
                    &request.max_premium_amount,
                    request.expires_at,
                    request.auto_bind_enabled,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        quote_request: request.quote_request.clone(),
        provider_policy: request.quote_request.body.provider_policy.clone(),
        facility: request.facility.clone(),
        underwriting_decision: request.underwriting_decision.clone(),
        capital_book: request.capital_book.clone(),
        envelope: request.envelope.clone(),
        max_coverage_amount: request.max_coverage_amount.clone(),
        max_premium_amount: request.max_premium_amount.clone(),
        expires_at: request.expires_at,
        auto_bind_enabled: request.auto_bind_enabled,
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_placement_artifact(
    request: &LiabilityPlacementIssueRequest,
    issued_at: u64,
) -> Result<LiabilityPlacementArtifact, CliError> {
    let artifact = LiabilityPlacementArtifact {
        schema: LIABILITY_PLACEMENT_ARTIFACT_SCHEMA.to_string(),
        placement_id: format!(
            "lqpl-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_response.body.quote_response_id,
                    &request.selected_coverage_amount,
                    &request.selected_premium_amount,
                    request.effective_from,
                    request.effective_until,
                    &request.placement_ref,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        quote_response: request.quote_response.clone(),
        selected_coverage_amount: request.selected_coverage_amount.clone(),
        selected_premium_amount: request.selected_premium_amount.clone(),
        effective_from: request.effective_from,
        effective_until: request.effective_until,
        placement_ref: request.placement_ref.clone(),
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_bound_coverage_artifact(
    request: &LiabilityBoundCoverageIssueRequest,
    issued_at: u64,
) -> Result<LiabilityBoundCoverageArtifact, CliError> {
    let bound_at = request.bound_at.unwrap_or(issued_at);
    let artifact = LiabilityBoundCoverageArtifact {
        schema: LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA.to_string(),
        bound_coverage_id: format!(
            "lqbc-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.placement.body.placement_id,
                    &request.policy_number,
                    &request.carrier_reference,
                    bound_at,
                    request.effective_from,
                    request.effective_until,
                    &request.coverage_amount,
                    &request.premium_amount,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        placement: request.placement.clone(),
        policy_number: request.policy_number.clone(),
        carrier_reference: request.carrier_reference.clone(),
        bound_at,
        effective_from: request.effective_from,
        effective_until: request.effective_until,
        coverage_amount: request.coverage_amount.clone(),
        premium_amount: request.premium_amount.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_auto_bind_decision_artifact(
    request: &LiabilityAutoBindIssueRequest,
    issued_at: u64,
    placement: SignedLiabilityPlacement,
    bound_coverage: SignedLiabilityBoundCoverage,
) -> Result<LiabilityAutoBindDecisionArtifact, CliError> {
    let artifact = LiabilityAutoBindDecisionArtifact {
        schema: LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: format!(
            "lqab-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.authority.body.authority_id,
                    &request.quote_response.body.quote_response_id,
                    &request.policy_number,
                    &request.carrier_reference,
                    &placement.body.placement_id,
                    &bound_coverage.body.bound_coverage_id,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        authority: request.authority.clone(),
        quote_response: request.quote_response.clone(),
        disposition: LiabilityAutoBindDisposition::AutoBound,
        findings: Vec::new(),
        placement: Some(placement),
        bound_coverage: Some(bound_coverage),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}
