//! Expected-trust verification recomputes advice from separately authorized
//! inputs. Valid signatures alone establish neither fact truth nor permission.
use crate::{evaluate_explanation, project_explanation};
use chio_core_types::{canonical::CanonicalBytes, recovery::*, PublicKey};
use chio_security_types::{recovery::*, InformationLabel};

/// Values come from the verifier's selected deployment, not a signed report.
pub struct ExplanationExpectedTrust<'a> {
    pub key: &'a PublicKey,
    pub trust_domain: &'a AuthorityDomainId,
    pub issuer: &'a IssuerId,
    pub scope: &'a RecoveryScopeV1,
    pub deployment_digest: DeploymentDigest,
    pub policy_digest: PolicyDigest,
    pub contract_digest: ContractDigest,
    pub intent_digest: IntentDigest,
    pub limits: ExplanationLimitsV1,
}
pub struct ExplanationAudience<'a> {
    pub recipient: &'a ActorId,
    pub clearance: &'a InformationLabel,
    pub validity_ceiling_unix_ms: SafeInteger,
}

fn evaluation_limits(limits: ExplanationLimitsV1) -> Result<ExplanationLimitsV1, ContractError> {
    limits.validate()?;
    if limits.work.get() < 2 {
        return Err(ContractError::WorkBudgetExceeded);
    }
    Ok(ExplanationLimitsV1 {
        offers: limits.offers,
        work: SafeInteger::new(limits.work.get() / 2)?,
    })
}

/// A fixed public window for restricted views is independent of secret evidence
/// deadlines. Visible deadlines derive only from already authorized facts.
pub fn explanation_view_payload(
    snapshot: &RecoverySnapshotV1,
    registry: &RecoveryRemedyRegistryV1,
    limits: ExplanationLimitsV1,
    audience: &ExplanationAudience<'_>,
    trust_domain: &AuthorityDomainId,
    issuer: &IssuerId,
    report_ref: ExplanationRef,
) -> Result<RecoveryExplanationViewV1, ContractError> {
    let projection = project_explanation(
        snapshot,
        registry,
        evaluation_limits(limits)?,
        audience.clearance,
    )?;
    let mut expires = SafeInteger::new(
        snapshot
            .observed_at_unix_ms
            .get()
            .checked_add(MAX_EXPLANATION_VALIDITY_MS)
            .ok_or(ContractError::ArithmeticOverflow)?,
    )?
    .min(audience.validity_ceiling_unix_ms);
    if projection.summary != ExplanationViewSummaryV1::AuthorizedInspectionRequired {
        expires = expires.min(snapshot.expires_at_unix_ms);
        for fact in snapshot.observations.as_slice() {
            if !matches!(fact.label, InformationLabel::Top)
                && fact.label.flows_to(audience.clearance)
                && fact.expires_at_unix_ms > snapshot.observed_at_unix_ms
            {
                expires = expires.min(fact.expires_at_unix_ms);
            }
        }
    }
    let body = RecoveryExplanationViewV1 {
        schema: RecoveryExplanationViewSchema::V1,
        version: VersionV1,
        planner_version: RecoveryPlannerVersion::V1,
        trust_domain: trust_domain.clone(),
        issuer: issuer.clone(),
        recipient: audience.recipient.clone(),
        report_ref,
        issued_at_unix_ms: snapshot.observed_at_unix_ms,
        expires_at_unix_ms: expires,
        projection,
    };
    body.validate()?;
    Ok(body)
}
pub struct ExplanationReportInputs<'a> {
    pub snapshot: &'a RecoverySnapshotV1,
    pub registry: &'a RecoveryRemedyRegistryV1,
    pub view: &'a RecoveryExplanationViewV1,
    pub audience: ExplanationAudience<'a>,
}

fn digest<T: serde::Serialize>(
    domain: RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], ContractError> {
    let body = CanonicalBytes::new(value).map_err(|_| ContractError::Malformed)?;
    Ok(*domain.digest(&body).as_bytes())
}

/// Builds unsigned classified evidence in a process with no live effect handle
/// or authority issuer. Signing and native use remain independent operations.
pub fn explanation_report_payload(
    inputs: &ExplanationReportInputs<'_>,
    limits: ExplanationLimitsV1,
) -> Result<RecoveryExplanationReportV1, ContractError> {
    let snapshot = inputs.snapshot.normalized()?;
    let registry = inputs.registry.normalized(&snapshot)?;
    let view = inputs.view;
    view.validate()?;
    if view.recipient != *inputs.audience.recipient
        || view.issued_at_unix_ms != snapshot.observed_at_unix_ms
    {
        return Err(ContractError::BindingMismatch);
    }
    let recomputed_view = explanation_view_payload(
        &snapshot,
        &registry,
        limits,
        &inputs.audience,
        &view.trust_domain,
        &view.issuer,
        view.report_ref.clone(),
    )?;
    if &recomputed_view != view {
        return Err(ContractError::BindingMismatch);
    }
    report_with_view(&snapshot, &registry, view, limits)
}

/// Creates both payloads with exactly one full and one projected evaluation.
/// Each gets half the fixed work allowance, including incomplete searches.
pub fn prepare_explanation_report(
    snapshot: &RecoverySnapshotV1,
    registry: &RecoveryRemedyRegistryV1,
    limits: ExplanationLimitsV1,
    audience: &ExplanationAudience<'_>,
    trust_domain: &AuthorityDomainId,
    issuer: &IssuerId,
    report_ref: ExplanationRef,
) -> Result<(RecoveryExplanationViewV1, RecoveryExplanationReportV1), ContractError> {
    let snapshot = snapshot.normalized()?;
    let registry = registry.normalized(&snapshot)?;
    let view = explanation_view_payload(
        &snapshot,
        &registry,
        limits,
        audience,
        trust_domain,
        issuer,
        report_ref,
    )?;
    let report = report_with_view(&snapshot, &registry, &view, limits)?;
    Ok((view, report))
}

fn report_with_view(
    snapshot: &RecoverySnapshotV1,
    registry: &RecoveryRemedyRegistryV1,
    view: &RecoveryExplanationViewV1,
    limits: ExplanationLimitsV1,
) -> Result<RecoveryExplanationReportV1, ContractError> {
    let evaluation = evaluate_explanation(snapshot, registry, evaluation_limits(limits)?)?;
    let mut expires = snapshot.expires_at_unix_ms;
    for fact in snapshot.observations.as_slice() {
        if fact.expires_at_unix_ms > snapshot.observed_at_unix_ms {
            expires = expires.min(fact.expires_at_unix_ms);
        }
    }
    let body = RecoveryExplanationReportV1 {
        schema: RecoveryExplanationReportSchema::V1,
        version: VersionV1,
        planner_version: RecoveryPlannerVersion::V1,
        scope: snapshot.scope.clone(),
        trust_domain: view.trust_domain.clone(),
        issuer: view.issuer.clone(),
        deployment_digest: snapshot.deployment_digest,
        policy_digest: snapshot.policy_digest,
        contract_digest: snapshot.contract_digest,
        snapshot_digest: SnapshotDigest::from_bytes(digest(
            RecoveryDigestDomain::ExplanationSnapshot,
            &snapshot,
        )?),
        registry_digest: RemedyRegistryDigest::from_bytes(digest(
            RecoveryDigestDomain::RemedyRegistry,
            &registry,
        )?),
        intent_digest: snapshot.intent_digest,
        evaluation_digest: EvaluationDigest::from_bytes(digest(
            RecoveryDigestDomain::ExplanationEvaluation,
            &evaluation,
        )?),
        projection_digest: ProjectionDigest::from_bytes(digest(
            RecoveryDigestDomain::ExplanationProjection,
            view,
        )?),
        protected_graph_ref: view.report_ref.clone(),
        recipient: view.recipient.clone(),
        limits,
        issued_at_unix_ms: snapshot.observed_at_unix_ms,
        expires_at_unix_ms: expires,
    };
    body.validate()?;
    Ok(body)
}

pub fn verify_explanation_report(
    report: &SignedRecoveryExplanationReportV1,
    inputs: &ExplanationReportInputs<'_>,
    expected: &ExplanationExpectedTrust<'_>,
    now: SafeInteger,
) -> Result<(), ContractError> {
    let body = report.body();
    if report.authority_key() != expected.key
        || &body.trust_domain != expected.trust_domain
        || &body.issuer != expected.issuer
        || &body.scope != expected.scope
        || body.deployment_digest != expected.deployment_digest
        || body.policy_digest != expected.policy_digest
        || body.contract_digest != expected.contract_digest
        || body.intent_digest != expected.intent_digest
        || body.limits != expected.limits
        || now < body.issued_at_unix_ms
        || now >= body.expires_at_unix_ms
        || !report
            .verify_signature()
            .map_err(|_| ContractError::BindingMismatch)?
    {
        return Err(ContractError::BindingMismatch);
    }
    let recomputed = explanation_report_payload(inputs, expected.limits)?;
    if &recomputed != body {
        return Err(ContractError::BindingMismatch);
    }
    Ok(())
}

/// Projection provenance only. This verifier intentionally accepts no full
/// graph digest and cannot claim recomputation without the authorized basis.
pub fn verify_explanation_view(
    view: &SignedRecoveryExplanationViewV1,
    key: &PublicKey,
    trust_domain: &AuthorityDomainId,
    issuer: &IssuerId,
    recipient: &ActorId,
    now: SafeInteger,
) -> Result<(), ContractError> {
    let body = view.body();
    if view.authority_key() != key
        || &body.trust_domain != trust_domain
        || &body.issuer != issuer
        || &body.recipient != recipient
        || now < body.issued_at_unix_ms
        || now >= body.expires_at_unix_ms
        || !view
            .verify_signature()
            .map_err(|_| ContractError::BindingMismatch)?
    {
        return Err(ContractError::BindingMismatch);
    }
    Ok(())
}
