//! Pure recomputation against an explicit native observation. No effect ports.
use crate::{
    evaluate_semantic_selector, validate_semantic_payload, CompiledSemanticRegistryV1,
    VerificationBudget,
};
use alloc::vec::Vec;
use chio_core_types::recovery::*;
use chio_security_types::{flow::InformationLabel as InfoLabel, recovery::*, semantic::*};

pub struct SemanticInvocationExpectationV1<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub request_id: &'a str,
    pub request_namespace: RequestNamespaceDigest,
    pub capability: CapabilityBodyDigest,
    pub request_semantics: CanonicalPayloadDigest,
    pub source_label: &'a InfoLabel,
    pub externally_influenced: bool,
    pub influence: CanonicalPayloadDigest,
    /// Data describing the separately verified native disclosure target. This
    /// observation grants no authority to a caller of the pure evaluator.
    pub native_disclosure_target: Option<&'a InfoLabel>,
    pub now_unix_ms: u64,
}

/// This describes verified data. Only the serving store can consume a native
/// witness inside the physical capture transaction.
#[derive(Clone, Debug)]
pub struct VerifiedSemanticInvocationV1 {
    pub action: SemanticActionDigest,
    pub valid_until_unix_ms: u64,
    pub endorsement_evidence: Vec<EvidenceRef>,
    pub held_evidence: Vec<EvidenceRef>,
    pub effective_constraints: crate::ResolvedSemanticConstraintsV1,
}

/// Readonly restrictions for the owning input classifier. A live native
/// disclosure target is checked separately at physical capture. This result
/// cannot be converted into a full invocation verification result.
///
/// ```compile_fail
/// use chio_semantic_contracts::{
///     VerifiedSemanticInputRestrictionsV1, VerifiedSemanticInvocationV1,
/// };
/// fn promote(input: VerifiedSemanticInputRestrictionsV1) -> VerifiedSemanticInvocationV1 {
///     input
/// }
/// ```
pub struct VerifiedSemanticInputRestrictionsV1 {
    facts: VerifiedSemanticInvocationV1,
}

impl VerifiedSemanticInputRestrictionsV1 {
    pub fn valid_until_unix_ms(&self) -> u64 {
        self.facts.valid_until_unix_ms
    }

    pub fn endorsement_evidence(&self) -> &[EvidenceRef] {
        &self.facts.endorsement_evidence
    }

    pub fn held_evidence(&self) -> &[EvidenceRef] {
        &self.facts.held_evidence
    }

    pub fn effective_constraints(&self) -> &crate::ResolvedSemanticConstraintsV1 {
        &self.facts.effective_constraints
    }
}

fn fresh(issued: u64, until: u64, now: u64) -> Result<(), ContractError> {
    if issued > now || now >= until {
        return Err(ContractError::InvalidState);
    }
    Ok(())
}

/// One strong provider version, never a wildcard or a list of alternate tags.
pub fn validate_semantic_provider_version(version: &str) -> Result<(), ContractError> {
    let bytes = version.as_bytes();
    if bytes.len() < 3
        || bytes.len() > 128
        || bytes[0] != b'"'
        || bytes[bytes.len() - 1] != b'"'
        || !bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte) && *byte != b'"')
    {
        return Err(ContractError::BindingMismatch);
    }
    Ok(())
}

/// Preserve inherited influence while adding actual native model provenance.
pub fn semantic_observed_influence(
    base: CanonicalPayloadDigest,
    model: Option<CanonicalPayloadDigest>,
) -> Result<CanonicalPayloadDigest, ContractError> {
    match model {
        None => Ok(base),
        Some(model) => semantic_content_digest(&("native-model-influence-v1", base, model))
            .map_err(|_| ContractError::Malformed),
    }
}

/// Bind every restriction and fact claim, including its selected signer. The
/// verifier checks authority before accepting this recomputed digest.
pub fn semantic_annotated_influence(
    base: CanonicalPayloadDigest,
    annotations: &[SignedSemanticAnnotationV1],
) -> Result<CanonicalPayloadDigest, ContractError> {
    if annotations.is_empty() {
        return Ok(base);
    }
    semantic_content_digest(&("semantic-annotations-v1", base, annotations))
        .map_err(|_| ContractError::Malformed)
}

pub fn verify_semantic_invocation(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
) -> Result<VerifiedSemanticInvocationV1, ContractError> {
    verify_invocation(registry, invocation, expected, budget, true, true, true)
}

/// Recompute only input restriction data. Every signature, binding, source,
/// selector and freshness check remains mandatory. This defers only live
/// native disclosure target acceptance, never effect or capture authority.
pub fn verify_semantic_input_restrictions(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
) -> Result<VerifiedSemanticInputRestrictionsV1, ContractError> {
    verify_invocation(registry, invocation, expected, budget, true, true, false)
        .map(|facts| VerifiedSemanticInputRestrictionsV1 { facts })
}

/// Model the predecessor's missing mandatory answer gate for upgrade tests.
/// Every other check is shared with the production verifier. This returns only
/// data and cannot construct or authorize a native capture witness.
#[cfg(feature = "admission-test-support")]
pub fn verify_modeled_legacy_incomplete_annotations(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
) -> Result<VerifiedSemanticInvocationV1, ContractError> {
    verify_invocation(registry, invocation, expected, budget, false, true, true)
}

/// Model only the predecessor's absent authored status audience. This shares
/// every other gate and returns data, never native effect or capture authority.
#[cfg(feature = "admission-test-support")]
pub fn verify_modeled_legacy_missing_withheld_status(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
) -> Result<VerifiedSemanticInvocationV1, ContractError> {
    verify_invocation(registry, invocation, expected, budget, true, false, true)
}

#[cfg(feature = "admission-test-support")]
pub enum ModeledSemanticInputProfileV1 {
    IncompleteAnnotations,
    MissingStatus,
}

/// The owning fixture selector chooses one predecessor profile. The result
/// still contains only readonly input data and cannot authorize capture.
#[cfg(feature = "admission-test-support")]
pub fn verify_modeled_legacy_input_restrictions(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
    profile: ModeledSemanticInputProfileV1,
) -> Result<VerifiedSemanticInputRestrictionsV1, ContractError> {
    let (annotations, status) = match profile {
        ModeledSemanticInputProfileV1::IncompleteAnnotations => (false, true),
        ModeledSemanticInputProfileV1::MissingStatus => (true, false),
    };
    verify_invocation(
        registry,
        invocation,
        expected,
        budget,
        annotations,
        status,
        false,
    )
    .map(|facts| VerifiedSemanticInputRestrictionsV1 { facts })
}

fn verify_invocation(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
    require_complete_annotations: bool,
    require_status_audience: bool,
    require_native_disclosure: bool,
) -> Result<VerifiedSemanticInvocationV1, ContractError> {
    let action = &invocation.action;
    let (route, contract) = registry.resolve(expected.server, expected.tool)?;
    action.validate()?;
    fresh(
        action.issued_at_unix_ms.get(),
        action.valid_until_unix_ms.get(),
        expected.now_unix_ms,
    )?;
    if action.scope != registry.deployment().scope
        || action.registry != registry.digest()
        || action.generation != registry.deployment().generation
        || action.operation != contract.operation
        || action.request_id.as_str() != expected.request_id
        || action.request_namespace != expected.request_namespace
        || action.request_semantics != expected.request_semantics
        || action.capability != expected.capability
        || action.payload
            != semantic_content_digest(&invocation.payload).map_err(|_| ContractError::Malformed)?
    {
        return Err(ContractError::BindingMismatch);
    }
    let destination = route
        .destinations
        .as_slice()
        .iter()
        .find(|destination| destination.destination == action.destination)
        .ok_or(ContractError::BindingMismatch)?;
    budget.charge(32)?;
    let audience = &invocation.audience;
    let acl = audience.body();
    if semantic_key_digest(audience.authority_key()).map_err(|_| ContractError::Malformed)?
        != route.resolver_key
        || !audience
            .verify_signature()
            .map_err(|_| ContractError::Malformed)?
        || acl.scope != action.scope
        || acl.provider != destination.provider
        || acl.account != destination.account
        || acl.resource != destination.resource
        || acl.audience != destination.audience
        || acl.subject_mapping != destination.subject_mapping
        || acl.query != destination.acl_query
        || acl.completeness != SemanticAudienceCompletenessV1::Complete
        || acl.pagination.pages_observed != acl.pagination.pages_expected
        || acl.pagination.pages_observed.get() == 0
        || acl.pagination.pages_observed.get() > 16
        || acl.pagination.cursor != SemanticAclCursorV1::Complete
    {
        return Err(ContractError::BindingMismatch);
    }
    fresh(
        acl.observed_at_unix_ms.get(),
        acl.valid_until_unix_ms.get(),
        expected.now_unix_ms,
    )?;
    if destination.require_provider_precondition {
        validate_semantic_provider_version(acl.provider_version.as_str())?;
    }
    let mut valid_until = action
        .valid_until_unix_ms
        .get()
        .min(acl.valid_until_unix_ms.get());
    let mut source = expected
        .source_label
        .join_restrictions(&contract.source_label)
        .map_err(|_| ContractError::BindingMismatch)?;
    let mut external = expected.externally_influenced || contract.external_influence;
    let mut observed_facts = 0usize;
    let required_annotations = route
        .annotators
        .as_slice()
        .len()
        .checked_mul(action.inputs.as_slice().len())
        .ok_or(ContractError::LimitExceeded)?;
    if require_complete_annotations && required_annotations > 8 {
        return Err(ContractError::LimitExceeded);
    }
    let mut observed_annotations = Vec::new();
    for annotation in invocation.annotations.as_slice() {
        budget.charge(32 + route.annotators.as_slice().len() as u32)?;
        let body = annotation.body();
        observed_facts += body.facts.as_slice().len();
        if observed_facts > 32 {
            return Err(ContractError::LimitExceeded);
        }
        let key = semantic_key_digest(annotation.authority_key())
            .map_err(|_| ContractError::Malformed)?;
        let authority = route
            .annotators
            .as_slice()
            .iter()
            .find(|authority| authority.key == key)
            .ok_or(ContractError::BindingMismatch)?;
        if !annotation
            .verify_signature()
            .map_err(|_| ContractError::Malformed)?
            || body.scope != action.scope
            || !action.inputs.as_slice().contains(&body.input)
            || (body.externally_influenced && !action.externally_influenced)
            || (!body.facts.as_slice().is_empty() && !authority.may_attest_facts)
            || !body
                .facts
                .as_slice()
                .iter()
                .all(|fact| authority.facts.as_slice().contains(fact))
        {
            return Err(ContractError::BindingMismatch);
        }
        fresh(
            body.issued_at_unix_ms.get(),
            body.valid_until_unix_ms.get(),
            expected.now_unix_ms,
        )?;
        valid_until = valid_until.min(body.valid_until_unix_ms.get());
        observed_annotations.push((key, body.input.clone()));
        external |= body.externally_influenced;
        source = source
            .join_restrictions(&body.restrictions)
            .map_err(|_| ContractError::BindingMismatch)?;
    }
    if require_complete_annotations {
        for authority in route.annotators.as_slice() {
            for input in action.inputs.as_slice() {
                budget.charge(observed_annotations.len() as u32 + 1)?;
                if !observed_annotations.contains(&(authority.key, input.clone())) {
                    return Err(ContractError::MissingDependency);
                }
            }
        }
    }
    if action.externally_influenced != external
        || action.influence
            != semantic_annotated_influence(expected.influence, invocation.annotations.as_slice())?
    {
        return Err(ContractError::BindingMismatch);
    }
    if contract.kind == SemanticOperationKindV1::SupportRead {
        // The verified read audience classifies both the returned value and
        // observable completion, independently of the native manifest floor.
        source = source
            .join_restrictions(&destination.audience)
            .map_err(|_| ContractError::BindingMismatch)?;
    }
    if action.output == SemanticOutputDispositionV1::Withhold {
        if let Some(status) = &contract.withheld_status {
            if !source.flows_to(&status.audience) {
                return Err(ContractError::BindingMismatch);
            }
            source = source
                .join_restrictions(&status.audience)
                .map_err(|_| ContractError::BindingMismatch)?;
        } else if require_status_audience {
            return Err(ContractError::MissingDependency);
        }
    }
    // Integrity endorsements cannot change this confidentiality comparison.
    if source != action.source_label
        || (require_native_disclosure
            && !source.flows_to(&destination.audience)
            && expected.native_disclosure_target != Some(&destination.audience))
    {
        return Err(ContractError::BindingMismatch);
    }
    validate_semantic_payload(
        &invocation.payload,
        contract.input_fields.as_slice(),
        budget,
    )?;
    for (index, selector) in contract.selectors.as_slice().iter().enumerate() {
        budget.charge(route.reviewed_overrides.as_slice().len() as u32 + 1)?;
        if !route
            .reviewed_overrides
            .as_slice()
            .iter()
            .any(|rule| rule.selector_index.get() == index as u64)
            && !evaluate_semantic_selector(selector, &invocation.payload, budget)?
        {
            return Err(ContractError::BindingMismatch);
        }
    }
    for selector in route.operator_selectors.as_slice() {
        if !evaluate_semantic_selector(selector, &invocation.payload, budget)? {
            return Err(ContractError::BindingMismatch);
        }
    }
    let digest = semantic_action_digest(action).map_err(|_| ContractError::Malformed)?;
    let mut assertions = Vec::new();
    let mut endorsements = Vec::new();
    for endorsement in invocation.endorsements.as_slice() {
        budget.charge(
            32 + endorsements.len() as u32 + contract.required_assertions.as_slice().len() as u32,
        )?;
        let body = endorsement.body();
        observed_facts += body.assertions.as_slice().len();
        if observed_facts > 32 {
            return Err(ContractError::LimitExceeded);
        }
        if semantic_key_digest(endorsement.authority_key()).map_err(|_| ContractError::Malformed)?
            != route.endorsement_key
            || !endorsement
                .verify_signature()
                .map_err(|_| ContractError::Malformed)?
            || body.scope != action.scope
            || body.target != (SemanticEndorsementTargetV1::ExactAction { action: digest })
            || body.influence != action.influence
            || body.destination != action.destination
            || body.purpose != destination.purpose
            || endorsements.contains(&body.evidence)
            || !body
                .assertions
                .as_slice()
                .iter()
                .all(|fact| contract.required_assertions.as_slice().contains(fact))
        {
            return Err(ContractError::BindingMismatch);
        }
        fresh(
            body.issued_at_unix_ms.get(),
            body.valid_until_unix_ms.get(),
            expected.now_unix_ms,
        )?;
        valid_until = valid_until.min(body.valid_until_unix_ms.get());
        assertions.extend_from_slice(body.assertions.as_slice());
        endorsements.push(body.evidence.clone());
    }
    budget.charge((assertions.len() * contract.required_assertions.as_slice().len() + 1) as u32)?;
    if !contract
        .required_assertions
        .as_slice()
        .iter()
        .all(|fact| assertions.contains(fact))
    {
        return Err(ContractError::MissingDependency);
    }
    if let Some(transformation) = &invocation.transformation {
        budget.charge(32)?;
        let body = transformation.body();
        if semantic_key_digest(transformation.authority_key())
            .map_err(|_| ContractError::Malformed)?
            != route.transformation_key
            || !transformation
                .verify_signature()
                .map_err(|_| ContractError::Malformed)?
            || body.scope != action.scope
            || body.output != action.payload
            || body.output_label != action.source_label
            || body.influence != action.influence
            || body.destination != action.destination
            || body.purpose != destination.purpose
            || body.disposition != action.output
        {
            return Err(ContractError::BindingMismatch);
        }
        fresh(
            body.issued_at_unix_ms.get(),
            body.valid_until_unix_ms.get(),
            expected.now_unix_ms,
        )?;
        valid_until = valid_until.min(body.valid_until_unix_ms.get());
    }
    let mut held = Vec::new();
    let mut facts = Vec::new();
    for prerequisite in invocation.prerequisites.as_slice() {
        budget.charge(32 + contract.prerequisites.as_slice().len() as u32 + facts.len() as u32)?;
        let body = prerequisite.body();
        observed_facts += 1;
        if observed_facts > 32 {
            return Err(ContractError::LimitExceeded);
        }
        if semantic_key_digest(prerequisite.authority_key())
            .map_err(|_| ContractError::Malformed)?
            != route.prerequisite_key
            || !prerequisite
                .verify_signature()
                .map_err(|_| ContractError::Malformed)?
            || body.scope != action.scope
            || body.action != digest
            || body.purpose != destination.purpose
            || facts.contains(&body.fact)
            || action.inputs.as_slice().iter().any(|input| {
                input.resource == body.resource
                    && (input.version != body.version || input.content != body.material)
            })
            || !contract.prerequisites.as_slice().iter().any(|requirement| {
                requirement.fact == body.fact
                    && requirement.kind == body.kind
                    && requirement.resource == body.resource
            })
        {
            return Err(ContractError::BindingMismatch);
        }
        fresh(
            body.issued_at_unix_ms.get(),
            body.valid_until_unix_ms.get(),
            expected.now_unix_ms,
        )?;
        valid_until = valid_until.min(body.valid_until_unix_ms.get());
        facts.push(body.fact.clone());
        if body.kind == SemanticPrerequisiteKindV1::HeldReservation {
            held.push(body.evidence.clone());
        }
    }
    if facts.len() != contract.prerequisites.as_slice().len() {
        return Err(ContractError::MissingDependency);
    }
    Ok(VerifiedSemanticInvocationV1 {
        action: digest,
        valid_until_unix_ms: valid_until,
        endorsement_evidence: endorsements,
        held_evidence: held,
        effective_constraints: crate::resolve_semantic_constraints(
            registry.digest(),
            route,
            contract,
            &action.destination,
            &source,
            budget,
        )?,
    })
}
