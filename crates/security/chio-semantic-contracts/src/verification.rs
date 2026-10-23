//! Pure recomputation of one semantic invocation against an explicit native
//! observation. No effect port, clock or store is reachable from here.
use crate::work::units;
use crate::{
    evaluate_semantic_selector, resolve_semantic_constraints, validate_semantic_payload,
    CompiledSemanticRegistryV1, ResolvedSemanticConstraintsV1, VerificationBudget,
};
use alloc::vec::Vec;
use chio_core_types::recovery::{
    semantic_action_digest, semantic_content_digest, semantic_key_digest, SemanticInvocationV1,
    SignedSemanticAnnotationV1,
};
use chio_security_types::flow::InformationLabel;
use chio_security_types::recovery::{
    CanonicalPayloadDigest, CapabilityBodyDigest, ContractError, EvidenceRef,
    RequestNamespaceDigest, SemanticActionDigest,
};
use chio_security_types::semantic::{
    SemanticAclCursorV1, SemanticAudienceCompletenessV1, SemanticEndorsementTargetV1,
    SemanticOperationKindV1, SemanticOutputDispositionV1, SemanticPrerequisiteKindV1,
};

pub const MAX_ACL_PAGES: u64 = 16;
pub const MAX_REQUIRED_ANNOTATIONS: usize = 8;
pub const MAX_OBSERVED_FACTS: usize = 32;
pub const MAX_PROVIDER_VERSION_BYTES: usize = 128;

/// What the native caller authenticated independently of the invocation:
/// the routed tool, the exact request, the capability, the request semantics,
/// the inherited source label and influence, an optionally verified native
/// disclosure target and the trusted current instant.
pub struct SemanticInvocationExpectationV1<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub request_id: &'a str,
    pub request_namespace: RequestNamespaceDigest,
    pub capability: CapabilityBodyDigest,
    pub request_semantics: CanonicalPayloadDigest,
    pub source_label: &'a InformationLabel,
    pub externally_influenced: bool,
    pub influence: CanonicalPayloadDigest,
    /// The separately verified native disclosure target. This observation
    /// grants no authority to a caller of the pure evaluator.
    pub native_disclosure_target: Option<&'a InformationLabel>,
    pub now_unix_ms: u64,
}

/// Verified data. Only the serving store can consume a native witness inside
/// the physical capture transaction.
#[derive(Clone, Debug)]
pub struct VerifiedSemanticInvocationV1 {
    pub action: SemanticActionDigest,
    pub valid_until_unix_ms: u64,
    pub endorsement_evidence: Vec<EvidenceRef>,
    pub held_evidence: Vec<EvidenceRef>,
    pub effective_constraints: ResolvedSemanticConstraintsV1,
}

/// Read-only restrictions for the owning input classifier. A live native
/// disclosure target is checked separately at physical capture. This result
/// cannot be converted into a full invocation verification result:
///
/// ```compile_fail
/// use chio_semantic_contracts::{
///     VerifiedSemanticInputRestrictionsV1, VerifiedSemanticInvocationV1,
/// };
/// fn promote(input: VerifiedSemanticInputRestrictionsV1) -> VerifiedSemanticInvocationV1 {
///     input
/// }
/// ```
///
/// Both types resolve, so the refusal above is the missing conversion:
///
/// ```
/// use chio_semantic_contracts::{
///     VerifiedSemanticInputRestrictionsV1, VerifiedSemanticInvocationV1,
/// };
/// fn keep(
///     input: VerifiedSemanticInputRestrictionsV1,
///     full: VerifiedSemanticInvocationV1,
/// ) -> (VerifiedSemanticInputRestrictionsV1, VerifiedSemanticInvocationV1) {
///     (input, full)
/// }
/// let _ = keep;
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

    pub fn effective_constraints(&self) -> &ResolvedSemanticConstraintsV1 {
        &self.facts.effective_constraints
    }
}

/// Valid on the half-open interval `[issued, until)`.
fn fresh(issued: u64, until: u64, now: u64) -> Result<(), ContractError> {
    if issued > now || now >= until {
        return Err(ContractError::InvalidState);
    }
    Ok(())
}

/// One strong quoted provider version of printable ASCII, never a wildcard,
/// a weak tag or a list of alternate tags. Refuses `BindingMismatch`.
pub fn validate_semantic_provider_version(version: &str) -> Result<(), ContractError> {
    let inner = version
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'));
    let Some(inner) = inner else {
        return Err(ContractError::BindingMismatch);
    };
    if inner.is_empty()
        || version.len() > MAX_PROVIDER_VERSION_BYTES
        || !inner
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'"')
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

/// Verify the whole invocation, including the destination audience or the
/// separately verified native disclosure target.
///
/// Refusals, in source order:
/// - the route: `UnsupportedProfile` or `MissingDependency`;
/// - `InvalidState`: an action interval outside the protocol window, or any
///   signed claim (action, audience, annotation, endorsement, transformation,
///   prerequisite) not valid at `now`;
/// - `BindingMismatch`: any scope, registry, generation, operation, request,
///   capability, semantics, payload, destination, signer, audience, ACL,
///   pagination, provider version, annotation, influence, source label,
///   disclosure, selector, endorsement, transformation or prerequisite
///   binding that differs;
/// - `LimitExceeded`: more than eight required annotations or more than 32
///   facts across annotations, endorsements and prerequisites;
/// - `MissingDependency`: an unanswered selected annotator and input, a
///   withheld output without a contract status audience, a missing required
///   assertion or a missing contract prerequisite;
/// - `Malformed`: a signed claim whose body fails its own validation;
/// - `WorkBudgetExceeded` on exhaustion.
pub fn verify_semantic_invocation(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
) -> Result<VerifiedSemanticInvocationV1, ContractError> {
    verify_invocation(registry, invocation, expected, budget, true)
}

/// Recompute input restriction data only. Every signature, binding, source,
/// selector, annotation and freshness check stays mandatory; only live native
/// disclosure target acceptance is deferred, never effect or capture
/// authority.
pub fn verify_semantic_input_restrictions(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
) -> Result<VerifiedSemanticInputRestrictionsV1, ContractError> {
    verify_invocation(registry, invocation, expected, budget, false)
        .map(|facts| VerifiedSemanticInputRestrictionsV1 { facts })
}

/// A signature check whose body fails its own validation is `Malformed`.
fn signed(valid: chio_core_types::Result<bool>) -> Result<bool, ContractError> {
    valid.map_err(|_| ContractError::Malformed)
}

fn verify_invocation(
    registry: &CompiledSemanticRegistryV1,
    invocation: &SemanticInvocationV1,
    expected: &SemanticInvocationExpectationV1<'_>,
    budget: &mut VerificationBudget,
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
        || !signed(audience.verify_integrity_embedded_key())?
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
        || acl.pagination.pages_observed.get() > MAX_ACL_PAGES
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
    let annotators = route.annotators.as_slice();
    let required_annotations = annotators
        .len()
        .checked_mul(action.inputs.as_slice().len())
        .ok_or(ContractError::LimitExceeded)?;
    if required_annotations > MAX_REQUIRED_ANNOTATIONS {
        return Err(ContractError::LimitExceeded);
    }
    let mut observed_annotations = Vec::new();
    for annotation in invocation.annotations.as_slice() {
        budget.charge(units(&[32, annotators.len()])?)?;
        let body = annotation.body();
        observed_facts = add_facts(observed_facts, body.facts.as_slice().len())?;
        let key = semantic_key_digest(annotation.authority_key())
            .map_err(|_| ContractError::Malformed)?;
        let authority = annotators
            .iter()
            .find(|authority| authority.key == key)
            .ok_or(ContractError::BindingMismatch)?;
        if !signed(annotation.verify_integrity_embedded_key())?
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
    // Every selected annotator answers for every input: a restriction it
    // would impose cannot be lifted by omitting its signed answer.
    for authority in annotators {
        for input in action.inputs.as_slice() {
            budget.charge(units(&[observed_annotations.len(), 1])?)?;
            if !observed_annotations
                .iter()
                .any(|(key, observed)| *key == authority.key && observed == input)
            {
                return Err(ContractError::MissingDependency);
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
        // its observable completion, independently of the native manifest floor.
        source = source
            .join_restrictions(&destination.audience)
            .map_err(|_| ContractError::BindingMismatch)?;
    }
    if action.output == SemanticOutputDispositionV1::Withhold {
        let status = contract
            .withheld_status
            .as_ref()
            .ok_or(ContractError::MissingDependency)?;
        if !source.flows_to(&status.audience) {
            return Err(ContractError::BindingMismatch);
        }
        source = source
            .join_restrictions(&status.audience)
            .map_err(|_| ContractError::BindingMismatch)?;
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
    let overrides = route.reviewed_overrides.as_slice();
    for (index, selector) in contract.selectors.as_slice().iter().enumerate() {
        budget.charge(units(&[overrides.len(), 1])?)?;
        let index = u64::try_from(index).map_err(|_| ContractError::LimitExceeded)?;
        if !overrides
            .iter()
            .any(|rule| rule.selector_index.get() == index)
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
    let required_assertions = contract.required_assertions.as_slice();
    let mut assertions = Vec::new();
    let mut endorsements = Vec::new();
    for endorsement in invocation.endorsements.as_slice() {
        budget.charge(units(&[32, endorsements.len(), required_assertions.len()])?)?;
        let body = endorsement.body();
        observed_facts = add_facts(observed_facts, body.assertions.as_slice().len())?;
        if semantic_key_digest(endorsement.authority_key()).map_err(|_| ContractError::Malformed)?
            != route.endorsement_key
            || !signed(endorsement.verify_integrity_embedded_key())?
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
                .all(|fact| required_assertions.contains(fact))
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
    let matching = assertions
        .len()
        .checked_mul(required_assertions.len())
        .ok_or(ContractError::ArithmeticOverflow)?;
    budget.charge(units(&[matching, 1])?)?;
    if !required_assertions
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
            || !signed(transformation.verify_integrity_embedded_key())?
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
    let requirements = contract.prerequisites.as_slice();
    let mut held = Vec::new();
    let mut facts = Vec::new();
    for prerequisite in invocation.prerequisites.as_slice() {
        budget.charge(units(&[32, requirements.len(), facts.len()])?)?;
        let body = prerequisite.body();
        observed_facts = add_facts(observed_facts, 1)?;
        // A proof covers the dependent action's exact reviewed input version
        // and material, never another version of the same resource.
        if semantic_key_digest(prerequisite.authority_key())
            .map_err(|_| ContractError::Malformed)?
            != route.prerequisite_key
            || !signed(prerequisite.verify_integrity_embedded_key())?
            || body.scope != action.scope
            || body.action != digest
            || body.purpose != destination.purpose
            || facts.contains(&body.fact)
            || action.inputs.as_slice().iter().any(|input| {
                input.resource == body.resource
                    && (input.version != body.version || input.content != body.material)
            })
            || !requirements.iter().any(|requirement| {
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
    if facts.len() != requirements.len() {
        return Err(ContractError::MissingDependency);
    }
    Ok(VerifiedSemanticInvocationV1 {
        action: digest,
        valid_until_unix_ms: valid_until,
        endorsement_evidence: endorsements,
        held_evidence: held,
        effective_constraints: resolve_semantic_constraints(
            registry.digest(),
            route,
            contract,
            &action.destination,
            &source,
            budget,
        )?,
    })
}

fn add_facts(observed: usize, added: usize) -> Result<usize, ContractError> {
    let total = observed
        .checked_add(added)
        .ok_or(ContractError::LimitExceeded)?;
    if total > MAX_OBSERVED_FACTS {
        return Err(ContractError::LimitExceeded);
    }
    Ok(total)
}
