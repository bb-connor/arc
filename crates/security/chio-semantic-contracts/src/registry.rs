use crate::VerificationBudget;
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec,
    vec::Vec,
};
use chio_core_types::{PublicKey, recovery::*};
use chio_security_types::{recovery::*, semantic::*};
use serde::{Deserialize, Serialize};

/// The host supplies its actual manifest, not a package's claim about exposure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposedSemanticToolV1 {
    pub server: ProtectedText<128>,
    pub tool: ProtectedText<128>,
    pub implementation: CanonicalPayloadDigest,
    pub input_schema: CanonicalPayloadDigest,
    pub output_schema: CanonicalPayloadDigest,
    pub channels: NonEmptyBoundedList<SemanticChannelRuleV1, 13>,
}

/// Resolved data is reusable historical evidence, not a native capture witness.
#[derive(Clone, Debug)]
pub struct CompiledSemanticRegistryV1 {
    deployment: SemanticDeploymentV1,
    packages: Vec<(SemanticPackageDigest, SemanticPackageV1)>,
    digest: SemanticRegistryDigest,
}
impl CompiledSemanticRegistryV1 {
    pub fn deployment(&self) -> &SemanticDeploymentV1 {
        &self.deployment
    }
    pub fn digest(&self) -> SemanticRegistryDigest {
        self.digest
    }
    pub fn resolve(
        &self,
        server: &str,
        tool: &str,
    ) -> Result<(&SemanticRouteV1, &SemanticOperationContractV1), ContractError> {
        let route = self
            .deployment
            .routes
            .as_slice()
            .iter()
            .find(|route| route.server.as_str() == server && route.tool.as_str() == tool)
            .ok_or(ContractError::UnsupportedProfile)?;
        for (digest, package) in &self.packages {
            if *digest == route.package {
                return package
                    .operations
                    .as_slice()
                    .iter()
                    .find(|op| op.operation == route.operation)
                    .map(|op| (route, op))
                    .ok_or(ContractError::MissingDependency);
            }
        }
        Err(ContractError::MissingDependency)
    }
}

const ALL_CHANNELS: [SemanticChannelV1; 13] = [
    SemanticChannelV1::Input,
    SemanticChannelV1::Success,
    SemanticChannelV1::Error,
    SemanticChannelV1::NoValue,
    SemanticChannelV1::Nested,
    SemanticChannelV1::Batch,
    SemanticChannelV1::Pagination,
    SemanticChannelV1::Redirect,
    SemanticChannelV1::Stream,
    SemanticChannelV1::File,
    SemanticChannelV1::Log,
    SemanticChannelV1::Shell,
    SemanticChannelV1::Model,
];
pub fn validate_semantic_channels(
    rules: &[SemanticChannelRuleV1],
    budget: &mut VerificationBudget,
) -> Result<(), ContractError> {
    if rules.len() != ALL_CHANNELS.len() {
        return Err(ContractError::UnsupportedProfile);
    }
    let mut seen = 0u16;
    for rule in rules {
        budget.charge(1)?;
        let index = match rule.channel {
            SemanticChannelV1::Input => 0,
            SemanticChannelV1::Success => 1,
            SemanticChannelV1::Error => 2,
            SemanticChannelV1::NoValue => 3,
            SemanticChannelV1::Nested => 4,
            SemanticChannelV1::Batch => 5,
            SemanticChannelV1::Pagination => 6,
            SemanticChannelV1::Redirect => 7,
            SemanticChannelV1::Stream => 8,
            SemanticChannelV1::File => 9,
            SemanticChannelV1::Log => 10,
            SemanticChannelV1::Shell => 11,
            SemanticChannelV1::Model => 12,
        };
        let bit = 1u16 << index;
        if seen & bit != 0 || rule.enabled != (index < 4) {
            return Err(ContractError::UnsupportedProfile);
        }
        seen |= bit;
    }
    Ok(())
}
fn validate_selectors(
    selectors: &[SemanticSelectorV1],
    fields: &[SemanticFieldId],
    budget: &mut VerificationBudget,
) -> Result<(), ContractError> {
    // A work unit is a bounded indexed lookup, not a repeated linear scan of
    // every field. All indexes contain at most sixteen field identities.
    budget.charge(fields.len() as u32)?;
    let fields: BTreeSet<_> = fields.iter().map(SemanticFieldId::as_str).collect();
    for selector in selectors {
        budget.charge(1)?;
        let field = match selector {
            SemanticSelectorV1::Present { field }
            | SemanticSelectorV1::Equals { field, .. }
            | SemanticSelectorV1::TextBytesAtMost { field, .. } => field,
        };
        if !fields.contains(field.as_str()) {
            return Err(ContractError::BindingMismatch);
        }
        if matches!(selector, SemanticSelectorV1::TextBytesAtMost { bytes, .. } if bytes.get() == 0 || bytes.get() > 4096)
        {
            return Err(ContractError::UnsupportedProfile);
        }
    }
    Ok(())
}

fn validate_package_dependencies(
    packages: &[SemanticPackageV1],
    digests: &[SemanticPackageDigest],
    budget: &mut VerificationBudget,
) -> Result<(), ContractError> {
    let indexes: BTreeMap<_, _> = digests
        .iter()
        .enumerate()
        .map(|(index, digest)| (*digest.as_bytes(), index))
        .collect();
    let mut dependents = vec![Vec::new(); packages.len()];
    let mut pending = vec![0usize; packages.len()];
    for (index, package) in packages.iter().enumerate() {
        budget.charge(1)?;
        let mut seen = BTreeSet::new();
        for dependency in package.dependencies.as_slice() {
            budget.charge(1)?;
            if !seen.insert(*dependency.as_bytes()) {
                return Err(ContractError::DuplicateIdentity);
            }
            let source = indexes
                .get(dependency.as_bytes())
                .ok_or(ContractError::MissingDependency)?;
            dependents[*source].push(index);
            pending[index] += 1;
        }
    }
    let mut ready: VecDeque<_> = pending
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect();
    let mut completed = 0usize;
    while let Some(index) = ready.pop_front() {
        budget.charge(1)?;
        completed += 1;
        for dependent in &dependents[index] {
            budget.charge(1)?;
            pending[*dependent] = pending[*dependent]
                .checked_sub(1)
                .ok_or(ContractError::InvalidState)?;
            if pending[*dependent] == 0 {
                ready.push_back(*dependent);
            }
        }
    }
    if completed != packages.len() {
        return Err(ContractError::DependencyCycle);
    }
    Ok(())
}

pub fn compile_semantic_registry(
    deployment: &SignedSemanticDeploymentV1,
    packages: &[SignedSemanticPackageV1],
    operator_root: &PublicKey,
    publisher_roots: &[PublicKey],
    exposed: &[ExposedSemanticToolV1],
    budget: &mut VerificationBudget,
) -> Result<CompiledSemanticRegistryV1, ContractError> {
    if packages.is_empty()
        || packages.len() > 16
        || publisher_roots.is_empty()
        || publisher_roots.len() > 16
        || exposed.len() > 16
        || deployment.authority_key() != operator_root
        || !deployment
            .verify_signature()
            .map_err(|_| ContractError::Malformed)?
    {
        return Err(ContractError::BindingMismatch);
    }
    let body = deployment.body();
    if body.exposure_binding
        != semantic_content_digest(&exposed).map_err(|_| ContractError::Malformed)?
    {
        return Err(ContractError::BindingMismatch);
    }
    if body.packages.as_slice().len() != packages.len()
        || body.routes.as_slice().len() != exposed.len()
    {
        return Err(ContractError::BindingMismatch);
    }
    let mut digests = Vec::new();
    let mut resolved = Vec::new();
    let mut operation_count = 0;
    let mut operation_ids = BTreeSet::new();
    let mut package_ids = BTreeSet::new();
    for package in packages {
        budget.charge(1)?;
        if !publisher_roots.contains(package.authority_key())
            || package.authority_key() == operator_root
            || !package
                .verify_signature()
                .map_err(|_| ContractError::Malformed)?
        {
            return Err(ContractError::BindingMismatch);
        }
        let digest =
            semantic_package_digest(package.body()).map_err(|_| ContractError::Malformed)?;
        if digests.contains(&digest)
            || !body.packages.as_slice().contains(&digest)
            || !package_ids.insert(package.body().package.as_str())
        {
            return Err(ContractError::DuplicateIdentity);
        }
        operation_count += package.body().operations.as_slice().len();
        if operation_count > 16 {
            return Err(ContractError::LimitExceeded);
        }
        for operation in package.body().operations.as_slice() {
            budget.charge(1)?;
            if !operation_ids.insert(operation.operation.as_str()) {
                return Err(ContractError::DuplicateIdentity);
            }
            validate_semantic_channels(operation.channels.as_slice(), budget)?;
            let mut fields = BTreeSet::new();
            for field in operation.input_fields.as_slice() {
                budget.charge(1)?;
                if !fields.insert(field.as_str()) {
                    return Err(ContractError::DuplicateIdentity);
                }
            }
            if operation.input_fields.as_slice().is_empty() {
                return Err(ContractError::UnsupportedProfile);
            }
            if operation.kind == SemanticOperationKindV1::IssueWrite
                && operation.required_assertions.as_slice().is_empty()
            {
                return Err(ContractError::UnsupportedProfile);
            }
            validate_selectors(
                operation.selectors.as_slice(),
                operation.input_fields.as_slice(),
                budget,
            )?;
            let mut facts = BTreeSet::new();
            for fact in operation.prerequisites.as_slice() {
                budget.charge(1)?;
                if !facts.insert(fact.fact.as_str()) {
                    return Err(ContractError::DuplicateIdentity);
                }
            }
            let mut projected = BTreeSet::new();
            for field in operation.projection_fields.as_slice() {
                budget.charge(1)?;
                if !fields.contains(field.as_str()) || !projected.insert(field.as_str()) {
                    return Err(ContractError::BindingMismatch);
                }
            }
            if (operation.kind == SemanticOperationKindV1::FieldProjection)
                == operation.projection_fields.as_slice().is_empty()
            {
                return Err(ContractError::UnsupportedProfile);
            }
        }
        digests.push(digest);
        resolved.push(package.body().clone());
    }
    validate_package_dependencies(&resolved, &digests, budget)?;
    let registry = CompiledSemanticRegistryV1 {
        deployment: body.clone(),
        packages: digests.into_iter().zip(resolved).collect(),
        digest: semantic_registry_digest(body).map_err(|_| ContractError::Malformed)?,
    };
    let mut selected_operations = BTreeSet::new();
    let mut selected_tools = BTreeSet::new();
    let mut actual_tools = BTreeMap::new();
    for tool in exposed {
        budget.charge(1)?;
        if actual_tools
            .insert((tool.server.as_str(), tool.tool.as_str()), tool)
            .is_some()
        {
            return Err(ContractError::DuplicateIdentity);
        }
    }
    for route in body.routes.as_slice() {
        budget.charge(1)?;
        if !selected_operations.insert(route.operation.as_str())
            || !selected_tools.insert((route.server.as_str(), route.tool.as_str()))
        {
            return Err(ContractError::DuplicateIdentity);
        }
        let (_, op) = registry.resolve(route.server.as_str(), route.tool.as_str())?;
        let actual = actual_tools
            .get(&(route.server.as_str(), route.tool.as_str()))
            .ok_or(ContractError::UnsupportedProfile)?;
        validate_selectors(
            route.operator_selectors.as_slice(),
            op.input_fields.as_slice(),
            budget,
        )?;
        let mut annotators = BTreeSet::new();
        for authority in route.annotators.as_slice() {
            budget.charge(1)?;
            if !annotators.insert(*authority.key.as_bytes())
                || (!authority.may_attest_facts && !authority.facts.as_slice().is_empty())
            {
                return Err(ContractError::BindingMismatch);
            }
        }
        if route.implementation != op.implementation
            || route.input_schema != op.input_schema
            || route.output_schema != op.output_schema
            || actual.implementation != op.implementation
            || actual.input_schema != op.input_schema
            || actual.output_schema != op.output_schema
            || actual.channels != op.channels
        {
            return Err(ContractError::BindingMismatch);
        }
        let mut destinations = BTreeSet::new();
        for destination in route.destinations.as_slice() {
            budget.charge(1)?;
            if !destinations.insert(destination.destination.as_str()) {
                return Err(ContractError::DuplicateIdentity);
            }
            // Canonical URL validation belongs to the native transport adapter.
            if !destination.endpoint.as_str().starts_with("https://") {
                return Err(ContractError::UnsupportedProfile);
            }
        }
        let mut overrides = BTreeSet::new();
        for override_rule in route.reviewed_overrides.as_slice() {
            budget.charge(1)?;
            let selector = usize::try_from(override_rule.selector_index.get())
                .map_err(|_| ContractError::LimitExceeded)?;
            if selector >= op.selectors.as_slice().len()
                || !overrides.insert(override_rule.selector_index.get())
            {
                return Err(ContractError::BindingMismatch);
            }
        }
    }
    Ok(registry)
}
