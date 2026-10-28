use chio_core_types::recovery::*;
use chio_security_types::{
    flow::InformationLabel, recovery::*, semantic::*, work::VerificationBudget,
};
use chio_semantic_contracts::*;

#[path = "semantic_contracts/fixture.rs"]
mod fixture;
use fixture::*;
#[path = "semantic_contracts/disclosure.rs"]
mod disclosure;
#[path = "semantic_contracts/evidence.rs"]
mod evidence;
#[path = "semantic_contracts/plans.rs"]
mod plans;
#[path = "semantic_contracts/registry.rs"]
mod registry;

fn compiled(fixture: &SemanticFixture) -> Result<CompiledSemanticRegistryV1, ContractError> {
    fixture.compiled()
}

fn verify(
    fixture: &SemanticFixture,
    invocation: &SemanticInvocationV1,
    now: u64,
) -> Result<VerifiedSemanticInvocationV1, ContractError> {
    fixture.verify(invocation, now)
}

fn select_fixture_annotator(fixture: &mut SemanticFixture) -> TestResult {
    let annotators = BoundedList::new(vec![SemanticAnnotatorBindingV1 {
        key: semantic_key_digest(&fixture.annotator.public_key())?,
        facts: BoundedList::new(vec![])?,
        may_attest_facts: false,
    }])?;
    fixture.rebind_route(|route| route.annotators = annotators)
}

fn resign_action(fixture: &SemanticFixture, invocation: &mut SemanticInvocationV1) -> TestResult {
    fixture.endorse(invocation)
}
