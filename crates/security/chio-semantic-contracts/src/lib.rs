//! Pure bounded semantic contract validation: dependency graphs, effect
//! contracts, semantic registries, selectors, plans and invocation
//! recomputation. No provider, plugin, filesystem, store or clock is
//! reachable, and no result is an execution permit.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod constraints;
mod effect;
mod graph;
mod plans;
mod registry;
mod selectors;
mod verification;
mod work;

pub use constraints::{
    resolve_semantic_constraints, ResolvedSemanticConstraintsV1, SemanticAppliedSelectorV1,
    SemanticNativeCeilingRequirementV1,
};
pub use effect::{
    DeduplicationPolicy, EffectContractInput, EffectContractSchema, EffectContractV1,
    LookupFinality, PartialSettlementPolicy, SubmissionIdentity, TransportRetryPolicy,
    MAX_EFFECT_CARDINALITY,
};
pub use graph::{
    validate_dependency_graph, DependencyGraphSchema, DependencyGraphV1, DependencyNodeV1,
    ValidatedDependencyGraph, MAX_DEPENDENCY_GRAPH_NODES, MAX_NODE_DEPENDENCIES,
};
pub use plans::validate_semantic_plan;
pub use registry::{
    compile_semantic_registry, validate_semantic_channels, CompiledSemanticRegistryV1,
    ExposedSemanticToolV1, MAX_EXPOSED_TOOLS, MAX_PUBLISHER_ROOTS, MAX_REGISTRY_OPERATIONS,
    MAX_REGISTRY_PACKAGES, MAX_SELECTOR_TEXT_BYTES,
};
pub use selectors::{
    evaluate_semantic_selector, project_semantic_fields, validate_semantic_payload,
    MAX_PROJECTED_FIELDS,
};
pub use verification::{
    semantic_annotated_influence, semantic_observed_influence, validate_semantic_provider_version,
    verify_semantic_input_restrictions, verify_semantic_invocation,
    SemanticInvocationExpectationV1, VerifiedSemanticInputRestrictionsV1,
    VerifiedSemanticInvocationV1, MAX_ACL_PAGES, MAX_OBSERVED_FACTS, MAX_PROVIDER_VERSION_BYTES,
    MAX_REQUIRED_ANNOTATIONS,
};
