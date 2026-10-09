//! HushSpec policy evaluation.
//!
//! Evaluates an action against a policy and returns a decision
//! (allow/warn/deny).

pub use context::{
    activate_panic, deactivate_panic, is_panic_active, Decision, EvaluationAction,
    EvaluationResult, OriginContext, PostureContext, PostureResult, RuntimeAttestationContext,
};
pub use engine::{evaluate, evaluate_with_context};
pub use matchers::selected_origin_profile_id;
pub use outcomes::glob_matches;

mod context;
mod engine;
mod matchers;
mod outcomes;
#[cfg(test)]
mod tests;
