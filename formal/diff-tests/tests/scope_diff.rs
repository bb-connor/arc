//! Differential tests: scope subsumption logic.
//!
//! Compares the reference specification's `is_subset_of` against the production
//! `pact_core::capability::PactScope::is_subset_of` on randomly generated scopes.

use pact_formal_diff_tests::generators::{
    arb_paired_grant, arb_paired_scope_pair, arb_spec_scope, arb_spec_tool_grant,
};
use pact_formal_diff_tests::spec::{SpecOperation, SpecPactScope, SpecToolGrant};

use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

/// Read case count from `PROPTEST_CASES` env var, falling back to the given default.
fn case_count(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: case_count(256),
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Core differential test: scope subset produces the same result in spec and impl.
    #[test]
    fn scope_subset_spec_matches_impl(
        ((spec_a, impl_a), (spec_b, impl_b)) in arb_paired_scope_pair()
    ) {
        let spec_result = spec_a.is_subset_of(&spec_b);
        let impl_result = impl_a.is_subset_of(&impl_b);

        prop_assert_eq!(
            spec_result, impl_result,
            "Scope subset mismatch!\n  spec: {}\n  impl: {}\n  child grants: {}\n  parent grants: {}",
            spec_result, impl_result, spec_a.grants.len(), spec_b.grants.len()
        );
    }

    /// Tool grant subset differential test.
    #[test]
    fn grant_subset_spec_matches_impl(
        (spec_parent, impl_parent) in arb_paired_grant(),
        (spec_child, impl_child) in arb_paired_grant(),
    ) {
        let spec_result = spec_child.is_subset_of(&spec_parent);
        let impl_result = impl_child.is_subset_of(&impl_parent);

        prop_assert_eq!(
            spec_result, impl_result,
            "Grant subset mismatch!\n  spec: {}\n  impl: {}\n  child: {:?}\n  parent: {:?}",
            spec_result, impl_result, spec_child, spec_parent
        );
    }
}

proptest! {
    #![proptest_config(config())]

    /// P1: Empty scope is a subset of any scope.
    #[test]
    fn empty_scope_is_subset(scope in arb_spec_scope()) {
        let empty = SpecPactScope { grants: vec![] };
        prop_assert!(
            empty.is_subset_of(&scope),
            "Empty scope must be a subset of any scope"
        );
    }

    /// P2: A scope is a subset of itself (reflexivity).
    #[test]
    fn scope_subset_reflexive(scope in arb_spec_scope()) {
        // Only holds for scopes where each grant is a subset of itself.
        // This is true when the grant subsumption check is reflexive,
        // which it is (same server, same tool, same ops, same constraints).
        prop_assert!(
            scope.is_subset_of(&scope),
            "Scope must be a subset of itself"
        );
    }

    /// P3: Removing a grant from a scope produces a subset.
    #[test]
    fn remove_grant_is_subset(scope in arb_spec_scope(), idx in any::<usize>()) {
        if scope.grants.is_empty() {
            return Ok(());
        }
        let remove_idx = idx % scope.grants.len();
        let mut child_grants = scope.grants.clone();
        child_grants.remove(remove_idx);
        let child = SpecPactScope { grants: child_grants };

        prop_assert!(
            child.is_subset_of(&scope),
            "Removing a grant must produce a subset"
        );
    }

    /// P4: Removing an operation from a grant produces a grant that is a subset.
    #[test]
    fn remove_operation_is_subset(
        grant in arb_spec_tool_grant(),
        op_idx in any::<usize>(),
    ) {
        if grant.operations.is_empty() {
            return Ok(());
        }
        let remove_idx = op_idx % grant.operations.len();
        let mut child_ops = grant.operations.clone();
        child_ops.remove(remove_idx);

        if child_ops.is_empty() {
            // Edge case: no operations left. Still a subset since
            // all (zero) child ops are in parent.
            return Ok(());
        }

        let child = SpecToolGrant {
            operations: child_ops,
            ..grant.clone()
        };

        prop_assert!(
            child.is_subset_of(&grant),
            "Removing an operation must produce a subset"
        );
    }

    /// P5: Reducing max_invocations produces a subset.
    #[test]
    fn reduce_budget_is_subset(
        grant in arb_spec_tool_grant(),
    ) {
        if let Some(max) = grant.max_invocations {
            if max > 0 {
                let child = SpecToolGrant {
                    max_invocations: Some(max / 2),
                    ..grant.clone()
                };
                prop_assert!(
                    child.is_subset_of(&grant),
                    "Reducing budget must produce a subset"
                );
            }
        }
    }

    /// P6: Wildcard tool name subsumes any specific tool name.
    #[test]
    fn wildcard_subsumes(
        server_idx in 0usize..10,
        tool_idx in 0usize..10,
    ) {
        let server = format!("srv-{server_idx}");
        let tool = format!("tool-{tool_idx}");
        let parent = SpecToolGrant {
            server_id: server.clone(),
            tool_name: "*".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
        };
        let child = SpecToolGrant {
            server_id: server,
            tool_name: tool,
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
        };

        prop_assert!(
            child.is_subset_of(&parent),
            "Wildcard tool must subsume any specific tool"
        );
    }

    /// P7: Different servers never produce a subset relationship.
    #[test]
    fn different_servers_not_subset(
        tool in arb_spec_tool_grant(),
    ) {
        let child = SpecToolGrant {
            server_id: format!("{}-different", tool.server_id),
            ..tool.clone()
        };
        prop_assert!(
            !child.is_subset_of(&tool),
            "Different servers must not be subsets"
        );
    }

    /// P8: Monotonicity -- if child is subset of parent, and parent is subset
    /// of grandparent, then child is subset of grandparent (transitivity).
    ///
    /// This is the key delegation chain property: multi-hop delegation preserves
    /// the subset relationship.
    #[test]
    fn subset_transitivity(scope in arb_spec_scope()) {
        // Construct grandparent -> parent -> child by progressive removal.
        let grandparent = scope.clone();

        // Parent: keep first half of grants
        let half = scope.grants.len() / 2;
        let parent = SpecPactScope {
            grants: scope.grants[..half].to_vec(),
        };

        // Child: keep first quarter of grants
        let quarter = half / 2;
        let child = SpecPactScope {
            grants: scope.grants[..quarter].to_vec(),
        };

        if parent.is_subset_of(&grandparent) && child.is_subset_of(&parent) {
            prop_assert!(
                child.is_subset_of(&grandparent),
                "Subset must be transitive: child <= parent <= grandparent implies child <= grandparent"
            );
        }
    }
}
