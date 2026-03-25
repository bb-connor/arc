//! Reference specification: independent reimplementation of scope subsumption.
//!
//! Mirrors the Lean formal spec. Does **not** call into `pact_core`.

/// Mirrors `pact_core::capability::Operation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpecOperation {
    Invoke,
    ReadResult,
    Delegate,
}

/// Mirrors `pact_core::capability::Constraint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecConstraint {
    PathPrefix(String),
    DomainExact(String),
    DomainGlob(String),
    RegexMatch(String),
    MaxLength(usize),
    Custom(String, String),
}

/// Mirrors `pact_core::capability::ToolGrant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<SpecOperation>,
    pub constraints: Vec<SpecConstraint>,
    pub max_invocations: Option<u32>,
}

impl SpecToolGrant {
    /// Reference implementation of `ToolGrant::is_subset_of`.
    ///
    /// Written for clarity rather than performance. Matches the Lean spec
    /// definition in `Pact.Core.Scope.ToolGrant.isSubsetOf`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &SpecToolGrant) -> bool {
        // Same server
        if self.server_id != parent.server_id {
            return false;
        }

        // Tool name: parent is wildcard or exact match
        if parent.tool_name != "*" && self.tool_name != parent.tool_name {
            return false;
        }

        // Operations: child ops must be subset of parent ops
        for op in &self.operations {
            if !parent.operations.contains(op) {
                return false;
            }
        }

        // Invocation budget: if parent has a cap, child must too and child <= parent
        if let Some(parent_max) = parent.max_invocations {
            match self.max_invocations {
                Some(child_max) if child_max <= parent_max => {}
                _ => return false,
            }
        }

        // Constraints: parent's constraints must all appear in child (more restrictive)
        for pc in &parent.constraints {
            if !self.constraints.contains(pc) {
                return false;
            }
        }

        true
    }
}

/// Mirrors `pact_core::capability::PactScope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecPactScope {
    pub grants: Vec<SpecToolGrant>,
}

impl SpecPactScope {
    /// Reference implementation of `PactScope::is_subset_of`.
    ///
    /// Every grant in `self` must be covered by some grant in `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &SpecPactScope) -> bool {
        self.grants
            .iter()
            .all(|cg| parent.grants.iter().any(|pg| cg.is_subset_of(pg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(server: &str, tool: &str, ops: Vec<SpecOperation>) -> SpecToolGrant {
        SpecToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: ops,
            constraints: vec![],
            max_invocations: None,
        }
    }

    fn scope(grants: Vec<SpecToolGrant>) -> SpecPactScope {
        SpecPactScope { grants }
    }

    #[test]
    fn empty_scope_is_subset_of_anything() {
        let parent = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        let child = scope(vec![]);
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn same_scope_is_subset() {
        let s = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(s.is_subset_of(&s));
    }

    #[test]
    fn fewer_grants_is_subset() {
        let parent = scope(vec![
            grant("a", "t1", vec![SpecOperation::Invoke]),
            grant("a", "t2", vec![SpecOperation::Invoke]),
        ]);
        let child = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn fewer_operations_is_subset() {
        let parent = scope(vec![grant(
            "a",
            "t1",
            vec![SpecOperation::Invoke, SpecOperation::ReadResult],
        )]);
        let child = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn different_server_not_subset() {
        let parent = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        let child = scope(vec![grant("b", "t1", vec![SpecOperation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn wildcard_tool_subsumes() {
        let parent = scope(vec![grant("a", "*", vec![SpecOperation::Invoke])]);
        let child = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn budget_check() {
        let parent = SpecToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(10),
        };
        let child_ok = SpecToolGrant {
            max_invocations: Some(5),
            ..parent.clone()
        };
        let child_exceed = SpecToolGrant {
            max_invocations: Some(20),
            ..parent.clone()
        };
        let child_none = SpecToolGrant {
            max_invocations: None,
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_exceed.is_subset_of(&parent));
        assert!(!child_none.is_subset_of(&parent));
    }

    #[test]
    fn constraint_superset_check() {
        let parent = SpecToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![SpecConstraint::PathPrefix("/app".to_string())],
            max_invocations: None,
        };
        let child_ok = SpecToolGrant {
            constraints: vec![
                SpecConstraint::PathPrefix("/app".to_string()),
                SpecConstraint::MaxLength(1024),
            ],
            ..parent.clone()
        };
        let child_bad = SpecToolGrant {
            constraints: vec![SpecConstraint::MaxLength(1024)],
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_bad.is_subset_of(&parent));
    }
}
