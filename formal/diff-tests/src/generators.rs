//! Proptest generators for differential testing.
//!
//! Uses pool-based string selection instead of regex strategies for performance.

use proptest::prelude::*;

use crate::spec::{SpecConstraint, SpecOperation, SpecPactScope, SpecToolGrant};

const SERVER_IDS: &[&str] = &[
    "srv-a",
    "srv-b",
    "srv-c",
    "srv-files",
    "srv-net",
    "srv-db",
    "srv-git",
    "srv-shell",
    "mcp-adapter:github",
    "mcp-adapter:slack",
];

const TOOL_NAMES: &[&str] = &[
    "file_read",
    "file_write",
    "shell_exec",
    "http_get",
    "db_query",
    "git_push",
    "send_message",
    "search",
    "create_issue",
    "list_tools",
    "*",
];

const PATH_PREFIXES: &[&str] = &[
    "/app",
    "/app/src",
    "/tmp",
    "/home/user",
    "/var/log",
    "/etc",
    "/app/data",
];

const DOMAINS: &[&str] = &[
    "api.example.com",
    "*.example.com",
    "api.github.com",
    "internal.corp.net",
];

fn pool_server(idx: usize) -> String {
    SERVER_IDS[idx % SERVER_IDS.len()].to_string()
}

fn pool_tool(idx: usize) -> String {
    TOOL_NAMES[idx % TOOL_NAMES.len()].to_string()
}

fn pool_path(idx: usize) -> String {
    PATH_PREFIXES[idx % PATH_PREFIXES.len()].to_string()
}

fn pool_domain(idx: usize) -> String {
    DOMAINS[idx % DOMAINS.len()].to_string()
}

pub fn arb_spec_operation() -> impl Strategy<Value = SpecOperation> {
    prop_oneof![
        Just(SpecOperation::Invoke),
        Just(SpecOperation::ReadResult),
        Just(SpecOperation::Delegate),
    ]
}

pub fn arb_spec_operations() -> impl Strategy<Value = Vec<SpecOperation>> {
    // Use boolean mask over the 3 variants, ensure at least one is selected.
    (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(invoke, read, delegate)| {
        let mut ops = Vec::new();
        if invoke || (!read && !delegate) {
            ops.push(SpecOperation::Invoke);
        }
        if read {
            ops.push(SpecOperation::ReadResult);
        }
        if delegate {
            ops.push(SpecOperation::Delegate);
        }
        ops
    })
}

pub fn arb_spec_constraint() -> impl Strategy<Value = SpecConstraint> {
    prop_oneof![
        (0usize..PATH_PREFIXES.len()).prop_map(|i| SpecConstraint::PathPrefix(pool_path(i))),
        (0usize..DOMAINS.len()).prop_map(|i| SpecConstraint::DomainExact(pool_domain(i))),
        (1usize..4096).prop_map(SpecConstraint::MaxLength),
    ]
}

pub fn arb_spec_constraints() -> impl Strategy<Value = Vec<SpecConstraint>> {
    prop::collection::vec(arb_spec_constraint(), 0..4)
}

pub fn arb_spec_tool_grant() -> impl Strategy<Value = SpecToolGrant> {
    (
        0usize..SERVER_IDS.len(),
        0usize..TOOL_NAMES.len(),
        arb_spec_operations(),
        arb_spec_constraints(),
        prop_oneof![Just(None), (1u32..100).prop_map(Some)],
    )
        .prop_map(
            |(server_idx, tool_idx, operations, constraints, max_invocations)| SpecToolGrant {
                server_id: pool_server(server_idx),
                tool_name: pool_tool(tool_idx),
                operations,
                constraints,
                max_invocations,
            },
        )
}

pub fn arb_spec_scope() -> impl Strategy<Value = SpecPactScope> {
    prop::collection::vec(arb_spec_tool_grant(), 0..8).prop_map(|grants| SpecPactScope { grants })
}

/// Generate a (parent, child) pair where child is a valid attenuation of parent.
///
/// Construction: start with a parent scope and derive a child by:
/// 1. Keeping a subset of grants (using boolean mask)
/// 2. Keeping the same operations per grant (narrowing is complex)
/// 3. Optionally adding constraints
/// 4. Optionally reducing budget
pub fn arb_attenuated_scope_pair() -> impl Strategy<Value = (SpecPactScope, SpecPactScope)> {
    arb_spec_scope().prop_flat_map(|parent| {
        let grants = parent.grants.clone();
        let len = grants.len();
        if len == 0 {
            return Just((parent.clone(), SpecPactScope { grants: vec![] })).boxed();
        }

        // Select a random subset of grant indices to keep
        prop::collection::vec(any::<bool>(), len..=len)
            .prop_flat_map(move |keep_mask| {
                let kept_grants: Vec<SpecToolGrant> = grants
                    .iter()
                    .zip(keep_mask.iter())
                    .filter(|(_, &keep)| keep)
                    .map(|(g, _)| g.clone())
                    .collect();

                // For each kept grant, optionally add constraints and reduce budget.
                // Keep the same operations (subset of operations requires more
                // complex generation; the grant-level differential tests cover that).
                let narrowed: Vec<_> = kept_grants
                    .into_iter()
                    .map(|g| {
                        let constraints = g.constraints.clone();
                        let max_inv = g.max_invocations;
                        let server_id = g.server_id.clone();
                        let tool_name = g.tool_name.clone();
                        let operations = g.operations.clone();

                        arb_spec_constraints().prop_map(move |extra_constraints| {
                            let child_budget = max_inv.map(|b| b / 2);
                            let mut all_constraints = constraints.clone();
                            all_constraints.extend(extra_constraints);
                            SpecToolGrant {
                                server_id: server_id.clone(),
                                tool_name: tool_name.clone(),
                                operations: operations.clone(),
                                constraints: all_constraints,
                                max_invocations: match max_inv {
                                    Some(_) => child_budget,
                                    None => None,
                                },
                            }
                        })
                    })
                    .collect();

                // Build up the child grants list sequentially
                narrowed
                    .into_iter()
                    .fold(Just(Vec::new()).boxed(), |acc, gen| {
                        (acc, gen)
                            .prop_map(|(mut v, g)| {
                                v.push(g);
                                v
                            })
                            .boxed()
                    })
            })
            .prop_map({
                let parent = parent.clone();
                move |child_grants| {
                    (
                        parent.clone(),
                        SpecPactScope {
                            grants: child_grants,
                        },
                    )
                }
            })
            .boxed()
    })
}

pub fn arb_impl_operation() -> impl Strategy<Value = pact_core::capability::Operation> {
    prop_oneof![
        Just(pact_core::capability::Operation::Invoke),
        Just(pact_core::capability::Operation::ReadResult),
        Just(pact_core::capability::Operation::Delegate),
    ]
}

pub fn arb_impl_operations() -> impl Strategy<Value = Vec<pact_core::capability::Operation>> {
    // Operation does not derive Hash, so we use a boolean mask over the 3 variants
    // and ensure at least one is selected.
    (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(invoke, read, delegate)| {
        let mut ops = Vec::new();
        if invoke || (!read && !delegate) {
            ops.push(pact_core::capability::Operation::Invoke);
        }
        if read {
            ops.push(pact_core::capability::Operation::ReadResult);
        }
        if delegate {
            ops.push(pact_core::capability::Operation::Delegate);
        }
        ops
    })
}

pub fn arb_impl_constraint() -> impl Strategy<Value = pact_core::capability::Constraint> {
    prop_oneof![
        (0usize..PATH_PREFIXES.len())
            .prop_map(|i| pact_core::capability::Constraint::PathPrefix(pool_path(i))),
        (0usize..DOMAINS.len())
            .prop_map(|i| pact_core::capability::Constraint::DomainExact(pool_domain(i))),
        (1usize..4096).prop_map(pact_core::capability::Constraint::MaxLength),
    ]
}

pub fn arb_impl_constraints() -> impl Strategy<Value = Vec<pact_core::capability::Constraint>> {
    prop::collection::vec(arb_impl_constraint(), 0..4)
}

pub fn arb_impl_tool_grant() -> impl Strategy<Value = pact_core::capability::ToolGrant> {
    (
        0usize..SERVER_IDS.len(),
        0usize..TOOL_NAMES.len(),
        arb_impl_operations(),
        arb_impl_constraints(),
        prop_oneof![Just(None), (1u32..100).prop_map(Some)],
    )
        .prop_map(
            |(server_idx, tool_idx, operations, constraints, max_invocations)| {
                pact_core::capability::ToolGrant {
                    server_id: pool_server(server_idx),
                    tool_name: pool_tool(tool_idx),
                    operations,
                    constraints,
                    max_invocations,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                }
            },
        )
}

pub fn arb_impl_scope() -> impl Strategy<Value = pact_core::capability::PactScope> {
    prop::collection::vec(arb_impl_tool_grant(), 0..8).prop_map(|grants| {
        pact_core::capability::PactScope {
            grants,
            ..pact_core::capability::PactScope::default()
        }
    })
}

fn spec_op_to_impl(op: &SpecOperation) -> pact_core::capability::Operation {
    match op {
        SpecOperation::Invoke => pact_core::capability::Operation::Invoke,
        SpecOperation::ReadResult => pact_core::capability::Operation::ReadResult,
        SpecOperation::Delegate => pact_core::capability::Operation::Delegate,
    }
}

fn spec_constraint_to_impl(c: &SpecConstraint) -> pact_core::capability::Constraint {
    match c {
        SpecConstraint::PathPrefix(s) => pact_core::capability::Constraint::PathPrefix(s.clone()),
        SpecConstraint::DomainExact(s) => pact_core::capability::Constraint::DomainExact(s.clone()),
        SpecConstraint::DomainGlob(s) => pact_core::capability::Constraint::DomainGlob(s.clone()),
        SpecConstraint::RegexMatch(s) => pact_core::capability::Constraint::RegexMatch(s.clone()),
        SpecConstraint::MaxLength(n) => pact_core::capability::Constraint::MaxLength(*n),
        SpecConstraint::Custom(k, v) => {
            pact_core::capability::Constraint::Custom(k.clone(), v.clone())
        }
    }
}

fn spec_grant_to_impl(g: &SpecToolGrant) -> pact_core::capability::ToolGrant {
    pact_core::capability::ToolGrant {
        server_id: g.server_id.clone(),
        tool_name: g.tool_name.clone(),
        operations: g.operations.iter().map(spec_op_to_impl).collect(),
        constraints: g.constraints.iter().map(spec_constraint_to_impl).collect(),
        max_invocations: g.max_invocations,
        max_cost_per_invocation: None,
        max_total_cost: None,
    }
}

fn spec_scope_to_impl(s: &SpecPactScope) -> pact_core::capability::PactScope {
    pact_core::capability::PactScope {
        grants: s.grants.iter().map(spec_grant_to_impl).collect(),
        ..pact_core::capability::PactScope::default()
    }
}

/// Generate paired (spec, impl) scopes from the same random seed.
pub fn arb_paired_scope() -> impl Strategy<Value = (SpecPactScope, pact_core::capability::PactScope)>
{
    arb_spec_scope().prop_map(|spec| {
        let impl_scope = spec_scope_to_impl(&spec);
        (spec, impl_scope)
    })
}

/// Generate paired (spec, impl) scope pairs for subset testing.
pub fn arb_paired_scope_pair() -> impl Strategy<
    Value = (
        (SpecPactScope, pact_core::capability::PactScope),
        (SpecPactScope, pact_core::capability::PactScope),
    ),
> {
    (arb_spec_scope(), arb_spec_scope()).prop_map(|(spec_a, spec_b)| {
        let impl_a = spec_scope_to_impl(&spec_a);
        let impl_b = spec_scope_to_impl(&spec_b);
        ((spec_a, impl_a), (spec_b, impl_b))
    })
}

/// Generate paired (spec, impl) tool grants from the same seed.
pub fn arb_paired_grant() -> impl Strategy<Value = (SpecToolGrant, pact_core::capability::ToolGrant)>
{
    arb_spec_tool_grant().prop_map(|spec| {
        let impl_grant = spec_grant_to_impl(&spec);
        (spec, impl_grant)
    })
}
