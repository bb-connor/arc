//! Proptest generators for differential testing.
//!
//! Uses pool-based string selection instead of regex strategies for performance.

use proptest::prelude::*;

use crate::spec::{
    SpecArcScope, SpecConstraint, SpecMonetaryAmount, SpecOperation, SpecPromptGrant,
    SpecResourceGrant, SpecRuntimeAssuranceTier, SpecToolGrant,
};

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

const RESOURCE_PATTERNS: &[&str] = &[
    "arc://receipts/*",
    "arc://receipts/session/*",
    "arc://lineage/*",
    "https://api.example.com/resources/*",
    "*",
];

const PROMPT_NAMES: &[&str] = &["triage", "investigate", "summarize", "risk_*", "*"];

const CURRENCIES: &[&str] = &["USD", "EUR"];

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

fn pool_resource_pattern(idx: usize) -> String {
    RESOURCE_PATTERNS[idx % RESOURCE_PATTERNS.len()].to_string()
}

fn pool_prompt_name(idx: usize) -> String {
    PROMPT_NAMES[idx % PROMPT_NAMES.len()].to_string()
}

fn pool_currency(idx: usize) -> String {
    CURRENCIES[idx % CURRENCIES.len()].to_string()
}

pub fn arb_spec_operation() -> impl Strategy<Value = SpecOperation> {
    prop_oneof![
        Just(SpecOperation::Invoke),
        Just(SpecOperation::ReadResult),
        Just(SpecOperation::Read),
        Just(SpecOperation::Subscribe),
        Just(SpecOperation::Get),
        Just(SpecOperation::Delegate),
    ]
}

pub fn arb_spec_tool_operations() -> impl Strategy<Value = Vec<SpecOperation>> {
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

pub fn arb_spec_resource_operations() -> impl Strategy<Value = Vec<SpecOperation>> {
    (any::<bool>(), any::<bool>()).prop_map(|(read, subscribe)| {
        let mut ops = Vec::new();
        if read || !subscribe {
            ops.push(SpecOperation::Read);
        }
        if subscribe {
            ops.push(SpecOperation::Subscribe);
        }
        ops
    })
}

pub fn arb_spec_prompt_operations() -> impl Strategy<Value = Vec<SpecOperation>> {
    Just(vec![SpecOperation::Get])
}

pub fn arb_spec_runtime_assurance_tier() -> impl Strategy<Value = SpecRuntimeAssuranceTier> {
    prop_oneof![
        Just(SpecRuntimeAssuranceTier::None),
        Just(SpecRuntimeAssuranceTier::Basic),
        Just(SpecRuntimeAssuranceTier::Attested),
        Just(SpecRuntimeAssuranceTier::Verified),
    ]
}

pub fn arb_spec_monetary_amount() -> impl Strategy<Value = SpecMonetaryAmount> {
    ((1u64..10_000), 0usize..CURRENCIES.len()).prop_map(|(units, currency_idx)| {
        SpecMonetaryAmount {
            units,
            currency: pool_currency(currency_idx),
        }
    })
}

pub fn arb_spec_constraint() -> impl Strategy<Value = SpecConstraint> {
    prop_oneof![
        (0usize..PATH_PREFIXES.len()).prop_map(|i| SpecConstraint::PathPrefix(pool_path(i))),
        (0usize..DOMAINS.len()).prop_map(|i| SpecConstraint::DomainExact(pool_domain(i))),
        (0usize..DOMAINS.len()).prop_map(|i| SpecConstraint::DomainGlob(pool_domain(i))),
        (1usize..4096).prop_map(SpecConstraint::MaxLength),
        Just(SpecConstraint::GovernedIntentRequired),
        (1u64..10_000)
            .prop_map(|threshold_units| SpecConstraint::RequireApprovalAbove { threshold_units }),
        (0usize..DOMAINS.len()).prop_map(|i| SpecConstraint::SellerExact(pool_domain(i))),
        arb_spec_runtime_assurance_tier().prop_map(SpecConstraint::MinimumRuntimeAssurance),
        ("[a-z]{3,8}", "[a-z]{3,8}").prop_map(|(k, v)| SpecConstraint::Custom(k, v)),
    ]
}

pub fn arb_spec_constraints() -> impl Strategy<Value = Vec<SpecConstraint>> {
    prop::collection::vec(arb_spec_constraint(), 0..4)
}

pub fn arb_spec_tool_grant() -> impl Strategy<Value = SpecToolGrant> {
    (
        0usize..SERVER_IDS.len(),
        0usize..TOOL_NAMES.len(),
        arb_spec_tool_operations(),
        arb_spec_constraints(),
        prop_oneof![Just(None), (1u32..100).prop_map(Some)],
        prop_oneof![Just(None), arb_spec_monetary_amount().prop_map(Some)],
        prop_oneof![Just(None), arb_spec_monetary_amount().prop_map(Some)],
        prop_oneof![Just(None), Just(Some(false)), Just(Some(true))],
    )
        .prop_map(
            |(
                server_idx,
                tool_idx,
                operations,
                constraints,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost,
                dpop_required,
            )| SpecToolGrant {
                server_id: pool_server(server_idx),
                tool_name: pool_tool(tool_idx),
                operations,
                constraints,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost,
                dpop_required,
            },
        )
}

pub fn arb_spec_resource_grant() -> impl Strategy<Value = SpecResourceGrant> {
    (
        0usize..RESOURCE_PATTERNS.len(),
        arb_spec_resource_operations(),
    )
        .prop_map(|(pattern_idx, operations)| SpecResourceGrant {
            uri_pattern: pool_resource_pattern(pattern_idx),
            operations,
        })
}

pub fn arb_spec_prompt_grant() -> impl Strategy<Value = SpecPromptGrant> {
    (0usize..PROMPT_NAMES.len(), arb_spec_prompt_operations()).prop_map(
        |(prompt_idx, operations)| SpecPromptGrant {
            prompt_name: pool_prompt_name(prompt_idx),
            operations,
        },
    )
}

pub fn arb_spec_scope() -> impl Strategy<Value = SpecArcScope> {
    (
        prop::collection::vec(arb_spec_tool_grant(), 0..8),
        prop::collection::vec(arb_spec_resource_grant(), 0..4),
        prop::collection::vec(arb_spec_prompt_grant(), 0..4),
    )
        .prop_map(|(grants, resource_grants, prompt_grants)| SpecArcScope {
            grants,
            resource_grants,
            prompt_grants,
        })
}

/// Generate a (parent, child) pair where child is a valid attenuation of parent.
///
/// Construction: start with a parent scope and derive a child by:
/// 1. Keeping a subset of grants (using boolean mask)
/// 2. Keeping the same operations per grant (narrowing is complex)
/// 3. Optionally adding constraints
/// 4. Optionally reducing budget
pub fn arb_attenuated_scope_pair() -> impl Strategy<Value = (SpecArcScope, SpecArcScope)> {
    arb_spec_scope().prop_flat_map(|parent| {
        let grants = parent.grants.clone();
        let len = grants.len();
        if len == 0 {
            return Just((
                parent.clone(),
                SpecArcScope {
                    grants: vec![],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
            ))
            .boxed();
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
                        let max_cost_per_invocation = g.max_cost_per_invocation.clone();
                        let max_total_cost = g.max_total_cost.clone();
                        let dpop_required = g.dpop_required;

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
                                max_cost_per_invocation: max_cost_per_invocation.clone(),
                                max_total_cost: max_total_cost.clone(),
                                dpop_required,
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
                        SpecArcScope {
                            grants: child_grants,
                            resource_grants: vec![],
                            prompt_grants: vec![],
                        },
                    )
                }
            })
            .boxed()
    })
}

pub fn arb_impl_operation() -> impl Strategy<Value = arc_core::capability::Operation> {
    prop_oneof![
        Just(arc_core::capability::Operation::Invoke),
        Just(arc_core::capability::Operation::ReadResult),
        Just(arc_core::capability::Operation::Read),
        Just(arc_core::capability::Operation::Subscribe),
        Just(arc_core::capability::Operation::Get),
        Just(arc_core::capability::Operation::Delegate),
    ]
}

pub fn arb_impl_tool_operations() -> impl Strategy<Value = Vec<arc_core::capability::Operation>> {
    (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(invoke, read, delegate)| {
        let mut ops = Vec::new();
        if invoke || (!read && !delegate) {
            ops.push(arc_core::capability::Operation::Invoke);
        }
        if read {
            ops.push(arc_core::capability::Operation::ReadResult);
        }
        if delegate {
            ops.push(arc_core::capability::Operation::Delegate);
        }
        ops
    })
}

pub fn arb_impl_resource_operations() -> impl Strategy<Value = Vec<arc_core::capability::Operation>>
{
    (any::<bool>(), any::<bool>()).prop_map(|(read, subscribe)| {
        let mut ops = Vec::new();
        if read || !subscribe {
            ops.push(arc_core::capability::Operation::Read);
        }
        if subscribe {
            ops.push(arc_core::capability::Operation::Subscribe);
        }
        ops
    })
}

pub fn arb_impl_prompt_operations() -> impl Strategy<Value = Vec<arc_core::capability::Operation>> {
    Just(vec![arc_core::capability::Operation::Get])
}

pub fn arb_impl_constraint() -> impl Strategy<Value = arc_core::capability::Constraint> {
    prop_oneof![
        (0usize..PATH_PREFIXES.len())
            .prop_map(|i| arc_core::capability::Constraint::PathPrefix(pool_path(i))),
        (0usize..DOMAINS.len())
            .prop_map(|i| arc_core::capability::Constraint::DomainExact(pool_domain(i))),
        (0usize..DOMAINS.len())
            .prop_map(|i| arc_core::capability::Constraint::DomainGlob(pool_domain(i))),
        (1usize..4096).prop_map(arc_core::capability::Constraint::MaxLength),
        Just(arc_core::capability::Constraint::GovernedIntentRequired),
        (1u64..10_000).prop_map(|threshold_units| {
            arc_core::capability::Constraint::RequireApprovalAbove { threshold_units }
        }),
        (0usize..DOMAINS.len())
            .prop_map(|i| arc_core::capability::Constraint::SellerExact(pool_domain(i))),
        prop_oneof![
            Just(arc_core::capability::RuntimeAssuranceTier::None),
            Just(arc_core::capability::RuntimeAssuranceTier::Basic),
            Just(arc_core::capability::RuntimeAssuranceTier::Attested),
            Just(arc_core::capability::RuntimeAssuranceTier::Verified),
        ]
        .prop_map(arc_core::capability::Constraint::MinimumRuntimeAssurance),
    ]
}

pub fn arb_impl_constraints() -> impl Strategy<Value = Vec<arc_core::capability::Constraint>> {
    prop::collection::vec(arb_impl_constraint(), 0..4)
}

pub fn arb_impl_tool_grant() -> impl Strategy<Value = arc_core::capability::ToolGrant> {
    (
        0usize..SERVER_IDS.len(),
        0usize..TOOL_NAMES.len(),
        arb_impl_tool_operations(),
        arb_impl_constraints(),
        prop_oneof![Just(None), (1u32..100).prop_map(Some)],
        prop_oneof![
            Just(None),
            ((1u64..10_000), 0usize..CURRENCIES.len()).prop_map(|(units, currency_idx)| {
                Some(arc_core::capability::MonetaryAmount {
                    units,
                    currency: pool_currency(currency_idx),
                })
            })
        ],
        prop_oneof![
            Just(None),
            ((1u64..10_000), 0usize..CURRENCIES.len()).prop_map(|(units, currency_idx)| {
                Some(arc_core::capability::MonetaryAmount {
                    units,
                    currency: pool_currency(currency_idx),
                })
            })
        ],
        prop_oneof![Just(None), Just(Some(false)), Just(Some(true))],
    )
        .prop_map(
            |(
                server_idx,
                tool_idx,
                operations,
                constraints,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost,
                dpop_required,
            )| {
                arc_core::capability::ToolGrant {
                    server_id: pool_server(server_idx),
                    tool_name: pool_tool(tool_idx),
                    operations,
                    constraints,
                    max_invocations,
                    max_cost_per_invocation,
                    max_total_cost,
                    dpop_required,
                }
            },
        )
}

pub fn arb_impl_scope() -> impl Strategy<Value = arc_core::capability::ArcScope> {
    (
        prop::collection::vec(arb_impl_tool_grant(), 0..8),
        prop::collection::vec(arb_impl_resource_grant(), 0..4),
        prop::collection::vec(arb_impl_prompt_grant(), 0..4),
    )
        .prop_map(
            |(grants, resource_grants, prompt_grants)| arc_core::capability::ArcScope {
                grants,
                resource_grants,
                prompt_grants,
            },
        )
}

fn spec_op_to_impl(op: &SpecOperation) -> arc_core::capability::Operation {
    match op {
        SpecOperation::Invoke => arc_core::capability::Operation::Invoke,
        SpecOperation::ReadResult => arc_core::capability::Operation::ReadResult,
        SpecOperation::Read => arc_core::capability::Operation::Read,
        SpecOperation::Subscribe => arc_core::capability::Operation::Subscribe,
        SpecOperation::Get => arc_core::capability::Operation::Get,
        SpecOperation::Delegate => arc_core::capability::Operation::Delegate,
    }
}

fn spec_constraint_to_impl(c: &SpecConstraint) -> arc_core::capability::Constraint {
    match c {
        SpecConstraint::PathPrefix(s) => arc_core::capability::Constraint::PathPrefix(s.clone()),
        SpecConstraint::DomainExact(s) => arc_core::capability::Constraint::DomainExact(s.clone()),
        SpecConstraint::DomainGlob(s) => arc_core::capability::Constraint::DomainGlob(s.clone()),
        SpecConstraint::RegexMatch(s) => arc_core::capability::Constraint::RegexMatch(s.clone()),
        SpecConstraint::MaxLength(n) => arc_core::capability::Constraint::MaxLength(*n),
        SpecConstraint::GovernedIntentRequired => {
            arc_core::capability::Constraint::GovernedIntentRequired
        }
        SpecConstraint::RequireApprovalAbove { threshold_units } => {
            arc_core::capability::Constraint::RequireApprovalAbove {
                threshold_units: *threshold_units,
            }
        }
        SpecConstraint::SellerExact(s) => arc_core::capability::Constraint::SellerExact(s.clone()),
        SpecConstraint::MinimumRuntimeAssurance(tier) => {
            arc_core::capability::Constraint::MinimumRuntimeAssurance(match tier {
                SpecRuntimeAssuranceTier::None => arc_core::capability::RuntimeAssuranceTier::None,
                SpecRuntimeAssuranceTier::Basic => {
                    arc_core::capability::RuntimeAssuranceTier::Basic
                }
                SpecRuntimeAssuranceTier::Attested => {
                    arc_core::capability::RuntimeAssuranceTier::Attested
                }
                SpecRuntimeAssuranceTier::Verified => {
                    arc_core::capability::RuntimeAssuranceTier::Verified
                }
            })
        }
        SpecConstraint::Custom(k, v) => {
            arc_core::capability::Constraint::Custom(k.clone(), v.clone())
        }
    }
}

fn spec_grant_to_impl(g: &SpecToolGrant) -> arc_core::capability::ToolGrant {
    arc_core::capability::ToolGrant {
        server_id: g.server_id.clone(),
        tool_name: g.tool_name.clone(),
        operations: g.operations.iter().map(spec_op_to_impl).collect(),
        constraints: g.constraints.iter().map(spec_constraint_to_impl).collect(),
        max_invocations: g.max_invocations,
        max_cost_per_invocation: g.max_cost_per_invocation.as_ref().map(|amount| {
            arc_core::capability::MonetaryAmount {
                units: amount.units,
                currency: amount.currency.clone(),
            }
        }),
        max_total_cost: g.max_total_cost.as_ref().map(|amount| {
            arc_core::capability::MonetaryAmount {
                units: amount.units,
                currency: amount.currency.clone(),
            }
        }),
        dpop_required: g.dpop_required,
    }
}

fn spec_resource_grant_to_impl(g: &SpecResourceGrant) -> arc_core::capability::ResourceGrant {
    arc_core::capability::ResourceGrant {
        uri_pattern: g.uri_pattern.clone(),
        operations: g.operations.iter().map(spec_op_to_impl).collect(),
    }
}

fn spec_prompt_grant_to_impl(g: &SpecPromptGrant) -> arc_core::capability::PromptGrant {
    arc_core::capability::PromptGrant {
        prompt_name: g.prompt_name.clone(),
        operations: g.operations.iter().map(spec_op_to_impl).collect(),
    }
}

fn spec_scope_to_impl(s: &SpecArcScope) -> arc_core::capability::ArcScope {
    arc_core::capability::ArcScope {
        grants: s.grants.iter().map(spec_grant_to_impl).collect(),
        resource_grants: s
            .resource_grants
            .iter()
            .map(spec_resource_grant_to_impl)
            .collect(),
        prompt_grants: s
            .prompt_grants
            .iter()
            .map(spec_prompt_grant_to_impl)
            .collect(),
    }
}

/// Generate paired (spec, impl) scopes from the same random seed.
pub fn arb_paired_scope() -> impl Strategy<Value = (SpecArcScope, arc_core::capability::ArcScope)> {
    arb_spec_scope().prop_map(|spec| {
        let impl_scope = spec_scope_to_impl(&spec);
        (spec, impl_scope)
    })
}

/// Generate paired (spec, impl) scope pairs for subset testing.
pub fn arb_paired_scope_pair() -> impl Strategy<
    Value = (
        (SpecArcScope, arc_core::capability::ArcScope),
        (SpecArcScope, arc_core::capability::ArcScope),
    ),
> {
    (arb_spec_scope(), arb_spec_scope()).prop_map(|(spec_a, spec_b)| {
        let impl_a = spec_scope_to_impl(&spec_a);
        let impl_b = spec_scope_to_impl(&spec_b);
        ((spec_a, impl_a), (spec_b, impl_b))
    })
}

/// Generate paired (spec, impl) tool grants from the same seed.
pub fn arb_paired_grant() -> impl Strategy<Value = (SpecToolGrant, arc_core::capability::ToolGrant)>
{
    arb_spec_tool_grant().prop_map(|spec| {
        let impl_grant = spec_grant_to_impl(&spec);
        (spec, impl_grant)
    })
}

fn spec_resource_to_impl(grant: &SpecResourceGrant) -> arc_core::capability::ResourceGrant {
    spec_resource_grant_to_impl(grant)
}

pub fn arb_impl_resource_grant() -> impl Strategy<Value = arc_core::capability::ResourceGrant> {
    (
        0usize..RESOURCE_PATTERNS.len(),
        arb_impl_resource_operations(),
    )
        .prop_map(
            |(pattern_idx, operations)| arc_core::capability::ResourceGrant {
                uri_pattern: pool_resource_pattern(pattern_idx),
                operations,
            },
        )
}

pub fn arb_impl_prompt_grant() -> impl Strategy<Value = arc_core::capability::PromptGrant> {
    (0usize..PROMPT_NAMES.len(), arb_impl_prompt_operations()).prop_map(
        |(prompt_idx, operations)| arc_core::capability::PromptGrant {
            prompt_name: pool_prompt_name(prompt_idx),
            operations,
        },
    )
}

pub fn arb_paired_resource_grant(
) -> impl Strategy<Value = (SpecResourceGrant, arc_core::capability::ResourceGrant)> {
    arb_spec_resource_grant().prop_map(|spec| {
        let impl_grant = spec_resource_to_impl(&spec);
        (spec, impl_grant)
    })
}

pub fn arb_paired_prompt_grant(
) -> impl Strategy<Value = (SpecPromptGrant, arc_core::capability::PromptGrant)> {
    arb_spec_prompt_grant().prop_map(|spec| {
        let impl_grant = spec_prompt_grant_to_impl(&spec);
        (spec, impl_grant)
    })
}
