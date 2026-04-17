//! Portable scope matching for tool grants.
//!
//! This module implements the subset of scope matching that can run
//! `no_std + alloc`: server/tool name matching (with `*` wildcard) and
//! `Operation::Invoke` presence. Parameter-level constraint evaluation
//! (regex, path normalization, model-safety floors, audience allowlists,
//! SQL policy, etc.) stays in `arc-kernel::request_matching` because it
//! pulls in `regex` and assorted heavier heuristics that are not required
//! for a portable TCB.
//!
//! Callers that want the full constraint pipeline continue to go through
//! `arc_kernel::capability_matches_request` -- the public API in the
//! orchestration shell is unchanged. This function is the pure-compute
//! kernel the portable adapters will consume directly.

use alloc::vec::Vec;

use arc_core_types::capability::{ArcScope, CapabilityToken, Operation, ToolGrant};

/// Borrowed match result, ordered by specificity.
///
/// Mirrors the layout of `arc_kernel::MatchingGrant` but is exposed
/// publicly so portable adapters can rank and iterate matches without
/// re-running the sort.
#[derive(Debug, Clone, Copy)]
pub struct MatchedGrant<'a> {
    /// Index of this grant inside the scope's grant vector.
    pub index: usize,
    /// The matched grant itself.
    pub grant: &'a ToolGrant,
    /// Specificity tuple: `(server-exact, tool-exact, constraint-count)`.
    pub specificity: (u8, u8, usize),
}

/// Errors that can be raised by the portable scope matcher.
///
/// The full matcher in `arc-kernel` surfaces richer error variants
/// (invalid-constraint, attestation-trust, etc.); the portable core
/// returns the two coarse-grained cases that do not require regex or
/// other IO-adjacent machinery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeMatchError {
    /// No grant in the scope covers the requested `(server, tool, Invoke)`.
    OutOfScope,
}

/// Resolve the set of grants that authorise a tool invocation on the
/// given server.
///
/// This is the portable subset of `arc_kernel::request_matching::resolve_matching_grants`.
/// The full kernel additionally evaluates parameter constraints, model
/// metadata, and governed/attestation trust material. Portable adapters
/// that need those checks must plumb them through a platform-specific
/// callback; most on-wire evaluations in the wild only need the plain
/// `(server, tool, Invoke)` check.
///
/// Returns the matched grants sorted by decreasing specificity
/// (exact-exact first, then exact-wildcard, then wildcard-wildcard; ties
/// broken by grant-list order).
pub fn resolve_matching_grants<'a>(
    scope: &'a ArcScope,
    tool_name: &str,
    server_id: &str,
) -> Vec<MatchedGrant<'a>> {
    let mut matches: Vec<MatchedGrant<'a>> = Vec::new();

    for (index, grant) in scope.grants.iter().enumerate() {
        if !grant_covers(grant, tool_name, server_id) {
            continue;
        }

        matches.push(MatchedGrant {
            index,
            grant,
            specificity: (
                u8::from(grant.server_id == server_id),
                u8::from(grant.tool_name == tool_name),
                grant.constraints.len(),
            ),
        });
    }

    matches.sort_by(|left, right| {
        right
            .specificity
            .cmp(&left.specificity)
            .then_with(|| left.index.cmp(&right.index))
    });

    matches
}

/// Convenience wrapper that runs [`resolve_matching_grants`] against a
/// full capability token.
pub fn resolve_capability_grants<'a>(
    capability: &'a CapabilityToken,
    tool_name: &str,
    server_id: &str,
) -> Result<Vec<MatchedGrant<'a>>, ScopeMatchError> {
    let matches = resolve_matching_grants(&capability.scope, tool_name, server_id);
    if matches.is_empty() {
        return Err(ScopeMatchError::OutOfScope);
    }
    Ok(matches)
}

fn grant_covers(grant: &ToolGrant, tool_name: &str, server_id: &str) -> bool {
    matches_pattern(&grant.server_id, server_id)
        && matches_pattern(&grant.tool_name, tool_name)
        && grant.operations.contains(&Operation::Invoke)
}

fn matches_pattern(pattern: &str, candidate: &str) -> bool {
    pattern == "*" || pattern == candidate
}
