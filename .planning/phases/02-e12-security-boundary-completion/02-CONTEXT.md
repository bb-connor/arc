# Phase 2: E12 Security Boundary Completion - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn negotiated roots into an enforced runtime boundary for filesystem-shaped tool calls and filesystem-backed resource reads.

This phase is not general sandboxing. It is specifically about making the existing roots surface materially enforceable where filesystem access is already implied.

</domain>

<decisions>
## Implementation Decisions

### Scope boundary
- Enforce roots only for filesystem-shaped tool calls and filesystem-backed resource reads.
- Do not pretend that every resource URI or every tool has a filesystem meaning.

### Runtime boundary
- Treat roots as session-owned input that constrains execution, not as informational metadata.
- Keep capability and policy checks in force for in-root access; roots do not replace those checks.

### Fail-closed rule
- Missing, stale, or non-provable root membership must not silently widen access for filesystem-shaped operations.
- Any access the runtime cannot prove is in-root should be denied with explicit evidence.

### Reuse over reinvention
- Reuse the existing path normalization utilities and filesystem tool classification logic rather than inventing a second path model.
- Prefer one common runtime enforcement path that both policy surfaces can reach, instead of format-specific behavior.

### Claude's Discretion
- Exact normalized representation of enforceable roots
- Exact error and receipt evidence shape for root-boundary denials
- Whether resource enforcement uses URI classification, provider metadata, or a narrow adapter helper, as long as the classification boundary is explicit and testable

</decisions>

<specifics>
## Specific Ideas

- `arc-kernel` already stores session roots and refreshes them through nested `roots/list`, so the phase should build on that substrate rather than reworking session ownership.
- `arc-guards` already classifies common filesystem tools and already has robust path normalization and allowlist behavior, so tool-side enforcement should start there.
- Resource enforcement is the higher-risk part because `read_resource` currently delegates directly to providers after scope checks and does not distinguish filesystem-backed from non-filesystem URIs.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Closing-cycle scope
- `docs/POST_REVIEW_EXECUTION_PLAN.md`
- `docs/epics/E12-security-boundary-completion.md`
- `docs/research/03-gap-analysis.md`

### Existing roots/session substrate
- `crates/arc-core/src/session.rs`
- `crates/arc-kernel/src/session.rs`
- `crates/arc-kernel/src/lib.rs`

### Existing filesystem classification and guards
- `crates/arc-guards/src/action.rs`
- `crates/arc-guards/src/path_normalization.rs`
- `crates/arc-guards/src/path_allowlist.rs`
- `crates/arc-guards/src/forbidden_path.rs`
- `crates/arc-cli/src/policy.rs`
- `crates/arc-policy/src/compiler.rs`

### MCP edge / resource surface
- `crates/arc-mcp-adapter/src/edge.rs`
- `docs/epics/E5-nested-flows-roots-sampling-elicitation.md`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Session::replace_roots` and `Kernel::replace_session_roots` already keep roots as session-scoped state.
- `SessionNestedFlowBridge::list_roots` already refreshes roots from the client and stores the latest snapshot on the session.
- `extract_action` in `crates/arc-guards/src/action.rs` already identifies common filesystem-shaped tool calls.
- `PathAllowlistGuard` already has symlink-aware path normalization behavior that Phase 2 should reuse.

### Missing Pieces
- `RootDefinition` is raw `{ uri, name }` only; there is no normalized root model or filesystem classification.
- The kernel's tool and resource evaluation paths do not compare filesystem access against session roots today.
- Resource reads currently validate capability scope and then call providers directly, with no filesystem-backed resource classification step.
- The operator-facing YAML policy path does not currently expose a root-aware guard.

### Integration Points
- Tool-side enforcement will likely need changes in `arc-kernel`, `arc-guards`, and the loaded policy/guard pipeline path.
- Resource-side enforcement will likely need kernel-side classification plus adapter/provider-aware tests.
- Cross-transport proof will need direct, wrapped, and remote coverage, because roots are negotiated over the MCP edge rather than local-only APIs.

</code_context>

<deferred>
## Deferred Ideas

- Full OS sandboxing
- Enforcement for non-filesystem tools that do opaque file access internally
- Broad policy product convergence beyond what is needed to make roots enforceable in the shared runtime path

</deferred>

---
*Phase: 02-e12-security-boundary-completion*
*Context gathered: 2026-03-19*
