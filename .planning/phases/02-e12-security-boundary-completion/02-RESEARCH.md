# Phase 2 Research: E12 Security Boundary Completion

## Goal

Turn negotiated roots into an enforced runtime boundary for filesystem-shaped tool calls and filesystem-backed resource reads.

## Current State

### Roots are negotiated and stored, but not normalized or enforced

- `crates/arc-core/src/session.rs` defines `RootDefinition` as `{ uri, name }` only. There is no normalized root model, filesystem classification, or enforcement metadata.
- `crates/arc-kernel/src/session.rs` stores roots as raw `Vec<RootDefinition>` on the session and replaces them wholesale via `replace_roots`.
- `crates/arc-kernel/src/lib.rs` refreshes roots through nested `roots/list` and stores them on the session with `replace_roots`, but it does not enforce them on tool calls or resource reads.
- `docs/research/03-gap-analysis.md` already calls this out directly: roots snapshots and propagation exist, but root-aware enforcement is still missing.

### Tool-side filesystem classification exists already

- `crates/arc-guards/src/action.rs` already classifies common filesystem-shaped tool calls into `ToolAction::FileAccess` and `ToolAction::FileWrite`.
- `crates/arc-guards/src/path_allowlist.rs` already has path normalization and allowlist enforcement, including symlink-aware normalization behavior.
- `crates/arc-cli/src/policy.rs` currently wires only `ForbiddenPathGuard`, `ShellCommandGuard`, and `EgressAllowlistGuard` from the operator-facing YAML path. There is no root-aware guard in the runtime pipeline today.

### Resource reads do not use roots

- `crates/arc-kernel/src/lib.rs` evaluates resource reads by validating capability scope and then calling `provider.read_resource(&operation.uri)`.
- There is no resource-side classification step for filesystem-backed URIs versus non-filesystem URIs.
- There is no root check before `provider.read_resource`.

## Concrete Enforcement Gaps

### Gap 1: no canonical root normalization model

Open questions the phase must freeze:

- which root URI schemes are in scope for enforcement
- how `file://` roots normalize across platforms
- how absent roots differ from empty roots
- whether non-filesystem roots are ignored, rejected, or retained as metadata-only
- how symlink resolution interacts with root membership checks

Without this, tool and resource enforcement will diverge.

### Gap 2: no root-aware tool enforcement path

The tool pipeline can already infer filesystem intent, but it cannot compare those paths to session roots.

Implication:

- a session can negotiate roots
- a tool call can clearly target `/etc/passwd`
- the runtime still cannot prove that the call is in-root or out-of-root

### Gap 3: no filesystem-backed resource classification

Resource URIs are currently treated as generic provider-owned identifiers. E12 needs a narrow model:

- only filesystem-backed resources should be root-enforced
- non-filesystem resources must keep working
- the kernel needs one place to decide whether a resource URI maps to a filesystem path subject to roots

### Gap 4: missing deny evidence and policy semantics

The phase needs explicit answers for:

- what error or receipt evidence is produced on root-boundary denial
- whether missing roots fail closed for filesystem-shaped access
- how roots interact with capability scope and policy defaults

## Most Relevant Files

### Roots/session state

- `crates/arc-core/src/session.rs`
- `crates/arc-kernel/src/session.rs`
- `crates/arc-kernel/src/lib.rs`
- `crates/arc-mcp-adapter/src/edge.rs`

### Tool-side enforcement

- `crates/arc-guards/src/action.rs`
- `crates/arc-guards/src/path_normalization.rs`
- `crates/arc-guards/src/path_allowlist.rs`
- `crates/arc-guards/src/forbidden_path.rs`
- `crates/arc-cli/src/policy.rs`
- `crates/arc-policy/src/compiler.rs`

### Resource-side enforcement

- `crates/arc-kernel/src/lib.rs`
- resource provider implementations under `crates/arc-kernel` and `crates/arc-mcp-adapter`

### Phase docs

- `docs/epics/E12-security-boundary-completion.md`
- `docs/research/03-gap-analysis.md`
- `docs/epics/E5-nested-flows-roots-sampling-elicitation.md`

## Recommended Slice Sequencing

### 02-01: freeze normalization and threat model first

This should define:

- canonical root normalization rules
- rootless and mixed-root behavior
- which URI schemes are enforceable
- what “filesystem-backed resource” means
- fail-closed rules when the runtime cannot prove containment

This is the highest-leverage planning artifact for the phase.

### 02-02: enforce roots for filesystem-shaped tools

This is the lowest-risk first implementation step because:

- tool-side filesystem intent already exists in `ToolAction`
- path normalization utilities already exist
- deny behavior can be added at the guard/kernel boundary without first solving generic resource mapping

### 02-03: enforce roots for filesystem-backed resources

This should come after tool enforcement because resource classification is more ambiguous. The phase should avoid over-claiming that every resource URI maps to a filesystem path.

### 02-04: test and doc the boundary across transports

Once the runtime model is frozen and both tool and resource enforcement exist, add direct/wrapped/remote coverage and document the boundary clearly.

## Key Risks

### Risk 1: path normalization mismatch across guard and root logic

If root checks normalize paths differently from `PathAllowlistGuard`, the runtime will be inconsistent and potentially bypassable.

Recommendation:

- reuse the existing normalization helpers instead of inventing a second path model

### Risk 2: over-enforcing non-filesystem resources

Blindly applying roots to all resource URIs will break legitimate non-filesystem providers.

Recommendation:

- define a resource classification boundary explicitly in `02-01`

### Risk 3: roots remain advisory when missing

If the runtime falls back to allow when roots are missing or stale, E12 will not actually close the security finding.

Recommendation:

- fail closed for filesystem-shaped access when the runtime cannot establish an allowed root set

### Risk 4: policy path drift

If root-aware behavior lands only in one policy surface, E12 will create another product split that E13 then has to unwind.

Recommendation:

- plan for root enforcement to live in the common runtime path, not in format-specific docs only

## Planning Assumptions To Make Explicit

- E12 should scope enforcement to filesystem-shaped tools and filesystem-backed resources only.
- Roots are session-owned input, not a substitute for capability or policy checks.
- In-root access is still subject to ordinary capability/policy evaluation.
- Out-of-root access should fail closed with explicit evidence.
- Missing roots should not silently widen access for filesystem-shaped operations.

## Proposed Planning Focus For 02-01

The next plan should produce:

- one normalized root model
- one filesystem-backed resource classification rule
- one fail-closed rule for missing or non-provable root membership
- a concrete write set for tool enforcement in `02-02` and resource enforcement in `02-03`
