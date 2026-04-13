---
phase: 314-native-protocol-conformance-and-standards-track
milestone: v2.82
created: 2026-04-13
status: complete
---

# Phase 314 Context

## Goal

Add a native-protocol conformance lane that is executable by third parties,
then package the normative protocol and security work into standards-track
artifacts.

## Current Reality

- `crates/arc-conformance` already ships a strong MCP-oriented compatibility
  harness with JSON scenarios, result artifacts, and generated reports.
- The repo does not yet have an equivalent checked-in conformance lane for the
  native ARC surfaces introduced in phases `311`-`313`.
- The standards story is spread across remediation and profile docs, but there
  is no one IETF-style draft or one alignment matrix for the core ARC protocol
  itself.

## Boundaries

- Keep the new native lane separate from the existing Wave 1-5 MCP harness so
  phase `314` does not destabilize the already-green compatibility suite.
- Prefer one narrow, reproducible harness contract over a large speculative
  framework.
- Build the standards-track documents on top of the actual shipped spec and
  threat model rather than inventing a broader public claim surface.

## Key Risks

- If the conformance runner depends on ARC-only internals from the target, it
  fails the "third-party implementation can run this" requirement.
- If the standards docs ignore the bounded positioning work already captured in
  `docs/review/12-standards-positioning-remediation.md`, phase `314` will
  regress into the same overclaiming problem it is supposed to fix.
- If the native suite is not executable in-repo, it will read like a proposal
  rather than a conformance surface.

## Decision

Create one dedicated native conformance lane under `tests/conformance/native`
with:

1. JSON scenario files covering the required categories
2. one language-neutral runner that supports `artifact`, `stdio`, and `http`
   driver modes
3. one deterministic fixture target for self-hosted verification

Then add:

4. one IETF-style Internet-Draft under `spec/ietf/`
5. one standards alignment matrix under `docs/standards/`
