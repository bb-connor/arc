# Phase 21: Release Hygiene and Codebase Structure - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 21 closes the first production-readiness gap in v2.3. The focus is
source-of-truth release inputs and a safer ownership boundary inside the
oversized CLI entrypoint, not new protocol features.

</domain>

<decisions>
## Implementation Decisions

### Release Inputs
- Remove tracked Python build, egg-info, and bytecode artifacts from the repo
  instead of trying to treat them as legitimate release inputs.
- Add a repo-level guard script and run it from the existing workspace CI lane
  so hygiene regressions fail fast.

### Structural Refactor
- Carve the trust/certification/provider admin command handlers out of
  `crates/pact-cli/src/main.rs` into a dedicated `admin.rs` module.
- Keep the refactor behavior-preserving and prove it through the existing
  provider-admin, certification, federated-issue, evidence-export, and
  reputation-issuance integration suites.

### Gate Cleanup
- Fix low-risk clippy findings encountered while validating the new Phase 21
  lane instead of carrying a knowingly red targeted lint gate into Phase 22.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 21 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `PROD-07`, `PROD-08`
- `.gitignore` -- repo-level release-input exclusions
- `scripts/check-release-inputs.sh` -- tracked-artifact guard
- `scripts/ci-workspace.sh` -- workspace CI entrypoint
- `packages/sdk/pact-py/MANIFEST.in` -- Python packaging intent
- `crates/pact-cli/src/main.rs` -- original oversized CLI entrypoint
- `crates/pact-cli/src/admin.rs` -- extracted admin command surface
- `crates/pact-cli/tests/provider_admin.rs` -- provider-admin regression lane
- `crates/pact-cli/tests/certify.rs` -- certification registry regression lane
- `crates/pact-cli/tests/federated_issue.rs` -- federated issuance regression lane

</canonical_refs>

<code_context>
## Existing Code Insights

- The repo was still tracking `packages/sdk/pact-py/build/lib`, both
  `*.egg-info` trees, Python `__pycache__`, and conformance fixture bytecode.
- Root ignore rules were missing Python packaging/cache exclusions even though
  `MANIFEST.in` already treated those artifacts as disposable.
- `crates/pact-cli/src/main.rs` had grown to 4,690 lines and still contained
  provider admin, certification registry, and federated issuance handlers that
  fit a standalone control-plane admin module better.
- The targeted `cargo clippy -p pact-cli -- -D warnings` lane surfaced a small
  set of older hygiene issues that were cheap to fix safely.

</code_context>

<deferred>
## Deferred Ideas

- Further split `trust_control.rs`, `remote_mcp.rs`, `pact-kernel/src/lib.rs`,
  and `pact-a2a-adapter/src/lib.rs` in later v2.3 phases.
- Expand the release-input guard into a broader release manifest if Phase 22
  needs a stricter qualification contract.
- Replace the targeted `#[allow(clippy::too_many_arguments)]` constructor
  exceptions with builder/input structs if those APIs continue to grow.

</deferred>

---

*Phase: 21-release-hygiene-and-codebase-structure*
*Context gathered: 2026-03-25*
