# Phase 21 Research

## Findings

1. `git ls-files packages/sdk/pact-py tests/conformance | rg '__pycache__|\.pyc$|egg-info|build/lib'`
   showed committed Python build output, egg-info metadata, and bytecode under
   both the SDK and conformance fixtures.
2. `.gitignore` did not ignore Python packaging/cache artifacts at the repo
   root, even though `packages/sdk/pact-py/MANIFEST.in` already pruned them from
   packaging outputs.
3. `scripts/ci-workspace.sh` had no pre-build release-input inventory check, so
   generated artifacts could quietly re-enter the repo and still make it into
   normal CI runs.
4. `wc -l` showed the main structural pressure points:
   - `crates/pact-cli/src/main.rs`: 4,690 lines before refactor
   - `crates/pact-cli/src/trust_control.rs`: 5,420 lines
   - `crates/pact-cli/src/remote_mcp.rs`: 6,611 lines
   - `crates/pact-a2a-adapter/src/lib.rs`: 8,048 lines
   - `crates/pact-kernel/src/lib.rs`: 8,875 lines
5. The cleanest low-risk extraction boundary in `main.rs` was the set of
   provider-admin, certification-registry, federated-issue, and delegation
   policy handlers, because they already formed a coherent control-plane admin
   slice with shared helpers.
6. After the extraction, `crates/pact-cli/src/main.rs` dropped to 4,190 lines
   and the new `crates/pact-cli/src/admin.rs` owns 510 lines of admin-only
   command handling.
7. Phase 21 validation uncovered older targeted lint issues in
   `evidence_export.rs`, `issuance.rs`, `remote_mcp.rs`, and `trust_control.rs`;
   those were corrected so the new Phase 21 gate leaves fewer known failures
   behind.

## Chosen Cut

- `21-01`: document release-input debt and select the `main.rs -> admin.rs`
  extraction boundary
- `21-02`: remove tracked generated artifacts and add a CI-enforced
  `check-release-inputs` guard
- `21-03`: extract the admin module and close the narrow lint/regression issues
  exposed by the new validation lane
