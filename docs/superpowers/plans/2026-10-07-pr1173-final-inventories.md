# PR1173 final inventory and payment-fixture qualification plan

> Use superpowers:executing-plans inline. The user authorizes continued production-block repairs and prohibits subagents.

**Goal:** Repair the four current-candidate qualification failures without weakening the kernel's payment recovery, constructor coverage, registry coverage or generated-source checks.

**Architecture:** Reconcile existing source inventories against reviewed physical call sites. Use the already pinned SDK generators. Move the existing market test rails into one focused fixture module and let their shared records report actual reference-bound authorization and terminal state. Production payment adapters and their unavailable-query default remain unchanged.

**Tech stack:** Existing Rust1.95, xtask/syn, TypeScript json-schema-to-typescript15.0.4, Go generator and the existing market fixtures.

**Spec:** `docs/superpowers/specs/2026-10-04-pr1173-production-readiness.md`, especially required properties1,4,5. The current hosted failures are on `a0447e36ae55014a59aad2ae0c489ab4551f6389`.

## Global constraints

- Retain all seven failed current-candidate jobs, all successful proof/native/fuzz results and the mandatory committed-evidence skip in their original scopes.
- No production payment behavior, schema, generator algorithm, dependency policy, authority variable, signed campaign binding or audit exemption changes.
- Preserve all existing constructor IDs, all existing dispatch coverage and source-scanner refusal rules. New references require individual review and classification.
- A fixture may report NoAuthorization only when it has no authorization in progress or completed for that exact reference. Missing IDs do not imply absence. Wrong IDs and uncertain outcomes must fail closed.
- Keep one Cargo owner per target, use meaningful existing regressions first and keep all authored text free of em dashes.
- The security agent still owns coherent source/definition authorization, genuine v7 native campaigns, the signed Linux package and policy. Do not bypass that handoff.

## Review focus

- SDK generation must remain byte-stable under the locked tools; generated namespace and payload changes must follow existing schemas.
- The registered sealed FROST round-two artifact must already be supported by the runtime before adding it to the expected conformance catalog.
- Explicit-clock factories and direct dispatch in examples remain classified with their actual source role. A constructor count is not operational qualification.
- Rail observation cannot turn a pending authorization into absence, substitute an authorization ID or report an unrelated reference's state.
- Moving test rails must preserve authorization hooks, counters, rail modes, terminal results and the original denial/no-effect assertions.

### Task1: Reconcile generated and physical source inventories

**Files:** Existing `sdks/typescript/packages/conformance/src/_generated/index.ts`, Go generated bindings if their real check fails, `formal/adapter-source-inventory.toml`, `docs/security/consumer-support.md`, and `crates/tooling/chio-conformance/tests/frost_quorum.rs`.

**Interfaces:** Keep `cargo xtask codegen --lang <rust|python|ts|go> --check`, `cargo xtask check adapter-no-bypass`, exact `constructor_sites`/`dispatch_sites`, and the runtime's existing signed-artifact catalog.

- [x] Execute all four current SDK checks without editing generated files; retain actual failures. The hosted TypeScript check reports347261 computed versus309876 committed bytes.
- [x] Repair the independently reproduced Sigstore build-context failure before using local market test results. Compile the existing `crates/trust/chio-attest-verify/build.rs` once and execute it against different runtime manifest directories in `scripts/tests/check-attest-build-context.test.py`. Require current paths and refusal for either missing trust file or missing Cargo metadata; then read `CARGO_MANIFEST_DIR` at build-script execution time. Preserve both trust files and all presence checks. The two original local market attempts stopped during compilation and are not behavioral RED.
- [x] Regenerate only failing language outputs through their existing pinned tools. Run each repaired check twice and review every changed namespace/payload against the existing schema. Build/test the affected SDK packages.
- [x] Reproduce the FROST catalog and adapter-source failures with the real existing commands. Confirm `chio.frost.dkg-round2-sealed.v1` is already implemented by the runtime and sealed-ceremony authority.
- [x] Add the one missing FROST schema/kind/path tuple to the exact expected catalog. Preserve runtime support and all other registry checks. Run the complete seven-case FROST conformance target and existing sealed-ceremony tests.
- [x] Review the nine stale and16 unclassified constructor/dispatch records reported by CI, including dynamic delegation, funded native work and MCP session factories. Retain stable IDs for moved targets; add individually classified IDs for new physical references. Update the consumer ledger's counts and descriptions.
- [x] Run the complete no-bypass checker, its existing wrapper and constructor controls. Require unknown-site rejection and exact counts. The first repaired inventory run reveals an additional scanner defect: file-level `#![cfg(test)]` is not recognized even though item-level test conditions are. Add actual AST regressions for disabled files and production-enabled/test-named paths, then honor the exact test condition in both effect and constructor readers. Do not skip a directory by name or add side-effect exceptions.
- [x] Register the four real Sigstore build-context controls in the existing root-CI structural gate. Preserve every current gate and the execution order of existing controls.

### Task2: Make market payment fixtures answer truthful settlement queries

**Files:** Existing `crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_wedge_purchase_e2e_tests.rs`; focused child module `finding_wedge_purchase_e2e_tests/payment_rail.rs`.

**Interfaces:** Preserve `PaymentCalls`, `ReversibleHoldAdapter { calls, authorize_hook }` and `PrepaidFinalAdapter { calls }` through parent imports. Keep the existing PaymentAdapter trait and kernel compensation implementation.

- [x] Reproduce a current failing denial case and the composed qualified profile without changing its assertions. The current error is the inherited unavailable settlement-state query during pre-dispatch compensation.
- [x] Add fixture tests for reference-specific absence, observation without an authorization ID, wrong-ID refusal, pending authorization and terminal state. Run them against the inherited unsupported query and retain RED.
- [x] Move the existing rails/counters into their focused child module. Record authorization in progress before invoking an authorization hook, retain immutable request identity, and expose actual held/prepaid/terminal state through the shared ledger. Preserve uncertainty on ambiguous failure and reject conflicting reference reuse. Do not hold a ledger mutex while invoking the hook.
- [x] Run the new fixture cases, all existing finding-wedge purchase tests and the composed cognition-market profile. Require the eight original failures to pass with their denial, no-payment and no-dispatch assertions intact.
- [x] Run relevant control-plane test-target Clippy and Rust format/hygiene checks. Review locking, idempotency, error disposition and helper visibility separately.

### Task3: Renew the verified candidate and accept its actual final gates

**Files:** Existing source-bound native21, receipt verifier, retained paper/research artifacts, private execution ledger and PR description.

- [ ] Review all changes against this plan and the production spec. Run the existing changed-boundary controls and complete CI contract before committing the source checkpoint.
- [ ] Freeze source, renew native21 and verifier, append current raw evidence while preserving all1177 preceding records, and rebuild/freeze the PDF twice. Keep the four publication gates and both false flags.
- [ ] Commit the derived outputs, push the authorized branch normally and preserve the automated PR footer. Collect every mandatory final-head workflow, native lifetime, full Kani, full fuzz, source audit and advisory result.
- [ ] Require final local/remote/PR identity, clean source, exact terminal CI, reviewed skips and no unresolved P0/P1/P2. Keep the security-owned source/package/policy handoff mandatory and distinguish it from research publication, merge and deployment.

Ruling: these are bounded repairs under the existing production-readiness authorization. Existing mechanisms remain authoritative. Inventory reconciliation does not certify production operation; fixture compensation must report actual rail state rather than relaxing the production unavailable-query default. No additional permission loop or delegation is introduced.
