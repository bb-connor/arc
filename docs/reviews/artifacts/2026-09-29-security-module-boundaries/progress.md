# SDD ledger - plan: docs/superpowers/plans/2026-09-29-security-module-boundaries.md
Base: d51afb4a5ffc1caafb63540b8651d19ac767b95e
Pre-flight: Tasks 1-4 share the public ports API; preserve exports and verify all consumers together. Task 5 changes helper package identity, not binary name; update test discovery and scripts atomically.
Ruling: Execute inline with one final reviewer, per user usage constraint and executing-plans skill. Cost: less independent inspection during individual cuts.
Ruling: Mechanical refactors use existing test inventory and compiler checks, not artificial red tests for unchanged behavior. New dependency/privacy gates require deliberate negative calibration. Cost: behavior preservation depends on existing tests and reviewed item-level diff.
Ruling: Scope covers the four owners and helper explicitly proposed; kernel's large test module remains the next Packet 7 owner. Cost: Packet 7 as a whole remains open.
Ruling: No full workspace rebuild for mechanical modules. Focused owner tests and dependent compilation cover this batch; native x86_64 enforcement and hosted qualification remain distinct.
Task 1: in_progress
Task 1: mechanical cut committed as 4c82a9178e; all-feature tests pass. Explicit import/privacy pass and no-std check remain.
Task 2: mechanical module cut implemented; focused compile in progress.
Task 3: mechanical module cut implemented, preserving SQL and item bodies.
Task 4: named production owners implemented; resolving test-only fixture visibility and path changes.
Task 5: shared chio-cage-plan and standalone chio-cage-init implemented; parent retains custody and launcher.
Ruling: Reuse chio-core-types canonical encoding inside the plan crate. It is the existing security-sensitive byte owner, so no new RFC 8785 implementation or signed-byte drift is introduced. Cost: helper retains the core-types graph until a separately reviewed canonical-codec extraction.
Ruling: nono-chio's upstream dependency carried unrelated network/trust code. Extract its exact reviewed ABI probe and remove the unused upstream capability container; the adapter's filesystem and deny-all network enforcement remain unchanged. Bump wrapper patch version to chio.3 and qualify the new graph. Cost: copied ABI probe changes must be reviewed explicitly on future upstream updates.
Task 2: mechanical ownership committed as 29ec6dd424; private endpoint/parser fields retained.
Task 3: mechanical ownership committed as 951d52009e; SQL body and principal relocation verified by exact query/owner/hash comparison.
Task 4: mechanical ownership committed as d2b721ea24; obsolete included test sources removed; tests that inspect private state are descendants of their owner.
Task 5: dependency budget self-test passed (12 real Cargo graph cases); Linux stack source gate and hostile self-tests passed; source inventory and runner self-tests passed (78 retained tests plus one standalone entrypoint case).
Ruling: Keep the hashed nono upstream tree as source provenance for the extracted ABI algorithm, marked reference-only; it is absent from the runtime graph. Cost: source-reference maintenance remains, with no runtime dependency or compatibility path.
Inventory: trust-boundary relocation preserved exact SQL/principals and decoder classifications; 355 constructors, 85 tenant tables, 170 SQL contracts pass. Negative assertion relocation preserved all 1,263 assertions without increasing counts or changing expiry.
Tasks 1-4: formatting committed separately; no_std check exposed a missing alloc::ToString import plus std-only imports, now corrected.
Ruling: Stop the CPU-heavy parallel native-flow campaign after diagnosing real-time 10s policy expiry; isolated before/after capture passes are preserved. Use focused module-owner cases and exact repaired regressions for this mechanical batch. Full native-flow wall-clock qualification remains open; cost if wrong: an unexercised integration regression could remain.
Regression evidence: original and new ledger corruption tests both fail on obsolete serde text; original and new host-crash tests both fail because the test clock never consumed its panic flag. Fixes assert the exact current store error and restore the test fault.
Final review: 3 Important findings accepted: broker validation-result construction, retained secret custody, and reserved response-plan construction were visible to sibling descendants. Compiler probes first accepted each unauthorized access (RED), then rejected all 4 broker access diagnostics and response-plan field mutation (GREEN). Original and final probe results retained.
Final: Ruling: Native x86 confinement, full native-flow timing, other platforms/features, full workspace/hosted/publication/operations were not reviewed as qualified runtime results. Preserve each gate as open; cost if wrong: deployment failures remain possible outside the measured platform and focused suites.
Final: Ruling: Existing public wire carriers remain explicitly runtime-validated untrusted inputs. Their redesign is outside these private proof/custody cuts; cost if wrong: those boundaries continue to depend on their validators.
Task 1: complete (commits d51afb4a5f..938b76c311; evidence: 67 unit/integration + 3 rustdocs; strict no_std Clippy).
Task 2: complete (commits d51afb4a5f..938b76c311; evidence: 171 broker unit cases; compiler rejects authority/audit/custody sibling probes).
Task 3: complete (commits d51afb4a5f..938b76c311; evidence: 106 security-state library + 33 security-state integration + 31 dispatch integration; exact SQL/principal preservation).
Task 4: complete (commits d51afb4a5f..938b76c311; evidence: 261 focused control-plane cases + 3 native ledger cases; compiler rejects reservation rebinding; strict Clippy).
Task 5: complete (commits d51afb4a5f..938b76c311; evidence: 17 cage + 5 plan + 1 helper + 1 helper entrypoint + 1 Landlock wrapper tests; budget72; hostile graph and release-package gates).
Final: fixed all three Important ownership findings in 68acb34aca; actual compiler probes RED to GREEN; broker171/171 and control261/261 pass, with one owned subprocess entrypoint ignored. Final strict Clippy passes. No deferred minors.
Final: fixed old helper package in release workflow in 938b76c311; package gate RED to GREEN, hostile source/provenance tests pass.
