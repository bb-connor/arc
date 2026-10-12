# Security wire contract reconciliation plan

> **For agentic workers:** Use superpowers:executing-plans in Root's native
> thread. Claude independently reviews the complete candidate. Root is the
> sole integrator and publisher.

**Goal:** Close F070 and F071 by aligning the published capability and response
plan contracts with their native validators and regenerated SDK consumers.

**Architecture:** Forward-port preserved producers `b4eae15e58` and
`65eeee7447`. Keep the existing validators and generators, enforce canonical
workload key spelling at validation, and regenerate all four languages from
the current schema inventory. Preserve unrelated source and generated changes.

**Tech stack:** Rust, JSON Schema, Go, Python/Pydantic and TypeScript.

**Spec:** F070/F071 in `docs/reviews/2026-10-06-pr1160/findings.md`, the original
protocol proposals `52bb942a1` and `74cf92be9`, and the existing native
`CapabilitySecurityBinding` and `GovernedResponsePlanIntentBody` validators.

## Constraints and review focus

- Private sequential follow-up based on `2102f01b14`; keep #1201/#1202 frozen.
  No third PR, publication, authority change or formal-engine campaign.
- Preserve valid signed bytes. Noncanonical workload key text must be refused
  before issuance; do not normalize an already signed predicate.
- Schema constraints must not claim to enforce canonical byte size, nesting,
  value count or relational/hash checks they cannot express.
- Keep all four generated outputs reproducible with their existing exact tool
  pins. Do not restore old generated trees or waive drift/structural gates.
- Exercise valid boundary values, duplicate effects, forbidden plan hash keys,
  empty bindings, padded/control/overlong identifiers and both noncanonical
  public key spellings. Preserve every original failure independently.

## Task 1: Pin current-source failures

Files: `crates/core/chio-core-types/src/capability/caveat_and_delegation_guard_tests.rs`,
`crates/core/chio-core-types/tests/wire_protocol_schema.rs` and
`crates/core/chio-core-types/tests/wire_protocol_schema/active_response_plan.rs`.

- [x] Apply only the preserved regression tests and their module registration.
- [x] Run `cargo test --locked --offline -p chio-core-types --lib
  security_binding_requires_canonical_workload_key_spelling -- --exact`
  using the full qualified test name if required. Assert that one test runs and
  fails because uppercase or prefixed key spelling is accepted.
- [x] Run `cargo test --locked --offline -p chio-core-types --test
  wire_protocol_schema active_response_schema_matches_native_plan_bounds`.
  Expect the schema to accept a value refused by the native validator.
- [x] Preserve the test-only source and terminal logs before production edits.

## Task 2: Reconcile canonical source contracts and consumers

Files: `spec/PROTOCOL.md`, `spec/schemas/chio-wire/v1/{agent,capability}`,
`crates/core/chio-core-types/src/capability/caveat.rs`, the new
`tests/wire_protocol_schema/security_binding.rs` within that crate,
`sdks/go/chio-go-http/protocol_validation{,_test}.go`,
`sdks/python/chio-sdk-python/tests/test_models.py`,
`sdks/typescript/packages/conformance/test/protocol_primitives_schema.test.ts`,
`tests/bindings/{fixtures,vectors}`, `xtask/src/codegen/python.rs`, and
`scripts/check-consumer-sdk-inventory.py`.

- [x] Apply the preserved semantic changes in producer order, excluding stale
  generated files and manifests. Resolve each conflict against current source.
- [x] Run both original regressions to green, plus the 15 security-binding
  vectors and the complete wire schema test target.
- [x] Regenerate `cargo xtask codegen --lang LANGUAGE` for rust, go, python and
  ts using the locked tools. Refresh schema/vector manifests from actual inputs.
- [x] Run each generator's `--check`, the schema registry, consumer inventory,
  wire identifier gate and formatting. Inspect every unexpected input/output
  change rather than accepting a mass regeneration blindly.

## Task 3: Qualify the complete private wave

- [x] Run owning core-types tests, owning core-types/xtask strict Clippy and
  the xtask generator tests; run the affected Go, Python and TypeScript suites.
- [x] Retain exact source hashes, producer mappings, original failures and
  generated-output evidence in a bounded qualification record.
- [x] Obtain Claude's independent complete-source review and repair confirmed
  findings. Keep hosted and native release acceptance separate from local tests.
- [x] Update the mailbox and board; preserve the private candidate until the
  active two-PR queue advances and actual-main composition is qualified.

## Integration correction

The old schema patterns used `\s`, whose ECMAScript meaning also rejects
U+FEFF at identifier edges. Native Rust accepts that format character. A real
TypeScript schema test reproduced the mismatch (2 pass, 1 fail under the
existing enrolled test names). Use explicit Unicode White_Space/control ranges
in both affected schema families. Retain valid format characters and negative
whitespace-edge cases in the public TypeScript validator and native schema
tests; regenerate all languages after the correction. No native string rule
is changed. The canonical-key oracle now uses a fixed seed and was rerun to
genuine failure before the production repair.

## Qualification

See [the bounded qualification record](../../security/audits/security-wire-contracts-20261012.json)
for immutable inputs, original failures, component results, review findings and
the remaining hosted/landing boundary. All six Rust campaign commands finished
with unchanged source. No production or native-release acceptance is claimed.
