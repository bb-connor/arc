# chio-policy architecture

## Responsibility and boundary

`HushSpec` owns a typed policy document. Public functions parse, validate,
resolve inheritance, merge documents, evaluate actions, analyze policy relations,
and compile policy into kernel primitives.
`CompiledPolicy` owns a `GuardPipeline`, `PostInvocationPipeline`, `ChioScope`,
optional threshold requirement, and ordered guard-name sidecar.
The caller installs these objects and selects capability issuance behavior.
The kernel owns enforcement admission, approval execution, and signed receipts.

The reference evaluator and compiler are separate interfaces with distinct
coverage. A reference Allow does not create a capability. `DecisionReceipt`
contains action and policy summaries, timing, and a UUID; it has no signature
or persistence mechanism.

## Structure

`models.rs` and `models/` define schema, defaults, and YAML safety checks.
`version.rs` supports HushSpec `0.1.0`. `validate.rs`, `regex_safety.rs`, and
`glob_pattern.rs` validate semantic and pattern constraints.
`resolve.rs` handles bounded inheritance and loaders; `merge.rs` applies replace,
merge, or default deep-merge strategy. Rule blocks generally replace their base
block when the child supplies that block; extension merging has separate logic.

`evaluate/` separates context selection, matching, outcomes, and engine control.
`conditions.rs` filters active rules. `detection.rs` supplies content detection.
`compiler/` separates rules, detection, budgets, scope, pattern overlap, and
sender-proof enforcement.
`crypto_floor.rs` and `weights.rs` load specialized policy configuration.
`rulesets/` embeds seven YAML rulesets.
`analyze/` lowers policy into an intermediate representation, compares glob
relations, and produces bounded findings and refinement reports.

## Data and control flow

`HushSpec::parse` performs YAML hazard checks and deserialization, including
unknown-field rejection. It catches parser panics and returns parse errors.
Parsing alone does not run semantic validation.
`validate` accumulates errors and warnings; `is_valid` requires an empty error
list. Missing rules produce a warning. Compilation checks unsupported execution
fields and validates before constructing guards.

The compiler processes enabled rule blocks in this order: forbidden paths;
velocity and agent velocity; shell commands; egress then internal network;
MCP tools then optional sender proof; secrets; patch integrity; path allowlist;
computer use; remote desktop; input injection; browser automation; code execution.
It then processes detection extensions and origin budgets. Secret rules also
add a separate sanitizer hook. Missing blocks add no corresponding guards.

Scope compilation requires enabled tool-access rules. It emits representable
grants and constraints, filters conflicting patterns, and returns an empty scope
for unsupported authority shapes. Explicit default-allow rules can yield a
wildcard scope when compatible with the configured constraints.
Threshold approvers require an authenticated directory; identifier consistency
and one nonempty directory version are checked before constructing requirements.

Resolution loads builtins or local files, follows parents, merges, and rejects
cycles. Default file limits are 4 MiB per document and inheritance depth 32.
HTTP references return `ResolveError::Http`. Caller-provided loaders own their
input acquisition and source identities.

## Trust and invariants

Validation rejects unsupported versions, invalid or excessive regex patterns,
invalid budgets, and checked extension constraints. Compilation adds guard
constructor checks and rejects approval fields without execution enforcement.
Origin-specific sender proof is rejected by the compiler; global tool-access
sender proof can compile into a guard and grant requirements.

Reference evaluation denies unknown action types and active panic mode.
Recognized actions without configured restrictions may allow.
`evaluate_with_context` rejects unknown condition keys with deny and propagates
clock errors. `evaluate_audited` checks supplied clock readings and duration.
These evaluation functions require callers to validate policies before use.

`receipt::compute_policy_hash` hashes `serde_json::to_string` output with SHA-256;
serialization failure falls back to the empty string. It does not invoke the
RFC 8785 canonicalizer. Consumers must use the kernel's signed receipt contracts
when cryptographic enforcement evidence is required.

Static analysis bounds atoms, automata, comparisons, findings, and confirmations.
Its report distinguishes unhandled policy surfaces and inconclusive refinement.
An analysis result applies to the modeled policy fragments and configured limits.

## Dependencies

`chio-guards` supplies concrete enforcement and sanitization; `chio-kernel`
provides budgets and approver directories; `chio-core` supplies scope and
threshold types. `chio-security-types` provides clocks and security vocabulary;
`chio-appraisal` is declared in the manifest; policy source has no direct import.
Serde, serde_json, and yaml_serde handle documents. Regex handles patterns;
SHA-256 and hex support hashing. UUID identifies decision records; chrono and
chrono-tz support timestamps and calendar conditions. Proptest is test-only.
The manifest declares no features; filesystem operations require host access.

## Verification

`tests/validate_boundary.rs` exercises pattern, limit, and semantic rejection.
`tests/implicit_authority.rs` checks missing/disabled tool rules, explicit grants,
and constraints. `tests/compile_policy.rs` exercises emitted guard families;
`compiler_overlap.rs` checks overlap-sensitive scope compilation.
Approval, clock, builtin ruleset, extension, and property tests cover additional
boundaries. `analyze/tests.rs` exercises bounded analysis and refinement reports.

```bash
cargo test -p chio-policy
cargo test -p chio-policy --test implicit_authority
cargo test -p chio-policy --test validate_boundary
```

These tests validate local policy behavior and compiler output. Callers own
runtime installation and acceptance of policy assets and context providers.
