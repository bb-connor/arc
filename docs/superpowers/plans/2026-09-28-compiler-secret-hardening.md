# Compiler enforcement and secret ownership

Base: `a76864ad1a`, `/tmp/arc-security-launch`, `packet/3-retention-accounting`.
Implements the approved next batch from hardening H1/H3/H4/H7 and Packet 0.3.

## Tasks

- [x] 1. Enforce documented unsafe operations in workspace policy and all mirrors;
  repair violations with explicit safety invariants.
- [x] 2. Forbid unsafe code in eligible library roots and gate justified exceptions.
- [x] 3. Apply the scoped security deny policy, repair production violations,
  justify narrow exceptions and enforce checked accounting arithmetic.
- [x] 4. Give remaining guard, broker and authority secrets explicit access and
  ownership; keep plaintext custody distinct from serializable public artifacts.
- [x] 5. Calibrate compiler and source gates with deliberate violations, verify
  affected tests and workspace lint integration, record review dispositions and
  the next substantial package.

## Execution and acceptance

Work inline in the existing isolated checkout. Preserve preexisting `output/`.
Batch source changes before verification, per the user's standing directive.
Use compiler diagnostics to identify actual violations rather than lexical totals.
Compile-fail probes must fail for the named rule and positive controls must pass.
Secret tests exercise public redaction, absent serialization and explicit custody.
Reuse existing build artifacts. One workspace Clippy qualification is warranted
because the policy is workspace-wide; no full release/fuzz/scale campaign here.

The original spec's census is historical. Determine current library roots from
Cargo metadata. Tests may explicitly use panic/indexing/casts; production library
policy remains enforced. No compatibility shims or historical wire readers.
Structural/helper changes, remaining authority readers and candidate delivery
remain separate packages in the remaining-work queue.

Completed September 29. The [execution record](../../reviews/2026-09-29-compiler-secret-hardening-execution.md)
contains terminal local checks, review dispositions and residual qualification
boundaries. Completion of this batch does not close the parent roadmap.
