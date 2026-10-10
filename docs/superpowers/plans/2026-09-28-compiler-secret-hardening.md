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

## Execution review (October 1, 2026)

Reviewed at `a2630c20a1` in the [gates and toolchain review](../../reviews/2026-10-01-execution-review-gates-toolchain.md). The cross-cutting verdict is in the [pass 9 execution review](../../reviews/2026-10-01-execution-review.md).

**Verdict:** Tasks 1 to 3 and 5 are delivered locally and task 4 is partial. The claim that CI enforces this policy is false at the tip, because the required job fails before its gates run.

Open findings against this plan:

- **GT1, Medium.** The required job's structural step fails at the tip, so no gate from this range, nor Clippy, the build or the tests, runs in hosted CI.
- **GT4, Medium.** The authority seed handoff and the policy-loaded guard API keys are plain `String` fields deriving `Debug` in a TCB crate, invisible to the secret gate.
- **GT5, Medium.** 164 existing allows were given one boilerplate reason that describes the commit, not the code.
- **GT11, Low.** Three secret buffers leave plaintext behind when they reallocate (also SF2).
- **GT14, Note.** About a dozen behavior changes are buried in the 666-file `d51afb4a5f`.

**Next:** Get the required job green on a pull request (GT1), then seal the two secret fields (GT4).
