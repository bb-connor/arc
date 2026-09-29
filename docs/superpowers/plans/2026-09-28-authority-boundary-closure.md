# Authority boundary closure implementation plan

> Execute inline using superpowers:executing-plans. The user approved this
> four-owner batch and requires implementation-first batching, minimal agents,
> focused verification and no compatibility scaffolding for unshipped APIs.

**Goal:** Finish the control-plane, runtime-core, secret-broker and core-types
reader review, preserve rejection causes, repair their arithmetic/clock defects,
and prove changed production boundaries.

**Architecture:** Reuse bounded `UntrustedJsonText`, the shared fallible clock,
existing verification constructors, registered redacted error codes and durable
stores. Wire DTOs remain unverified. A signature or successful parse alone never
establishes authority. Preserve exact canonical versus native integer contracts.

**Tech stack:** Rust, serde, SQLite, existing clock and source gates.

**Spec:** [Unrepresentable defects](../specs/2026-09-26-unrepresentable-defects-design.md),
corrections 1D/1F/3A/4A/4B and Packet 10.2 of the
[engineering plan](2026-09-26-security-engineering-excellence.md).

Base: `a3217b9145`, `packet/3-retention-accounting`, `/tmp/arc-security-launch`.
Scope: 76 baseline reader files, 37 pending arithmetic entries and 51 clock
occurrences in the four named owners. These inventories include fixtures,
generated code and intentional typed conversions; they are not defect counts.

## Constraints and review focus

- Preserve signature, principal, request, capability, source, lease and replay
  bindings. Parsing does not replace authorization. Keep proof construction sealed.
- Shared parser internals and typed deserializers must not recursively invoke
  themselves. Classify them explicitly. Change generators rather than generated
  files when generation actually requires repair.
- Preserve private error causes; expose only redacted codes at external ports.
- Clock, overflow and malformed-input failures must refuse before mutation.
- Pair wrong-binding and malformed-input negatives with working controls; assert
  the intended error, durable invariants and exact replay behavior.
- Keep `output/` and historical evidence intact. No new legacy compatibility.
- Run one Cargo owner, batch compilation, and reserve workspace/scale/hosted gates
  for the separately scoped candidate qualification. No em dashes.

## Tasks

1. [x] Classify the 13 core-type baseline files. Harden genuine original-byte
   boundaries; register parser internals, generated code and typed conversions.
   Preserve `UntrustedJsonError` and its existing registered codes.
2. [x] Harden all 13 runtime-core baseline owners, including `serde_io.rs`,
   replay, admission SQLite records, treaty/swarm artifacts and proof parsing.
   Replace touched stringified parser errors with structured redacted causes.
   Preserve signature/trust selection and source/record identity checks.
3. [x] Classify and repair the seven broker baseline files, including prepared
   IPC, response decoding, persisted custody and test fragments. Retain frame
   bounds, exact prepared request binding and resource/descriptor ownership.
4. [x] Classify and repair all 43 control-plane baseline files, spanning native
   evidence, response simulation, attestation and trust/Finding composition.
   Preserve redacted causes through owning errors and stable port projections.
   Audit proof results in the touched paths and seal actual authority tokens.
5. [x] Resolve all 37 arithmetic entries and 51 clock occurrences against current
   code. Reuse shared checked values and fallible clock/fence contracts. Record
   bounded fixture behavior explicitly; add regressions for demonstrated defects.
6. [x] Add production reader, signed wrong-binding, expiry/replay/restart and
   atomic refusal regressions at the changed boundaries. Demonstrate actual
   parser and authority-check bypasses are caught, restoring source exactly.
7. [x] Compile owning targets and direct consumers, run focused regressions and
   strict Clippy, formatting, trust/calibration, clock, arithmetic, assertion and
   hygiene gates. Update inventories, execution record and remaining-work queue.
   Review the full diff and commit locally with original failures preserved.

The six later roadmap packages (compiler enforcement, broader owner migrations,
helper/module isolation, performance, lifecycle assurance and delivery) retain
their separate acceptance boundaries in the remaining-work queue.

## Execution

Implemented and locally qualified. See the [execution record](../../reviews/2026-09-28-authority-boundary-closure.md)
for exact scope, terminal tests, four killed production bypasses, restored-source
controls, original failures and the unchanged successor-work boundaries.
