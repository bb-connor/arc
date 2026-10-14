# Recovery architecture and deletion review

Status: bounded architecture review delivered. Whole-change code review and
runtime qualification remain incomplete. Production source is unchanged by this
review; the other execution session continued independently.

## Verdict

The strongest observed problem is unfinished native integration, alongside
unnecessary maintenance and packaging complexity. The source examined does not
support a claim of seven competing recovery runtimes. The workspace adds two
pure crates with distinct roles and extends the existing Kernel, Store, Process
and host. Those ownership boundaries are mostly necessary.

A concrete gap remains: the new Kernel native-finishing path calls unsupported
Store defaults, and Process has no caller of the provider-aware Kernel entry
point. Declaring that path complete, or deleting the refusal to make it proceed,
would both be wrong. See the [lifecycle trace](lifecycle.md).

There are justified simplifications: repeated pure validation, parallel Kernel
command pipelines, JSON conversions between matching reservation data types,
repeated predecessor catalog checks and an extra HTTP task handoff. There are
also multiple earlier formats introduced within this PR without an established
external support obligation. Prune those only after deciding which persisted
data is actually supported. The current restore writer's `Legacy` representation
is still used and must not be deleted because of its name.

The questioned terminal assertion is appropriate: it proves the workflow
actually reached capture, admission closure and settlement before the test
claims retirement. The questionable obligation is maintaining an experimental
predecessor forever, not asserting that its test exercised the intended path.

## Subject and method

The subject is PR #1179 at `4b9229dca4329141ba3c929264ef71aee12e37c6`, compared
with `de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`, plus nineteen captured tracked
working-tree overlays. Capture time: `2026-10-10T06:07:59.673248+00:00`.
[subject.json](subject.json) records the hashes. Its SHA256 is
`21969aa7116b114ce1a269a2ac1e3045b98b8d1a5ebd7e8d5edc1dc4f709dec3`.

The overlay bytes, complete changed-path inventory and source-access log are
under `target/recovery-architecture-review/`. Later concurrent edits are not
included. Source line references throughout this report address that subject,
not the moving checkout. Snapshot-reader ranges record access, not automatic
semantic approval. [Coverage](coverage.md) and
[inspected-paths.csv](inspected-paths.csv) distinguish full readings, excerpts,
excluded access and unread bodies.

The method was to trace owners and consumers, compare compatibility with the
pre-recovery baseline, then propose deletion units with preserved invariants.
Generated source was assessed through its generator and consumers; vendor
patches were separated from upstream bodies. No safe-deletion estimate follows
from line count alone.

## Delivered decisions

1. [Compatibility](compatibility.md): baseline admission schema 34 and Process
   journal 1; current admission 40 and Process versions 1-7; pre-existing signed
   grant/ABI boundaries; conditional policy for PR-local predecessors. External
   persisted consumers remain unknown, rather than assumed absent.
2. [Lifecycle](lifecycle.md): public command through authorization, exact
   reservation, approval, invocation, settlement and current release; owners
   and the missing concrete finishing connection.
3. [Deletion and consolidation plan](decisions.md): specific symbols, files,
   consumers, conditions, preserved tests and implementation order. No proposed
   deletion has been applied.
4. [Packaging](packaging.md): immutable evidence archive proposal, maintained
   verifier boundary, generated consumers and dependency-patch decisions.
5. [Coverage](coverage.md): exact review limits and remaining qualification.

Supporting source notes cover [pure contracts](pure-contracts.md),
[knowledge](knowledge.md), and [hosts/confinement](hosts-and-confinement.md).
An unapplied three-file example patch for the small local changes is at
`target/recovery-architecture-review/local-simplifications.patch`. It targets
the pin and is not permission to overwrite the other session's changes. It
passes `git apply --check` against isolated copies of those pinned files; that
is an applicability check, not compilation or behavioral validation.

## Footprint, not executable size

The committed diff contains 7,655 changed paths, 1,081,874 added lines and 25,242
removed lines. These figures exclude the captured uncommitted delta. The six
categories below are disjoint and sum to all added lines. The final category
includes inline tests and test support; it is not handwritten executable LOC.

| Category | Added lines |
|---|---:|
| Documentation and evidence | 482,014 |
| Generated bindings and API lock | 263,780 |
| Vendored dependencies | 78,636 |
| Specifications, schemas, vectors and fixtures | 53,518 |
| Other explicit test paths | 83,852 |
| Remaining source/configuration, including inline tests | 120,074 |

This is a large review and contributor-experience burden even after accounting
for generated/evidence material. Packaging history separately reduces that
burden; it does not fix the unfinished lifecycle. Conversely, treating every
added line as a new runtime implementation misdiagnoses the problem.

## Limits and confidence

Confidence is high in the cited source/caller observations and baseline
comparison, moderate in the eventual reduction from the proposed consolidations,
and unknown in external use of PR-local persisted formats. Seventy full-text
architecture readings and selected excerpts do not constitute review of every
changed file. The complete scope accounting is in coverage.md.

Report verification confirmed every recorded overlay and inspected-file hash,
the inventory totals, coverage counts and local document links. The source
inventory includes 21 binary diff entries, excluded from line counts.

Parked work remains parked. No runtime tests, deployments, commits, pushes,
provider calls or hosted checks were performed for this review. Historical
qualification does not cover this source. This report closes no P1/P2 finding
and makes no production-readiness claim.
