# Economy authority reader qualification

Source base: `593b642da96bba939e4ae26055f2ebe26b06668c`. Scope: all 22 economy
readers pinned by the platform handoff, supporting owners and direct consumers,
on local Linux/aarch64. The commit containing this record and final source hashes
is the final candidate identity.

## Accepted evidence

- [Complete eight-package campaign](post-consumer-packages.log): terminal exit
  zero, **950 passed, zero failed, zero ignored**, across 49 test/doc targets.
  This includes the final economy parser, witness, numeric-profile and nested
  source-custody behavior. Earlier campaigns are retained separately.
- [Market package rerun](market-test-module.log): terminal exit zero, **79
  passes**, after moving the unchanged policy authentication/input test into a
  child module to respect the existing file cap. This repeats market tests from
  the combined campaign and is not added to a unique-test total.
- [Actual control-plane adapters](consumer-cause-final.log): **two passes**;
  native causes survive purchase/recovery mapping, kernel prefixing and cloning,
  while public formatting and deterministic equality remain closed. The command
  filters 1,186 unrelated tests. The earlier [regression run](consumer-cause-red.log)
  reproduced both missing native causes before the bridge was implemented.
- [Kernel denial tests](kernel-denial.log): **five passes**, retaining denial
  family, detail, receipt metadata and prefix contracts. These and the final
  adapter run follow the trait-object coercion lint cleanup.
- [Rekor conformance](rekor-conformance.log): **seven passes**, exercising real
  clients against faithful local mock endpoints: honest publication, substituted
  bodies/UUIDs, pinned and untrusted SET signatures, and public-witness policy.
  This is mock-provider conformance, not live endpoint qualification.
- [Settlement identity fixture](settlement-fixture.log): the production domain
  matches its independent canonical payload and digest after removing an
  existing single-element test loop. This repeats a test from the owner campaign.
- [19 direct consumers](direct-consumers-2.log) compile with `--all-targets`,
  terminal exit zero. [All-target Clippy](clippy-final.log) passes for all eight
  owners plus kernel and control plane with `-D warnings`. No lint allowance was
  added. The consumer compile precedes the equivalent trait-object coercion
  cleanup; final Clippy and actual kernel/adapter execution qualify that form.
- The kernel-only graph exposed an unused private oracle constructor with web3
  disabled. Its implementation now follows the web3 feature that owns its sole
  callers; the public error type/variant remain unconditional. Both
  [default](link-default-clippy.log) and [no-default-feature](link-no-default-clippy.log)
  all-target oracle Clippy checks pass. The earlier combined graphs enabled
  web3, whose behavior is unchanged.
- [Trust inventory](trust-final.log), [file hygiene](hygiene-accepted.log),
  [negative assertions](negative-final.log), [formatting](format-final.log),
  [clock gate](clock-gate.log), [wire schemas](wire-gate.log) and
  [domain separation](domain-gate.log) pass. The subsequent one-line coercion and
  unchanged fixture-body cleanup pass [their formatting](format-followup.log)
  [checks](format-fixture.log); the feature gate also passes
  [formatting](format-link.log). No caps, negative allowances or ambient-clock
  exceptions increased. The clock census remains 154; the negative baseline is
  1,257 assertions at 1,175 sites. Wire declarations match the existing lock.
- [Independent review](review.md): one read-only review of the complete source
  batch found no material findings. The qualification-only coercion, test-module
  relocation, fixture-loop cleanup and private constructor feature gate followed
  that review; no re-review is claimed. Root rulings preserve each explicit
  acceptance boundary.

[Qualification metadata](qualification.json), [per-command test totals](test-summary.json)
and [source hashes](source-hashes.json) identify the accepted evidence and final
source. Each command has same-name JSON metadata with its exact command,
environment, duration and terminal exit. Raw logs remain unchanged, including
blank end-of-file lines; they are excluded from source whitespace checks.

The dependency change adds only the existing workspace `chio-security-types`
edge to `chio-anchor`. Package versions are unchanged. Local results do not
establish full-workspace, alternate backend/device, native Firecracker,
live-provider, hosted exact-candidate, supply-chain, M5, merge or release
acceptance. Production Rekor HttpEgressContract threading and stronger public-log
inclusion guarantees remain separate from this reader contract.

## Retained earlier attempts

| Attempt | Terminal outcome and disposition |
| --- | --- |
| `credit-fiscal-red`, `credit-fiscal-red-2` | Exit 101: the new fixture used incorrect public method names. Compile failures, not reproduced behavioral failures. |
| `credit-fiscal-red-3` | Exit 101: three regression failures reproduced lost native causes and missing original credit bounds. |
| `remaining-red`, `readers-red-4` | Exit 101: original nested duplicates, lost native sources, oversized predicate/publisher input and zero-attempt dead letters reproduced their pre-fix behavior. |
| `publisher-red` | Exit 101: the new observation fixture omitted its required finality field. Corrected fixture before behavioral verification. |
| `credit-fiscal-suite` | Exit 101: the added IOU input-error variant needed source-preserving factor conversion. |
| `credit-fiscal-suite-2` | Exit 101: eight existing assertions expected the old flattened error variants. They now assert precise native cause codes; the full final suites pass. |
| `credit-through-settlement` | Exit 101: a purchase carrier constant used the wrong public name. Corrected to the existing owner limit. |
| `witnesses-red` | Exit 101: five controls reproduced ignored nested duplicates, unbounded proof/response input, future authenticated time and receipt timestamp substitution. |
| `rpc-red` | Exit 101: a concurrent manifest edit left the ongoing build without its new workspace dependency edge. This is a compile attempt, not a security regression result. |
| `rpc-red-2` | Exit 101: two controls reproduced duplicate normalization and native RPC cause loss. |
| `owning-packages` | Exit 101: two existing market/purchase assertions still expected old error variants. The updated precise assertions pass in complete subsequent campaigns. |
| `owning-packages-accepted` | Exit zero: 949 passes before the last diagnostic-shape and unsigned JSON-RPC numeric corrections. Superseded by the 950-pass final campaign. |
| `numeric-and-diagnostic-red` | Exit 101: malformed Rekor hash text could reach public mismatch diagnostics; the first RPC migration incorrectly rejected ordinary `0.10` metadata. Both controls pass after the final contract-preserving corrections. |
| `pre-review-packages` | Exit zero: 950 passes before the final kernel-facing error bridge. Superseded by `post-consumer-packages`. |
| `direct-consumers` | Exit 101: exhaustive purchase/recovery consumer matches needed the new variants. Fixed with closed families and retained native causes. |
| `consumer-cause-red`, `consumer-cause-green` | Exit 101 then zero: both real adapters initially erased parser causes; the bridge repairs them. The final run also covers the equivalent trait-object coercion cleanup. |
| `hygiene-final` | Exit one: one new assertion line exceeded the existing market test-file cap. Move the unchanged test into its own module; no cap increase. `hygiene-accepted` passes. |
| `clippy` | Exit 101: the kernel source bridge used an explicit trait-object `as` cast. An implicit coercion satisfies the existing lint. |
| `clippy-accepted` | Exit 101 despite the label: an existing settlement fixture loop had one element. Direct binding retains the same assertions. Only `clippy-final` is accepted as the final lint result. |

## Reader accounting and next batch

[Reviewed readers](reviewed-readers.json) records all 22 original paths;
[supporting owners](supporting-owners.json) covers local parser/clock/error
ownership and the actual kernel-facing adapters. [Remaining readers](remaining-readers.json)
contains **45** baseline files, down from 67. These are semantic review counts,
not vulnerability totals or threat closure.

The next batch is all **23 core, kernel and SDK readers** in
[next-readers.json](next-readers.json): core supervision/adversarial ingress,
browser/mobile kernels, process persistence/replay/mailboxes/nonces/children,
runtime harness/proof assembly, binding helpers, Rust/C++ FFI, receipt evaluation
and guard glue. It leaves 22 observability/product/tooling reader files and the
independent roadmap gates in the [remaining-work queue](../../2026-09-28-remaining-security-work.md).
