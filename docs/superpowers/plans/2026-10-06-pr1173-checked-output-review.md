# PR 1173 Checked-Output Review Closure

> Execute inline with superpowers:executing-plans. The user prohibits subagents.

**Goal:** Close review thread `PRRT_kwDOR0fQBc6pXSyr` against
`9c152fbdfade4a13d38f719dcc7d86f831c7a1d1` without weakening ordinary output
guards, zero-charge authority, retained denial, or source-bound qualification.

**Finding:** `record_durable_tool_return` evaluates a contractual output checker
and discards its rejection. Durable evaluation calls the checker again. A checker
that rejects or panics once and subsequently accepts can therefore produce an
Allow receipt, expose output, and capture a payment.

**Design:** Preserve ordinary fail-closed validation before raw-return persistence.
Defer opted-in contractual checkers to the existing authoritative durable
evaluation, where raw and transformed rejections are combined monotonically and
the resolved decision is persisted before settlement and output release. Use an
internal enum to distinguish release, pre-record validation, and durable
evaluation. Do not add transient denial state, forge receipt metadata, extend the
durable outcome schema, or introduce a second checker pipeline. A contract probe
that panics must fail closed. Existing immutable replay and settlement authority
remain unchanged.

Persisting the first preliminary rejection would require a new authenticated
durable schema and recovery contract. Carrying a boolean only in memory would
lose rejection across restart. Deferring contractual validation to the existing
authoritative point avoids both changes and retains the original ordinary-guard
recovery behavior.

## Execution

1. Add real kernel regressions for a contractual checker that rejects once,
   panics once, and later accepts. Require a signed redacted Deny, exactly one
   invocation and hold release, no output or capture, and identical retained
   replay. Exercise a terminal-projection failure after the resolved denial.
2. Run the new cases against the original implementation. Preserve actual
   behavioral failure separately from setup or compilation failures.
3. Introduce the internal validation phase and defer only opted-in checkers at
   pre-record validation. Preserve ordinary guard checks and authoritative raw
   plus transformed-output rejection aggregation.
4. Register the complete checked-output module in the information-flow gate
   and its real omission/substitution controls. Require all existing ordinary,
   panic, mixed-contract and replay cases as well as the new regressions.
5. Run complete kernel tests, strict affected Clippy, the flow gate and its
   negative controls, formatting, proof selection and file hygiene. Review the
   actual diff inline. A new code change requires fresh x86 hosted acceptance.
6. Preserve the preceding qualified artifacts and all terminal hosted results
   with their actual candidate scope. Commit the repaired source, renew the
   21-command source-bound package and receipt verifier, reconcile the evidence
   inventory and reproducible PDF, then push the derived artifact commit normally.
7. Require final-candidate x86 workspace, consumer, native PostgreSQL, Kani,
   advisories, supply-chain and fuzz results. Resolve each review thread only
   after its stated acceptance boundary is met. Keep the external signed Linux
   evidence package and open publication research gates explicitly separate.

## Newly yanked blob-provider dependency

Hosted `cargo-deny` job `112157028357` rejects registry `iroh-blobs 0.103.0`.
The publisher yanked it at 07:39 UTC on October 6 after publishing unyanked
`0.103.1`. Both registry archives are authenticated by their registry checksums.
The patch fixes request-type selection in `EventMask`: the old implementation
uses the `get` mode for push, get-many and observe requests as well.

After the current Cargo owner exits:

1. Review every changed release file and surrounding event selection, provider
   dispatch, actor termination and hash iteration. Record the exact archive
   checksums, upstream commits, delta and retained base acceptance boundary.
2. Reproduce unsolicited push acceptance against the old dependency with actual
   peer/store behavior; require the replacement to reject it while explicit
   permitted transfer still works. Preserve actual failing and passing evidence.
3. Require at least `0.103.1` in the existing transport manifest and update every
   active locked graph that selects the yanked version. Keep archived historical
   research snapshots immutable. Review any required `cfg_aliases` build-helper
   change; record a genuine delta audit rather than a new exemption.
4. Require the complete affected federation/Iroh suites, strict Clippy, all six
   locked audit graphs, deny/advisory policy and unchanged exemption rules before
   the source checkpoint and renewed native/paper qualification. Later hosted
   acceptance must cover this replacement graph as well.

## Native PostgreSQL retirement fixture

The final `9c152fbdfa` PostgreSQL job passes both real worker/recovery trajectory
steps, then fails the unignored retirement test at its destination-substitution
assertion. The actual IPC denial is `chio.broker.authorization_denied`; the
fixture expects legacy local code `authorization_denied`. Existing signed IPC
envelope and client tests require the qualified broker namespace and reject the
kernel namespace. Keep that authenticated wire contract unchanged.

After the current Cargo owner exits, update this fixture to require the exact
qualified code for all five substitutions. Preserve its existing signature,
quotas, canary confinement, launch binding, lifecycle and replay assertions.
Retain both verified trajectory reports separately from the failed overall job.
Require the complete portable broker suites, strict affected Clippy, and a fresh
final-candidate unignored x86 retirement test before resolving the lifetime
review thread or claiming PostgreSQL qualification.

## Delivery-preparation formal mirrors

Hosted workspace job `112157028121` stops at the formal-mirror guard before
workspace execution. Two manifest entries still contain the previous body hash
for `ChioKernel::wait_for_tool_dispatch_readiness`: `RevocationPropagation` and
`PostAdmissionDropGuard`. The implementation now retains the registered server
connection when its readiness callback returns no replacement connection.

Review both complete model abstractions before blessing the entries. The
revocation model still requires monotone revocation propagation and clock state;
the post-admission model still tracks dispatch, cleanup ownership, receipt
commitment and retained unknown outcomes. The repaired readiness callback still
requires mutable authorization revalidation before commit. Retaining the
registered connection changes neither modeled action nor invariant.

These models do not encode concrete connection identity or native launch receipt
bindings. A matching mirror hash is a review record, not a Rust refinement proof.
Preserve the portable delivery tests and require the actual unignored native
retirement test for those concrete boundaries. Reproduce the mirror failure,
inspect every additional drift, then require the ordinary mirror and
proof-coverage checks.

The live checker also finds the checked-output repair's
`ChioKernel::record_durable_tool_return` anchor in `PostAdmissionDropGuard`.
Ordinary rejection still leaves the operation at dispatch-committed with unknown
exposure. Deferring contractual checkers does not change raw-return persistence,
resource ownership or receipt append authority; both accepted and denied returned
outcomes remain modeled actions. The model does not encode stateful checker calls,
monotone contractual rejection or the external payment adapter. Those properties
require the actual checked-output regressions and durable settlement tests.
Bless exactly these three reviewed entries, inspect the symbol and aggregate
hash changes, and preserve every other anchor and model action.

## Multi-hop federation evidence fixture

The preceding candidate's MSRV workspace lane fails the existing multi-hop
federation test because evidence export omits required `--kernel-seed-file`.
The corresponding import also omits required `--trusted-kernel-pubkey`.
Keep both production requirements and the existing private-file validation.

After the active Cargo owner exits, supply the fixture's existing private shared
signer file to export. Pin import to the independently derived authority public
key already computed from that fixture file, rather than a key read from the
exported manifest. Preserve all issued-capability, delegation ceiling, imported
parent, four-hop lineage and replay assertions. Run the complete federation-issue
and evidence-export integration suites, including existing wrong-key and package
substitution controls, and strict affected Clippy. The hosted MSRV failure is
actual red evidence; require fresh final-candidate MSRV and workspace acceptance.

The first repaired-command run passes all fourteen evidence-export tests, then
the multi-hop import correctly rejects its selected receipt's untrusted random
kernel signer. The common package verifier rejects it locally before any remote
request. Extend the existing receipt fixture helper to accept an explicit signer.
Keep the two historical seed receipts' existing independent random signers, but
sign the selected multi-hop receipt with the private shared fixture key used for
export. Pin import to the public key independently derived from that same file.
Preserve the failed campaign and rerun both complete integration targets and
strict Clippy. Do not change production trust policy or infer keys from the bundle.

## Deception inventory closure

The preceding active-defense job passes all sixteen compiled materialization
tests, then rejects the stale fifteen-name inventory. The sealed registry target
also includes an existing tenant-isolation source module omitted by its inventory.
Keep the exact Cargo targets and reject missing, extra, ignored and substituted
identities.

Register both existing cases. Bind the contract to the materializer's production
source module and the sealed registry's complete, declared source fragments.
Add actual omission and same-count substitution controls for both boundaries.
The strengthened contract must fail against the old runner before its repair.
Require all twelve inventories and eighty-five actual tests, preserving each
gate's original command and filtering policy. This closes the owned stale gate;
the external security source and signed Linux package still require their owner.

**Tracking:** Freeze this plan before native qualification. Record later status
in the excluded execution ledger and retained evidence, without changing source
hashes under a qualified campaign. Preserve the PR's ready-for-review state.
