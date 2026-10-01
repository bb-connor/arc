# Platform authority reader execution

Base: `377ee5b773eff424d12182682b411867b4d643be`, branch
`packet/3-retention-accounting`, checkout `/tmp/arc-security-launch`.
Scope: all 31 paths pinned by the preceding guard/security batch, their shared
owners and direct consumers. This continues remaining-work item 2 and the
approved unrepresentable-defects mechanisms A/B/C.

## Delivered tasks

1. **HTTP authority and transaction evidence (10 pinned readers).** Original
   inputs are bounded before projection. Capabilities retain lossless native
   integer semantics, while unsigned plan arguments accept ordinary floats.
   Capability expiry, approval retry expiry and HTTP receipts use the kernel's
   fenced authority clock. Native causes remain local behind fixed HTTP bodies
   or safe signed denial text. Evidence bundles have per-document and aggregate
   limits; graphs have cardinality bounds and iterative cycle traversal.
   Standalone transparency inspection also checks the complete artifact budget.
2. **Commerce and exported evidence (13 pinned readers).** Commerce orders,
   mandates, replay and settlement, enterprise exports, web interoperability and
   trust-market context validate original bytes and collection budgets before
   hash/signature work or replay consumption. Fallible auxiliary evidence
   lookups retain parser causes. Existing claim, signer, exact digest and
   consuming replay requirements remain mandatory.
3. **Hosted ingress, workers and PostgreSQL (8 pinned readers).** Hosted ingress
   retains strict external canonical bytes and fixed HTTP error classes. Worker
   jobs cannot normalize noncanonical stored bytes into an accepted digest;
   result identity is checked before output delivery. Native sources survive
   store/port/edge errors. Checkpoint and principal readback preserve their
   native writer's full-width integers and exact typed canonical bytes. Hosted
   time and worker completion use fenced clocks, and host cgroup reads bound
   actual retention.
4. **Review, accounting and publication.** All five independent review findings
   have implemented fixes and regression controls. The current inventory drops
   from 98 to 67 baseline readers; this is semantic review debt, not a count of
   vulnerabilities. Three existing test files were split into owned child
   modules without raising hygiene limits. The clock gate now includes the
   three migrated production owners without adding ambient-clock exceptions.
   Qualification also repairs a forbidden direct slice in shared signing custody
   using checked access to its existing zeroizing buffer.

The [plan](../superpowers/plans/2026-10-01-platform-authority-readers.md),
[31 reader contracts](artifacts/2026-10-01-platform-authority-readers/reviewed-readers.json),
[supporting owners](artifacts/2026-10-01-platform-authority-readers/supporting-owners.json),
[review resolutions](artifacts/2026-10-01-platform-authority-readers/review.md) and
[qualification record](artifacts/2026-10-01-platform-authority-readers/README.md)
pin implementation and validation separately.

## Publication scope

The user's October 1 clarification authorizes security-roadmap branches and
source changes. The existing integration and completed packet branches were
pushed before this batch. Divergent local packet tips were preserved under
`archive/20261001/packet-1-dry-run` and
`archive/20261001/packet-9-measurement`, without force-pushing remote history.
All 24 selected starting security branch tips have recorded
[remote containment](artifacts/2026-10-01-platform-authority-readers/published-starting-tips.json).

Unfinished formal-model, adversarial-case and checkpoint snapshots were committed
and pushed separately as WIP (`806b42c12c`, `21b32859b9`, `534e8040c3`). They are
not integrated or newly qualified by this batch. Older September 5-6 preview/probe
worktrees, conflicted PR 1029 experiments, machine-local output links and skill
scratch remain outside the clarified scope. The final platform implementation
and evidence are published on `packet/3-retention-accounting`.

## Qualification boundary

The qualification record retains every terminal failure and retry, the accepted
package results, direct consumer compilation, local PostgreSQL execution,
source gates and exact source hashes. Dependencies add only three existing
workspace security-types edges; package versions are unchanged. Plan parsing
also enables Serde's existing `raw_value` feature for original capability bytes.

This batch does not establish full-workspace, native Firecracker, live-provider,
optional device/backend, dedicated TLS worker-lease, hosted exact-candidate,
supply-chain, M5, merge or release acceptance. Parsing is not authentication.
Broader semantic error taxonomy and clock/arithmetic ownership remain queued.

## Next substantial batch

Execute all **22 economy readers** pinned in
[next-readers.json](artifacts/2026-10-01-platform-authority-readers/next-readers.json):

- Credit credentials, IOUs, factors and obligation binding/status (5 readers).
- Fiscal evidence, continuity and readiness (3 readers).
- Settlement configuration, CCIP, replay, retries and finding enforcement
  observation/publication (6 readers).
- Market purchases/recovery, parametric/listing outcome evidence, anchor/Rekor
  witnesses and Chainlink observations (8 readers).

At each original boundary preserve the owner's numeric/signature contract,
bound input before projection, retain native causes, and verify identity,
replay, custody and effect ownership. Repair concrete clock/accounting/lifecycle
issues found in those paths; add positive and precise negative controls, qualify
owning packages and direct consumers, and record per-reader dispositions. This
leaves 45 other baseline readers plus the independent arithmetic, clock,
assertion, schema, formal/runtime, retention, supply-chain and launch gates in
[the remaining-work queue](2026-09-28-remaining-security-work.md).
