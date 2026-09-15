# Inline review: public authority enrollment and verifier custody

Reviewed without sub-agents. Scope includes the new provisioning, public verifier,
file handoff and process harness plus their shared native agreement, Finding,
journal, observation and decision paths. The manifest identifies the exact source
objects and executable qualified by the commands. This is local review and test
evidence, not a remote review, release approval or public deployment.

## Authority inputs

- Provider provisioning checks six administratively selected, distinct Ed25519
  role keys and the externally signed execution context before creating stores.
  The original marker precedes native provisioning. Completed retry compares the
  original UUID, exact policy/context/domain and implementation; partial or lost
  custody cannot authorize replacement authority.
- Verifier initialization checks its own seed against immutable administrative
  enrollment. Requests cannot supply an observation or substitute that enrollment.
  Public validation requires the original bilateral signatures, complete policy,
  original allocation derivation and authentic native execution commitments.
- The public request contains no private capability or native request preimage.
  Native request/waiver checks stay in the native wrapper. Public verification
  checks signed request/raw-outcome commitments without overstating preimage
  recomputation or financial backing.
- Execution standing, receipt action input, resolved output, original authority,
  operation, hold, authorization and checkpoint chronology stay bound together.
  An authenticated incorrect submitted output is a rejection. Missing or invalid
  authority is an error and cannot become either financial decision.

## Timing correction found during review

The first implementation observed the original claim before invoking the Python
checker, then signed using that observation. A checker could cross the claim's
resolution deadline. The owned-chain regression advanced to refund time inside
`Checker::check` and demonstrated that the implementation incorrectly minted a
decision. The retained development red/green logs document the reproduction.

The corrected verifier reobserves the exact original prepared claim after the
checker returns, compares the original transaction and inclusion block, and
revalidates the resolution window and current Finding/execution authority. The
final observation and refreshed assessment commit together. It does not repeat
the checker or native tool execution. Historical cached replay still validates
at the original assessment time and never reobserves or refreshes authority.

## Custody and file boundaries

- Provider external export and local decision selection use the same atomic
  journal exclusion. External selection cannot silently fall back to local keys.
- The verifier commits request, its actual observation and first signed decision
  in one FULL-synchronous SQLite transaction before output publication. Later
  writers return exact custody or reject changed requests. Missing state is opened
  without CREATE; malformed versions, partial rows and corrupt signed artifacts
  are denied. No new rollback-protection claim is made for this local journal.
- First import validates against the provider's original retained submission,
  prepared claim and native execution bundle, then observes the original claim
  through its own configured source. Exact retained imports replay without
  observation and never replace a conflicting decision.
- All public CLI inputs use the bounded raw-first canonical typed decoder.
  Duplicate keys, extra observation fields, noncanonical bytes and oversize
  requests fail. Existing output files are preserved. Process tests force failed
  publication after commit, remove the signer and observer, and recover the exact
  first response with the Python checker also unavailable.
- Isolated corrupted database copies test decision-signature changes, changed
  observation identity, partial rows, unknown versions, missing files and truncated
  files. They never mutate the actual committed operator journal. After all
  failures, the original database still returns the exact response.

## Qualification and retained boundaries

The report and manifest enumerate final test counts and command results. Selected
regressions include original checkpoint handoff, native resolution, earned-child
recovery and execution-custody process loss. Workspace crates, dependencies,
native same-signer checkpoint rules and original checkout remain unchanged.
No new unsafe blocks, dynamic code evaluation, powerful workspace dependencies or
production unwrap/expect calls were introduced. The new process harness invokes
only the current executable; checker execution retains the existing pinned-source,
bounded-output and timeout implementation.

The fixture coordinator still reads buyer/provider seeds, and context generation
reads governance/status seeds together. Role directories are not OS access
isolation. The read-only observer is receiver configured but still backed by the
same locally owned chain. Public RPC finality, independent administration,
external revocation, rollback-aware multi-allocation custody and hostile-network
transport remain unqualified. Fresh exports require currently valid authority;
keep the original request for historical recovery. Native implementation pins
remain exact, with no automatic in-place migration of prior policy state.
