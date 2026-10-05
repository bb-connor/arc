# Additional production and evidence review

The external static review of `5dc7921d3c6437db40a01ceea20a9fdb1396ba31`
reported 37 additional findings (four P1, 30 P2 and three P3). This disposition
records the repairs separately from the earlier review. Source changes pass the current local source-bound package. Final hosted
candidate qualification remains pending; passing historical jobs do not qualify it.

## Runtime and protocol repairs

| Finding | Owning repair and acceptance boundary |
| --- | --- |
| Delegated permit expiry during execution or replay | Fresh dispatch uses current time; immutable output-contract validation uses the signed issuance interval. Expiry/restart regressions retain exact receipts and payment identity. |
| Definite payment decline becomes ambiguous | Persist cancellation only for the adapter's authoritative `Declined` or `InsufficientFunds` response. Unavailable or ambiguous authorization retains exposure. |
| Ordinary output denial wedges restart | Raw guards run before return retention. Post-transform denials retain output and hold under a checked recovery claim without blocking unrelated startup. All 15 delegation lifecycle tests pass, including both denial paths. |
| A2A conformance does not compile | Use canonical byte ingress in the actual conformance target. |
| Forged receipt identity tests expect success | Require strict signature failure for substituted weak identities. |
| Capture waiver is reported as failed payment | Completed contractual release is settled at zero monetary charge, preserving positive realized budget cost and signed successor authority. |
| Dispatch sealing commits before signing can fail | Validate, sign, insert and claim allocation in one immediate transaction; failed sealing rolls back and permits replacement. |
| Blocking A2A results exhaust global retention | Release blocking task custody on both success and failure; deferred custody is bounded globally and per capability subject. |
| Native launch-owner regression misses the call site | Retire the preparation Tokio runtime after the actual broker MCP preparation call, then require real confined TLS execution and receipts on x86. |
| Bilateral wire errors expose local details | Both refusal profiles emit fixed public codes/reasons; typed internal causes remain local. |
| Revocation sink mixes independent epoch domains | Pin one root verifier, construct its empty view locally and authenticate every root before selecting a batch epoch. Multi-origin aggregation is not supplied. |
| Underscore consistency aliases bypass the spec vocabulary | Reject underscore forms in both parsers; update active fixtures to the hyphenated vocabulary. |
| SQLite journal codec omits successor states | Decode resolving/resolved and contractual capture waiver exactly. |
| Presenter text overrides typed error prefixes | Prefer registered prefixes; recognize only the exact locally generated signer-independence diagnostic. |

## Qualification and supply-chain repairs

The main CI workflow now selects packet and integration bases. A new matrix
builds, lints and tests all five standalone research workspaces; their locked
graphs use the production patch set. Cargo Vet checks each graph, and Cargo Audit
checks the root, both generated deployment locks and all five standalone locks.
The Python participant uses hash-locked dependencies and all its unit tests.
Unfiltered OSV results are blocking even when a local suppression file exists.
Proof-room lock drift and registered-work schema controls run in structural CI.
Experimental escrow is excluded from production web3 compilation while retaining
its dedicated bytecode suite. No new audit exemption or advisory ignore is added.

The Vet policy checker rejects weakened criteria as well as new exemption rows.
Its sole explicit composite exception is the exact AWS-LC upstream-review
policy joined to the fork reconstruction, feature and lint gates. Cargo Vet
alone does not certify the published upstream crate as deployable.

CODEOWNERS now covers the source, audit, npm and Kani trust anchors using a valid
repository owner. The inspected repository ruleset requires selected status
checks but does not enforce code-owner approval. File ownership is consequently
review routing, not an independently enforced approval barrier. This repair does
not invent a branch-protection guarantee or change repository policy.

## Research and manuscript corrections

- The baseline excludes two unpaired agreement-version cases and a denial caused
  incidentally by the fixture approval record. Its selected comparison has three
  hardened survivors; it establishes no universal protocol limitation. The new
  diagnostic report disqualifies its own timing samples.
- The paper explicitly locates the cross-record joins in the fixed-profile
  example guard, including the 100-unit program. General runtime admission
  integration remains W1 work rather than an implementation claim.
- A real host canary replaces the machine-specific nonexistent path; the
  unconstrained positive control reads it. Existing retained files open without
  symlink following or FIFO blocking and must be regular files. Transient TLS
  accept errors back off and retry.
- Claim replay covers post-deadline Payable/Paid states and exact error reasons.
  Its source-bound record contains 270 traces, 738 matched SQL steps and 271
  passing bytecode tests; the expire-payable mutation produces nine failures.
  Historical 118-trace records are retained separately.
- The lab now mutates accepted knowledge clearing and rollback and independently
  checks release binding, read authority, scope and epochs. Seeded faults trigger
  the assertions. All 40 tests and five source-bound qualification commands pass.
  Initial knowledge remains supplied and garbage-collection payloads are outside
  the model. G2 records that the previous zero-violation counts did not establish
  these missing predicates.
- The partial-outcome subfinding is not confirmed: F06/F14 correctly withhold a
  partial result after a lost acknowledgement, then authenticated provider
  evidence establishes Partial. New assertions check both steps in both arms.
- Normative supplements specify execution-only receipts and monetary successors.
  DSSE co-signing requires reconstruction and party/fingerprint checks, without
  inventing independent policy evaluation. The receipt ALPN and bounded framing
  are specified; passport revocation is scoped to transport-directory removal.
- Canonical reproduction instructions use portable paths. Missing private
  historical observations are marked unverified and are not qualification
  inputs. Private session narration is removed from canonical design documents;
  authenticated historical artifacts retain their original bytes.
- Generated evidence is marked for review display. Current appendix counts are
  derived from authenticated terminal output, with optional chain results bound
  to their historical source inventory. Publication checks require frozen named
  evidence and claim-register agreement; changing status flags alone fails.
  Publication and foundational claims remain open.

## Local qualification

Source `2ce480588721ce206c740ff1a601c4d2a9c9889a` passes all 21 terminal
qualification commands against 37,305 source files and 48 retained outputs.
Before/after hashes agree. Actual parent SIGKILL, evolving funded work and all
four earned-child payment cases pass. The funded suite retains its 96 passing
tests and six explicit opt-in skips. All 18 artifact-tool tests pass. Historical
successes and the interrupted pre-pin attempt retain their original evidence.

## Final acceptance

The replacement candidate still needs terminal main CI, research matrix, all
34 x86 fuzz targets, 53 selected Kani harnesses, the complete AWS-LC composite
gate, advisory scans, the actual native broker call-site regression and both
confined PostgreSQL trajectories with 23 independently verified receipts.
This record is not merge, deployment, external-operation or publication approval.

The full CI aggregate also requires the separately authorized committed Linux
evidence package. On October 5, the repository had no
`CHIO_COMMITTED_LINUX_EVIDENCE_SHA` or `CHIO_ENTERPRISE_EVIDENCE_POLICY_JSON`.
Another execution lane was rotating the authorized source and definition. This
PR does not replace those trust roots, self-authorize its source, or synthesize a
signed evidence package. The missing operational prerequisite remains open until
the protected capture and finalizer supply and verify the actual package.
The user confirmed that the security agent owns that package. This candidate's
CI caller uses the already merged, repository-authorized definition
`4f3c967f04af40b5025b9222e8db95a3aee0b5f4`; repository authority variables remain
under that separate lane's ownership.

The first replacement at `28842e598e` exposed two additional qualification
defects: the publication freeze omitted four named claim sources, and the
composite build-custody test lacked a newly invoked shell-control fixture. Both
are repaired with retained reproductions. All 20 paper-tool tests and the
complete AWS-LC composite gate pass locally. Neither repair changes production
Rust behavior or weakens an acceptance check. Renewed source qualification and
replacement-commit hosted acceptance remain required.
