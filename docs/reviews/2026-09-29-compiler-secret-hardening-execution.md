# Compiler enforcement and secret ownership execution

Base `a76864ad1a`, branch `packet/3-retention-accounting`, worktree
`/tmp/arc-security-launch`. Implements the
[approved plan](../superpowers/plans/2026-09-28-compiler-secret-hardening.md).
Implementation and qualification started September 28 and continued September 29.
All five implementation-plan tasks are complete and locally qualified at the
boundaries below. This record does not establish hosted, release, merge or
operator acceptance.

## Delivered implementation

1. Workspace policy denies unsafe operations inside unsafe functions,
   undocumented unsafe blocks and multiple unsafe operations in one block.
   All 177 member manifests participate: 158 inherit and 19 explicitly mirror
   the five required workspace lints, including the existing unwrap/expect pair.
   Pointer validation, initialization and foreign calls now have separate safety
   claims. The MCP edge no longer asserts `Send` unsafely: exclusive receiver
   borrows and a `Send` writer establish its actual ownership requirements.
2. Every eligible library root forbids unsafe code. The catalog covers 165
   library roots and names 12 justified exceptions, including generated bindings
   and actual platform/FFI boundaries. The source gate checks root attributes,
   rather than accepting comments or attributes inside a child module.
3. The production deny policy covers 25 TCB libraries. Accounting arithmetic is
   enforced on 49 module owners and four textual fragments through their
   enclosing owners. The checked-conversion migration refuses narrowing across
   SQLite and wire fields. `PublicKey::ed25519_bytes` returns a typed rejection
   for another algorithm; Ed25519 keypairs expose their fixed public bytes.
   DPoP and approval replay constructors reject invalid capacities. Signing
   permit conversion rejects unrepresentable or over-budget lengths. Control
   plane credit limits use exact integer percentages with one final division,
   avoiding precision loss above `2^53`. Clock failures propagate through the
   attestation import path. Broker HTTP parsing uses bounded slices and explicit
   malformed-input rejection. File-size caps were preserved with private module
   extractions rather than raised.
4. Six external-guard configurations, authority key documents, broker-owned
   credentials/audit inputs/admin tokens and settlement release keys use explicit
   secret ownership. Ordinary authority key documents cannot derive Clone or
   Serialize. Their explicit custody exporter projects borrowed plaintext into
   zeroizing canonical output, and the reader still requires original-byte
   equality. Broker vectors keep their original allocations. Existing FROST
   sealed envelopes and private custody boundaries are preserved. Transient
   serializer/IPC buffers and already-private FROST custody owners retain their
   explicit zeroizing APIs; this is not a claim that every transient plaintext
   copy has been removed from the workspace.
5. Compiler probes include a positive control and 14 named violations. Source
   calibration covers policy removal, unjustified exceptions and secret derives.
   CI invokes both gates. The `secrecy 0.10.3` source audit is recorded in
   [the supply-chain review](../security/supply-chain/secrecy-0.10.3.md).
   The broker budget grows from 479 to 480 solely for that audited dependency;
   the cage budget remains 260. No vet exemption was introduced.

Compiler integration also exposed and repaired stale consumers of the previous
batch: the UntrustedInput FFI error mapping, a buyer-attestation parser-error
adapter, a verified-capability test accessor, a fallible passport status reader,
and three retired retained-request schema lock entries. These do not restore
historical readers or compatibility APIs.

Runtime verification found a deterministic-harness clock split: evaluation used
the fixed scenario instant while the kernel's durable return-context check used
wall time. The harness now injects the same fixed clock into the kernel, and all
22 scenario tests pass. Production freshness checks remain enforced. Two stale
test expectations were also repaired: the broker exposes its registered redacted
clock code, and DPoP's production predicate refines the verified saturating model
with a representable-deadline requirement. Its property test generates across the
full `u64` input domain using a widened mathematical deadline, including overflow
rejection and accepted boundary controls; the formal helper was not weakened.

The narrower documentation build also exposed an undeclared `uuid/v4` feature:
the kernel now declares the feature its nested request identifiers use, instead
of relying on another workspace consumer to enable it. WASM qualification exposed
browser-only float conversions. A small checked helper preserves the existing
finite/nonnegative/range checks and truncation behavior; its explicit cast
exception is confined to already-validated values. Native tests exercise both
time domains at invalid and representable boundaries.

## Verification

All results below are terminal local results, not hosted qualification:

| Check | Result | Evidence under `/tmp/chio-compiler-hardening-20260928/` |
| --- | --- | --- |
| `CARGO_INCREMENTAL=0 cargo clippy --locked --workspace --all-targets --keep-going --message-format=json -j 8 -- -D warnings` | Exit 0, successful build-finished event, zero compiler errors | `clippy-28.jsonl`, `clippy-28.stderr` |
| Focused Rust unit/integration tests | 1,660 passed across the selected owner and boundary suites | `focused-qualified-results.json`, `changed-results.json`, isolated native logs, `browser-tests.log` |
| Secret API rustdoc examples | 8 passed, including six compile-fail examples and two positive controls | `secret-doc-tests-2.log` |
| WASM strict Clippy, guard SDK and browser kernel libraries | Exit 0 on `wasm32-unknown-unknown` | `wasm-clippy-2.stderr`, `platform-final-results.json` |
| Source policy calibration | 19 passed | `inactive-policy-green.log` |
| Compiler calibration | Positive control plus 14 violations produced the named expected outcomes | `compiler-probes-2.log` |
| Source/format checks | Lint parity, root/TCB/secret policy, arithmetic, clocks, trust boundaries, negative assertions, file hygiene, wire schemas, toolchain parity, dependency budget, formatting and diff checks passed | Final gate logs and `final-source-results.json` |

The focused count includes 171 broker owner tests, 29 browser tests and three
isolated native broker cases. It excludes repeated runs and two existing ignored
tests: explicit FROST vector regeneration and a native x86_64 cage boundary.
The remaining workspace tests, non-host platforms, feature combinations,
sanitizers, formal campaigns and release qualification were not run here.

The initial combined broker unit run reached its 300-second limit, with native
process failures recorded before the timeout. It is not passing evidence. The
direct real-TLS case and both reported broker-death cutpoints subsequently passed
individually, with complete logs. All 171 remaining broker owner tests passed
separately from the process campaign. The larger native-process campaign remains
a separate qualification boundary; isolated passes do not explain the earlier
failures.

`cargo vet --locked` accepts the new secrecy audit but fails on the existing
`aws-lc-rs 1.18.1` safe-to-deploy audit requirement. That source audit remains
in the candidate-qualification queue. Formatting the audit store was required;
the subsequent failure is the audit gap, not a formatting failure.

Diagnostic Clippy runs are retained under
`/tmp/chio-compiler-hardening-20260928/`. Failed diagnostic runs are not passing
qualification. One run exhausted local disk while writing incremental caches;
only this worktree's regenerable incremental cache was removed, and subsequent
checks use `CARGO_INCREMENTAL=0` while preserving dependency artifacts.

## Independent review and decisions

One fresh read-only review examined the batch, with no delegated implementation.
It found two important source-gate defects and no runtime defect in the boundaries
it inspected. Both findings have reproductions that failed before their fixes:

- Split derive attributes and an array field's semicolon could hide a later
  secret field. The gate now combines derive attributes and scans balanced
  struct bodies; the additional calibration cases pass.
- Test-only or inactive cfg attributes could masquerade as production denies.
  The gate now accepts unconditional denies or the explicitly supported
  `cfg_attr(not(test), deny(...))` form. Three inactive-condition reproductions
  now fail the policy check as intended.

No minor findings were raised. This was a risk-focused source review, not
exhaustive semantic verification of every line or target/feature combination.

Decisions carried from the implementation ledger:

- Batch implementation and verification per the user's directive. Cost if
  wrong: integration regressions surface later in the batch; terminal compiler
  and focused runtime checks remain acceptance requirements.
- Use the current member/TCB census rather than the spec's obsolete counts.
  Cost if wrong: an omitted owner would lose enforcement; metadata membership
  and the explicit TCB census are checked by the gate.
- Sequence documentation/visibility warnings with the structural/privacy
  package. Cost if wrong: those warnings remain unenforced until that package;
  this batch claims the named security deny set only.
- Repair preexisting integration gaps exposed by the new compiler floor.
  Cost if wrong: a wider review surface; the changes preserve typed rejection
  causes and remove obsolete consumers without adding compatibility paths.
- Preserve existing report clamps, statistical approximations and private
  transient custody buffers outside the migrated owners. Cost if wrong:
  preexisting semantic or copy-lifetime defects could remain; the owner review
  queue and FROST/private-custody boundaries remain separate acceptance work.
- Historical wire compatibility is excluded by the user's directive. Cost:
  artifacts from removed unshipped formats are rejected.
- Hosted delivery, broad platform qualification and the AWS-LC audit remain
  separate gates. Cost: locally qualified code is not a release-ready candidate.
- Retain this local branch and worktree for the user's continuing implementation
  cadence. Use the scoped tests above instead of the branch-finishing skill's
  blanket full-suite rerun, under the user's explicit focused-verification
  directive. Cost: integration and broader test qualification remain pending;
  no merge, push or publication is implied by this local commit.

## Next package

Continue with structural boundaries and helper isolation from Packet 7/H11:
replace textual assembly with real modules in the security ports, broker service,
SQLite security state and control-plane security composition; enforce the intended
visibility; split a minimal `chio-cage-init` package and tighten its measured
dependency budget. Keep mechanical moves and behavior changes separately
reviewable, and preserve focused boundary tests. Remaining reader/rejection,
storage performance, lifecycle and candidate-delivery queues remain listed in
[the reconciled queue](2026-09-28-remaining-security-work.md).
