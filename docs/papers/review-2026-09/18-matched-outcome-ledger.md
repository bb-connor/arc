# An ordinary ledger matches the local outcome gate

2026-09-13. Continuing the breakthrough objective after
[the outcome-continuation prototype](17-outcome-continuation-experiment.md).
The previous experiment made concrete progress: a verified artifact could
survive replacement of its proposing agent and authorize one publication.
This experiment implements the strongest immediate objection to its novelty.

**The independent ledger reproduces every tested observation.** The local
effect-slot mechanism is useful engineering, but these results do not establish
a new authorization capability or a Bitcoin-level breakthrough. The broader
objective remains active.

## What was built

[The receiver ledger](../../../examples/composed-baseline/src/outcome_ledger.rs)
is a separate implementation with its own types, validation, schema and SQL.
It shares cryptographic and canonical JSON primitives with Chio, but never
calls the runtime's outcome checker or effect-slot store. Its owner provisions
an immutable job identified by receiver, workflow and step. A valid signed
outcome can be exchanged for an unpredictable opaque handle. Multiple handles
and candidate outcomes refer to the same durable one-effect budget.

At dispatch, the ledger resolves the handle and checks the current owner rule,
revocation, validity, selected verifier, contract, predecessor, exact artifact,
resource and target. An immediate SQLite transaction changes the job from
waiting to claimed before the external append. Completion stores the result;
an uncertain claim has no automatic reset. Re-provisioning the same owner rule
does not restore consumption or remove revocation.

Application-defined evidence is explicitly permitted. The historical
composed baseline's carrier inventory is not a restriction on this alternative.
Both gates receive the same verifier, contract, logical budget, local clock,
trusted storage and external effect semantics. Both use WAL and
`synchronous=FULL`. The ledger's additional evidence-to-handle exchange differs
from Chio's non-consuming preview, so this experiment makes no timing claim.

The [comparison runner](../../../examples/outcome-ledger-comparison/README.md)
drives both gates through one adapter interface. The artifact workload uses an
identical Chio kernel and publishing tool host for each gate, deliberately
isolating the gate under test. This is not a comparison between two complete
agent protocols. The ordinary external append has no deduplication; a second
authorization would produce a second physical effect.

## What was observed

The retained [machine-readable comparison](evidence/18-matched-outcome-ledger/comparison.json)
contains 28 paired scenarios: 16 positive/substitution cases, six state
transitions, five process scenarios and one kernel artifact workflow.
Each paired scenario records both implementations and asserts the relevant
expected effects as well as equality between implementations.

| Scenario | Chio outcome gate | Independent ledger |
| --- | --- | --- |
| Valid outcome, then another attempt | One effect total | One effect total |
| Fifteen invalid bindings or outcomes, each followed by the valid request | Invalid attempt writes zero; valid follow-up writes once | Same |
| Revocation, expiry or argument mutation after preparation and receiver reopen | No claim and zero effects | Same |
| Fresh signature or verified candidate after completion | No fresh budget | Same |
| Two authorizations prepared before either dispatches | One claim and one effect | Same |
| Eight processes released at a shared start barrier | One physical append | Same |
| SIGKILL before the claim | Replacement completes once | Same |
| SIGKILL after claim, before the append | Zero effects; uncertainty retained; retry denied | Same |
| SIGKILL after the synced append, before completion | One effect; uncertainty retained; retry denied | Same |
| SIGKILL after completion | One effect; result retained; retry denied | Same |
| Kernel publication followed by reopen and a fresh agent capability | Exact artifact published once; signed receipts verify; replacement denied | Same |

The fifteen negative cases change verifier key, contract, predecessor, receiver,
workflow, step, artifact, resource, pass result, verification time in either
direction, server, tool, signed bytes, or schema. The schema case has a valid
signature under the selected key, isolating schema rejection from signature
rejection. Every invalid case leaves the legitimate job usable.

Baseline-specific checks also prove that issued handles actually differ, a
caller-invented handle is rejected, and the second valid handle cannot refill
the job budget. The baseline is not relying on deterministic reissuance to
make that test pass.

Each fault run kills an owned child at an observed checkpoint and checks its
exit status. The retained run includes eight SIGKILL terminations, four per
gate, and sixteen race contenders in total. These children directly exercise
the gate/effect boundary. The separately driven kernel workload verifies
capability admission, result-to-receipt content binding and signatures, but
does not qualify the kernel's whole crash-recovery pipeline.

## Why this changes the judgment

Removing agent identity from the durable budget does prevent a useful class
of accidental or hostile reissuance. It does not require a new wire format or
authorization theory. A receiver-owned ordinary ledger can resolve signed
application evidence and consume a stable local job in the same way.

The strongest objection to this conclusion is the limited comparison surface.
The experiment shares a trusted outer kernel, tests a finite corpus, and does
not measure how much integration work independently administered deployments
need. Chio may offer valuable integration and audit benefits. Those benefits
must be demonstrated directly; they do not follow from this gate's name,
signature format, source length or field inventory.

What would change this judgment is a useful deployment whose independently
verified completion, recovery intervention or application security burden
improves materially against an equally provisioned alternative. A larger graph
of the same local transitions is not enough by itself. Nor can safe retry of
an unknown non-idempotent effect be claimed without a mechanism that resolves
that uncertainty under explicit receiver and sink assumptions.

## Research implications

Microsoft's June 2026 information-flow prototype propagates security labels
and checks policy around tool calls, including through MCP metadata extensions.
That is further reason to treat application-defined conditions and deterministic
enforcement as available to serious alternatives. We read the primary report;
we have not reproduced its implementation.
[Information-flow control: Moving toward secure, autonomous agents](https://commandline.microsoft.com/information-flow-control-moving-toward-secure-autonomous-agents/).

Microsoft's April 2026 agent-network red team reports malicious instruction
propagation and trust capture across interacting agents. These are useful
adversarial workloads for a broader execution experiment. Our static scope
artifact and selected verifier do not test those attacks, and their report
does not establish that this implementation would stop them.
[Red teaming a network of agents](https://www.microsoft.com/en-us/research/blog/red-teaming-a-network-of-agents-understanding-what-breaks-when-ai-agents-interact-at-scale/).

The next implementation target remains a useful artifact graph across
independently restarted receivers: proposals, contract verification and bounded
publication, with duplicated or delayed evidence and replaced workers. The
matched ledger must remain available throughout that experiment. Measure
completed work and unresolved interventions; do not convert missing baseline
features into a protocol impossibility claim. A graph that merely matches the
ledger would still advance the product, while leaving the breakthrough
objective unproven.

## Reproduction and evidence boundary

```sh
CARGO_TARGET_DIR=target cargo run --locked \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
CARGO_TARGET_DIR=target cargo test --locked \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
CARGO_TARGET_DIR=target cargo clippy --locked \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml \
  --all-targets -- -D warnings
cargo test --locked --manifest-path examples/composed-baseline/Cargo.toml
```

The [evidence manifest](evidence/18-matched-outcome-ledger/manifest.json)
records the retained run, tests, source hashes and qualification limits.
The export includes the shared inputs, per-gate signed kernel receipts,
physical append files, approved artifacts and 57 read-only receiver database
snapshots. It does not require the temporary databases to inspect the results.

| Final check | Result |
| --- | --- |
| Paired experiment regression | Passed: 28 paired scenarios plus opaque-handle checks |
| Separately retained executable run | Passed: all paired observations match; eight observed SIGKILL exits |
| Original composed-baseline suite | Nine tests passed |
| Comparison and baseline all-target Clippy | Passed with warnings denied |
| Both example workspaces' formatting and diff whitespace | Passed |
| Rebuilt paper, references and derived-macro checks | Passed: 12 pages, 4,823 body words |

The run uses fixed test policies, seeds and logical time, not live model work.
An initial kernel fixture mixed wall-clock capability issuance with that fixed
clock and failed before useful dispatch; the fixture now signs capabilities
under the same logical clock used by both evaluators.

Both gates trust the selected verifier's statement, the protected adapter,
local database and clock. The experiment does not address database rollback,
cloned receiver authority, host power loss, dishonest verifiers, independently
administered remote deployments or general semantic equivalence. The original
treaty predicate and effect-slot APIs have not been merged or released by
this work. This remains a local, uncommitted result with no exact-commit remote
CI qualification.
