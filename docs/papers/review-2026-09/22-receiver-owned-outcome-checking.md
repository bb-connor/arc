# Receiver-owned outcome checking

2026-09-13. Continuing the breakthrough objective after
[the verified source repair](21-verified-source-repair.md). The previous turn
fixed a real defect and tested its source before publication, but publication
still trusted the selected upstream verifier's signature. This turn makes that
assumption executable and adds a receiver configuration that checks the work
itself. The improvement changes the trusted parties for this workload. Both
outcome gates obtain it, and the breakthrough claim remains unproven.

## The counterexample is a valid signature over a false claim

The existing outcome rule selects a verifier key and contract digest. Its
checker authenticates the result and its bindings. It does not independently
execute the contract. The API states that the verifier is trusted for the
truth of its result.

The new
[comparison](../../../examples/outcome-ledger-comparison/src/graph/repair_receiver_check.rs)
signs the original buggy Git-helper source with the actual selected upstream
key, asserting that it passed the contract. Both Chio and the independent
ledger publish that source under the attestation profile. Their receipts are
valid and the published bytes match the bad artifact exactly.

This is an intentional violation of a declared trust assumption. It is not
an invalid signature, a caller-created replacement issuer, a binding mismatch
or evidence of a production authorization bug. It demonstrates why signature
verification alone cannot establish that the required computation happened.
An unsigned valid repair is rejected by this profile before the dishonest
attestation is presented, confirming that the selected signature is required.

## Receiver checking changes that requirement

The new profile is installed through the trusted receiver constructor. It
accepts a raw source artifact and checks its baseline hashes, allowed paths
and size bounds. It then runs the same seven-case behavioral contract from
report 21 before claiming the publication slot. Candidate Python remains
isolated from the trusted checker and its Git repositories.

Only after successful checking does the receiving publisher construct an
outcome under its own key for the existing durable gate. No upstream signature
or verification service is required. Normal kernel capabilities and admission
still apply; an unsigned artifact is not an unauthenticated tool call.

The input cannot select the profile. A signed upstream envelope sent to the
receiver-checking endpoint is rejected as the wrong input shape, and sending
the same buggy source directly reaches the behavioral checker and fails there.
The failed checks leave the logical publication slot waiting and cause zero
publication effects. A valid unsigned repair then passes and publishes once.

After reopening, the publisher rejects a repeat under a fresh capability
before running candidate code again. The final durable claim still rechecks
the gate's state; the early completed-state check does not replace that atomic
claim. The experiment preserves the prior uncertainty semantics rather than
turning a claimed effect into a retryable one.

## What the run observed

[The retained comparison](evidence/22-receiver-owned-outcome-checking/receiver-check-comparison.json)
contains both owner profiles and both gate backends. Observations match between
Chio and the ledger within each profile.

| Property | Upstream attestation | Receiver checking |
| --- | --- | --- |
| Upstream artifact signature | Required | Not required |
| Upstream verifier honesty | Required | Not required |
| Valid signature claiming the buggy source passed | Bad source is published | Cannot bypass local checking |
| Buggy source checked locally | No local check in this profile | Rejected; publication count stays zero |
| Valid unsigned repair | Rejected | Published once |
| Reopened receiver, fresh capability | Repeat rejected | Repeat rejected before candidate re-execution |
| Checker invocations at receiving publisher | Zero | Two per gate: bad source, then valid repair |

There are sixteen signed kernel decision records: three per attestation
backend and five per receiver-checking backend. All signatures and allowed
output hashes are checked during the run. The local checkers execute 28 Git
commit cases in total. The fourteen cases for the original source produce
42 hook markers; the fourteen for the repaired source produce none. Each of
the four profile/backend instances publishes once, but the attestation
counterexamples intentionally publish the buggy source into their isolated
review directories. Those files are never applied to the operator checkout.

These counts are not a cost comparison between honest deployments. The
attestation counterexample deliberately omits honest upstream checking.
Report 21 already exercises that upstream computation. The new result is that
the receiver can perform it instead, accepting source without that separate
signing authority. Its runtime, checker, store, operator and host kernel
remain trusted, and the receiver now pays the checking cost itself.

## Prior art constrains the novelty claim

Proof-carrying authentication and foundational proof-carrying code already
separate an untrusted producer from a locally trusted checker. Princeton's
project description explicitly discusses minimizing the trusted proof checker.
Our finite regression replay is not a foundational proof of program safety.
[Foundational Proof-Carrying Code](https://www.cs.princeton.edu/~appel/fpcc.html).

Prezta, a July 2026 preprint, executes authorization policy in a zkVM and has
the receiving device verify a proof. Its outsourcing discussion explicitly
removes prover honesty under its proof-system assumptions. We read the primary
paper but did not reproduce its compiler, implementation or reported timing
results. Adding proof-carrying policy evaluation alone would not establish our
novelty. [Prezta](https://arxiv.org/html/2607.11466v1).

The February 2026 verifiable-compilation preprint binds source, compiler and
output using a zkVM, and discusses independent rebuilding as the direct
alternative. We have not reproduced its experiments. Compilation provenance
and general source correctness are distinct claims.
[Verifiable Provenance of Software Artifacts](https://arxiv.org/html/2602.11887v1).

RISC Zero documents receipt verification against an expected program image
identifier and public output journal. My inference for Chio is that any such
integration must pin the intended checker and inputs; proving execution of a
program that merely trusts a signature would retain that signature's truth
assumption. This turn installs no zkVM dependencies and makes no zkVM claim.
[RISC Zero receipts](https://dev.risczero.com/api/zkvm/receipts).

## Judgment and next discriminating evidence

This configuration removes a separate upstream verifier from the trusted
parties and availability dependencies for the actual source-repair workload.
It does so by running the established checker at the receiver. The strongest
objection to calling that a breakthrough is that the same configuration works
with the ordinary ledger, and re-execution is an established way to check a
computation. No new primitive or measured system-wide advantage has emerged.

The finite contract remains limited to seven selected commit cases. It does
not prevent test-specific implementations or prove arbitrary code correct.
No aggregate resource quota, seccomp policy, independently administered host,
public anti-equivocation, host power-loss durability or deployment activation
is qualified here. Receiver checking can impose expensive work on admission;
the existing test ingress is not a production service or a denial-of-service
benchmark. The prior graph's crash tests pass separately and are not evidence
for new crash behavior in this source-repair configuration.

A stronger result needs a useful workload where removing that upstream
dependency provides a measured operational advantage, or where independently
checkable evidence reduces receiver cost without introducing an equivalent
trusted party. That comparison must still grant the alternative equivalent
policy, state and checking infrastructure. This result rules out upstream
attestation trust as a necessary property of the experiment, not ordinary
ledger implementations as an alternative.

## Reproduction and validation

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-receiver-check examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
CARGO_TARGET_DIR=target cargo test --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
CARGO_TARGET_DIR=target cargo clippy --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml \
  --all-targets -- -D warnings
```

The Linux sandbox and runtime prerequisites remain in the
[experiment README](../../../examples/outcome-ledger-comparison/README.md).
The optional final argument selects a new output directory. Offline Cargo
requires cached dependencies. The fifth integration test repeats both profiles;
the other four retain the prior graph, source-repair and local-gate coverage.
The evidence manifest records final test and Clippy results, raw receipts,
checker observations, source artifacts, owner contracts and store snapshots.
All five integration tests, all-target Clippy, formatting and diff checks pass.
The whitepaper build passes at 12 pages and 4,962 body words.

The production Python repair is unchanged in this continuation. No production
runtime implementation, dependency manifest or lockfile changed. The work
remains local and uncommitted on `paper/roadmap-phase-0-1`, based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`, without exact-commit remote CI,
release qualification or an achieved-breakthrough claim.
