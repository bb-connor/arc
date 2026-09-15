# Federated work: agree, execute, verify and account

Buyer and provider negotiate an exact job using production Chio bid, ask,
reservation and acceptance artifacts over the production A2A adapter and edge.
The paid profile executes a bounded OpenAPI authentication review through the
kernel, records a local-credit charge, publishes a signed finding and lets the
buyer independently recompute the result and verify its receipt inclusion proof.
A rejected review produces a signed zero-charge terminal and restores the buyer's
reservation after verification.

The Python buyer also retains a [verifiable unresolved incident](INCIDENTS.md)
after a provider crash that leaves no durable tool return. Its reservation stays
held, and both Python and Rust can verify the native incident projection.

This is an experimental one-host implementation. The selected ledger records
synthetic TST credits. No cash, cryptocurrency or other external funds move.

```sh
CARGO_TARGET_DIR=target cargo build --locked --offline \
  --manifest-path examples/federated-work/Cargo.toml
python3 examples/federated-work/paid_smoke.py
```

The harness requires Linux, `/usr/bin/bwrap` and enabled unprivileged user
namespaces. It fails if the sandbox cannot start. Each role receives its own
state directory, executable, libraries and private temporary storage. Existing
keys and configuration are mounted read-only. Peers' state directories are
absent. Networking shares the host loopback interface, and the client accepts
only `http://127.0.0.1:PORT`. This is not a hostile-network or independent-host
deployment. The provider's native review tool and kernel share a trusted
process; this does not qualify isolation of arbitrary untrusted tool code.

## Two explicit agreement profiles

| Profile | Meaning |
| --- | --- |
| `chio.example.security-review-agreement.v1` | Negotiation only; selects `buyer-local-credit-promise-v1`. No review or payment is executed. |
| `chio.example.security-review-agreement.v3` | Authorizes disclosure of the exact digest-bound input to the configured provider, the named checker, and `provider-local-credit-checked-or-zero-v1`. A successful output check permits local capture; a rejected check requires zero charge and hold release. |
| `chio.example.security-review-agreement.v4` | Adds one explicitly selected specialist and delegated agent, an exact authentication-only disclosure, and a receiver-enforced 100 TST procurement permit. Both work deliveries remain independently verifiable. |

The earlier v2 experiment is retained in report 29's source snapshot. It is not
accepted by this executable. Use fresh scenario state; no in-place migration of
old agreements or unresolved holds is provided.

Both supported profiles bind the participant pins, job id, source-byte digest, checker, absolute
deadline, price ceiling and no-subcontracting rule. The buyer reserves 100 of
its 1,000 local test units. The provider retains the exact agreement and caps
accepted jobs at ten, limiting this example's total accepted credit exposure
to 1,000 units. There is no automatic renewal or external repayment path.

The provider issues the one-call work capability with 100 TST maximum cost and
required Chio proof of possession. The existing adapter carries the proof in a
sensitive `Chio-Sender-Proof` header. This is Chio's action-bound signed proof,
not an RFC 9449 JWT. The host configures its nonce store; durable invocation
and monetary budgets enforce the one-call ceiling across restarts. The nonce
cache itself is in memory. Negotiation and delivery use a separate bearer
capability that cannot invoke `review`.

The native guard verifies the exact retained acceptance, capability and input
digest, including immediate dispatch revalidation. It recomputes and checks
the tool output before release and payment. It explicitly opts into the kernel's
`Guard::output_rejection_is_zero_charge` pricing contract. The kernel retains the
raw return, resolves the checker denial durably, releases the reversible hold
and projects a signed `DeniedAfterDelivery` receipt. A receipt-visible redaction
binding withholds the rejected report and its actual content digest. The provider uses the existing
`SqliteFindingOperatorPaymentAdapter`, `SqliteAuthorityStore`,
`SqliteReceiptStore` and `DurableAdmissionMode::All`.

The buyer recomputes the same specified check, verifies a production
`chio.finding.v1`, the signed paid kernel receipt, its checkpoint and Merkle
inclusion proof, and records one local expense. This verification occurs after
provider-local capture. The agreement explicitly trusts that selected ledger;
buyer verification is not an escrow release condition or an independent
confirmation of external funds. A malicious provider controlling its signing
key and database can misstate its ledger. The buyer's recomputation can still
reject an incorrect review result.

## The check and its limits

The input is a self-contained OpenAPI 3.1.0 JSON document, at most 64 KiB,
with 1..256 inline paths, path names at most 256 bytes, and 1..512 operations.
The checker inventories whether each operation declares required authentication.
It handles inherited security, operation overrides, empty requirements and
anonymous alternatives. It accepts inline HTTP and API-key security schemes.
Duplicate JSON keys, unsupported versions, referenced security schemes or path
items, unknown scheme references, callbacks and webhooks reject.

These rules follow the [OpenAPI 3.1.0 security definitions](https://spec.openapis.org/oas/v3.1.0.html#security-requirement-object).
The checker does not call an API, fetch references, execute supplied code or
establish deployed authorization behavior. Its report is a declaration inventory,
not a comprehensive vulnerability assessment. The fixture includes a refund
operation with no required authentication and an explicitly anonymous health
operation, alongside two authenticated operations.

The finding's deterministic replay recipe binds the checker name and input
digest. Its receipt commits the production reveal envelope. Its `unbacked:`
bond and `local-job:` status references are explicitly non-admitted profile
references: no collateral, authenticated market status feed or market
publication is claimed. Receipt inclusion proves membership in the pinned
provider's local checkpoint, not public transparency or non-equivocation.

## Failure experiments

The paid harness exercises normal completion and three completed recovery cases:
provider SIGKILL after capture but before its acknowledgement reaches the
kernel; provider SIGKILL after terminal settlement but before replying to the
buyer; and buyer SIGKILL after checking delivery but before recording its
expense. Every completed case retains one review, one capture and one expense.
Another invocation with the same work capability is denied.

A provider kill after writing its review result but before the kernel records
the return leaves one hold and an uncertain outcome. Recovery does not replay
the review or release the hold. This uncertain case still needs authorized
adjudication; a timeout is not evidence that no effect occurred.

An injected, provider-signed incorrect report is rejected by the agreed checker.
Its hold is released, capture is zero, and the buyer verifies the signed denial
and its inclusion proof before restoring its reservation. The rejected report
is absent from the public package. Provider kills after rail release and after
terminal denial, plus buyer death before recording the restored reservation,
recover to one review, one released hold, zero expenses and one restored
reservation. Repeated retrieval cannot restore credit again or invoke more work.
Concurrent recovery fixes one terminal per job. Conflicting terminals and reuse
of a terminal receipt id by another job fail before changing the account.

Ordinary security guards do not receive refund authority from this API. The
zero-charge contract is an explicit trusted configuration. The kernel rejects
non-reversible rails and combinations with digest, Finding purchase or recovery
contracts before admission; those combinations are not qualified here.

Missing proof of possession and changed disclosed input are denied before
review execution or capture. A separate verifier with only public artifacts
and configured peer pins rejects changed input, report, finding, receipt and
inclusion coordinates. The original harness uses Rust for all roles. The
[Python participant](python_buyer/README.md) separately implements the buyer,
verifier and journal and runs the same provider fault scenarios. Its namespaces
contain no Chio executable or library. Both implementations still share
one project author, operator and host.

The [HTTPS enrollment interface](HTTPS.md) supports separately provisioned
participants, provider-signed public enrollment, locally activated TLS roots
and sender-constrained negotiation credentials. Its complete recovery suite
still runs on one host; independent company operation remains unmeasured.

The earlier negotiation-only recovery suite remains runnable:

```sh
python3 examples/federated-work/smoke.py
```

It covers provider death after acceptance commit, buyer death before sending
acceptance, concurrent duplicate acceptances and changed terms. Job ids and
exact signed artifacts are durable recovery keys; A2A task ids remain ephemeral.

## Evidence

The harness prints its output directory. Keep complete role directories private:
they contain signing seeds and a negotiation bearer credential. Selected
`public.json`, `verification.json` and `summary.json` artifacts omit those
credentials. Public paid-work artifacts include the full review input; the
included fixture is public test data. Do not publish real company inputs merely
because an artifact is cryptographically verifiable.

```sh
target/debug/chio-federated-work verify-work PEERS_JSON PUBLIC_JSON
target/debug/chio-federated-work verify-agreement PEERS_JSON NEGOTIATION_JSON
CARGO_TARGET_DIR=target cargo test --locked --offline \
  --manifest-path examples/federated-work/Cargo.toml
CARGO_TARGET_DIR=target cargo clippy --locked --offline \
  --manifest-path examples/federated-work/Cargo.toml --all-targets -- -D warnings
```

The verifier establishes signed bindings and the agreed deterministic result.
Unsigned harness observations, balances and process-isolation measurements
remain separate evidence. Neither this example nor its test counts establish
a breakthrough, external settlement, cross-border compliance or independent
administration.

The [mutual release protocol](RESOLUTION.md) resolves a retained unknown hold through separate consent, native rail recovery and independently verified buyer accounting.

The [three-party subcontract profile](SUBCONTRACT.md) adds bounded disclosure,
separate agent and kernel keys, an isolated procurement worker, receiver-side
spending enforcement and recovery of the child's separate account.

The experimental [checkpoint operator handoff](../../docs/market/open-agent-work/execution/27-checkpoint-operator-handoff.md)
exports a funded native execution receipt to a separately enrolled signer and
imports its verified checkpoint bundle. It includes actual payout/refund process
reproductions and Python public-witness verification. The fixture remains under
one local administrator with one allocation per checkpoint log.
