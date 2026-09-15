# Recoverable work agreements between agents

This experimental example carries existing Chio signed bids, offers,
reservations and acceptances through the production A2A adapter and
kernel-backed edge. Buyer and provider run as separate Linux processes with
their own keys, journals and configured peer pins. A provider acknowledgement
binds the exact accepted agreement.

The selected job is a bounded OpenAPI security review. This slice negotiates
that job. It does not transfer the OpenAPI input, execute the review, check a
deliverable or settle payment. Its proposed `review` capability is not exposed
as an executable tool here. Future execution must enforce the agreement's input
and checker bindings at dispatch, as well as live authority and consumption.

## Run

From the repository root:

```sh
CARGO_TARGET_DIR=target cargo build --locked --offline \
  --manifest-path examples/federated-work/Cargo.toml
python3 examples/federated-work/smoke.py
```

The harness requires Linux, `/usr/bin/bwrap` and enabled unprivileged user
namespaces. It fails if the sandbox cannot start. Each role receives its own
state directory, the executable, shared libraries and private temporary storage.
Existing keys and configuration are mounted read-only. Peer state directories
are absent; the harness verifies each role can open its own key and cannot open
the peer's key. The verifier receives only public artifacts and peer pins.

Network access shares the host's loopback interface. The client accepts only
`http://127.0.0.1:PORT`, using a provider-issued bearer capability for negotiation.
Signed buyer artifacts additionally bind the business operations. This is not
TLS, DPoP transport qualification, hostile-network isolation, independent host
administration or cross-border deployment. The same trusted launcher configures
both parties, and all roles use this Rust implementation.

## What recovery does

The buyer freezes a signed request before sending it. The provider stores one
offer per job and rejects different terms under that job id. The buyer verifies
the offer against its configured provider and exact job profile before atomically
retaining acceptance and one local reservation. It records `attempted` before
transmitting acceptance. The provider commits the exact acceptance once before
returning its signed acknowledgement.

The harness runs three scenarios:

- Normal acceptance, buyer restart, and four concurrent duplicate acceptance
  requests retain one provider acceptance and one buyer reservation.
- Provider SIGKILL after committing acceptance but before replying. A replacement
  provider uses its existing SQLite authority and application stores. A restarted
  buyer asks `status`, verifies the recorded agreement and retains the same
  reservation. The interrupted kernel operation remains uncertain.
- Buyer SIGKILL after recording send intent but before transmitting it. On
  restart, the provider reports `quoted`. The buyer preserves its pending state
  and reservation for reconciliation. It does not send another acceptance or
  infer that credits can be released.

Both completed-agreement scenarios reject altered acceptance and reservation
fields, a newly signed conflicting input under the same job id, and a newly
signed request permitting subcontracting contrary to the provider's profile.
The public verifier rejects an altered settlement assertion, a task status
contradicting its signed decision, and a mismatched provider pin. Unit tests also
reject widened offers signed by the actual provider.

The provider uses `SqliteAuthorityStore`, `SqliteReceiptStore` and
`DurableAdmissionMode::All`. Its business journal uses SQLite transactions with
WAL and `synchronous=FULL`. Failed business calls can leave kernel operations
at `dispatch_committed`; restart conservatively classifies such calls as unknown.
Application status reconciliation does not fabricate a successful kernel
terminal receipt for the interrupted invocation. A2A task ids remain ephemeral;
the durable business job and exact signed artifacts are the recovery keys.

## Explicit credit assumption

The signed agreement selects `buyer-local-credit-promise-v1`. The buyer starts
with 1,000 synthetic TST units, reserves 100 and retains 900 available. Its own
key signs the reservation. The provider therefore trusts the buyer's promise;
the signature proves neither independent funds availability nor escrow. No
credits are transferred or spent. Job summaries explicitly report
`workExecuted: false` and `settled: false`.

The production `verify_acceptance` helper verifies the received signature and
exact offer/reservation bindings without accessing the buyer's private key.
This example additionally checks the original bid, participant pins, job digest,
price, absolute deadline, checker, one-call scope, DPoP requirement and
subcontracting rule. Application profile names are experimental, not registered
normative protocol schemas.

## Evidence and verification

The harness prints its output directory. Keep that directory private: role
states contain signing seeds and a bearer credential. The selected
`normal/public.json`, `acceptance-sigkill/public.json`, scenario verification
outputs and `summary.json` omit private keys and the bearer token.

For offline verification, supply peer pins from your trusted configuration:

```sh
target/debug/chio-federated-work verify-agreement PEERS_JSON PUBLIC_JSON
```

This verifies signed agreements, acknowledgements and receipt records. It does
not prove unsigned harness observations such as filesystem isolation, process
death or the buyer's balance. The verifier uses the same implementation as the
participants; it is not an independent implementation interoperability test.

```sh
CARGO_TARGET_DIR=target cargo test --locked --offline \
  --manifest-path examples/federated-work/Cargo.toml
CARGO_TARGET_DIR=target cargo clippy --locked --offline \
  --manifest-path examples/federated-work/Cargo.toml --all-targets -- -D warnings
cargo test --locked --offline -p chio-open-market --lib
```
