# A second implementation of the checked-work participant

The Python buyer now negotiates, purchases, verifies and recovers checked work
from the existing Rust provider over A2A. It owns its identity, signatures,
HTTP requests, artifact checks and SQLite accounting. It does not load a Chio
library or invoke the Rust buyer or verifier. The same public work package also
passes the separate Rust verifier.

This is a concrete step toward the selected goal: a protocol companies' agents
can use to agree on work and evidence while retaining their own authority.
It does not establish a breakthrough. Both implementations were written within
this project and run under one operator on one host. The strongest objection
remains the amount of application-specific agreement and recovery code. A
second implementation working with the first is useful protocol evidence, but
it does not show a new mechanism or an advantage over an equally provisioned
alternative. Independent operators using the contract for useful work with less
bespoke integration would change that judgment more than additional local tests.

## What changed

The new [Python participant](../../../examples/federated-work/python_buyer/README.md)
implements the version 3 checked-or-zero agreement directly as JSON objects.
Its public wire document records transport routing, required bindings, signing
preimages, deterministic checking and durable state transitions. The implementation
uses the existing native market bid, ask, reservation and acceptance schemas;
it does not create a replacement market or currency.

The Python process generates its signing seed privately. It signs the bid,
reservation, acceptance and proof of possession itself. Agent discovery cannot
change the configured provider pin or forward credentials to another origin.
Paid work requires the provider's one-call capability, with exact tool, operation,
price, total liability and proof-of-possession requirement. Signed but wider
offers reject before reservation.

The buyer verifies the returned A2A task against the signed kernel decision and
the actual artifact digest. It independently recomputes the review inventory
and verifies report, native Finding, receipt id and signature, financial and
terminal evidence, checkpoint signature, and Merkle inclusion. The native
receipt signing preimage is `{id,body}`, not the flat serialized receipt with
its signature omitted. The Finding has a different content-address and signing
preimage, which is documented explicitly.

The new journal makes the buyer's own decisions durable. It retains the exact
terms, reserves once, and records an attempted send before acceptance or work.
An uncertain acceptance uses `status`; uncertain work uses `delivery`. Neither
path repeats the effect or treats timeout as proof of absence. A verified terminal
and the corresponding expense or restored reservation commit together, with one
receipt id across all jobs. A conflicting retained terminal fails before account
mutation. Concurrent recovery records one expense or one restoration.

There are no new production Rust changes in this phase. The provider continues
to exercise the market, kernel, reversible local payment and checked-rejection
recovery implemented in the preceding phases.

## Interoperability and failure evidence

The process harness passes all 16 scenarios with a Python buyer and Rust provider:

| Scenarios | Observed result |
| --- | --- |
| Normal work; provider death after capture; provider death after settlement; buyer death after checking | One review, one captured local payment and one expense per job |
| Incorrect signed report; provider death after release; provider death after signed denial; buyer death after checking rejection | One review, one released hold, zero expenses and one restored reservation |
| Provider death after review write, before durable kernel return capture | One review and a retained hold; no replay, capture or expense |
| Missing sender proof and changed disclosed input | Both deny before review or capture |
| Two distinct jobs | Two reviews, two captures, two expenses; 800 available and zero reserved |
| Provider death after agreement acceptance | One acceptance event; status recovery followed by one completed paid job |
| Buyer death before acceptance send; buyer death before work send | Zero reviews and expenses, with 100 reserved; repeated recovery does not infer permission to resend |
| Unicode request keys and input paths | Python verifies the native signature across UTF-16 key ordering; both verifiers accept the completed review |
| Four concurrent expense recoveries after buyer death | One review, capture and expense; all four buyers return the same result |

The rejection recovery scenario also runs four simultaneous Python buyers and
checks one restored reservation. The completed successful and rejected cases
try another paid invocation with the consumed capability and verify that no
review or payment repeats. The public verifier rejects substituted input,
report, Finding, receipt, agreement, charge and inclusion coordinates.

Buyer, provider and public verifier run in separate Linux mount namespaces.
The buyer cannot read the provider's seed and vice versa. The Python buyer
and verifier mounts contain no Chio executable or library. Their cryptographic
dependency contains native code; this is independence from the Chio application
implementation, not a pure-Python implementation of cryptographic primitives.
The shared launcher provisions both peers, has access to their private state,
and separately invokes the Rust verifier. It is part of the experiment's trusted
administrative boundary, not a third company or independent implementer.

## Validation and reproducibility

Ten Python unit tests pass. They exercise native successful and rejected public
artifacts, externally configured pins, substitution failures, validly signed
offer widening, receipt preimages and semantics, strict JSON and numeric forms,
Unicode canonicalization, Merkle inclusion at every position across six tree
sizes, declaration checking, transactional accounting conflicts, and forbidden
transport targets. The existing process fault suite is reused with the participant
implementation changed; additional cases test agreement recovery, unsent work,
Unicode and concurrent expenses.

The clean Python environment was installed using required hashes from the
retained dependency lock file. The tested versions are Python 3.12.3,
cryptography 50.0.1, rfc8785 0.1.4, cffi 2.1.1 and pycparser 3.0 on Linux aarch64.
Version selection and installation are recorded in the evidence. Ed25519 and
canonical JSON use maintained implementations of those primitives, rather than
new cryptographic code. See the
[Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)
and [canonical JSON package](https://pypi.org/project/rfc8785/).
The transport uses the A2A 1.0 `returnImmediately` configuration and JSON-RPC
binding described in the [A2A specification](https://a2a-protocol.org/latest/specification/).

The paper still builds within its limits: 12 pages and 4,995 body words. Its
opening now distinguishes Python-Rust interoperability from independent
operation and novelty. Whitespace and no-em-dash checks pass. The prior phase's
native Rust qualification is retained as historical evidence; it was not rerun
or relabeled as a new kernel test run.

The [evidence manifest](evidence/31-python-rust-work-interoperability/manifest.json)
binds this phase's public artifacts, implementation snapshot, dependency lock,
logs and source inventory. It records the prior source comparison and binary
hash without claiming a reproducible build. Export checks exclude both seeds
and the negotiation bearer credential. The disclosed inputs are public test
fixtures. Local balance summaries and process measurements remain unsigned
experiment observations, separate from the signed delivery evidence.

## Remaining boundary

The provider-local test ledger is explicitly trusted by the agreement. It
captures a successful result before the buyer independently verifies it. A
malicious provider with its signing key and database can misstate settlement;
the buyer's recomputation still rejects an incorrect report. Neither proof of
inclusion nor a Finding signature proves real funds, collateral, honest private
state or public non-equivocation.

The checker only inventories authentication declarations in a bounded OpenAPI
document. It does not run an API or establish deployed security. Uncertain
post-dispatch work still needs an authorized resolution protocol. These tests
cover process death, not power loss, hostile storage rollback or an adversarial
wide-area network.

The next useful boundary is an independently operated participant, confidential
authenticated transport, a deliberately chosen settlement authority and a
non-fixture job. Generalizing agreement and recovery across that boundary is
closer to the user's goal than inventing another isolated local mechanism.

This work is local and uncommitted on the tree based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. It is not remote CI qualification,
a release, public market activation, independent adoption or an achieved
breakthrough.
