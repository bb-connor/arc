# Recoverable market agreements over the A2A connection

The next implementation slice connects the production A2A adapter and
kernel-backed edge to existing signed market artifacts. A buyer and provider
negotiate a bounded security-review job, retain their own journals and recover
its accepted agreement after a provider process is killed before replying.

The experiment is `examples/federated-work`. It uses fresh participant keys,
separate Linux mount namespaces, loopback HTTP, production SQLite authority and
receipt stores, and an explicitly selected buyer-local credit promise. It does
not execute the proposed security review or settle a purchase. This advances
items 2 and 3 of report 27 within one host, and exercises two acceptance failure
boundaries from item 4. Independent administration and the complete workflow
remain unqualified.

## Production change

`chio-open-market::bidding::verify_acceptance` verifies a received accepted bid
under caller-selected buyer and provider keys without requiring the buyer's
private key. It shares the existing `accept` validation path: signed offer,
token issuer and signature, historical acceptance window, token subject,
reservation authority witness, complete liability, and exact accepted-body
bindings. Reconstructing the expected body rejects semantic substitutions even
when the real buyer signs the changed body.

The caller still selects the reservation authority before constructing the
verified witness. The helper does not validate the original job profile, reserve
money, prove current funds, authorize execution or settle. The example supplies
the additional original-bid and agreement checks. No workspace member manifest
or signed market schema was changed.

## What the example binds

The buyer signs a production `SignedBidRequest`. Its capability-scope prefix
includes the canonical digest of an agreement naming both pinned participants,
job id, input digest, checker, absolute deadline, price ceiling, no subcontracting
and the selected credit profile. The provider validates these fields against its
own configuration and signs a production `SignedAskResponse`.

The offer contains one provider-issued, buyer-bound `review` grant, one permitted
invocation, 100 TST maximum liability and required DPoP. The buyer rejects extra
grants, altered operations, weakened sender binding, changed costs and changed
job references. The provider narrows the generic market's relative token and
offer window to the buyer's signed absolute deadline without rewriting the bid.

The buyer atomically records a 100-unit local hold, signed reservation and
`SignedAcceptedBid`. The provider persists the exact signed acceptance once and
signs an acknowledgement of its retained state. This is a negotiated proposed
capability: `review` is not registered as an executable tool in this slice.
Agreement-specific input and checker enforcement at actual dispatch remains
required work.

The provider's kernel activates only its own issuer key. Negotiation requests
use a provider-issued bearer capability. Received bids and acceptances are
evidence checked against the configured buyer pin; their embedded keys do not
activate additional capability issuers. The host profile is loopback HTTP, not
production transport authentication or DPoP qualification.

## Measured execution

The local harness runs three complete scenarios. Each participant process has
only its own state mounted; keys and configuration are mounted read-only after
initialization. Tests confirm own-key readability and peer-key non-readability.
The trusted host launcher still controls every process and mount. These are
filesystem isolation measurements within one administrative domain.

| Scenario | Provider acceptance records | Buyer reservation | Result |
| --- | ---: | --- | --- |
| Normal acceptance, buyer restart, four concurrent duplicate requests | 1 | One hold, 100 reserved, 900 available | Same signed agreement retained |
| Provider SIGKILL after acceptance commit and before reply, provider/buyer restart | 1 | Same hold and balances | Recovered through `status`; interrupted kernel operation remains unknown |
| Buyer SIGKILL after durable send intent and before transmission | 0 | Hold retained, 100 reserved, 900 available | Provider remains `quoted`; buyer remains pending for reconciliation |

Both process-kill commands actually terminate the targeted sandbox process;
the launcher returns 137. Fault injection is a local CLI option, never a field
accepted from an RPC request. This tests process death, not power-loss durability.

In the provider-kill scenario, the restarted production authority store marks
the interrupted operation `outcome_unknown_after_dispatch`. The buyer obtains
a newly signed application status; neither side fabricates a successful terminal
receipt for the interrupted call. The original operation is not replayed.
The buyer-kill scenario confirms that a missing acceptance does not automatically
release the reservation or authorize another acceptance send.

Each completed-agreement scenario also sends four adversarial HTTP requests:
changed accepted price, changed reservation id, a freshly signed conflicting
input under the same job id, and a freshly signed subcontracting request denied
by the provider's configured profile. All return failed tasks and leave one
acceptance record. The four failed business calls are retained at
`dispatch_committed` in that running kernel's store. This example does not claim
their generic terminal recovery has been completed.

A third process receives only public artifacts and separately selected peer
pins. It verifies the exact acceptance, provider acknowledgement, and eleven
signed kernel receipt records in each completed-agreement scenario. It checks
request parameters and tool names, signed allow/failure consistency, and signed
business outputs. Altered settlement assertions, contradictory task status and
a substituted provider pin are rejected. It uses the same implementation as the
participants; it does not establish independent implementation interoperability.
Unsigned balances, process observations and mount tests remain harness evidence.

## Economic and protocol limits

The agreement explicitly selects `buyer-local-credit-promise-v1`. The buyer is
the reservation authority and begins with 1,000 synthetic units. The provider
trusts that promise. A malicious buyer with its key and database can misstate its
credit position; no external escrow or settlement service prevents that here.
Every job summary reports `workExecuted: false` and `settled: false`.

This does not transfer source data, run a security checker, authorize an actual
subcontract, release funds, deliver a finding or settle payment. Nor does it
qualify TLS, credential renewal, revocation propagation, denial of service,
database rollback attacks, arbitrary malicious processes, separate host
administrators or geographic restrictions. The bounded host and unsigned A2A
card are experimental. Task ids are ephemeral; recovery uses the durable job
binding and signed artifacts.

The repository already contains payment-channel lifecycle stores in
`chio-settle` and `chio-store-sqlite`, in addition to the single-operator finding
purchase coordinator. Selecting and qualifying an appropriate existing rail is
the next economic integration task. This experiment does not infer the state of
those implementations from historical milestone notes or substitute a new
local credit table for their settlement guarantees.

## Validation and next acceptance condition

The local `chio-open-market` library suite passes all 46 tests. Its new acceptance
test rejects 13 buyer-signed body substitutions, wrong participant pins, a forged
signer, signature damage and a substituted reservation. The example unit test
rejects 13 widened offers with valid provider and token signatures. The process
harness passes the three scenarios above. Clippy runs with warnings denied;
formatting, whitespace and the paper build are checked separately.

The paper now explicitly distinguishes signed agreement/reservation evidence
from completed work and guaranteed funds. It builds at 12 pages and 4,999 body
words. Commands, retained public transcripts, logs and source hashes are indexed
in [the evidence manifest](evidence/28-recoverable-market-agreements/manifest.json).
The work is uncommitted on the checkout based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`; it has no exact-commit remote CI or
release qualification.

The next acceptance condition is one executed security review: enforce the
accepted input and checker at provider dispatch, publish a signed deliverable,
have the buyer independently check it, and bind the accepted result to the
selected existing settlement rail. Then repeat fault injection at dispatch,
delivery and payment before making an independent deployment claim.

The breakthrough judgment remains negative. The strongest objection to this
direction is that it may be a useful packaging of known integration patterns.
What would change that judgment is independent organizations and different
implementations completing useful work with materially less partner-specific
security and recovery code while retaining their own authority.
