# Hole 10 Remediation Memo: Economic Authorization and Payment Binding

Date: 2026-04-13
Owner: Economic-authorization and payment-binding gap

## Problem

ARC currently speaks as if one object does four jobs at once:

- capability token
- spending authorization
- settlement record
- liability-ready evidence package

The shipped system does not yet make those four statements true.

Today the runtime does have useful economic-control primitives:

- a signed capability can carry monetary ceilings
- the kernel can pre-debit a local budget before dispatch
- governed intent can carry seller and quote context
- an optional payment adapter can perform one external authorization hop
- signed receipts can record financial metadata
- trust-control can store mutable reconciliation sidecars

That is meaningful control-plane infrastructure. It is not yet enough to justify
the strongest claims in `README.md` and `docs/AGENT_ECONOMY.md`, especially:

- "a capability token is simultaneously a permission grant and a spending authorization"
- "the delegation chain is the same structure that tracks cost responsibility"
- "the receipt log is already a pre-audited billing ledger"
- broader liability-adjacent language implying the protocol itself establishes
  merchant binding, payer binding, settlement truth, or responsible-party truth

To make those claims actually true, ARC needs a stricter end-state:

- explicit economic parties and settlement rails in the authorization object
- cryptographic binding from approval to merchant, payee, payer account, asset,
  settlement mode, and quote or tariff
- verifiable ex ante hold or prepayment before execution when strong payment
  claims are made
- verifiable post-execution metering that is not just tool self-report
- truthful receipt semantics that never collapse local budget truth, rail truth,
  and legal or liability truth into one field

Without that, ARC should describe itself as a governed execution and evidence
layer that can integrate with payment rails, not as a completed payment or
liability substrate.

## Current Evidence

The repo already ships several useful building blocks.

### 1. Capability-side monetary ceilings exist

- `CapabilityToken` binds issuer, subject, scope, and time in
  `crates/arc-core-types/src/capability.rs`.
- `ToolGrant` already includes `max_cost_per_invocation` and
  `max_total_cost`.
- `ToolGrant::is_subset_of` already requires child cost caps to stay within
  parent caps.

This is real budget control. It is not yet full payment authorization.

### 2. Governed intent already carries some economic context

`GovernedTransactionIntent` in `crates/arc-core-types/src/capability.rs`
already supports:

- `max_amount`
- `commerce { seller, shared_payment_token_id }`
- `metered_billing { settlement_mode, quote, max_billed_units }`
- approval-token binding through `binding_hash()`

This is useful because the economic context can already be hashed and attached
to request approval. The current surface is still incomplete:

- there is no canonical payer-account binding
- there is no canonical payee settlement-destination binding
- there is no canonical merchant-of-record or beneficiary-of-funds binding
- there is no canonical rail or asset binding beyond loose currency fields

### 3. The kernel already performs one external authorization hop

`authorize_payment_if_needed` in `crates/arc-kernel/src/lib.rs` forwards a
`PaymentAuthorizeRequest` when a payment adapter is configured.

The current payment request shape in `crates/arc-kernel/src/payment.rs`
includes:

- `amount_units`
- `currency`
- `payer`
- `payee`
- `reference`
- optional governed context
- optional commerce context

That is good scaffolding. The current binding is still too weak:

- `payer` is just `request.agent_id`
- `payee` is just `request.server_id`
- there is no explicit payer account or custody source
- there is no explicit merchant settlement destination
- there is no cryptographic requirement that the rail authorization returned is
  bound to the same seller, merchant, quote, or governed intent hash

### 4. The repo already distinguishes quote truth, receipt truth, and mutable reconciliation truth

`docs/TOOL_PRICING_GUIDE.md` correctly says manifest pricing is advisory and
not the enforcement boundary.

`docs/ECONOMIC_INTEROP_GUIDE.md` correctly separates:

- signed receipt truth
- mutable economic-evidence truth
- derived authorization-context truth

`spec/PROTOCOL.md` also states that quoted cost, actual charge, and external
usage evidence are kept distinct.

This is the right philosophical direction. The strongest marketing language
still collapses these layers anyway.

### 5. The runtime already stores settlement status and payment references

`FinancialReceiptMetadata` in `crates/arc-core-types/src/receipt.rs` includes:

- `payment_reference`
- `settlement_status`
- `cost_breakdown`
- `oracle_evidence`
- `attempted_cost`

That is useful accounting metadata. The same type also admits an important
limitation in its own documentation: its invariants are not enforced by the
type system.

### 6. Payment-interop and web3 layers already exist as bounded adapters

The repo already contains:

- `docs/standards/ARC_PAYMENT_INTEROP_PROFILE.md`
- `crates/arc-kernel/src/payment.rs`
- `crates/arc-web3/src/lib.rs`

These surfaces already frame themselves more honestly as interoperability or
dispatch overlays rather than universal financial truth. That bounded posture
is much closer to the claim boundary the repo should use until the stronger
end-state exists.

## Why Claims Overreach

### 1. A budget cap is not the same thing as payment authority

`max_cost_per_invocation` and `max_total_cost` only answer:

- how much local spend ARC is willing to permit

They do not answer:

- which payer account is funding the action
- which merchant or beneficiary is allowed to receive funds
- which rail is authorized
- which asset or token is authorized
- which custody provider or settlement source is on the hook
- whether the authorization is revocable, capturable, or already final

That means the current capability token is a governed budgeted permission, not
yet a full spending authorization instrument.

### 2. Current payer and payee binding are semantically wrong for strong claims

In `authorize_payment_if_needed`, ARC sends:

- `payer = request.agent_id`
- `payee = request.server_id`

That is not strong economic identity.

For many real transactions:

- the payer is not the agent key but an enterprise wallet, card, treasury
  account, escrow, or prepaid balance
- the payee is not the tool server but a merchant, marketplace seller,
  service provider, or settlement contract
- the tool host may be different from the merchant of record
- the party receiving funds may differ from the party performing the tool call

As long as the runtime binds money to `agent_id` and `server_id`, the strongest
payment-authority claims remain false.

### 3. Merchant binding is partial and advisory, not end-to-end enforced

ARC already supports seller-scoped approval through:

- `GovernedCommerceContext { seller, shared_payment_token_id }`
- `Constraint::SellerExact`

That is good, but still incomplete:

- seller is a free-form identifier, not a canonical merchant identity profile
- there is no required mapping from `seller` to the rail-side payee or
  settlement account
- there is no proof that the payment adapter actually authorized the same
  merchant that the approval token covered
- there is no settlement receipt schema that requires merchant equality across
  approval, authorization, capture, and final settlement

This is approval context, not yet merchant-bound payment execution.

### 4. Ex ante approval is still mostly based on a provisional estimate

The kernel pre-debits the worst-case `max_cost_per_invocation` before tool
execution in `crates/arc-kernel/src/lib.rs`.

That gives ARC a local hard stop on its own budget store. It does not prove
that:

- the rail has actually held or transferred funds
- the authorized amount is the real economic amount
- the merchant is locked
- the capture cannot exceed the user-approved envelope

For metered tools, the actual cost can arrive only after execution through
`ToolInvocationCost`, which is defined in `crates/arc-kernel/src/runtime.rs`
as a tool-server-reported structure. That makes the current model one of:

- ex ante local budget control
- optional rail preauthorization
- ex post tool-reported reconciliation

That is not the same thing as "the capability token itself is spending
authorization."

### 5. Metering is not verifiable enough for strong billing claims

`ToolInvocationCost` is tool self-report, with optional breakdown.

That is insufficient for strong economic semantics because the party benefiting
from higher or lower reported usage may be:

- the tool server
- the operator
- the downstream merchant

Without an independent meter, signed usage receipt, or rail-backed observable
quantity, ARC cannot honestly claim:

- the recorded amount is the true billable amount
- the approved quote and actual billed usage were faithfully connected
- the billing ledger is already pre-audited in a strong external sense

### 6. Receipt settlement semantics overstate what happened

Today, if no payment adapter is configured, the kernel can still produce
`ReceiptSettlement::settled()` in the post-execution path in
`crates/arc-kernel/src/lib.rs`.

That is a claim-discipline problem. "Settled" should mean an external
settlement rail or prepaid balance actually reached a final or policy-declared
terminal state. It should not mean:

- "ARC finished the tool call"
- "ARC charged its internal budget"
- "no rail applied, so we marked it settled anyway"

As long as those are conflated, the receipt cannot be described as a truthful
billing ledger in the strong sense.

### 7. Liability-adjacent claims require more than signed local metadata

A useful evidence package for liability-adjacent review must say, at minimum:

- who approved the act
- who funded it
- who received funds
- who hosted the tool
- who was merchant of record
- who held custody
- what settlement rail and asset were used
- what contract, bond, policy, or indemnity envelope governed the act
- what dispute or reversal path applied

ARC today can encode fragments of that picture across governed intent,
financial receipt metadata, web3 dispatch artifacts, and sidecar records. It
does not yet produce one strongly bound package with contractual or rail-backed
truth for all of those roles.

That means ARC can reasonably claim "liability-relevant evidence" or
"liability-ready instrumentation" only after it grows a much stricter economic
truth model.

## Target End-State

The target should not be one vague economic claim. It should be four explicit
truth classes with strict upgrade rules.

### Truth Class A: Budget Authorization

ARC proves:

- a trusted ARC authority allowed a governed action up to a local spending cap
- the kernel enforced that cap against the configured budget store

This is the honest meaning of the current capability token plus kernel budget
logic.

### Truth Class B: Rail-Backed Spending Authorization

ARC proves:

- the governed action was approved for one exact economic envelope
- that envelope named the payer, merchant, payee destination, rail, asset,
  amount ceiling, and settlement mode
- the rail returned an authorization or prepaid commitment bound to that same
  envelope before execution

Only this class should justify "spending authorization" language.

### Truth Class C: Verifiable Settlement and Metering Evidence

ARC proves:

- the rail authorization was captured, released, refunded, or settled under the
  same economic envelope
- any variable usage component was measured by a trusted meter or signed meter
  authority rather than by unaudited tool self-report
- the signed receipt points to the exact rail and meter evidence that explain
  the final amount

Only this class should justify strong "billing ledger" language.

### Truth Class D: Liability-Ready Economic Evidence

ARC proves:

- the economic envelope
- the rail evidence
- the meter evidence
- the responsible-party chain
- the contract or policy references that define who is on the hook if the act
  fails or causes loss

Even here ARC should still avoid claiming that protocol artifacts alone decide
legal liability. The honest claim is that ARC can assemble a cryptographically
bound evidence package suitable for liability review, underwriting, dispute, or
compliance workflows.

## Required Protocol/Payment Changes

### 1. Separate budget semantics from payment semantics in the protocol

Stop treating one field family as both "budget" and "payment."

Keep `ToolGrant.max_cost_per_invocation` and `max_total_cost`, but define them
explicitly as:

- kernel budget ceilings
- not sufficient on their own for payment-authorization claims

Add a new typed economic block, for example `economic_authorization`, attached
to `GovernedTransactionIntent`.

Minimum fields:

- `economic_mode`: `budget_only`, `prepaid_fixed`, `hold_capture`,
  `metered_hold_capture`, `external_dispatch`
- `payer { party_id, funding_source_ref, custody_provider?, obligor_ref? }`
- `merchant { merchant_id, merchant_of_record?, order_ref? }`
- `payee { beneficiary_id, settlement_destination_ref }`
- `rail { kind, asset, network?, facilitator?, contract_or_account_ref? }`
- `amount_bounds { approved_max, hold_amount?, settlement_cap }`
- `pricing_basis { quote_hash?, tariff_hash?, quote_expiry? }`
- `metering { provider, meter_profile_hash, max_billable_units?, billing_unit? }`
- `liability_refs { bond_id?, policy_id?, indemnity_ref?, dispute_policy_ref? }`

This block must be canonicalized and included in the governed intent hash.

### 2. Upgrade approval from "intent hash only" to "economic envelope hash"

The current approval token binds:

- subject
- request id
- governed intent hash

That is good, but the strong claim boundary requires the governed intent to
contain the full economic envelope above. Once that exists, the approval token
inherits stronger meaning automatically.

For truly strong spend claims, ARC should additionally support a dedicated
`EconomicApprovalToken` or equivalent multi-party approval artifact that can be
signed by:

- the policy authority
- the actual payer or treasury delegate
- the merchant-side counterparty when bilateral confirmation is required

At minimum, the signed approval surface must cover:

- payer binding
- merchant binding
- payee binding
- rail binding
- asset binding
- amount ceiling
- quote or tariff hash
- settlement mode
- dispute or reversal posture

### 3. Make merchant and payee first-class, typed identities

Replace loose free-text `seller` semantics with typed party references.

Add canonical party types such as:

- `EconomicPartyId`
- `FundingSourceRef`
- `SettlementDestinationRef`
- `MerchantProfileRef`

Then require consistency checks across:

- governed intent
- approval token
- payment authorize request
- payment authorize response
- capture or release response
- final settlement receipt

ARC should fail closed if:

- merchant id changes mid-flight
- payee destination differs from approved destination
- rail asset differs from approved asset
- authorization response omits approved merchant or destination bindings

### 4. Replace `payer = agent_id` and `payee = server_id` with real economic identities

Revise `PaymentAuthorizeRequest` in `crates/arc-kernel/src/payment.rs`.

The request should carry:

- `payer_party_id`
- `payer_funding_source_ref`
- `merchant_id`
- `payee_destination_ref`
- `tool_provider_id`
- `governed_intent_hash`
- `economic_authorization_hash`
- `amount_units`
- `currency_or_asset`
- `settlement_mode`
- `idempotency_key`
- `quote_or_tariff_hash`

The response must return an attested envelope that repeats the same bindings.

Do not rely on adapter-local JSON metadata for the important semantics.
Important semantics must live in typed fields.

### 5. Require rail-backed ex ante commitment for strong spending claims

ARC should only use "spending authorization" wording for modes where execution
is blocked until one of the following is true:

- prepaid balance transfer is complete for the governed amount
- hold or authorization exists for the exact approved merchant, payee, asset,
  and amount ceiling
- escrow or bond is locked for the approved economic envelope
- delegated external settlement dispatch is prepared with a signed, immutable
  dispatch artifact tied to the same intent hash

If ARC only has a local budget debit and no external hold or prepayment, the
claim must stay at Truth Class A: budget authorization.

### 6. Introduce verifiable metering for variable-cost tools

For `allow_then_settle` or other variable-cost flows, `ToolInvocationCost`
cannot remain the sole source of actual billable truth.

Add a separate metering interface, for example `MeteringAdapter`, that can
produce a signed `MeterEvidence` object with:

- `meter_id`
- `provider`
- `receipt_id`
- `governed_intent_hash`
- `billing_unit`
- `observed_units`
- `pricing_basis_hash`
- `observed_cost`
- `captured_at`
- signature or verifiable attestation

Strong-path policy should require one of:

- independent metering service
- trusted platform meter
- signed merchant invoice receipt
- rail-native observable quantity

Tool self-report can remain as advisory or debugging data, but it should not be
the basis for strong billing-ledger or settlement claims.

### 7. Split receipt-side economic state into separate typed truths

Replace the overloaded receipt story with explicit fields or nested blocks:

- `budget_status`
- `approval_status`
- `rail_authorization_status`
- `metering_status`
- `capture_status`
- `settlement_status`
- `finality_status`

Also record typed evidence references:

- `economic_authorization_id`
- `rail_authorization_ref`
- `rail_transaction_ref`
- `meter_evidence_ref`
- `merchant_id`
- `payer_party_id`
- `payee_destination_ref`

Two hard rules should follow:

- if no external payment adapter or prepaid balance exists, `settlement_status`
  must never be `settled`
- if actual cost depends on unverified metering, ARC may record
  `metering_status = unverified` and must not claim final audited billing truth

### 8. Make settlement finality explicit and rail-specific

`SettlementStatus` is currently too coarse for the strongest claims.

Add a richer internal state model that can distinguish:

- authorized
- held
- captured
- pending_finality
- finalized
- released
- refunded
- failed
- not_applicable

Then map that carefully into public claims. For example:

- "funds reserved"
- "capture submitted"
- "rail finalized"
- "prepaid and consumed"

Do not use `settled` as a catch-all success label.

### 9. Bind capture and release operations to the approved envelope

`capture()` and `release()` should not operate only on:

- `authorization_id`
- `amount`
- `currency`
- `reference`

They must also verify:

- same `economic_authorization_hash`
- same merchant id
- same payee destination
- same payer funding source
- same asset
- capture amount within approved envelope
- idempotency and replay protections on the rail side

This closes the current gap where a rail authorization can exist, but the repo
does not yet force the post-execution operations to prove they stayed within
the originally approved economic terms.

### 10. Add an economic state machine and reject impossible transitions

Define a machine-readable state machine in the spec. Example:

- `budget_authorized`
- `rail_authorized`
- `executed`
- `metered`
- `captured`
- `finalized`
- `released`
- `refunded`
- `failed`

Then explicitly reject illegal transitions such as:

- `budget_authorized -> finalized` without rail evidence
- `executed -> settled` when metering is required but missing
- `authorized -> captured` with merchant mismatch
- `captured -> finalized` with asset mismatch

This is what turns the economics layer from metadata accumulation into a real
protocol.

### 11. Add a liability-evidence envelope instead of implying liability from receipts alone

If ARC wants liability-adjacent claims to be true, add a separate typed
artifact, for example `EconomicLiabilityEnvelope`, that can reference:

- responsible operator
- payer obligor
- merchant of record
- custodian of record
- bond or insurance artifact
- delegated execution chain
- dispute forum or policy
- governing contract or terms reference

This should be treated as:

- evidence package
- not automatic legal judgment

That distinction matters for truthful product and compliance language.

### 12. Gate claims by economic mode and evidence class

Add one doc and one linted manifest, for example `docs/ECONOMIC_CLAIMS.md`,
that map approved public phrases to evidence classes.

Examples:

- "budgeted authorization": allowed with local kernel budget evidence
- "rail-backed spending authorization": allowed only with ex ante rail hold or
  prepayment bound to the economic envelope
- "billing ledger": allowed only when meter evidence and settlement evidence
  are both present and typed
- "liability-ready evidence package": allowed only when the liability envelope
  is present

This is the cheapest way to stop the repo from relapsing into semantic inflation
after the technical work lands.

## Validation Plan

Validation has to prove both semantics and adversarial robustness.

### 1. Protocol-shape validation

- schema tests for the new `economic_authorization` block
- canonicalization tests showing that approval hashes change when payer,
  merchant, payee, rail, asset, quote, or meter profile changes
- backward-compatibility tests for non-economic and budget-only flows

### 2. Kernel enforcement validation

- unit tests that reject merchant mismatch between governed intent and payment
  adapter response
- unit tests that reject payee destination mismatch
- unit tests that reject asset or currency mismatch
- unit tests that reject capture over approved ceiling
- unit tests that reject settlement finalization without rail evidence
- regression test that no-adapter flows produce `not_applicable` or
  `budget_only`, never `settled`

### 3. Metering validation

- tests where tool self-report differs from signed meter evidence
- tests where meter evidence exceeds `max_billed_units`
- tests where quote hash and meter pricing basis hash diverge
- tests where missing meter evidence keeps the receipt in a non-final state

### 4. Rail integration validation

- sandbox tests for every supported payment adapter
- tests that rail authorize response repeats the approved merchant and payee
  bindings
- tests that capture and refund preserve the same envelope hash
- idempotency and replay tests on authorize, capture, release, and refund

### 5. End-to-end governed-flow validation

- full happy-path fixed-price prepaid flow
- full happy-path hold-and-capture flow
- full happy-path metered-hold-capture flow
- denial path when payer approval exists but rail authorization fails
- denial path when rail authorization exists but merchant binding mismatches
- failure path when tool executes but meter evidence is absent or invalid

### 6. Claim-discipline validation

- lint README, `docs/AGENT_ECONOMY.md`, `docs/ECONOMIC_INTEROP_GUIDE.md`,
  release docs, and standards docs against the approved evidence-class matrix
- fail CI if docs claim settlement or liability semantics stronger than the
  evidence class of the covered flow

## Milestones

### Milestone 1: Claim containment and truthful semantics

Scope:

- narrow economic language in README and vision docs
- document the four truth classes
- stop using "settled" for no-adapter success paths

Exit:

- public docs distinguish budget truth, rail truth, meter truth, and
  liability-evidence truth

### Milestone 2: Canonical economic envelope

Scope:

- add `economic_authorization` to governed intent
- make payer, merchant, payee, rail, asset, and amount ceiling first-class
- bind approval to the new envelope

Exit:

- ARC has one canonical, hashed economic envelope for governed actions

### Milestone 3: Rail-backed fixed-price authorization

Scope:

- upgrade `PaymentAuthorizeRequest`
- require ex ante rail-backed hold or prepayment for strong spending claims
- type-check capture and release against the approved envelope

Exit:

- ARC can truthfully claim rail-backed spending authorization for fixed-price
  and ceiling-bounded flows

### Milestone 4: Verifiable metering

Scope:

- add `MeteringAdapter`
- add signed `MeterEvidence`
- require verified meter evidence for variable-cost finalization

Exit:

- ARC can truthfully claim verifiable billed amount for supported metered flows

### Milestone 5: Liability-ready evidence package

Scope:

- add `EconomicLiabilityEnvelope`
- bind responsible-party, custody, and coverage references to the same action
- expose export and review tooling

Exit:

- ARC can truthfully claim a liability-ready economic evidence package for the
  bounded supported profiles

### Milestone 6: Release gating and partner qualification

Scope:

- CI doc lint
- sandbox rail qualification
- adversarial merchant, payee, and meter mismatch tests
- release report describing supported economic truth classes

Exit:

- no release ships with stronger economic claims than the qualified profiles

## Acceptance Criteria

The strong "capability as spending authorization" and liability-adjacent claims
are only allowed to return when all of the following are true:

1. ARC has a typed canonical economic envelope that includes payer, merchant,
   payee destination, rail, asset, and amount ceiling.
2. Approval tokens or equivalent signed approval artifacts bind that exact
   envelope hash.
3. Strong-path execution is blocked until ARC obtains a rail-backed hold,
   prepayment, escrow lock, or explicit settlement dispatch artifact bound to
   the same envelope.
4. Capture, release, refund, and settlement operations verify the same
   envelope rather than only a loose authorization id.
5. Metered flows use verifiable meter evidence or another trusted billable
   source, not only tool self-report.
6. Signed receipts expose separate typed truths for budget, authorization,
   metering, capture, and settlement state.
7. No-adapter flows never emit receipt semantics that imply external
   settlement finality.
8. Merchant mismatch, payee mismatch, payer mismatch, asset mismatch, quote
   mismatch, and over-ceiling capture all fail closed in tests.
9. Liability-adjacent claims are backed by a typed evidence envelope naming the
   responsible parties and coverage or dispute artifacts for the supported
   profiles.
10. README, protocol, standards docs, and release docs are linted against the
    approved evidence-class vocabulary.

Anything short of this may still be valuable economic-control infrastructure,
but it is not enough to justify the current strongest thesis.

## Risks/Non-Goals

### Risks

- Scope explosion if the team tries to make every ARC tool call universally
  payment-capable instead of defining bounded economic profiles.
- Integration complexity across multiple payment rails with incompatible
  notions of authorization, capture, refund, and finality.
- Metering trust risk if the chosen meter is not actually independent from the
  party with economic incentive to misreport.
- Legal-language drift if product docs begin treating liability evidence as
  legal liability determination.
- Architecture coupling risk if payment, metering, and liability semantics are
  mixed back into one overloaded receipt field.

### Non-Goals

- Building a universal payment processor or marketplace
- Proving that a merchant delivered off-protocol goods or services
- Letting arbitrary tool self-report qualify as audited billing truth
- Claiming that protocol artifacts alone determine legal liability in every
  jurisdiction
- Replacing external treasury, custody, accounting, claims, or compliance
  systems

The honest end-state is not "ARC magically turns every capability into money."
It is: "for bounded supported profiles, ARC can bind governed approval,
economic parties, rail authorization, metering evidence, and settlement
evidence into one fail-closed execution and review package."
