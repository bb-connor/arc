# Economic Interop Guide

ARC's economic interop surface exists to make governed receipts legible to IAM,
finance, and partner-review systems without rewriting execution truth.

This guide ties the shipped surface back to the research direction in
`docs/research/DEEP_RESEARCH_1.md`: a two-source cost model, standards-legible
authorization details, and explicit transaction context are prerequisites for
underwriting and later market layers.

## Truth Model

ARC keeps three different truths separate:

1. Signed receipt truth:
   what the kernel allowed or denied, what tool ran, and what amount ARC
   charged or attempted to charge.
2. Mutable economic-evidence truth:
   post-execution metered billing evidence and operator reconciliation state
   keyed by `receipt_id`.
3. Derived authorization-context truth:
   a standards-legible projection generated from signed governed receipt
   metadata, not a second operator-authored authorization document.

That separation prevents silent widening of billing scope or delegated
authority through reporting artifacts.

The normative enterprise-facing mapping over that projection is now documented
in [ARC_OAUTH_AUTHORIZATION_PROFILE.md](standards/ARC_OAUTH_AUTHORIZATION_PROFILE.md).
ARC still treats signed governed receipts as the source of truth; the profile
only explains how those receipts project into OAuth-family authorization
details and transaction context.

The profile now also makes sender-constrained semantics explicit:

- every row carries `senderConstraint.subjectKey`
- DPoP is reflected only when the matched grant required it
- runtime assurance and delegated call-chain context remain visible as
  sender-bound conditions rather than a second mutable trust document

The hosted edge now uses the same profile at request time:

- `/oauth/authorize` accepts ARC-governed `authorization_details` plus
  `arc_transaction_context`
- the request must carry a `resource` parameter matching the protected
  resource metadata
- the issued access token echoes the same bounded request-time contract
- approval tokens, ARC capabilities, and reviewer packs remain audit or review
  artifacts rather than alternate bearer tokens

## Operator Surfaces

IAM-facing authorization-context projection:

```bash
arc --json --receipt-db receipts.sqlite3 \
  trust authorization-context list \
  --capability cap-123 \
  --limit 20
```

Remote trust-control equivalent:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://trust.example/v1/reports/authorization-context?capabilityId=cap-123&authorizationLimit=20"
```

Hosted request-time authorize example:

```bash
curl -G "https://edge.example/oauth/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=arc-cli" \
  --data-urlencode "redirect_uri=https://client.example/callback" \
  --data-urlencode "scope=mcp" \
  --data-urlencode "resource=https://edge.example/mcp" \
  --data-urlencode 'authorization_details=[{"type":"arc_governed_tool","locations":["shell"],"actions":["bash"]}]' \
  --data-urlencode 'arc_transaction_context={"intentId":"intent-live-auth-1","intentHash":"intent-hash-live-auth-1"}'
```

Machine-readable profile metadata for enterprise reviewers:

```bash
arc --json --receipt-db receipts.sqlite3 \
  trust authorization-context metadata
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://trust.example/v1/reports/authorization-profile-metadata"
```

Reviewer pack tying one governed flow back to signed receipt truth:

```bash
arc --json --receipt-db receipts.sqlite3 \
  trust authorization-context review-pack \
  --capability cap-123 \
  --limit 20
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://trust.example/v1/reports/authorization-review-pack?capabilityId=cap-123&authorizationLimit=20"
```

Finance-facing metered reconciliation:

```bash
arc --json --receipt-db receipts.sqlite3 \
  trust behavioral-feed export \
  --capability cap-123 \
  --receipt-limit 20
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://trust.example/v1/reports/metered-billing?capabilityId=cap-123&meteredLimit=20"
```

Operator reconciliation action:

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://trust.example/v1/metered-billing/reconcile \
  -d '{
    "receiptId": "rc-123",
    "adapterKind": "manual_meter",
    "evidenceId": "usage-123",
    "observedUnits": 17,
    "billedCost": { "units": 4200, "currency": "USD" },
    "recordedAt": 1710000000,
    "reconciliationState": "reconciled"
  }'
```

## What Reviewers Should Look For

IAM reviewers:

- `authorizationDetails[*].type` shows the bounded governed tool action and,
  when present, separate commerce or metered-billing scope.
- `transactionContext.intentHash` proves the report is anchored to the
  approval-bound governed intent.
- `senderConstraint` shows which capability subject was bound to the governed
  action and whether DPoP was required for that matched grant.
- request-time hosted authorization uses the same bounded
  `authorization_details` and `transactionContext` story rather than a second
  looser OAuth payload model.
- `transactionContext.callChain` shows delegated provenance when the request
  continued from an upstream governed flow.
- `/v1/reports/authorization-profile-metadata` gives the canonical profile id,
  discovery paths, supported field families, and explicit non-goals without
  requiring a reviewer to reconstruct ARC semantics from the raw report alone.
- `/v1/reports/authorization-review-pack` gives one evidence package with the
  projected `authorizationContext`, the typed `governedTransaction`, and the
  full signed receipt JSON for the same action.

Finance reviewers:

- `metadata.financial` on the signed receipt records ARC's charged or attempted
  amount.
- `/v1/reports/metered-billing` shows post-execution usage evidence and whether
  it exceeded quoted units, quoted cost, or explicit billable ceilings.
- reconciliation state is mutable and operator-visible, but it does not rewrite
  signed receipt JSON.

Partner reviewers:

- the same governed receipt can be inspected as receipt truth, behavioral-feed
  evidence, and authorization-context projection without conflicting numbers or
  conflicting delegated scope.
- runtime-assurance data travels with the authorization-context projection when
  present, and ARC now feeds that same canonical context into separate
  underwriting surfaces without changing the underlying receipt truth.
- hosted edges can publish the same profile mechanically through
  `/.well-known/oauth-protected-resource/mcp` and
  `/.well-known/oauth-authorization-server/{issuer-path}`, but those metadata
  documents remain informational only and do not widen trust by themselves.
- mismatched `resource` indicators, malformed request-time transaction
  context, and replay of review artifacts as bearer tokens all fail closed.

## Enterprise Review Package

The intended enterprise review flow is now explicit:

1. Fetch `authorization-profile-metadata` to understand ARC's supported
   profile, discovery paths, and boundaries.
2. Fetch `authorization-context` for the governed capability, subject, or tool
   slice being reviewed.
3. Fetch `authorization-review-pack` over the same filter to inspect the exact
   signed receipts and governed transaction metadata behind the projection.

ARC fails closed instead of downgrading the review package if sender binding,
runtime-assurance projection, or delegated call-chain fields cannot be
represented truthfully.

## Example Projection Shape

```json
{
  "authorizationDetails": [
    {
      "type": "arc_governed_tool",
      "locations": ["shell"],
      "actions": ["bash"],
      "purpose": "delegate external partner workflow",
      "maxAmount": { "units": 4200, "currency": "USD" }
    },
    {
      "type": "arc_governed_commerce",
      "maxAmount": { "units": 4200, "currency": "USD" },
      "commerce": {
        "seller": "merchant.example",
        "sharedPaymentTokenId": "spt_live_auth_1"
      }
    },
    {
      "type": "arc_governed_metered_billing",
      "meteredBilling": {
        "settlementMode": "allow_then_settle",
        "provider": "billing.arc",
        "quoteId": "quote-auth-1",
        "billingUnit": "1k_tokens",
        "quotedUnits": 12,
        "quotedCost": { "units": 3800, "currency": "USD" },
        "maxBilledUnits": 18
      }
    }
  ],
  "transactionContext": {
    "intentId": "intent-auth-1",
    "intentHash": "intent-hash-auth-1",
    "approvalTokenId": "approval-auth-1",
    "runtimeAssuranceTier": "verified",
    "callChain": {
      "chainId": "chain-ext-1",
      "parentRequestId": "req-upstream-1"
    }
  }
}
```

## Explicit Boundary

ARC now ships truthful economic evidence and authorization-context interop as
the substrate that the separate underwriting surfaces consume.

This guide itself does not define:

- signed underwriting decisions or appeal lifecycle handling
- underwriting simulation and policy what-if analysis
- liability pricing or broader market-layer capital allocation

Those higher layers now exist elsewhere in ARC, but they still depend on this
guide's separation between receipt truth, mutable reconciliation truth, and
derived authorization-context projection.
