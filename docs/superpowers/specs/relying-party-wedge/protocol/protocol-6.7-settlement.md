<!--
Target: spec/PROTOCOL.md
Insertion point: new subsection after "### 6.6 HTTP Receipts", before "## 7. Manifest Contract".
Move the text below this comment into place unchanged; drop this comment.
-->

### 6.7 Settlement Block And Closure

Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Sections in force until then: 6.2 and 6.4.4.

Typed asset: `MonetaryAmount.currency` is replaced by `asset`, a closed
grammar of `iso4217:<CODE>` or `caip19:<chain>/<namespace>:<reference>`. A
child capability's asset must equal its parent's. A tool's price asset must
equal the cap's asset. Authority performs no conversion between assets.

A `caip19:` asset is accepted only for a CAIP-2 chain id in the compiled-in
testnet allowlist. Policy load, manifest load and `serve-http` startup reject
any other chain id. Chio never holds wallet keys, funds or payment
instruments.

Receipt `settlement` block:

```json
"settlement": {
  "rail": "x402",
  "scheme": "exact",
  "state": "settled",
  "asset": "caip19:eip155:84532/erc20:0x036c...",
  "amount": "250000",
  "pay_to": "eip155:84532:0xprovider...",
  "hold_id": "hold_01J...",
  "rail_refs": [
    { "kind": "x402.payment_requirements", "digest": "sha256:..." },
    { "kind": "x402.settlement_response", "id": "eip155:84532:0x5e9c...", "digest": "sha256:..." }
  ]
}
```

- `state` is closed: `settled`, `authorized_pending`, `failed`.
- `rail_refs[].kind` is closed: `x402.payment_requirements`,
  `x402.payment_payload`, `x402.settlement_response`. Digests are over the
  canonical JSON of the decoded base64 payloads.
- Amounts are integer minor units encoded as decimal strings.

`chio.settlement-closure.v1`, signed by the kernel key:

```json
{
  "schema": "chio.settlement-closure.v1",
  "terminal_receipt_id": "5a1f...c4",
  "hold_id": "hold_01J...",
  "rail": "x402",
  "state": "settled",
  "asset": "caip19:eip155:84532/erc20:0x036c...",
  "amount": "250000",
  "rail_refs": [ { "kind": "x402.settlement_response", "id": "eip155:84532:0x...", "digest": "sha256:..." } ],
  "observed_at": 1792234990,
  "kernel_key": "9f2d...",
  "signature": "..."
}
```

A terminal receipt with inline settlement needs no closure. Exactly one
closure may exist per `authorized_pending` terminal receipt, and its `hold_id`
must match. A terminal receipt plus its closure is the joined receipt. The
mutable reconciliation sidecar stays an operator view and is never authority
(section 6.4).

Tool pricing lives in the signed tool manifest: per tool,
`pricing { asset, amount, scheme: "exact", pay_to, networks: [...] }`. A price
the edge cannot express as x402 `accepts` rejects at manifest load.

Payment rules (no dispatch on any of these):

- price above the capability's caps;
- price asset different from the cap asset;
- `payTo` mismatch against the manifest;
- facilitator `/verify` invalid, or `/settle` not settled.

A settled amount different from the challenged amount produces a terminal
receipt with `settlement.state = failed`, and the hold stays open for operator
action. A settlement that matches no hold goes to the dead-letter path and
credits nothing.
