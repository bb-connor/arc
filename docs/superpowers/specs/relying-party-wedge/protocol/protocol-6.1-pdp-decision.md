<!--
Target: spec/PROTOCOL.md
Insertion point: inside "### 6.1 Receipt Semantics And Decisions", a new paragraph block after the paragraph that ends "collapsed into an undifferentiated error state.", before "### 6.2 Authoritative Spend".
Move the text below this comment into place unchanged; drop this comment.
-->

#### `pdp_decision` receipts

Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Sections in force until then: the three receipt kinds listed at the start of 6.1.

A `pdp_decision` receipt records a decision Chio made for an external policy
enforcement point (PEP) that enforces it. The closed enums gain
`receipt_kind = "pdp_decision"`, `boundary_class = "prevent_external"` and
`trust_level = "delegated"`. `pdp_decision` requires `prevent_external` and
`delegated`; every other combination involving any of the three rejects.

A `pdp_decision` receipt carries a `decision`, has no `content_commitment`
(Chio never sees the result), and carries a required `enforcement` block:

```json
"enforcement": {
  "pep_id": "kong-prod-eu",
  "pep_key": "77b0...",
  "pep_profile": "authzen_1_0_fail_closed",
  "request_id": "req_01J...",
  "decision_expires_at": 1792234930
}
```

Decoding is strict (section 4.5): an unknown member in `enforcement` rejects
the receipt.

Only `mediated_decision` + `prevent` + `Allow` is Chio-enforced
authorization. A verifier renders a `pdp_decision` Allow as "authorized by
Chio, enforced by the named PEP", and only when `pep_key` is pinned in its
trust file (section 5.6.8).

AuthZEN profile (OpenID AuthZEN Authorization API 1.0): `serve-http` serves
`POST /access/v1/evaluation`, `POST /access/v1/evaluations` and
`GET /.well-known/authzen-configuration`.

```json
{
  "subject": {
    "type": "chio_capability",
    "id": "cap_01J...",
    "properties": {
      "presentation": { "schema": "chio.capability-presentation.v1", "...": "..." },
      "dpop_proof": "..."
    }
  },
  "action": { "name": "search", "properties": { "operation": "invoke" } },
  "resource": { "type": "chio_tool", "id": "paid-search/search" },
  "context": {
    "request_id": "req_01J...",
    "parameters": { "...": "canonical arguments; committed in the receipt per policy" }
  }
}
```

The response is
`{"decision": true|false, "context": {"chio": {"receipt": {...}, "opening": {...}, "reason_code": "urn:chio:error:...", "expires_at": 1792234930}}}`,
where `receipt` is the signed `pdp_decision` receipt and `opening` is a
`chio.receipt-disclosure.v1` holding the parameters salt only. The opening
never carries the anchor subject or tenant salts.

The PEP authenticates with mTLS or a per-PEP token, and its identity selects
`pep_id` and `pep_key` from the PEP allowlist. A request from an unlisted PEP
gets HTTP 401 and no receipt. A request without a presentation, with an
unknown `subject.type` or `resource.type`, or for a grant that needs a hold,
a payment or an output check denies.
