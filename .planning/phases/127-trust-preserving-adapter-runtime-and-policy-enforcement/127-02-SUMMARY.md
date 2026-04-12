# Summary 127-02

Bound extension execution to local policy and signed-truth guardrails.

## Delivered

- negotiation and manifest validation now reject truth-mutation and
  trust-widening claims
- evidence-capable extensions must declare subject binding, signer
  verification, freshness checks, and local policy activation
- policy-required extension points now fail closed if a manifest omits those
  safeguards

## Result

Custom execution can plug into ARC only through envelopes that preserve ARC's
local policy authority and signed artifact truth.
