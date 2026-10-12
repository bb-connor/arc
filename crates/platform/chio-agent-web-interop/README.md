# chio-agent-web-interop

Verifies projections of external protocol evidence into Chio transaction
bundles. Agent Web envelopes bind external subject bytes, projection rules,
passport scope, and signed Chio receipts to produce an interop report.

## Usage

Demonstrate the empty-trust default rejecting a supplied passport. Complete
verification needs caller-pinned passport, kernel, and sidecar keys plus
committed graph/artifact bytes. The fixture is embedded at compile time.

```rust
use std::collections::BTreeMap;
use chio_agent_web_interop::{verify_agent_web_interop_with_trust,
    AgentWebInteropBundle, AgentWebVerifierTrust};
use chio_transaction_passport::{decode_evidence_json, TransactionPassport,
    TransactionPassportError};

let passport: TransactionPassport = decode_evidence_json(include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/proof-room/",
        "enterprise-export/valid-autonomous-commerce/transaction-passport.json")))?;
let bundle = AgentWebInteropBundle {
    passport, evidence_graph_bytes: vec![], root_evidence_graph_bytes: None,
    verifier_policy_bytes: vec![], artifacts: BTreeMap::new(),
};
let trust = AgentWebVerifierTrust::new();
assert!(matches!(verify_agent_web_interop_with_trust(&bundle, &trust),
    Err(TransactionPassportError::MissingTrustedTransactionRootKeys)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`verify_agent_web_interop_with_trust` authenticates passport roots, enforces
disjoint signer roles, binds projection manifests/envelopes, and rechecks
referenced Chio receipts. External-subject validators enforce
protocol-specific fields and explicit unsupported-claim limitations.

Read-only verification does not reserve webhook IDs. Consuming variants
reserve the validated Standard Webhooks batch only after full verification;
the report-matching variant first compares a supplied read-only result.
`InMemoryAgentWebReplayStore` rejects replay, clock rollback, and capacity
exhaustion. Injected stores must uphold the `AgentWebReplayStore` contract.

## Status

Implemented offline projection verifier and replay-store contract. `[lib]
test = false`; integration tests cover composition.
`InMemoryAgentWebReplayStore` retains state for its object lifetime. Hosts
provide durable replay state for restart protection and trusted time/secret
material. External identity or success fields require the declared
projection checks and bound Chio authority receipts.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#646-agent-web-envelope-family)
- [chio-transaction-passport](../chio-transaction-passport/README.md)
- [License](../../../LICENSE)
