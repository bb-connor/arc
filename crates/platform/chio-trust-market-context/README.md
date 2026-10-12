# chio-trust-market-context

Verifies transaction evidence for provider discovery/selection, local
scorecards, reputation imports, SLA performance, risk, collateral,
guarantees, and jurisdiction. It produces a trust-market family report
consumed by higher-level Chio proof composition.

## Usage

Exercise missing-root-pin rejection offline. Complete verification needs
committed graph/policy/artifact bytes, root pins, and market-authority keys
selected outside the bundle. The passport fixture is embedded at compile
time.

```rust
use std::collections::BTreeMap;
use chio_trust_market_context::{verify_trust_market_context, TrustMarketBundle};
use chio_transaction_passport::{decode_evidence_json, TransactionPassport,
    TransactionPassportError};

let passport: TransactionPassport = decode_evidence_json(include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/proof-room/",
        "enterprise-export/valid-autonomous-commerce/transaction-passport.json")))?;
let bundle = TrustMarketBundle {
    passport, evidence_graph_bytes: vec![], root_evidence_graph_bytes: None,
    verifier_policy_bytes: vec![], artifacts: BTreeMap::new(),
    trusted_passport_signer_keys: vec![], trusted_market_authority_keys: vec![],
};
assert!(matches!(verify_trust_market_context(&bundle),
    Err(TransactionPassportError::MissingTrustedTransactionRootKeys)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`verify_trust_market_context` authenticates the passport and then intersects
caller-trusted market keys with policy-pinned market keys.
`parse_signed_artifact` binds each artifact to its graph digest/schema and
verifies its signature against that intersection.

Family checks bind provider selection, score recomputation, reputation
weight, SLA metrics, risk references, collateral, guarantee terms, and
jurisdiction. Policy-required unsupported market claims are rejected; the
report lists declared unsupported claims.

## Status

Implemented offline trust-market evidence verifier. `[lib] test = false`;
integration tests exercise signed bundles. Freshness and SLA windows are
evaluated over supplied timestamps. The crate does not discover providers,
update reputation, enforce SLA remedies, operate a market, or execute
sanctions.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#643-transaction-passport-proof-root)
- [chio-commerce-order](../chio-commerce-order/README.md)
- [License](../../../LICENSE)
