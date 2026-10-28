# chio-egress-contract

Defines tenant-scoped HTTP egress policy and reusable URL, DNS, redirect, and
response-size checks for Chio adapters.

## Usage

```rust
use chio_egress_contract::HttpEgressContract;
use std::collections::BTreeSet;

let contract = HttpEgressContract {
    tenant_egress_namespace: "tenant-a".into(),
    allowed_schemes: BTreeSet::from(["https".into()]),
    allowed_authority_set: BTreeSet::from(["api.example".into()]),
    deny_loopback: true,
    deny_link_local: true,
    deny_ipv6_ula: true,
    max_redirect_chain: 2,
    max_response_bytes: 4096,
    private_network_allowances: Default::default(),
};
let target = contract.enforce_url("https://api.example/items", 0)?;
assert_eq!(target.authority, "api.example");
# Ok::<(), chio_egress_contract::HttpEgressError>(())
```

This example validates a URL without DNS or network access. DNS checks require
`enforce_url_with_dns`; a dispatcher must also enforce observed response bytes.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | On | Empty feature set; contract checks are available. |
| `reqwest-egress` | Off | Adds contract client, dispatch, and operator readiness helpers. |

## Guarantees

- `HttpEgressContract::prepare` validates shape and captures an immutable snapshot.
- `enforce_url` checks schemes, normalized authorities, address literals, userinfo,
  and redirect count. It does not resolve domain names.
- `private_network_allowances` is the only way to reach a private address: each
  entry pins one `host:port` to a CIDR every resolved address must fall inside.
  Link-local and cloud metadata addresses are never reachable.
- `enforce_url_with_dns` checks every resolved address. Response-size enforcement
  requires an observed byte count or the feature-gated dispatch helper.

## Status

Implemented contract validation with optional reqwest transport enforcement.
Callers own tenant policy selection and must use the enforcing APIs on their
actual dispatch path. `permissive_for_tests` is intended for test fixtures.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-a2a-adapter](../chio-a2a-adapter/README.md)

## License

[Workspace license](../../../LICENSE).
