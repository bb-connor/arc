# chio-external-guards

HTTP-backed guard adapters for Chio. Concrete adapters evaluate Bedrock,
Azure Content Safety, Vertex safety, VirusTotal, Safe Browsing, and Snyk
responses. Shared retry, cache, rate-limit, and circuit infrastructure comes
from `chio-guards`.

## Usage

Build a concrete adapter and kernel bridge without contacting a provider:

```rust
use std::sync::Arc;
use chio_external_guards::{
    AsyncGuardAdapter, SafeBrowsingConfig, SafeBrowsingGuard, ScopedAsyncGuard,
};
use chio_kernel::Guard;

let provider = SafeBrowsingGuard::new(
    SafeBrowsingConfig::new("example-key").with_base_url("http://127.0.0.1:8080"),
)?;
let adapter = AsyncGuardAdapter::builder(Arc::new(provider)).build();
let guard = ScopedAsyncGuard::new(adapter, vec!["fetch_*".into()]);
assert!(!guard.name().is_empty());
# Ok::<(), chio_external_guards::ExternalGuardError>(())
```

The example uses existing package dependencies and performs no request.
Evaluation requires a service implementing the selected provider contract and
valid credentials. Loopback HTTP is supported for local test endpoints.

## Guarantees

- `http_egress::send_request_with_contract` routes HTTP dispatch through the
  shared egress contract with an authority allowlist and bounded responses.
- `input::arguments` and `input::response` retain bounded original JSON for
  duplicate-aware contract validation before provider projection.
- `AsyncGuardAdapter::evaluate` maps exhausted or permanent errors to denial;
  successful verdicts can be cached and count as circuit successes.
- `ScopedAsyncGuard` normalizes tool patterns and matches `*` and `?`.
  An empty pattern set evaluates every tool; unmatched tools pass through.

## Status

Implemented adapters translate provider responses into local verdicts.
Repository tests use mock HTTP services and local guard contexts. They do not
qualify credentials, API compatibility, or behavior against live upstreams.
Provider thresholds, cache TTLs, and breaker/rate-limit verdicts are caller
configuration. VirusTotal's recognized unseen response defaults to denial;
explicit unseen allow is supported as a policy choice.

## Related

- [Architecture](ARCHITECTURE.md)
- [Shared guard infrastructure](../chio-guards/README.md)
- [Protocol HTTP egress contract](../../../spec/PROTOCOL.md#84-http-egress-contract-enforcement-w22)

## License

See [LICENSE](../../../LICENSE).
