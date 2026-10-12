# chio-envoy-ext-authz

Implements Envoy ext_authz gRPC request translation and response mapping around a caller-provided authorization evaluator.

This crate sits at Chio's protocol boundary. Its embedding application
chooses the surrounding runtime and transport wiring.

## Usage

The example runs locally without opening a listener or spawning an agent.

```rust
use async_trait::async_trait;
use chio_envoy_ext_authz::{ChioExtAuthzService, EnvoyKernel, KernelError, ToolCallRequest, Verdict};

struct DenyAll;
#[async_trait]
impl EnvoyKernel for DenyAll {
    async fn evaluate(&self, _: ToolCallRequest) -> Result<Verdict, KernelError> {
        Ok(Verdict::deny("access disabled", "example"))
    }
}
let _service = ChioExtAuthzService::new(DenyAll);
```

## Guarantees

`Authorization::check` returns a denied HTTP 500 response on translation or evaluator errors. `check_request_to_tool_call` rejects missing request components and invalid method shape. The evaluator owns actual authorization.

Envoy must enforce the CheckResponse. Identity precedence favors a capability
header, then bearer presentation, then the Envoy peer principal.

## Status

Implemented translation and tonic service. No concrete Chio kernel dependency or automatic receipt signing is installed. Deployments supply `EnvoyKernel`, register the service, and configure Envoy transport trust and filter behavior.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#http-and-openapi-surfaces)
- [chio-http-serve](../chio-http-serve/README.md)

## License

See the workspace [license](../../../LICENSE).
