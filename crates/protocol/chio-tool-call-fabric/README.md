# chio-tool-call-fabric

Defines provider-neutral tool invocations, provenance signatures, adapter traits,
and buffered stream transitions used by Chio provider integrations.

## Usage

```rust
use chio_tool_call_fabric::{Principal, ProvenanceStamp, ProviderId, ToolInvocation};
use std::time::SystemTime;

let invocation = ToolInvocation {
    provider: ProviderId::OpenAi,
    tool_name: "lookup".into(),
    arguments: br#"{"id":1}"#.to_vec(),
    provenance: ProvenanceStamp {
        provider: ProviderId::OpenAi,
        request_id: "call-1".into(),
        api_version: "local-fixture".into(),
        principal: Principal::OpenAiOrg { org_id: "org-1".into() },
        received_at: SystemTime::UNIX_EPOCH,
    },
    bridge_security: None,
};
invocation.validate()?;
# Ok::<(), chio_tool_call_fabric::ToolInvocationValidationError>(())
```

The example validates an offline normalized invocation. Provider adapters
implement lifting and lowering; callers still obtain kernel verdicts before
executing tools or forwarding verdict-dependent output.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `schema-subsumption` | Off | Enables a compile-only assertion in the structural invariant test; adds no schema validator. |

## Guarantees

- `ToolInvocation::validate` checks provider/principal consistency, identities,
  canonical object arguments, and optional admitted bridge-tool binding.
- `verify_signed_provenance` checks algorithm agreement, exact canonical bytes,
  and the signature against the envelope public key.
- `StreamPhase::transition` rejects invalid transitions and bounds appended
  buffered bytes with its default ceiling.

## Status

Implemented shared contracts and stream state machine. Standalone provenance
verification returns the signing key; callers decide whether that key is trusted.
The schema-subsumption property currently checks structural fields.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-openai-adapter](../chio-openai-adapter/README.md)

## License

[Workspace license](../../../LICENSE).
