# chio-provider-conformance

Loads provider NDJSON captures, replays native adapter behavior, and compares
canonical invocation, verdict, and lowered-response results. The record binary
refreshes existing OpenAI, Anthropic, and Bedrock scenarios with credentials.
The library provides offline assertions without enabling a provider adapter.

## Usage

Compare differently ordered JSON objects using canonical bytes offline.
No fixture feature, credential, or network connection is needed.

```rust
use chio_provider_conformance::assert_canonical_json_eq;
use serde_json::json;

assert_canonical_json_eq(
    "tool arguments", &json!({"city": "Boston", "units": "C"}),
    &json!({"units": "C", "city": "Boston"}),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
|---|---|---|
| `default` | Yes | Empty; shared capture and assertion APIs remain available. |
| `fixtures-openai` | Off | Enables openai adapter replay and manifest dependency. |
| `fixtures-anthropic` | Off | Enables anthropic adapter replay and manifest dependency. |
| `fixtures-bedrock` | Off | Enables bedrock adapter replay and manifest dependency. |
| `fixtures-cohere` | Off | Enables cohere adapter replay and manifest dependency. |
| `fixtures-gemini` | Off | Enables gemini adapter replay and manifest dependency. |
| `fixtures-groq` | Off | Enables groq adapter replay and manifest dependency. |
| `fixtures-mistral` | Off | Enables mistral adapter replay and manifest dependency. |
| `fixtures-ollama` | Off | Enables ollama adapter replay and manifest dependency. |

The Anthropic fixture feature also enables its computer-use surface.
The OpenAI fixture feature enables its provider-adapter surface.

## Guarantees

`assert_canonical_json_eq` compares RFC 8785 encodings; `assert_verdict_eq`
requires exact verdict equality. `input::read_fixture` bounds file reads,
requires regular files, and rejects symlinks through platform-specific checks.
`load_fixture` validates capture identity and record structure before replay.
Provider replay functions compare projected results against captured expectations.

## Status

Implemented test support for eight provider corpora and a three-provider recorder.
Replay features select the optional adapters; disabled replay paths report errors.
Captured verdicts are test expectations, and replay uses local admission fixtures.
This harness does not qualify a live provider deployment or create kernel authority.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Provider adapter core](../chio-provider-adapter-core/README.md)
- [Capture directory](fixtures/)
- [License](../../../LICENSE)
