# chio-sdk-python

Python SDK for the [Chio protocol](../../../spec/PROTOCOL.md). A thin,
async HTTP client to the Chio sidecar kernel, plus the typed models for
capabilities, scopes, verdicts, and receipts that the higher-level
framework integrations (FastAPI, Django, LangChain, and others) build on.

The sidecar runs as a local process exposing a localhost HTTP API. This
package never signs or evaluates anything itself; it forwards requests to
the sidecar and returns typed results.

## Install

```bash
uv pip install chio-sdk-python
# or
pip install chio-sdk-python
```

The package depends only on `httpx` and `pydantic`.

## Quickstart

```python
from chio_sdk import ChioClient
from chio_sdk.errors import ChioDeniedError


async def main() -> None:
    # Defaults to the local sidecar at http://127.0.0.1:9090.
    async with ChioClient() as client:
        await client.health()

        advisory = await client.evaluate_tool_call_advisory(
            capability_id="cap-123",
            tool_server="search-srv",
            tool_name="search_documents",
            parameters={"query": "capability-based security"},
        )
        print(f"advisory receipt: {advisory.id}")

        # `evaluate_tool_call` is fail-closed for id-only callers: it runs
        # advisory evaluation for audit, then always raises `ChioDeniedError`,
        # because a capability id alone is not execution authorization. It never
        # returns a receipt. Wrappers gate on this raise; use
        # `evaluate_tool_call_advisory` for a non-authoritative observation, or
        # `evaluate_tool_call_mediated` with a full signed token for
        # authoritative enforcement.
        try:
            await client.evaluate_tool_call(
                capability_id="cap-123",
                tool_server="search-srv",
                tool_name="search_documents",
                parameters={"query": "capability-based security"},
            )
        except ChioDeniedError as error:
            print(f"not authorized: {error}")
```

Caller preparation uses the kernel-mediated `POST /v1/evaluate` route,
which requires a full signed capability token. Its reservation is not permission
to execute. The trusted executor must use `start_mediated_execution`, verify and
durably claim the committed authorization, then return authenticated evidence
with `report_mediated_execution`. The SDK methods transport these artifacts;
they do not implement an executor or verify its durable claim. See the
[caller-delivery contract](../../../docs/security/authenticated-caller-delivery.md)
for control credentials, compatibility and supported custody profiles. The
id-only SDK wrappers hold a capability id, not a signed token, so
`evaluate_tool_call` (and the adapters built on it) take a `capability_id` and
delegate to the advisory `POST /v1/evaluate/advisory` route. The advisory route
returns `authorization: false`, `authorizationBasis: "advisory_only"`, and a
non-authoritative `ChioReceipt` (`trust_level == "advisory"`). Callers holding a
full signed token can drive the mediated route with
`evaluate_tool_call_mediated`.

Point the client at a non-default sidecar with `ChioClient(base_url=...)`.

## Capability subject ownership

`create_capability(subject=..., scope=...)` sends the caller's public key to
`POST /v1/capabilities`. Pass the 64-character hex Ed25519 public key from
your agent's existing signer (or its supported kernel crypto wire format).
Keep the private key with that signer. The sidecar rejects missing, malformed,
weak Ed25519 keys and job or role labels with HTTP 400; it never derives a
subject signing key from request metadata. Scope grants that require DPoP
need proofs signed by that caller key. A token alone does not supply the proof.

```python
import os
from chio_sdk import ChioClient

# Run minting in the trusted operator, separate from the untrusted agent.
# agent_public_key_hex comes from your separately provisioned agent signer.
async with ChioClient(
    control_token=os.environ["CHIO_SIDECAR_CONTROL_TOKEN"]
) as operator:
    token = await operator.create_capability(
        subject=agent_public_key_hex, scope=scope, ttl_seconds=600
    )
    assert token.subject == agent_public_key_hex
```

The optional constructor `control_token` supplies the bearer only on capability
minting, never on health or evaluation requests. It is not a default HTTP header.
Other privileged SDK methods retain their own explicit credential contracts.
Keep the operator token out of agent processes; give the agent its minted
capability and its separately owned subject signer.

Legacy canonical `scopes: [strings]` requests also require a public subject key.
Their shorthand grants do not require DPoP; request `dpop_required=True` on the
structured `ToolGrant` scope to require sender possession.

## What is in the box

- `ChioClient` -- async client for sidecar health, capability minting and
  validation, fail-closed attenuation, receipt verification, and tool-call
  evaluation.
- Typed models -- `CapabilityToken`, `ChioScope`, `ToolGrant`,
  `ResourceGrant`, `PromptGrant`, `Operation`, `Constraint`, `Decision`,
  `Verdict`, `ChioReceipt`, `HttpReceipt`, `CallerIdentity`, and the
  supporting types. See `chio_sdk.models`.
- Errors -- `ChioError` and the `ChioConnectionError`,
  `ChioDeniedError`, `ChioTimeoutError`, `ChioValidationError`
  subclasses. Errors fail closed: a denial or an unreachable sidecar
  raises rather than silently allowing.

## Testing

The mock does not cryptographically validate caller public keys; real sidecar
subject validation is covered by the production router tests.

The SDK ships a drop-in `MockChioClient` via `chio_sdk.testing`, with
`allow_all()`, `deny_all()`, and `with_policy(...)` helpers so you can
exercise capability-checked code paths without a running sidecar:

```python
from chio_sdk.testing import allow_all, deny_all
```

## License

Apache-2.0
