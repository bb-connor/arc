# ARC Python SDK Reference

This document covers all five ARC Python packages. Each package communicates with the ARC Rust kernel via a localhost HTTP sidecar, so there is no native compilation or FFI required.

## Quick Start

```bash
# Core client (required by all other packages)
pip install arc-sdk-python

# Pick your framework integration
pip install arc-asgi       # Starlette, FastAPI, Litestar, any ASGI framework
pip install arc-fastapi    # FastAPI decorators and dependency injection
pip install arc-django     # Django/DRF middleware
pip install arc-langchain  # LangChain tool integration
```

```python
from arc_sdk.client import ArcClient

async with ArcClient() as client:
    healthy = await client.health()
    print(healthy)
```

## Sidecar Communication Model

All ARC Python SDKs communicate with the ARC Rust kernel through localhost HTTP. The kernel runs as a sidecar process alongside your application.

- **Default URL**: `http://127.0.0.1:9090`
- **Configurable via**: `ARC_SIDECAR_URL` environment variable or constructor argument
- **No native compilation or FFI**: pure Python over HTTP
- **Fail-closed by default**: when the sidecar is unreachable, requests are denied (503). Configure `fail_open=True` to change this behavior.

---

## 1. arc-sdk-python

The core client library. All other ARC Python packages depend on this.

### Installation

```bash
pip install arc-sdk-python
```

### ArcClient

Async HTTP client for the ARC sidecar kernel. Uses `httpx` under the hood.

```python
from arc_sdk.client import ArcClient

# Default: connects to http://127.0.0.1:9090
client = ArcClient()

# Custom URL and timeout
client = ArcClient("http://localhost:9090", timeout=15.0)

# Use as async context manager
async with ArcClient() as client:
    data = await client.health()
```

**Constructor parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_url` | `str \| None` | `"http://127.0.0.1:9090"` | Base URL of the ARC sidecar |
| `timeout` | `float` | `10.0` | Request timeout in seconds |

### Capability Operations

```python
from arc_sdk.client import ArcClient
from arc_sdk.models import ArcScope, ToolGrant, Operation

async with ArcClient() as client:
    # Create a capability token
    scope = ArcScope(grants=[
        ToolGrant(
            server_id="deploy-server",
            tool_name="deploy",
            operations=[Operation.INVOKE],
        ),
    ])
    token = await client.create_capability(
        subject="<hex-ed25519-pubkey>",
        scope=scope,
        ttl_seconds=3600,
    )

    # Validate a token
    is_valid = await client.validate_capability(token)

    # Attenuate (narrow) a token
    narrower_scope = ArcScope(grants=[
        ToolGrant(
            server_id="deploy-server",
            tool_name="deploy",
            operations=[Operation.INVOKE],
            max_invocations=5,
        ),
    ])
    child_token = await client.attenuate_capability(
        token, new_scope=narrower_scope
    )
```

### Tool Evaluation

```python
receipt = await client.evaluate_tool_call(
    capability_id="cap-abc-123",
    tool_server="my-server",
    tool_name="my-tool",
    parameters={"key": "value"},
)

if receipt.is_allowed:
    print(f"Allowed, receipt: {receipt.id}")
else:
    print(f"Denied by {receipt.decision.guard}: {receipt.decision.reason}")
```

### HTTP Request Evaluation

```python
from arc_sdk.models import CallerIdentity, AuthMethod

caller = CallerIdentity(
    subject="user-123",
    auth_method=AuthMethod.bearer(token_hash="abc..."),
    verified=False,
)

http_receipt = await client.evaluate_http_request(
    request_id="req-001",
    method="POST",
    route_pattern="/api/tools/{tool_id}",
    path="/api/tools/42",
    caller=caller,
    body_hash="sha256hex...",
    capability_id="cap-abc-123",
)
```

### Receipt Verification

```python
# Single receipt
valid = await client.verify_receipt(arc_receipt)

# HTTP receipt
valid = await client.verify_http_receipt(http_receipt)

# Receipt chain (contiguous content hashes)
chain_valid = await client.verify_receipt_chain([receipt1, receipt2, receipt3])
```

### Typed Models

All models use Pydantic v2 and match the Rust kernel's canonical JSON format.

**CapabilityToken** -- Ed25519-signed, scoped, time-bounded capability token.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Unique token identifier |
| `issuer` | `str` | Hex-encoded Ed25519 public key of the issuer |
| `subject` | `str` | Hex-encoded Ed25519 public key of the agent |
| `scope` | `ArcScope` | What this token authorizes |
| `issued_at` | `int` | Unix timestamp |
| `expires_at` | `int` | Unix timestamp |
| `delegation_chain` | `list[DelegationLink]` | Delegation history |
| `signature` | `str` | Hex-encoded Ed25519 signature |

**ArcReceipt** -- signed proof that a tool call was evaluated by the kernel.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Receipt identifier |
| `timestamp` | `int` | Unix timestamp |
| `capability_id` | `str` | Token used for the call |
| `tool_server` | `str` | Tool server ID |
| `tool_name` | `str` | Tool name |
| `action` | `ToolCallAction` | Parameters and their hash |
| `decision` | `Decision` | Kernel verdict (`allow`, `deny`, `cancelled`, `incomplete`) |
| `content_hash` | `str` | SHA-256 of canonical request content |
| `policy_hash` | `str` | Hash of the policy set used |
| `evidence` | `list[GuardEvidence]` | Per-guard evaluation evidence |
| `kernel_key` | `str` | Kernel's Ed25519 public key |
| `signature` | `str` | Ed25519 signature over the receipt |

**HttpReceipt** -- signed receipt for HTTP request evaluation.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Receipt identifier |
| `request_id` | `str` | Correlation ID for the HTTP request |
| `route_pattern` | `str` | Matched route pattern |
| `method` | `str` | HTTP method |
| `caller_identity_hash` | `str` | SHA-256 of caller identity |
| `verdict` | `Verdict` | HTTP-layer verdict |
| `evidence` | `list[GuardEvidence]` | Per-guard evaluation evidence |
| `response_status` | `int` | HTTP status code |
| `timestamp` | `int` | Unix timestamp |
| `content_hash` | `str` | SHA-256 of canonical request content |
| `policy_hash` | `str` | Policy set hash |
| `kernel_key` | `str` | Kernel's Ed25519 public key |
| `signature` | `str` | Ed25519 signature |

**Decision** -- kernel verdict on a tool call.

```python
from arc_sdk.models import Decision

d = Decision.allow()
d = Decision.deny(reason="rate limit exceeded", guard="velocity-guard")
d.is_allowed  # bool
d.is_denied   # bool
```

**Verdict** -- HTTP-layer verdict (extends Decision with `http_status`).

```python
from arc_sdk.models import Verdict

v = Verdict.deny(reason="forbidden", guard="rbac", http_status=403)
v.http_status  # 403
```

**CallerIdentity** and **AuthMethod**:

```python
from arc_sdk.models import CallerIdentity, AuthMethod

# Bearer token
caller = CallerIdentity(
    subject="token-hash",
    auth_method=AuthMethod.bearer(token_hash="abc123"),
    verified=False,
)

# API key
caller = CallerIdentity(
    subject="key-hash",
    auth_method=AuthMethod.api_key(key_name="x-api-key", key_hash="def456"),
    verified=False,
)

# Cookie
caller = CallerIdentity(
    subject="cookie-hash",
    auth_method=AuthMethod.cookie(cookie_name="session", cookie_hash="ghi789"),
    verified=False,
)

# Anonymous
caller = CallerIdentity.anonymous()
```

### Error Types

| Error | Code | When |
|-------|------|------|
| `ArcError` | varies | Base error for all SDK operations |
| `ArcConnectionError` | `CONNECTION_ERROR` | Cannot reach the sidecar |
| `ArcTimeoutError` | `TIMEOUT` | Sidecar request timed out |
| `ArcDeniedError` | `DENIED` | Kernel denied the request (has `.guard` and `.reason`) |
| `ArcValidationError` | `VALIDATION_ERROR` | Local validation failed before contacting sidecar |

---

## 2. arc-asgi

ASGI middleware for any ASGI framework (FastAPI, Starlette, Litestar, etc.).

### Installation

```bash
pip install arc-asgi
```

### Basic Usage

```python
from fastapi import FastAPI
from arc_asgi import ArcASGIMiddleware, ArcASGIConfig

app = FastAPI()
app.add_middleware(
    ArcASGIMiddleware,
    config=ArcASGIConfig(sidecar_url="http://127.0.0.1:9090"),
)
```

With Litestar:

```python
from litestar import Litestar
from arc_asgi import ArcASGIMiddleware

app = Litestar(middleware=[ArcASGIMiddleware])
```

### Configuration

`ArcASGIConfig` is a frozen dataclass with these fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sidecar_url` | `str` | `"http://127.0.0.1:9090"` | Sidecar base URL |
| `timeout` | `float` | `10.0` | Sidecar request timeout in seconds |
| `exclude_paths` | `frozenset[str]` | `frozenset()` | Paths to skip evaluation |
| `exclude_methods` | `frozenset[str]` | `frozenset({"OPTIONS"})` | HTTP methods to skip |
| `receipt_header` | `str` | `"X-Arc-Receipt"` | Response header for receipt ID |
| `fail_open` | `bool` | `False` | Allow requests when sidecar is unreachable |

```python
config = ArcASGIConfig(
    sidecar_url="http://127.0.0.1:9090",
    exclude_paths=frozenset({"/health", "/ready"}),
    exclude_methods=frozenset({"OPTIONS", "HEAD"}),
    fail_open=False,
)
```

### Identity Extractors

The middleware uses a `CompositeExtractor` by default, which tries these extractors in order:

1. **BearerTokenExtractor** -- `Authorization: Bearer <token>` header
2. **ApiKeyExtractor** -- `X-API-Key` header (configurable header name)
3. **CookieExtractor** -- `session` cookie (configurable cookie name)
4. Falls back to **anonymous** if none match

All credential values are hashed with SHA-256 before being sent to the sidecar. Raw secrets are never transmitted.

Custom extractors:

```python
from arc_asgi import ArcASGIMiddleware, ArcASGIConfig
from arc_asgi.extractors import (
    CompositeExtractor,
    BearerTokenExtractor,
    ApiKeyExtractor,
    CookieExtractor,
    IdentityExtractor,
)

# Custom composite with different order or config
extractor = CompositeExtractor([
    ApiKeyExtractor(header_name="x-my-api-key"),
    BearerTokenExtractor(),
    CookieExtractor(cookie_name="auth_session"),
])

app.add_middleware(
    ArcASGIMiddleware,
    config=ArcASGIConfig(),
    extractor=extractor,
)
```

You can implement `IdentityExtractor` to build fully custom extractors:

```python
from arc_asgi.extractors import IdentityExtractor
from arc_sdk.models import CallerIdentity

class MyExtractor(IdentityExtractor):
    def extract(self, scope: dict) -> CallerIdentity | None:
        # Return CallerIdentity or None to skip to next extractor
        ...
```

### Receipt Callback

```python
from arc_sdk.models import HttpReceipt

async def log_receipt(receipt: HttpReceipt) -> None:
    print(f"ARC receipt: {receipt.id}, verdict: {receipt.verdict.verdict}")

app.add_middleware(
    ArcASGIMiddleware,
    config=ArcASGIConfig(),
    on_receipt=log_receipt,
)
```

---

## 3. arc-fastapi

FastAPI-specific decorators and dependency injection for route-level ARC enforcement.

### Installation

```bash
pip install arc-fastapi
```

### Decorators

**`@arc_requires(server_id, tool_name, operations=None)`**

Enforces that the request carries a valid ARC capability token (via `X-Arc-Capability` header or `arc_capability` query parameter) authorizing the specified server/tool/operations.

```python
from fastapi import FastAPI, Request
from arc_fastapi import arc_requires

app = FastAPI()

@app.post("/tools/deploy")
@arc_requires("deploy-server", "deploy", ["Invoke"])
async def deploy(request: Request):
    receipt = request.state.arc_receipt  # HttpReceipt attached on success
    return {"status": "deployed", "receipt_id": receipt.id}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `server_id` | `str` | required | ARC tool server ID |
| `tool_name` | `str` | required | Tool name |
| `operations` | `list[str] \| None` | `["Invoke"]` | Required operations |

**`@arc_approval(threshold_cents=0, currency="USD")`**

Requires human approval above a monetary threshold. Must be combined with `@arc_requires`. Checks for an `X-Arc-Approval` header.

```python
@app.post("/tools/transfer")
@arc_approval(threshold_cents=10000)
@arc_requires("payments", "transfer", ["Invoke"])
async def transfer(request: Request):
    ...
```

**`@arc_budget(max_cost_cents, currency="USD")`**

Enforces a per-request budget limit. If the invocation cost would exceed the limit, the sidecar denies the request.

```python
@app.post("/tools/query")
@arc_budget(max_cost_cents=500, currency="USD")
@arc_requires("ai", "query", ["Invoke"])
async def query(request: Request):
    ...
```

### Dependency Injection

```python
from fastapi import Depends, Request
from arc_sdk.client import ArcClient
from arc_sdk.models import CallerIdentity, HttpReceipt
from arc_fastapi.dependencies import (
    get_arc_client,
    get_caller_identity,
    get_arc_receipt,
    set_arc_client,
)

# Inject the ARC client
@app.get("/items")
async def list_items(client: ArcClient = Depends(get_arc_client)):
    health = await client.health()
    ...

# Inject caller identity (extracted from request headers)
@app.get("/me")
async def whoami(caller: CallerIdentity = Depends(get_caller_identity)):
    return {"subject": caller.subject, "method": caller.auth_method.method}

# Inject receipt (set by middleware or decorators)
@app.get("/receipt")
async def show_receipt(receipt: HttpReceipt | None = Depends(get_arc_receipt)):
    if receipt is None:
        return {"status": "no receipt"}
    return {"receipt_id": receipt.id}

# Override the client singleton for testing
set_arc_client(mock_client)
set_arc_client(None)  # reset to default
```

---

## 4. arc-django

Django middleware for ARC protocol evaluation. Uses synchronous `httpx` since Django WSGI middleware runs synchronously.

### Installation

```bash
pip install arc-django
```

### Setup

Add to your Django settings:

```python
# settings.py

MIDDLEWARE = [
    # ... other middleware ...
    "arc_django.ArcDjangoMiddleware",
    # ... other middleware ...
]

# ARC configuration
ARC_SIDECAR_URL = "http://127.0.0.1:9090"  # default
ARC_FAIL_OPEN = False                        # default, fail-closed
ARC_EXCLUDE_PATHS = ["/health", "/ready"]    # paths to skip
ARC_EXCLUDE_METHODS = ["OPTIONS"]            # methods to skip (default)
ARC_RECEIPT_HEADER = "X-Arc-Receipt"         # response header (default)
ARC_TIMEOUT = 10.0                           # seconds (default)
```

### Django Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ARC_SIDECAR_URL` | `str` | `"http://127.0.0.1:9090"` | Sidecar base URL |
| `ARC_FAIL_OPEN` | `bool` | `False` | Allow when sidecar is down |
| `ARC_EXCLUDE_PATHS` | `list[str]` | `[]` | Paths to skip evaluation |
| `ARC_EXCLUDE_METHODS` | `list[str]` | `["OPTIONS"]` | HTTP methods to skip |
| `ARC_RECEIPT_HEADER` | `str` | `"X-Arc-Receipt"` | Response header name for receipt ID |
| `ARC_TIMEOUT` | `float` | `10.0` | Request timeout in seconds |

### Accessing Receipts in Views

```python
from django.http import JsonResponse

def my_view(request):
    # Receipt is attached by middleware on successful evaluation
    receipt = getattr(request, "arc_receipt", None)
    if receipt:
        return JsonResponse({
            "receipt_id": receipt.get("id"),
            "verdict": receipt.get("verdict", {}).get("verdict"),
        })
    return JsonResponse({"status": "no receipt"})
```

### DRF Support

The middleware works with Django REST Framework out of the box. It runs at the Django middleware layer, so all DRF views benefit from ARC evaluation automatically.

### Identity Extraction

The Django middleware extracts caller identity from request headers using the same priority as other ARC SDKs:

1. `Authorization: Bearer <token>` header
2. `X-API-Key` header
3. `session` cookie
4. Falls back to anonymous

---

## 5. arc-langchain

Wrap ARC tools as LangChain `BaseTool` objects for use in agents, chains, and pipelines.

### Installation

```bash
pip install arc-langchain
```

### ArcToolkit (Auto-Discovery)

Discover tools from the sidecar's registered tool server manifests:

```python
from arc_langchain import ArcToolkit

toolkit = ArcToolkit(
    capability_id="cap-abc-123",
    sidecar_url="http://127.0.0.1:9090",
)

# Discover all tools from all servers
tools = await toolkit.get_tools()

# Discover tools from a specific server only
tools = await toolkit.get_tools(server_id="my-server")
```

**ArcToolkit constructor:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `capability_id` | `str` | required | ARC capability token ID |
| `sidecar_url` | `str` | `"http://127.0.0.1:9090"` | Sidecar base URL |

### ArcTool (Manual Creation)

Create a tool when you know the definition ahead of time:

```python
tool = toolkit.create_tool(
    name="search",
    description="Search the knowledge base",
    server_id="knowledge-server",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "limit": {"type": "integer", "description": "Max results"},
        },
        "required": ["query"],
    },
)
```

### Using with LangChain Agents

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI

toolkit = ArcToolkit(capability_id="cap-abc-123")
tools = await toolkit.get_tools()

llm = ChatOpenAI(model="gpt-4")
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

result = await executor.ainvoke({"input": "Deploy the latest build"})
```

ARC tools require async invocation. They raise `NotImplementedError` if called synchronously. Use `ainvoke` or `_arun`.

### Accessing Receipts

After each tool invocation, the signed receipt is stored on the tool:

```python
tool = toolkit.create_tool(
    name="deploy",
    description="Deploy to production",
    server_id="deploy-server",
)

result = await tool.ainvoke({"environment": "production"})
receipt = tool.last_receipt  # ArcReceipt or None
if receipt and receipt.is_allowed:
    print(f"Deployed with receipt {receipt.id}")
```

### Error Handling

On denial or sidecar errors, ArcTool returns a JSON string with error details rather than raising an exception. This allows LangChain agents to observe and react to denials:

```json
{"error": "denied", "guard": "velocity-guard", "reason": "rate limit exceeded"}
```
