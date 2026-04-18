# arc-lambda-python

Python client for the [ARC Lambda Extension](../arc-lambda-extension/).

The extension runs in-process alongside the Lambda function handler and
exposes an evaluator on `http://127.0.0.1:9090`. This package wraps that
endpoint with a typed synchronous client and a `@arc_tool` decorator so a
handler can gate every invocation with a capability check.

## Install

```bash
pip install arc-lambda-python
```

During local development (inside this monorepo) install with the workspace
path dep that pyproject.toml already wires up:

```bash
cd sdks/lambda/arc-lambda-python
uv pip install -e '.[dev]'
```

## Quickstart

```python
from arc_lambda import ArcLambdaClient, ArcLambdaError

client = ArcLambdaClient()  # defaults to http://127.0.0.1:9090

def handler(event, context):
    try:
        verdict = client.evaluate(
            capability_id=event["arc_capability_id"],
            tool_server="tools.example",
            tool_name="database-query",
            scope="db:read",
            arguments={"sql": event["body"]},
        )
    except ArcLambdaError as exc:
        # Fail-closed: treat unreachable extension as a deny.
        return {"statusCode": 503, "body": f"ARC unreachable: {exc}"}

    if verdict.denied:
        return {
            "statusCode": 403,
            "body": verdict.reason or "capability denied",
        }

    result = run_query(event["body"])
    return {
        "statusCode": 200,
        "body": result,
        "headers": {"X-Arc-Receipt": verdict.receipt_id},
    }
```

## Decorator usage

```python
from arc_lambda import arc_tool

@arc_tool(
    scope="db:read",
    tool_server="tools.example",
    tool_name="database-query",
)
def handler(event, context, capability_id, verdict):
    # Runs only if the extension returns allow. The decorator injects
    # `capability_id` and `verdict` if the wrapped function declares them.
    return run_query(event["body"])
```

The decorator looks for the capability id in this order:

1. Explicit `capability_id=...` keyword on the call.
2. `event["arc_capability_id"]` (key configurable via
   `capability_event_key`).
3. `$ARC_CAPABILITY_ID` environment variable (name configurable via
   `capability_env`).

If none of those resolve, the decorator raises `ArcLambdaError` without
calling the wrapped function. If the extension is unreachable or denies
the request, the decorator also raises `ArcLambdaError` -- ensuring
handlers cannot silently bypass policy.

## Testing

```bash
cd sdks/lambda/arc-lambda-python
uv run pytest
uv run ruff check src/ tests/
uv run mypy src/
```

The test suite uses `httpx.MockTransport` so no live extension is
required.

## Fail-closed contract

* `ArcLambdaClient.evaluate` raises `ArcLambdaError` when the extension is
  unreachable, times out, returns 5xx, returns non-JSON, or returns a JSON
  body missing `decision` / `receipt_id`.
* Any `decision` value other than the literal string `"allow"` is
  surfaced as `verdict.denied == True`.
* `@arc_tool` raises on both deny and unreachable. Handlers only run when
  the extension unambiguously said `allow`.
