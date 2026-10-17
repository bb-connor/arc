# chio-lambda-extension

A detect-only Chio observer packaged as an **AWS Lambda Extension**. It runs
alongside the function handler, exposes a localhost HTTP evaluator that runs
portable capability evaluation, and writes each unsigned observation record
to DynamoDB before answering.

## Status: detect-only

* Evaluation results are **observations, not authorizations**. Every
  response carries `authorized: false`, `authoritative: false` and
  `boundary_class: "detect_only"`. The companion Python client treats every
  such response as a deny.
* Observations are **not Chio receipts**. They are unsigned JSON records with
  no kernel signature, so nothing downstream can verify them as receipts.
* No guard implementations are bundled. The guard pipeline must be selected
  explicitly with `CHIO_GUARDS=none`; any other value refuses to boot.
* Evaluation checks the capability token signature against the configured
  trusted issuers, its time window, and its tool scope.

## What it does

* **Registers** with the Lambda Extensions Runtime API for the `INVOKE` and
  `SHUTDOWN` lifecycle events.
* **Serves** an HTTP evaluator on `127.0.0.1:9090` that accepts JSON tool
  call descriptions and returns the observed allow / deny outcome with an
  observation ID.
* **Writes through** each observation to a configurable DynamoDB table with
  one `PutItem` before the response is sent. Nothing is buffered, so there
  is no capacity limit and nothing to flush on `SHUTDOWN`.
* **Fails closed**: missing or malformed configuration, or an unreachable
  Runtime API, exits non-zero at boot. An unreadable trusted clock, or an
  observation write that fails or exceeds 2 seconds, fails the evaluate
  request with HTTP 503 instead of answering without a stored record.

This crate is **outside** the main Chio Cargo workspace (it declares its own
`[workspace]` and lock file). CI builds, lints and tests it through its own
manifest.

## Configuration

| Variable                      | Required | Default             | Meaning                                         |
|-------------------------------|----------|---------------------|-------------------------------------------------|
| `CHIO_OBSERVATION_TABLE`      | yes      | _(none)_            | DynamoDB table observations are written to.     |
| `CHIO_GUARDS`                 | yes      | _(none)_            | Guard set. The only accepted value is `none`.   |
| `CHIO_TRUSTED_ISSUERS`        | yes      | _(none)_            | JSON array of trusted issuer public keys (hex). |
| `CHIO_CAPABILITY_TOKENS_JSON` | no       | _(none)_            | JSON object of capability tokens by ID, used when a request carries no inline token. |
| `CHIO_EXTENSION_ADDR`         | no       | `127.0.0.1:9090`    | Local socket address for the evaluator.         |
| `AWS_LAMBDA_RUNTIME_API`      | auto     | set by Lambda       | Advertised by the Lambda runtime at boot.       |
| `AWS_REGION` etc.             | auto     | set by Lambda       | Standard AWS SDK credential discovery.          |
| `RUST_LOG`                    | no       | `chio_lambda_extension=info` | Tracing filter.                        |

## DynamoDB schema

The extension does **not** create the table; provision it in your IaC:

```yaml
ObservationTable:
  Type: AWS::DynamoDB::Table
  Properties:
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: observation_id
        AttributeType: S
      - AttributeName: timestamp
        AttributeType: N
    KeySchema:
      - AttributeName: observation_id
        KeyType: HASH        # partition key
      - AttributeName: timestamp
        KeyType: RANGE       # sort key
```

Every item written by the extension carries:

| attribute        | type | meaning                                    |
|------------------|------|--------------------------------------------|
| `observation_id` | S    | UUIDv7 unique observation identifier.      |
| `timestamp`      | N    | Unix seconds from the trusted clock.       |
| `capability_id`  | S    | Capability token the call was bound to.    |
| `tool_server`    | S    | Tool server identifier.                    |
| `tool_name`      | S    | Name of the invoked tool.                  |
| `decision`       | S    | Observed `allow` or `deny`.                |
| `reason`         | S    | Optional deny reason.                      |
| `payload`        | S    | JSON of the full observation response.     |

Each write uses the AWS SDK's standard retry policy, bounded by the 2 second
write timeout.

## Evaluator HTTP surface

The evaluator deliberately speaks a minimal JSON over HTTP/1.1 dialect so
that any language can call it with the standard library alone.

### `GET /health`, `GET /chio/health`

```json
{"status": "ok", "extension": "chio"}
```

### `POST /v1/evaluate`

Request:

```json
{
  "capability_id": "cap-01HW...",
  "tool_server":  "tools.example",
  "tool_name":    "database-query",
  "arguments":    {"sql": "SELECT 1"}
}
```

The capability token is supplied inline as `capability`, in the
`x-chio-capability` header, or by ID through `CHIO_CAPABILITY_TOKENS_JSON`.
Trusted issuers come only from `CHIO_TRUSTED_ISSUERS`. Unknown fields,
including `scope` and `trusted_issuers`, are rejected with HTTP 400.

Response (HTTP 200):

```json
{
  "observation_id": "01908f4a-...",
  "decision":       "allow",
  "authorized":     false,
  "authoritative":  false,
  "boundary_class": "detect_only",
  "reason":         null,
  "metadata":       null,
  "capability_id":  "cap-01HW...",
  "tool_server":    "tools.example",
  "tool_name":      "database-query",
  "timestamp":      1713225600
}
```

A missing `capability_id`, `tool_server` or `tool_name`, an unresolvable or
untrusted capability token, or an out-of-scope call returns
`"decision": "deny"` with a descriptive `reason`.

Error responses (HTTP 503, no observation is recorded):

| `error`                  | Meaning                                         |
|--------------------------|-------------------------------------------------|
| `clock_unavailable`      | The trusted clock could not be read; `message` is the clock error code. |
| `observation_unrecorded` | The DynamoDB write failed or timed out.         |

## Build

```bash
# From the crate root:
cd sdks/lambda/chio-lambda-extension
CARGO_TARGET_DIR=target/lambda cargo build --release

# Run the tests:
CARGO_TARGET_DIR=target/lambda cargo test
```

### Cross-compile for Lambda

Lambda requires a Linux binary. Install the matching Rust targets and a
cross-linker:

```bash
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu

# On macOS, install cross-linkers, e.g. via brew or the `cross` crate:
cargo install cross --git https://github.com/cross-rs/cross
```

Then:

```bash
# Build both architectures, zip them into Lambda Layer structure:
./scripts/package-layer.sh both
# -> dist/chio-extension-arm64.zip
# -> dist/chio-extension-x86_64.zip

# Or one arch at a time:
./scripts/package-layer.sh arm64
./scripts/package-layer.sh x86_64
```

The script produces a zip with the standard Lambda Extension layout:

```
extensions/chio              # the registered extension binary
bin/chio-lambda-extension    # same binary, on PATH for debugging
```

## Publish the Lambda layer

```bash
aws lambda publish-layer-version \
  --layer-name chio-kernel-extension \
  --description 'Chio detect-only observer as Lambda Extension' \
  --zip-file fileb://dist/chio-extension-arm64.zip \
  --compatible-architectures arm64 \
  --compatible-runtimes python3.11 python3.12 python3.13 nodejs20.x nodejs22.x
```

Then reference the layer ARN on your function and grant the function's
execution role `dynamodb:PutItem` on `CHIO_OBSERVATION_TABLE`.

## Using from Python

Install the companion client. Against this detect-only extension every
verdict is denied, so `verdict.denied` is always true and `@chio_tool`
handler bodies do not run.

```bash
pip install chio-lambda-python  # or use the in-repo workspace dep
```

```python
from chio_lambda import ChioLambdaClient, chio_tool

# Option 1: thin HTTP client
client = ChioLambdaClient()
verdict = client.evaluate(
    capability_id="cap-01HW...",
    tool_server="tools.example",
    tool_name="database-query",
    arguments={"sql": "SELECT 1"},
)
if verdict.denied:
    return {"statusCode": 403, "body": verdict.reason}

# Option 2: decorator (evaluates before the function body runs)
@chio_tool(tool_server="tools.example", tool_name="database-query")
def handler(event, context, capability_id):
    # Body only runs on an authoritative prevent allow
    return run_query(event["body"])
```

See `../chio-lambda-python/README.md` for the full client reference.
