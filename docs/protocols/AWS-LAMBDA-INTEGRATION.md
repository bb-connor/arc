# AWS Lambda Integration: Serverless Tool Server Security

> **Status**: Tier 1 -- proposed April 2026
> **Priority**: High -- serverless functions are a natural deployment model
> for tool servers. Lambda Extensions provide a sidecar-equivalent mechanism
> that can run the Chio kernel alongside each function invocation.

## 1. Why Lambda

AWS Lambda is the dominant serverless compute platform. Agent tool servers
deployed as Lambda functions inherit automatic scaling, pay-per-invocation
pricing, and zero infrastructure management. But they also lose the ability
to run a persistent sidecar -- the standard Chio deployment model.

Lambda Extensions solve this. An Extension runs as a co-process alongside
the function handler, persists across warm invocations, and can intercept
the function lifecycle. This is the Chio sidecar model adapted for serverless.

### What Chio Adds to Lambda

| Lambda alone | Lambda + Chio |
|--------------|--------------|
| IAM role-based authorization | Capability-scoped, time-bounded, per-tool authorization |
| CloudWatch logs | Merkle-committed, signed receipt log |
| No tool-level policy | Guard pipeline evaluates each invocation |
| Binary allow/deny | Budget-aware, scope-narrowing, conditional access |
| No cross-invocation audit trail | Receipt chain links related invocations |

## 2. Architecture

### 2.1 Lambda Extension Model

```
Lambda Execution Environment
+----------------------------------------------------------+
|                                                          |
|  +------------------+     +---------------------------+  |
|  | Function Handler |     | Chio Extension             |  |
|  |                  |     |                           |  |
|  | async def handler|---->| HTTP :9090 (internal)     |  |
|  |   arc.evaluate() |     | Capability | Guard | Rcpt |  |
|  |   ... do work ...|     |                           |  |
|  |   arc.receipt()  |     | Lifecycle hooks:          |  |
|  +------------------+     |   INVOKE -> pre-evaluate  |  |
|                           |   SHUTDOWN -> flush rcpts |  |
|                           +---------------------------+  |
|                                                          |
|  +--------------------------------------------------+   |
|  | Lambda Runtime API                                |   |
|  +--------------------------------------------------+   |
+----------------------------------------------------------+
```

### 2.2 Extension Lifecycle

Lambda Extensions participate in three lifecycle phases:

1. **INIT** -- The Chio extension starts, loads policy from S3/SSM/bundled
   config, initializes the kernel, and opens the local HTTP listener on
   port 9090. This happens once per cold start.

2. **INVOKE** -- For each function invocation, the extension receives the
   event before the handler. In "transparent" mode, it pre-evaluates the
   invocation against policy. In "explicit" mode, the handler calls the
   extension via HTTP.

3. **SHUTDOWN** -- The extension flushes any buffered receipts to the
   configured receipt sink (S3, DynamoDB, or remote Chio control plane)
   before the execution environment is recycled.

### 2.3 Cold Start Optimization

The Chio kernel is a small Rust binary. Compiled as a Lambda Extension
Layer, it adds minimal cold start overhead:

```
Component                Cold start delta
----------------------------------------------
Chio kernel binary        ~15ms (precompiled ARM64)
Policy load (bundled)    ~2ms
Policy load (S3)         ~40-80ms (cached after first)
Guard WASM init          ~10-30ms per guard
----------------------------------------------
Total (bundled policy)   ~25-50ms
Total (S3 policy)        ~65-125ms
```

For warm invocations, the extension is already running -- zero overhead
beyond the HTTP call to port 9090 (~1-2ms loopback).

## 3. Integration Modes

### 3.1 Transparent Mode (Lambda Extension Hook)

The extension intercepts every invocation automatically. No code changes
to the handler:

```yaml
# chio-policy.yaml (bundled in layer or loaded from S3)
mode: transparent
evaluation:
  # Map Lambda event fields to Chio evaluation context
  identity_field: "requestContext.authorizer.principalId"
  tool_field: "resource"         # API Gateway resource path
  scope_field: "httpMethod"      # GET -> read, POST -> write
  arguments_field: "body"

policy:
  default: deny
  rules:
    - tool: "/api/search"
      scopes: ["tools:search:invoke"]
      guards: ["rate-limit", "pii-filter"]
    - tool: "/api/write"
      scopes: ["tools:write:invoke"]
      guards: ["approval-required"]
```

### 3.2 Explicit Mode (Handler SDK)

The handler calls Chio explicitly for fine-grained control:

**Python:**

```python
from chio_lambda import ChioLambda

arc = ChioLambda()  # connects to extension on :9090

async def handler(event, context):
    # Evaluate capability before executing tool logic
    verdict = await arc.evaluate(
        tool="database-query",
        scope="db:read",
        arguments=event["body"],
        identity=event["requestContext"]["authorizer"],
    )

    if verdict.denied:
        return {
            "statusCode": 403,
            "body": json.dumps({
                "error": "capability_denied",
                "reason": verdict.reason,
                "receipt_id": verdict.receipt_id,
            }),
        }

    # Execute the actual tool logic
    result = execute_query(event["body"])

    # Record successful execution receipt
    receipt = await arc.record(
        verdict=verdict,
        result_hash=sha256(json.dumps(result)),
    )

    return {
        "statusCode": 200,
        "body": json.dumps(result),
        "headers": {"X-Chio-Receipt": receipt.receipt_id},
    }
```

**TypeScript/Node:**

```typescript
import { ChioLambda } from "@chio-protocol/lambda";

const arc = new ChioLambda();

export const handler = async (event: APIGatewayProxyEvent) => {
  const verdict = await arc.evaluate({
    tool: "database-query",
    scope: "db:read",
    arguments: JSON.parse(event.body ?? "{}"),
    identity: event.requestContext.authorizer,
  });

  if (verdict.denied) {
    return { statusCode: 403, body: JSON.stringify({ error: verdict.reason }) };
  }

  const result = await executeQuery(event.body);

  const receipt = await arc.record({
    verdict,
    resultHash: sha256(JSON.stringify(result)),
  });

  return {
    statusCode: 200,
    body: JSON.stringify(result),
    headers: { "X-Chio-Receipt": receipt.receiptId },
  };
};
```

### 3.3 API Gateway Authorizer Mode

Chio can run as a Lambda Authorizer, evaluating capabilities at the API
Gateway layer before the function is even invoked:

```
Client -> API Gateway -> Chio Authorizer Lambda -> Policy decision
                              |                        |
                              |                   allow/deny
                              |                        |
                              +-----> Target Lambda (only if allowed)
```

```python
# chio_authorizer.py -- deployed as a separate Lambda
from chio_lambda import ChioAuthorizer

authorizer = ChioAuthorizer(policy_source="s3://my-bucket/chio-policy.yaml")

def handler(event, context):
    return authorizer.evaluate(event)
    # Returns IAM policy document with allow/deny
```

## 4. Receipt Persistence

Lambda functions are ephemeral. Receipts must be flushed to durable storage
before the execution environment is recycled.

### Receipt Sinks

| Sink | Latency | Durability | Cost |
|------|---------|------------|------|
| DynamoDB | ~5ms | High | Per-write |
| S3 (buffered) | ~50ms | High | Per-object (batch) |
| SQS -> processor | ~10ms | High | Per-message |
| Chio Control Plane | ~20-50ms | High | Managed |

### Flush Strategy

```
Per-invocation:
  verdict -> DynamoDB (immediate, single item)

Batch (SHUTDOWN hook):
  buffered receipts -> S3 (batch write, one object per environment lifecycle)

Async:
  receipt IDs -> SQS -> receipt aggregator Lambda -> Merkle tree update
```

## 5. Lambda@Edge and CloudFront Functions

For distributed tool access at the edge:

```
CloudFront -> Lambda@Edge (Chio evaluation) -> Origin (tool server)
```

Lambda@Edge constraints: 5s timeout (viewer request), 30s (origin request),
no VPC access, limited package size. The Chio evaluation must be:

- Bundled policy only (no S3 fetch at edge)
- Pre-compiled guards (no WASM runtime at edge -- use pre-evaluated policy)
- Receipt buffered to CloudWatch, flushed asynchronously

This is a restricted mode: full guard evaluation happens at the origin;
edge evaluation handles scope checks and token validation only.

## 6. Infrastructure as Code

### SAM Template

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Resources:
  ChioExtensionLayer:
    Type: AWS::Serverless::LayerVersion
    Properties:
      LayerName: chio-kernel-extension
      Description: Chio protocol kernel as Lambda Extension
      ContentUri: layers/chio-extension/
      CompatibleRuntimes:
        - python3.12
        - python3.13
        - nodejs20.x
        - nodejs22.x
      CompatibleArchitectures:
        - arm64
        - x86_64

  ToolFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: handler.handler
      Runtime: python3.13
      Architectures: [arm64]
      Layers:
        - !Ref ChioExtensionLayer
      Environment:
        Variables:
          CHIO_POLICY_SOURCE: !Sub "s3://${PolicyBucket}/chio-policy.yaml"
          CHIO_RECEIPT_TABLE: !Ref ReceiptTable
      Policies:
        - S3ReadPolicy:
            BucketName: !Ref PolicyBucket
        - DynamoDBCrudPolicy:
            TableName: !Ref ReceiptTable

  ReceiptTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: chio-receipts
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: receipt_id
          AttributeType: S
        - AttributeName: workflow_id
          AttributeType: S
      KeySchema:
        - AttributeName: receipt_id
          KeyType: HASH
      GlobalSecondaryIndexes:
        - IndexName: by-workflow
          KeySchema:
            - AttributeName: workflow_id
              KeyType: HASH
          Projection:
            ProjectionType: ALL
```

### CDK (TypeScript)

```typescript
import { ChioExtensionLayer } from "@chio-protocol/cdk";

const arcLayer = new ChioExtensionLayer(this, "ChioExtension", {
  policySource: PolicySource.s3(policyBucket, "chio-policy.yaml"),
  receiptSink: ReceiptSink.dynamodb(receiptTable),
});

const toolFn = new lambda.Function(this, "ToolFunction", {
  runtime: lambda.Runtime.PYTHON_3_13,
  handler: "handler.handler",
  layers: [arcLayer],
});
```

## 7. Package Structure

```
sdks/lambda/
  chio-lambda-extension/
    Cargo.toml              # Rust binary, compiles to Lambda Extension
    src/
      main.rs               # Extension lifecycle (INIT/INVOKE/SHUTDOWN)
      evaluator.rs          # HTTP server on :9090
      receipt_sink.rs       # DynamoDB/S3/SQS flush
    Makefile                # Cross-compile for arm64/x86_64 Lambda

  chio-lambda-python/
    pyproject.toml          # deps: chio-sdk-python
    src/chio_lambda/
      __init__.py
      client.py             # ChioLambda, ChioAuthorizer
      transparent.py        # Event-to-evaluation mapping

  chio-lambda-node/
    package.json            # deps: @chio-protocol/node-http
    src/
      index.ts
      client.ts             # ChioLambda class

  chio-lambda-cdk/
    package.json            # CDK constructs
    src/
      extension-layer.ts
      constructs.ts
```

## 8. Open Questions

1. **Provisioned concurrency.** With provisioned concurrency, the extension
   is always warm. Should the extension pre-fetch and cache policy updates
   on a background timer in this mode?

2. **SnapStart (Java).** Lambda SnapStart checkpoints the JVM after INIT.
   The Chio extension state must be checkpoint-safe -- no open sockets or
   time-dependent state at checkpoint time.

3. **Function URLs vs. API Gateway.** Function URLs bypass API Gateway.
   The Authorizer pattern does not apply. Should the extension automatically
   switch to transparent mode when invoked via Function URL?

4. **Multi-function workflows.** Step Functions orchestrating multiple
   Lambda functions -- should each function carry a grant token that the
   orchestrator acquired, similar to the Temporal `WorkflowGrant` model?
