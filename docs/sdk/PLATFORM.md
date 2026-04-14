# Platform-Level SDKs

This document covers ARC's platform-level SDK integrations: middleware and
controllers that embed ARC evaluation into infrastructure rather than
application code.

All platform SDKs communicate with the ARC Rust kernel running as a localhost
sidecar. They send evaluation requests to `POST /arc/evaluate`, enforce the
returned verdict, and attach the signed receipt to the response. The normative
sidecar protocol is defined in `spec/HTTP-SUBSTRATE.md`.

---

## 1. arc-tower (Rust)

**Location:** `crates/arc-tower`

A `tower::Layer` that wraps any Tower-compatible HTTP service with ARC
capability validation and receipt signing. Works with Axum (HTTP) and
Tonic (gRPC).

### API Surface

```rust
use arc_tower::ArcLayer;
use arc_core_types::crypto::Keypair;
use tower::Layer;

// Generate or load a kernel keypair.
let keypair = Keypair::generate();

// Create the ARC layer with a keypair and policy hash.
let layer = ArcLayer::new(keypair, "policy-hash-abc".to_string());

// Wrap any tower::Service.
let service = layer.layer(inner_service);
```

### Evaluator Configuration

The `ArcEvaluator` supports builder-style configuration:

```rust
use arc_tower::{ArcEvaluator, ArcLayer};
use arc_core_types::crypto::Keypair;

let keypair = Keypair::generate();
let evaluator = ArcEvaluator::new(keypair, "policy-hash".to_string())
    .with_identity_extractor(custom_extractor)
    .with_route_resolver(custom_resolver)
    .with_fail_open(false); // fail-closed by default

let layer = ArcLayer::from_evaluator(evaluator);
```

### What It Does

- Extracts caller identity from request headers (Bearer tokens, API keys,
  mTLS certificates)
- Evaluates each request against the ARC kernel policy
- Safe methods (GET, HEAD, OPTIONS) are allowed with session-scoped receipts
- Side-effect methods (POST, PUT, PATCH, DELETE) require a capability token
  in the `X-Arc-Capability` header
- Signs an `HttpReceipt` for every request (allow or deny)
- Attaches the receipt ID as the `X-Arc-Receipt-Id` response header

### Axum Example

```rust
use axum::{Router, routing::get};
use arc_tower::ArcLayer;
use arc_core_types::crypto::Keypair;

let keypair = Keypair::generate();
let arc_layer = ArcLayer::new(keypair, "my-policy".to_string());

let app = Router::new()
    .route("/pets", get(list_pets).post(create_pet))
    .layer(arc_layer);
```

### Exports

| Export | Purpose |
|--------|---------|
| `ArcLayer` | Tower `Layer` implementation |
| `ArcService` | Tower `Service` wrapper |
| `ArcEvaluator` | Core evaluation logic (capability check, receipt signing) |
| `EvaluationResult` | Verdict + signed receipt + guard evidence |
| `ArcTowerError` | Error type for evaluation failures |
| `extract_identity` | Default identity extraction from HTTP headers |
| `IdentityExtractor` | Function type for custom identity extraction |

---

## 2. Kubernetes Controller

**Location:** `sdks/k8s/`

A Kubernetes admission controller that enforces ARC capability policies at
pod deployment time and optionally injects the ARC sidecar container.

### Components

| Component | Path | Purpose |
|-----------|------|---------|
| Validating webhook | `webhooks/validating-webhook.yaml` | Rejects pods without ARC capability annotations |
| Mutating webhook | `webhooks/mutating-webhook.yaml` | Injects the `arc-sidecar` container into annotated pods |
| ArcPolicy CRD | `crds/arcpolicy-crd.yaml` | Namespace-scoped policy defining required scopes and sidecar config |
| Controller | `controller/main.go` | Go binary serving `/validate` and `/mutate` endpoints |

### Validating Webhook

The validating webhook rejects pods that lack the required
`arc.backbay.io/capability-token` annotation, unless the pod carries an
explicit `arc.backbay.io/exempt: "true"` exemption.

The webhook is scoped to namespaces with the `arc.backbay.io/enforce: "true"`
label. It runs on pod CREATE and UPDATE operations.

### Mutating Webhook

The mutating webhook injects an `arc-sidecar` container when a pod has the
`arc.backbay.io/inject: "true"` annotation. The sidecar runs `arc api protect`
and proxies HTTP traffic through the ARC kernel on port 9090.

### Pod Annotations

| Annotation | Required | Description |
|------------|----------|-------------|
| `arc.backbay.io/capability-token` | Yes (unless exempt) | ARC capability token for the workload |
| `arc.backbay.io/required-scopes` | No | Comma-separated required ARC scopes |
| `arc.backbay.io/exempt` | No | Set to `"true"` to skip capability validation |
| `arc.backbay.io/inject` | No | Set to `"true"` to trigger sidecar injection |
| `arc.backbay.io/sidecar-image` | No | Override the default sidecar image (default: `ghcr.io/backbay-labs/arc:latest`) |
| `arc.backbay.io/upstream` | No | Upstream URL the sidecar proxies to (default: `http://127.0.0.1:8080`) |
| `arc.backbay.io/spec-path` | No | Path to the OpenAPI spec file inside the pod |
| `arc.backbay.io/receipt-store` | No | Receipt storage backend URI |

### ArcPolicy CRD

The `ArcPolicy` custom resource defines namespace-level capability requirements:

```yaml
apiVersion: arc.backbay.io/v1alpha1
kind: ArcPolicy
metadata:
  name: production-policy
  namespace: my-app
spec:
  requiredScopes:
    - "db:read"
    - "api:write"
  selector:
    matchLabels:
      app: my-service
  enforcement: enforce   # enforce | audit | disabled
  sidecarConfig:
    image: ghcr.io/backbay-labs/arc:v1.0
    upstream: http://127.0.0.1:8080
    autoInject: true
```

### Deployment

```bash
# Install CRDs
kubectl apply -f sdks/k8s/crds/

# Install webhooks
kubectl apply -f sdks/k8s/webhooks/

# Label namespaces for enforcement
kubectl label namespace my-app arc.backbay.io/enforce=true
kubectl label namespace my-app arc.backbay.io/inject=true
```

---

## 3. JVM (arc-spring-boot)

**Location:** `sdks/jvm/arc-spring-boot/`

A Spring Boot starter that auto-configures the ARC servlet filter. Add
the dependency and ARC protection is active with zero code changes.

### Configuration

In `application.properties` or `application.yml`:

```properties
arc.sidecar-url=http://127.0.0.1:9090
arc.timeout-seconds=5
arc.on-sidecar-error=deny
arc.enabled=true
arc.url-patterns=/*
arc.filter-order=1
```

Or via `application.yml`:

```yaml
arc:
  sidecar-url: http://127.0.0.1:9090
  timeout-seconds: 5
  on-sidecar-error: deny
  enabled: true
  url-patterns:
    - "/*"
```

### @ConfigurationProperties

The `ArcProperties` class maps the `arc.*` prefix:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `arc.sidecar-url` | String | `ARC_SIDECAR_URL` env or `http://127.0.0.1:9090` | Sidecar kernel URL |
| `arc.timeout-seconds` | Long | 5 | HTTP timeout for sidecar calls |
| `arc.on-sidecar-error` | String | `deny` | `deny` (fail-closed) or `allow` (fail-open) |
| `arc.enabled` | Boolean | true | Enable/disable ARC protection |
| `arc.url-patterns` | List | `["/*"]` | URL patterns to protect |
| `arc.filter-order` | Int | 1 | Servlet filter ordering |

### ArcFilter

The `ArcFilter` is a standard Jakarta Servlet `Filter` that:

1. Extracts caller identity from request headers
2. Resolves the route pattern
3. Hashes the request body (SHA-256)
4. Builds an `ArcHttpRequest` and sends it to `POST /arc/evaluate`
5. Attaches `X-Arc-Receipt-Id` to the response
6. Returns a structured JSON error on deny (403) or sidecar failure (502)

### Auto-Configuration

`ArcAutoConfiguration` registers the filter automatically when:
- `ArcFilter` is on the classpath (`@ConditionalOnClass`)
- `arc.enabled` is `true` or absent (`@ConditionalOnProperty`, `matchIfMissing = true`)

No `@Bean` declarations are needed in application code.

### Minimal Spring Boot Example

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.backbay:arc-spring-boot:1.0")
}

// application.properties
// arc.sidecar-url=http://127.0.0.1:9090

// That's it. ArcFilter is auto-registered.
```

---

## 4. .NET (ArcMiddleware)

**Location:** `sdks/dotnet/ArcMiddleware/`

ASP.NET Core middleware for ARC capability validation and receipt signing.
Two extension methods cover registration and pipeline insertion.

### Setup

```csharp
var builder = WebApplication.CreateBuilder(args);

// Register ARC services with optional configuration.
builder.Services.AddArcProtection(options =>
{
    options.SidecarUrl = "http://127.0.0.1:9090";
    options.TimeoutSeconds = 5;
    options.OnSidecarError = "deny"; // fail-closed
});

var app = builder.Build();

// Insert ARC middleware into the request pipeline.
app.UseArcProtection();

app.MapGet("/pets", () => Results.Ok(new[] { "dog", "cat" }));
app.Run();
```

### ArcMiddlewareOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `SidecarUrl` | string | `ARC_SIDECAR_URL` env or `http://127.0.0.1:9090` | Sidecar kernel URL |
| `TimeoutSeconds` | int | 5 | HTTP timeout for sidecar calls |
| `OnSidecarError` | string | `deny` | `deny` (fail-closed) or `allow` (fail-open) |
| `IdentityExtractor` | delegate | Header-based extraction | Custom identity extraction function |
| `RouteResolver` | delegate | Raw path passthrough | Custom route pattern resolver |

### Extension Methods

| Method | Purpose |
|--------|---------|
| `services.AddArcProtection()` | Register ARC services and options in the DI container |
| `app.UseArcProtection()` | Insert `ArcProtectMiddleware` into the ASP.NET Core pipeline |

### What the Middleware Does

1. Validates the HTTP method
2. Extracts caller identity (Bearer token, API key, or custom extractor)
3. Resolves the route pattern
4. Hashes the request body (SHA-256) with buffering enabled
5. Sends an `ArcHttpRequest` to `POST /arc/evaluate` on the sidecar
6. Attaches `X-Arc-Receipt-Id` to the response
7. Returns structured JSON errors on deny (403) or sidecar failure (502)
8. Calls `next(context)` on allow

### Minimal Example

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddArcProtection();

var app = builder.Build();
app.UseArcProtection();
app.MapGet("/hello", () => "world");
app.Run();
```

---

## Common Patterns

All four platform SDKs share the same operational model:

1. **Sidecar communication.** Every SDK talks to the ARC Rust kernel at
   `POST /arc/evaluate` on localhost. The kernel handles capability validation,
   guard evaluation, and receipt signing.

2. **Fail-closed by default.** If the sidecar is unreachable or returns an
   error, the request is denied. Fail-open mode is available as an explicit
   opt-in for each SDK.

3. **Receipt attachment.** Every evaluated request (allow or deny) produces a
   signed receipt. The receipt ID is attached as `X-Arc-Receipt-Id` on the
   HTTP response.

4. **Identity extraction.** Each SDK extracts caller identity from standard
   HTTP headers (Authorization, X-Api-Key, etc.) and supports custom
   extractors for application-specific identity models.

5. **Capability header.** Side-effect methods (POST, PUT, PATCH, DELETE) require
   a capability token in the `X-Arc-Capability` request header. Safe methods
   (GET, HEAD, OPTIONS) are allowed with session-scoped audit receipts.

For the normative sidecar evaluation protocol, see `spec/HTTP-SUBSTRATE.md`.
