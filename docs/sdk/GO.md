# ARC Go SDK Reference

This document covers the `arc-go-http` package, which provides HTTP middleware for the ARC protocol in Go. It wraps any `http.Handler` with capability validation and receipt signing via the ARC sidecar.

## Quick Start

```bash
go get github.com/backbay-labs/arc/sdks/go/arc-go-http
```

```go
package main

import (
	"net/http"

	arc "github.com/backbay-labs/arc/sdks/go/arc-go-http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/pets", handlePets)

	protected := arc.Protect(mux, arc.ConfigFile("arc.yaml"))
	http.ListenAndServe(":8080", protected)
}

func handlePets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`[{"name":"Fido"}]`))
}
```

## Sidecar Communication Model

The Go SDK communicates with the ARC Rust kernel through localhost HTTP. The kernel runs as a sidecar process alongside your application.

- **Default URL**: `http://127.0.0.1:9090`
- **Configurable via**: `ARC_SIDECAR_URL` environment variable or `WithSidecarURL()` option
- **No native compilation or FFI**: pure Go over HTTP using `net/http`
- **Fail-closed by default**: when the sidecar is unreachable, requests are denied with a 502 response. Use `WithOnSidecarError("allow")` to change this.

---

## arc.Protect

`Protect` wraps any `http.Handler` with ARC capability validation. All requests are evaluated against the sidecar before being forwarded to the inner handler.

```go
func Protect(handler http.Handler, opts ...Option) http.Handler
```

Allowed requests proceed with an `X-Arc-Receipt-Id` response header. Denied requests receive a structured JSON error response.
Fail-open passthroughs proceed without that header and expose an explicit
`ArcPassthrough` marker on the request context.

### Request Flow

1. Normalize and validate the HTTP method
2. Extract caller identity from request headers
3. Resolve the route pattern
4. Build an `ArcHTTPRequest` (with body hash, query params, headers)
5. POST to `{sidecarURL}/arc/evaluate`
6. On allow: forward to inner handler with receipt header
7. On deny: return JSON error with receipt ID and suggestion

---

## Configuration Options

Pass options as variadic arguments to `Protect`:

```go
protected := arc.Protect(handler,
	arc.ConfigFile("arc.yaml"),
	arc.WithSidecarURL("http://127.0.0.1:9090"),
	arc.WithTimeout(10),
	arc.WithOnSidecarError("deny"),
	arc.WithIdentityExtractor(myExtractor),
	arc.WithRouteResolver(myResolver),
)
```

### Option Reference

**`ConfigFile(path string)`**

Set the path to the `arc.yaml` configuration file. The sidecar reads route patterns and policies from this file.

```go
arc.ConfigFile("arc.yaml")
```

**`WithSidecarURL(url string)`**

Override the sidecar base URL. By default, reads from the `ARC_SIDECAR_URL` environment variable, falling back to `http://127.0.0.1:9090`.

```go
arc.WithSidecarURL("http://localhost:9090")
```

**`WithTimeout(seconds int)`**

Set the HTTP timeout for sidecar calls in seconds. Default: 5.

```go
arc.WithTimeout(10)
```

**`WithOnSidecarError(behavior string)`**

Control behavior when the sidecar is unreachable.

| Value | Behavior |
|-------|----------|
| `"deny"` | Fail-closed (default). Return 502 error. |
| `"allow"` | Fail-open. Forward request to inner handler without attaching an ARC receipt header. |

```go
arc.WithOnSidecarError("allow")  // fail-open
```

Retrieve the explicit degraded-state marker inside a handler:

```go
func handler(w http.ResponseWriter, r *http.Request) {
	if passthrough, ok := arc.GetArcPassthrough(r); ok {
		log.Printf("ARC passthrough: %s (%s)", passthrough.Mode, passthrough.Error)
	}
}
```

**`WithIdentityExtractor(fn IdentityExtractorFunc)`**

Provide a custom identity extraction function. The default extractor (`DefaultIdentityExtractor`) checks headers in this order:

1. `Authorization: Bearer <token>` -- hashes the token with SHA-256
2. `X-API-Key` / `X-Api-Key` / `x-api-key` -- hashes the key value
3. First cookie -- hashes the cookie value
4. Falls back to anonymous

```go
arc.WithIdentityExtractor(func(r *http.Request) arc.CallerIdentity {
	// Custom extraction logic
	return arc.CallerIdentity{
		Subject: "custom-subject",
		AuthMethod: arc.AuthMethod{
			Method:    "bearer",
			TokenHash: "sha256hex...",
		},
		Verified: true,
	}
})
```

**`WithRouteResolver(fn RouteResolverFunc)`**

Map a raw request path to a route pattern. This is important for frameworks that use path parameters (e.g., `/pets/42` should resolve to `/pets/{petId}` for consistent policy evaluation).

The default resolver returns the raw path.

```go
arc.WithRouteResolver(func(method, path string) string {
	// Use your router's pattern matching
	return path
})
```

---

## Types

### CallerIdentity

```go
type CallerIdentity struct {
	Subject    string     `json:"subject"`
	AuthMethod AuthMethod `json:"auth_method"`
	Verified   bool       `json:"verified"`
	Tenant     string     `json:"tenant,omitempty"`
	AgentID    string     `json:"agent_id,omitempty"`
}
```

**Helper:**

```go
anon := arc.AnonymousIdentity()
```

### AuthMethod

Tagged union matching the Rust serde format. Set the `Method` field to indicate the variant, and populate the relevant fields for that method type.

```go
type AuthMethod struct {
	Method      string `json:"method"`          // "bearer", "api_key", "cookie", "mtls_certificate", "anonymous"
	TokenHash   string `json:"token_hash,omitempty"`   // bearer
	KeyName     string `json:"key_name,omitempty"`     // api_key
	KeyHash     string `json:"key_hash,omitempty"`     // api_key
	CookieName  string `json:"cookie_name,omitempty"`  // cookie
	CookieHash  string `json:"cookie_hash,omitempty"`  // cookie
	SubjectDN   string `json:"subject_dn,omitempty"`   // mtls_certificate
	Fingerprint string `json:"fingerprint,omitempty"`  // mtls_certificate
}
```

### Verdict

```go
type Verdict struct {
	Verdict    string `json:"verdict"`               // "allow", "deny", "cancel", "incomplete"
	Reason     string `json:"reason,omitempty"`
	Guard      string `json:"guard,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

v.IsAllowed() bool
v.IsDenied() bool
```

### HTTPReceipt

Signed proof that an HTTP request was evaluated by ARC.

```go
type HTTPReceipt struct {
	ID                 string          `json:"id"`
	RequestID          string          `json:"request_id"`
	RoutePattern       string          `json:"route_pattern"`
	Method             string          `json:"method"`
	CallerIdentityHash string          `json:"caller_identity_hash"`
	SessionID          string          `json:"session_id,omitempty"`
	Verdict            Verdict         `json:"verdict"`
	Evidence           []GuardEvidence `json:"evidence,omitempty"`
	ResponseStatus     int             `json:"response_status"` // ARC evaluation-time HTTP status; allow receipts may be signed before downstream response completion.
	Timestamp          int64           `json:"timestamp"`
	ContentHash        string          `json:"content_hash"`
	PolicyHash         string          `json:"policy_hash"`
	CapabilityID       string          `json:"capability_id,omitempty"`
	Metadata           interface{}     `json:"metadata,omitempty"`
	KernelKey          string          `json:"kernel_key"`
	Signature          string          `json:"signature"`
}
```

### GuardEvidence

```go
type GuardEvidence struct {
	GuardName string `json:"guard_name"`
	Verdict   bool   `json:"verdict"`
	Details   string `json:"details,omitempty"`
}
```

### EvaluateResponse

```go
type EvaluateResponse struct {
	Verdict  Verdict         `json:"verdict"`
	Receipt  HTTPReceipt     `json:"receipt"`
	Evidence []GuardEvidence `json:"evidence"`
}
```

### ErrorResponse

Structured error body returned by the middleware on deny:

```go
type ErrorResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	ReceiptID  string `json:"receipt_id,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}
```

### Error Codes

```go
const (
	ErrAccessDenied       = "arc_access_denied"
	ErrSidecarUnreachable = "arc_sidecar_unreachable"
	ErrEvaluationFailed   = "arc_evaluation_failed"
	ErrInvalidReceipt     = "arc_invalid_receipt"
	ErrTimeout            = "arc_timeout"
)
```

---

## SidecarClient

For advanced use cases, you can use the sidecar client directly:

```go
client := arc.NewSidecarClient("http://127.0.0.1:9090", 5)

// Evaluate a request
result, err := client.Evaluate(ctx, arcHTTPRequest)
if err != nil {
	// Handle *SidecarError
}

// Verify a receipt signature
valid, err := client.VerifyReceipt(ctx, receipt)

// Health check
ok, err := client.HealthCheck(ctx)
```

### SidecarError

```go
type SidecarError struct {
	Code       string  // e.g., "arc_sidecar_unreachable", "arc_evaluation_failed"
	Message    string
	StatusCode int     // HTTP status from sidecar (0 if connection failed)
}
```

---

## Framework Integration Examples

### Chi Router

```go
import (
	"github.com/go-chi/chi/v5"
	arc "github.com/backbay-labs/arc/sdks/go/arc-go-http"
)

r := chi.NewRouter()
r.Get("/pets", handlePets)
r.Post("/pets", handleCreatePet)

protected := arc.Protect(r,
	arc.ConfigFile("arc.yaml"),
	arc.WithRouteResolver(func(method, path string) string {
		// Chi provides route context; extract pattern if needed
		return path
	}),
)
http.ListenAndServe(":8080", protected)
```

### Gorilla Mux

```go
import (
	"github.com/gorilla/mux"
	arc "github.com/backbay-labs/arc/sdks/go/arc-go-http"
)

r := mux.NewRouter()
r.HandleFunc("/pets/{petId}", handleGetPet).Methods("GET")

protected := arc.Protect(r,
	arc.ConfigFile("arc.yaml"),
	arc.WithRouteResolver(func(method, path string) string {
		return path
	}),
)
http.ListenAndServe(":8080", protected)
```

### Standard Library (Go 1.22+)

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /pets/{petId}", handleGetPet)
mux.HandleFunc("POST /pets", handleCreatePet)

protected := arc.Protect(mux, arc.ConfigFile("arc.yaml"))
http.ListenAndServe(":8080", protected)
```
