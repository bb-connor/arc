// Package chio provides HTTP middleware for the Chio protocol.
//
// Chio (Chio) secures HTTP APIs with
// cryptographic receipts and capability-based access control. This package
// wraps any net/http Handler, sending evaluation requests to the Chio Rust
// kernel running as a localhost sidecar and attaching signed receipt IDs to
// evaluated responses. Fail-open passthroughs do not synthesize Chio receipts.
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/pets", handlePets)
//	protected := chio.Protect(mux, chio.ConfigFile("chio.yaml"))
//	http.ListenAndServe(":8080", protected)
package chio

import (
	"net/http"
)

// Protect wraps an http.Handler with Chio capability validation and receipt
// signing. All requests are evaluated against the Chio sidecar kernel before
// being forwarded to the inner handler. Denied requests receive a structured
// JSON error response; allowed requests proceed with a signed receipt ID in
// the X-Chio-Receipt-Id response header when Chio evaluation succeeds.
//
// The middleware fails closed: if the sidecar is unreachable or returns an
// error, the request is denied (unless OnSidecarError is set to "allow" in
// the config).
func Protect(handler http.Handler, opts ...Option) http.Handler {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	client := NewSidecarClient(cfg.SidecarURL, cfg.TimeoutSeconds)
	return &chioMiddleware{
		inner:             handler,
		client:            client,
		config:            cfg,
		identityExtractor: cfg.IdentityExtractor,
		routeResolver:     cfg.RouteResolver,
	}
}

// chioMiddleware implements http.Handler with Chio evaluation.
type chioMiddleware struct {
	inner             http.Handler
	client            *SidecarClient
	config            Config
	identityExtractor IdentityExtractorFunc
	routeResolver     RouteResolverFunc
}

func (m *chioMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Normalize method.
	method, ok := normalizeMethod(r.Method)
	if !ok {
		writeJSONError(w, http.StatusMethodNotAllowed, ErrorResponse{
			Error:   ErrEvaluationFailed,
			Message: "unsupported HTTP method: " + r.Method,
		})
		return
	}

	// Extract caller identity from request headers.
	caller := m.identityExtractor(r)

	// Resolve route pattern.
	routePattern := m.routeResolver(method, r.URL.Path)

	// Build Chio HTTP request.
	chioReq := buildChioHTTPRequest(r, method, routePattern, caller)
	capabilityToken := extractCapabilityToken(r)

	// Evaluate against sidecar.
	result, err := m.client.Evaluate(r.Context(), chioReq, capabilityToken)
	if err != nil {
		if m.config.OnSidecarError == "allow" {
			passthrough := &ChioPassthrough{
				Mode:    "allow_without_receipt",
				Error:   ErrSidecarUnreachable,
				Message: "Chio sidecar error: " + err.Error(),
			}
			m.inner.ServeHTTP(w, r.WithContext(withChioPassthrough(r.Context(), passthrough)))
			return
		}
		writeJSONError(w, http.StatusBadGateway, ErrorResponse{
			Error:   ErrSidecarUnreachable,
			Message: "Chio sidecar error: " + err.Error(),
		})
		return
	}

	// Attach receipt ID to response.
	w.Header().Set("X-Chio-Receipt-Id", result.Receipt.ID)

	// Check verdict.
	if result.Verdict.Verdict == "deny" {
		status := result.Verdict.HTTPStatus
		if status == 0 {
			status = http.StatusForbidden
		}
		writeJSONError(w, status, ErrorResponse{
			Error:      ErrAccessDenied,
			Message:    result.Verdict.Reason,
			ReceiptID:  result.Receipt.ID,
			Suggestion: "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
		})
		return
	}

	// Request allowed -- forward to inner handler.
	m.inner.ServeHTTP(w, r)
}
