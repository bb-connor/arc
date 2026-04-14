package arc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// validMethods maps HTTP method strings to their normalized uppercase forms.
var validMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"PATCH":   true,
	"DELETE":  true,
	"HEAD":    true,
	"OPTIONS": true,
}

// normalizeMethod returns the uppercase HTTP method if valid.
func normalizeMethod(method string) (string, bool) {
	upper := strings.ToUpper(method)
	if validMethods[upper] {
		return upper, true
	}
	return "", false
}

// buildArcHTTPRequest constructs an ArcHTTPRequest from a net/http request.
func buildArcHTTPRequest(r *http.Request, method, routePattern string, caller CallerIdentity) ArcHTTPRequest {
	// Parse query parameters.
	query := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[key] = values[0]
		}
	}

	// Extract selected headers for policy evaluation.
	headers := filterHeaders(r, []string{
		"content-type",
		"content-length",
		"x-arc-capability",
	})

	// Read and hash body for content binding.
	var bodyHash string
	var bodyLength int64
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil && len(bodyBytes) > 0 {
			h := sha256.Sum256(bodyBytes)
			bodyHash = hex.EncodeToString(h[:])
			bodyLength = int64(len(bodyBytes))
		}
	}

	capabilityID := r.Header.Get("X-Arc-Capability")

	return ArcHTTPRequest{
		RequestID:    uuid.New().String(),
		Method:       method,
		RoutePattern: routePattern,
		Path:         r.URL.Path,
		Query:        query,
		Headers:      headers,
		Caller:       caller,
		BodyHash:     bodyHash,
		BodyLength:   bodyLength,
		SessionID:    "",
		CapabilityID: capabilityID,
		Timestamp:    time.Now().Unix(),
	}
}

// filterHeaders extracts only the allowed headers from the request.
func filterHeaders(r *http.Request, allowed []string) map[string]string {
	result := make(map[string]string)
	for _, name := range allowed {
		value := r.Header.Get(name)
		if value != "" {
			result[strings.ToLower(name)] = value
		}
	}
	return result
}

// writeJSONError sends a structured JSON error response.
func writeJSONError(w http.ResponseWriter, status int, body ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
