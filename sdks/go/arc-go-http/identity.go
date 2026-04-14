package arc

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// sha256Hex computes the SHA-256 hex digest of a string.
func sha256Hex(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// DefaultIdentityExtractor extracts caller identity from HTTP headers.
// It checks in order: Authorization Bearer token, X-API-Key header,
// Cookie header, then falls back to anonymous.
func DefaultIdentityExtractor(r *http.Request) CallerIdentity {
	// 1. Bearer token
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		tokenHash := sha256Hex(token)
		return CallerIdentity{
			Subject: "bearer:" + tokenHash[:16],
			AuthMethod: AuthMethod{
				Method:    "bearer",
				TokenHash: tokenHash,
			},
			Verified: false,
		}
	}

	// 2. API key
	for _, keyHeader := range []string{"X-API-Key", "X-Api-Key", "x-api-key"} {
		keyValue := r.Header.Get(keyHeader)
		if keyValue != "" {
			keyHash := sha256Hex(keyValue)
			return CallerIdentity{
				Subject: "apikey:" + keyHash[:16],
				AuthMethod: AuthMethod{
					Method:  "api_key",
					KeyName: keyHeader,
					KeyHash: keyHash,
				},
				Verified: false,
			}
		}
	}

	// 3. Cookie
	cookies := r.Cookies()
	if len(cookies) > 0 {
		c := cookies[0]
		cookieHash := sha256Hex(c.Value)
		return CallerIdentity{
			Subject: "cookie:" + cookieHash[:16],
			AuthMethod: AuthMethod{
				Method:     "cookie",
				CookieName: c.Name,
				CookieHash: cookieHash,
			},
			Verified: false,
		}
	}

	// 4. Anonymous
	return AnonymousIdentity()
}
