package arc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCapabilityTokenUnmarshalJSON_PreservesCanonicalToken(t *testing.T) {
	raw := `{"id":"cap-1","issuer":"issuer-1","subject":"subject-1","scope":{"grants":[{"server_id":"*","tool_name":"search","operations":["invoke"]}]},"issued_at":1713355200,"expires_at":1713358800,"signature":"sig-1"}`

	var token CapabilityToken
	if err := json.Unmarshal([]byte(raw), &token); err != nil {
		t.Fatalf("unmarshal capability token: %v", err)
	}

	if token.ID != "cap-1" {
		t.Fatalf("unexpected id: %q", token.ID)
	}
	if token.Token != raw {
		t.Fatalf("expected raw token to be preserved, got %q", token.Token)
	}
	if token.Issuer != "issuer-1" || token.Subject != "subject-1" {
		t.Fatalf("unexpected issuer/subject: %q %q", token.Issuer, token.Subject)
	}
	if len(token.Scope.Grants) != 1 || token.Scope.Grants[0].ToolName != "search" {
		t.Fatalf("unexpected scope: %#v", token.Scope)
	}
	if token.IssuedAt.UTC() != time.Unix(1713355200, 0).UTC() {
		t.Fatalf("unexpected issued_at: %v", token.IssuedAt)
	}
	if token.ExpiresAt.UTC() != time.Unix(1713358800, 0).UTC() {
		t.Fatalf("unexpected expires_at: %v", token.ExpiresAt)
	}
}

func TestCapabilityTokenMarshalJSON_EmitsCanonicalShape(t *testing.T) {
	token := CapabilityToken{
		ID:        "cap-2",
		Issuer:    "issuer-2",
		Subject:   "subject-2",
		Scope:     capabilityScope{Grants: []toolGrant{{ServerID: "*", ToolName: "fetch", Operations: []string{"invoke"}}}},
		IssuedAt:  time.Unix(1713355200, 0).UTC(),
		ExpiresAt: time.Unix(1713358800, 0).UTC(),
		Signature: "sig-2",
	}

	bytes, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshal capability token: %v", err)
	}

	jsonText := string(bytes)
	if strings.Contains(jsonText, `"token"`) {
		t.Fatalf("unexpected legacy token wrapper in %s", jsonText)
	}
	if !strings.Contains(jsonText, `"scope":{"grants":[{"server_id":"*","tool_name":"fetch","operations":["invoke"]}]}`) {
		t.Fatalf("expected canonical scope in %s", jsonText)
	}
	if !strings.Contains(jsonText, `"issued_at":1713355200`) {
		t.Fatalf("expected unix issued_at in %s", jsonText)
	}
}

func TestMintRequestMarshalJSON_UsesExplicitTTLNanos(t *testing.T) {
	request := MintRequest{
		Subject: "job/default/demo",
		Scopes:  []string{"tools:search"},
		TTL:     500 * time.Millisecond,
		JobUID:  "job-uid-1",
	}

	bytes, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal mint request: %v", err)
	}

	jsonText := string(bytes)
	if strings.Contains(jsonText, `"ttl":`) {
		t.Fatalf("unexpected ambiguous ttl field in %s", jsonText)
	}
	if !strings.Contains(jsonText, `"ttl_nanos":500000000`) {
		t.Fatalf("expected ttl_nanos field in %s", jsonText)
	}
}
