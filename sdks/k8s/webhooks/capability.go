package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CapabilityToken is the canonical Chio capability token shape. The webhook
// parses tokens directly from admission payloads (typically pod annotations)
// and verifies them against a configured trusted-key set.
type CapabilityToken struct {
	ID              string          `json:"id"`
	Issuer          string          `json:"issuer"`
	Subject         string          `json:"subject"`
	Scope           CapabilityScope `json:"scope"`
	IssuedAt        uint64          `json:"issued_at"`
	ExpiresAt       uint64          `json:"expires_at"`
	DelegationChain []any           `json:"delegation_chain,omitempty"`
	// ParameterBinding optionally pins the capability to a concrete admission
	// shape: operation (CREATE/UPDATE/...), namespace, resource. A token that
	// declares a binding is only valid when the admission request matches.
	ParameterBinding *ParameterBinding `json:"parameter_binding,omitempty"`
	Signature        string            `json:"signature"`
}

// ParameterBinding pins a capability to one or more admission parameters.
// Empty fields are treated as wildcards. The verifier rejects tokens whose
// binding does not match the admission request.
type ParameterBinding struct {
	Operations []string `json:"operations,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Resources  []string `json:"resources,omitempty"`
}

// CapabilityScope is the canonical Chio scope envelope.
type CapabilityScope struct {
	Grants         []ToolGrant     `json:"grants,omitempty"`
	ResourceGrants []ResourceGrant `json:"resource_grants,omitempty"`
	PromptGrants   []PromptGrant   `json:"prompt_grants,omitempty"`
}

// ToolGrant authorizes a specific tool operation.
type ToolGrant struct {
	ServerID   string   `json:"server_id"`
	ToolName   string   `json:"tool_name"`
	Operations []string `json:"operations"`
}

// ResourceGrant authorizes operations against a resource URI pattern.
type ResourceGrant struct {
	URIPattern string   `json:"uri_pattern"`
	Operations []string `json:"operations"`
}

// PromptGrant authorizes operations against a prompt name.
type PromptGrant struct {
	PromptName string   `json:"prompt_name"`
	Operations []string `json:"operations"`
}

// VerifierConfig holds the trust set and required-scope configuration the
// webhook enforces. There is no default-permissive fallback: an empty config
// causes every verification to fail.
type VerifierConfig struct {
	// TrustedKernelKeys is the set of ed25519 issuer public keys (hex)
	// whose capability signatures the webhook will trust. The webhook
	// refuses to admit if this set is empty.
	TrustedKernelKeys map[string]struct{}
	// RequiredScopes is the list of canonical scopes the webhook requires
	// every admitted capability to cover. Empty -> fail closed.
	RequiredScopes []string
}

// NewVerifierConfig builds a VerifierConfig from string slices. It validates
// that every kernel key is a well-formed ed25519 public key and that no scope
// entry is empty.
func NewVerifierConfig(trustedKeys, requiredScopes []string) (VerifierConfig, error) {
	config := VerifierConfig{
		TrustedKernelKeys: make(map[string]struct{}),
	}

	for _, raw := range trustedKeys {
		key := strings.TrimSpace(raw)
		if key == "" {
			return VerifierConfig{}, fmt.Errorf(
				"webhook configuration: empty trusted kernel key",
			)
		}
		normalized, err := normalizePublicKeyHex(key)
		if err != nil {
			return VerifierConfig{}, fmt.Errorf(
				"webhook configuration: invalid trusted kernel key: %w",
				err,
			)
		}
		config.TrustedKernelKeys[normalized] = struct{}{}
	}

	for _, raw := range requiredScopes {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			return VerifierConfig{}, fmt.Errorf(
				"webhook configuration: empty required scope",
			)
		}
		config.RequiredScopes = append(config.RequiredScopes, scope)
	}

	return config, nil
}

// trustsIssuer reports whether the issuer public key is in the trust set.
func (c VerifierConfig) trustsIssuer(issuer string) bool {
	_, ok := c.TrustedKernelKeys[issuer]
	return ok
}

// AdmissionContext captures the admission parameters a capability must bind to.
type AdmissionContext struct {
	Operation string
	Namespace string
	Resource  string
}

// VerifyCapability runs the full verification flow:
//  1. Reject if no trusted-key set is configured.
//  2. Reject if required scopes are not configured.
//  3. Reject if the token is missing or malformed.
//  4. Reject if the issuer is not in the trust set.
//  5. Reject if the signature does not verify.
//  6. Reject if the token is not yet valid or has expired.
//  7. Reject if the parameter binding does not cover the admission context.
//  8. Reject if any required scope is not covered by the token's grants.
//
// Every failure path returns a typed error message suitable for surfacing in
// an admission deny.
func VerifyCapability(raw string, ctx AdmissionContext, config VerifierConfig, now time.Time) error {
	if len(config.TrustedKernelKeys) == 0 {
		return fmt.Errorf(
			"webhook denies admission: no trusted kernel keys configured (set trustedKernelKeys)",
		)
	}
	if len(config.RequiredScopes) == 0 {
		return fmt.Errorf(
			"webhook denies admission: no required scopes configured (set requiredScopes)",
		)
	}

	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf(
			"webhook denies admission: missing capability token",
		)
	}

	token, err := parseCapabilityToken(raw)
	if err != nil {
		return fmt.Errorf("webhook denies admission: %w", err)
	}

	issuer, err := normalizePublicKeyHex(token.Issuer)
	if err != nil {
		return fmt.Errorf(
			"webhook denies admission: capability issuer is invalid: %w",
			err,
		)
	}
	if !config.trustsIssuer(issuer) {
		return fmt.Errorf(
			"webhook denies admission: capability issuer is not in the trusted kernel key set",
		)
	}

	if err := verifyCapabilitySignature(raw, token.Issuer, token.Signature); err != nil {
		return fmt.Errorf("webhook denies admission: %w", err)
	}

	nowUnix := uint64(now.Unix())
	if nowUnix < token.IssuedAt {
		return fmt.Errorf("webhook denies admission: capability token is not yet valid")
	}
	if nowUnix >= token.ExpiresAt {
		return fmt.Errorf("webhook denies admission: capability token has expired")
	}

	if err := checkParameterBinding(token.ParameterBinding, ctx); err != nil {
		return fmt.Errorf("webhook denies admission: %w", err)
	}

	for _, scope := range config.RequiredScopes {
		required, err := parseRequiredScope(scope)
		if err != nil {
			return fmt.Errorf("webhook denies admission: %w", err)
		}
		if !token.Scope.covers(required) {
			return fmt.Errorf(
				"webhook denies admission: capability token does not cover required scope %q",
				scope,
			)
		}
	}

	return nil
}

func parseCapabilityToken(raw string) (CapabilityToken, error) {
	var token CapabilityToken
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&token); err != nil {
		return CapabilityToken{}, fmt.Errorf("malformed capability token: %w", err)
	}
	if token.ID == "" || token.Issuer == "" || token.Signature == "" {
		return CapabilityToken{}, fmt.Errorf("malformed capability token: missing required fields")
	}
	return token, nil
}

// capabilitySchema is the only capability schema the webhook accepts and the
// signing-wrapper id its signature covers.
const capabilitySchema = "chio.capability.v1"

// signingWrapperPrefix opens every Chio signing wrapper; byte 23 is 0x00.
const signingWrapperPrefix = "chio.signing-wrapper.v1\x00"

var capabilityMembers = map[string]struct{}{
	"schema": {}, "id": {}, "issuer": {}, "subject": {}, "scope": {}, "issued_at": {},
	"expires_at": {}, "delegation_chain": {}, "aggregate_invocation_budget": {}, "caveats": {},
	"scope_attenuations": {}, "attenuation_proof": {}, "budget_share_bps": {},
	"parameter_binding": {}, "root_anchor": {}, "signature": {},
}

var rootAnchorMembers = map[string]struct{}{
	"kind": {}, "context_digest": {}, "root_policy_digest": {}, "anchored_at": {}, "assertion_exp": {},
}

var rootAnchorKinds = map[string]struct{}{
	"oauth_id_jag": {}, "entra_jwt": {}, "entra_agent_id": {}, "oidc_jwt": {},
	"oauth_introspection": {}, "chio_local_as": {}, "chio_operator_key": {}, "operator_static_bearer": {},
}

var rootAnchorDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const maxRootAnchorInteger = 1<<53 - 1

// signingWrapper returns the 88 bytes a Chio capability signature covers.
func signingWrapper(schemaID string, canonical []byte) []byte {
	schemaDigest := sha256.Sum256([]byte(schemaID))
	bodyDigest := sha256.Sum256(canonical)
	wrapper := make([]byte, 0, 88)
	wrapper = append(wrapper, signingWrapperPrefix...)
	wrapper = append(wrapper, schemaDigest[:]...)
	return append(wrapper, bodyDigest[:]...)
}

// verifyCapabilitySignature reconstructs the canonical signing body from the
// raw token bytes (the token without its signature) and verifies the ed25519
// signature over its signing wrapper against the issuer public key.
func verifyCapabilitySignature(raw, issuerHex, signatureHex string) error {
	var parsed map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&parsed); err != nil {
		return fmt.Errorf("malformed capability token: %w", err)
	}
	for key := range parsed {
		if _, ok := capabilityMembers[key]; !ok {
			return fmt.Errorf("malformed capability token: unknown member %q", key)
		}
	}
	if anchor, ok := parsed["root_anchor"]; ok {
		if err := validateRootAnchor(anchor); err != nil {
			return fmt.Errorf("malformed capability token: %w", err)
		}
	}
	delete(parsed, "signature")
	if parsed["schema"] != capabilitySchema {
		return fmt.Errorf("malformed capability token: schema must be %q", capabilitySchema)
	}

	canonical, err := canonicalJSON(parsed)
	if err != nil {
		return fmt.Errorf("malformed capability token: %w", err)
	}

	publicKey, err := decodeFixedHex(issuerHex, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("capability signature verification failed: %w", err)
	}
	signature, err := decodeFixedHex(signatureHex, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("capability signature verification failed: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), signingWrapper(capabilitySchema, canonical), signature) {
		return fmt.Errorf("capability signature verification failed")
	}
	return nil
}

func validateRootAnchor(value any) error {
	anchor, ok := value.(map[string]any)
	if !ok {
		return errors.New("root_anchor must be a JSON object")
	}
	for key := range anchor {
		if _, ok := rootAnchorMembers[key]; !ok {
			return fmt.Errorf("root_anchor has unknown member %q", key)
		}
	}
	for _, member := range []string{"kind", "context_digest", "root_policy_digest", "anchored_at", "assertion_exp"} {
		if _, ok := anchor[member]; !ok {
			return fmt.Errorf("root_anchor is missing member %s", member)
		}
	}
	kind, ok := anchor["kind"].(string)
	if _, known := rootAnchorKinds[kind]; !ok || !known {
		return errors.New("root_anchor kind is not a known anchor kind")
	}
	for _, member := range []string{"context_digest", "root_policy_digest"} {
		digest, ok := anchor[member].(string)
		if !ok || !rootAnchorDigest.MatchString(digest) {
			return fmt.Errorf("root_anchor %s must be a sha256 digest", member)
		}
	}
	for _, member := range []string{"anchored_at", "assertion_exp"} {
		number, ok := anchor[member].(json.Number)
		if !ok {
			return fmt.Errorf("root_anchor %s must be an unsigned integer", member)
		}
		parsed, err := strconv.ParseUint(number.String(), 10, 64)
		if err != nil || parsed > maxRootAnchorInteger {
			return fmt.Errorf("root_anchor %s must be an unsigned integer", member)
		}
	}
	return nil
}

func checkParameterBinding(binding *ParameterBinding, ctx AdmissionContext) error {
	if binding == nil {
		// Unbound tokens are permitted; scope coverage carries the
		// authorization. Operators who want strict binding can require it
		// at policy-time by issuing only bound tokens.
		return nil
	}
	if len(binding.Operations) > 0 && !containsCaseInsensitive(binding.Operations, ctx.Operation) {
		return fmt.Errorf(
			"capability binding does not cover operation %q",
			ctx.Operation,
		)
	}
	if len(binding.Namespaces) > 0 && !containsCaseSensitive(binding.Namespaces, ctx.Namespace) {
		return fmt.Errorf(
			"capability binding does not cover namespace %q",
			ctx.Namespace,
		)
	}
	if len(binding.Resources) > 0 && !containsCaseSensitive(binding.Resources, ctx.Resource) {
		return fmt.Errorf(
			"capability binding does not cover resource %q",
			ctx.Resource,
		)
	}
	return nil
}

func containsCaseInsensitive(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

func containsCaseSensitive(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

// requiredScopeKind enumerates the supported scope dimensions.
type requiredScopeKind string

const (
	requiredScopeTool     requiredScopeKind = "tool"
	requiredScopeResource requiredScopeKind = "resource"
	requiredScopePrompt   requiredScopeKind = "prompt"
)

type requiredScope struct {
	kind      requiredScopeKind
	serverID  string
	name      string
	operation string
}

// parseRequiredScope accepts two forms:
//
//	"<kind>:<name>:<op>"                 resource or prompt scope
//	"tool:<server>:<name>:<op>"          fully-qualified tool scope
func parseRequiredScope(raw string) (requiredScope, error) {
	parts := strings.Split(raw, ":")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" {
			return requiredScope{}, fmt.Errorf("invalid scope %q", raw)
		}
	}

	switch len(parts) {
	case 3:
		kind := requiredScopeKind(parts[0])
		operation, err := normalizeScopeOperation(parts[2])
		if err != nil {
			return requiredScope{}, fmt.Errorf("invalid scope %q: %w", raw, err)
		}
		if kind != requiredScopeResource && kind != requiredScopePrompt {
			return requiredScope{}, fmt.Errorf("invalid scope %q", raw)
		}
		return requiredScope{
			kind:      kind,
			name:      parts[1],
			operation: operation,
		}, nil
	case 4:
		if parts[0] != string(requiredScopeTool) {
			return requiredScope{}, fmt.Errorf("invalid scope %q", raw)
		}
		operation, err := normalizeScopeOperation(parts[3])
		if err != nil {
			return requiredScope{}, fmt.Errorf("invalid scope %q: %w", raw, err)
		}
		return requiredScope{
			kind:      requiredScopeTool,
			serverID:  parts[1],
			name:      parts[2],
			operation: operation,
		}, nil
	default:
		return requiredScope{}, fmt.Errorf("invalid scope %q", raw)
	}
}

func normalizeScopeOperation(raw string) (string, error) {
	switch raw {
	case "invoke", "read_result", "read", "subscribe", "get", "delegate":
		return raw, nil
	}
	return "", fmt.Errorf("unsupported operation %q", raw)
}

func (scope CapabilityScope) covers(required requiredScope) bool {
	switch required.kind {
	case requiredScopeTool:
		for _, grant := range scope.Grants {
			if !patternCovers(grant.ServerID, required.serverID) {
				continue
			}
			if !patternCovers(grant.ToolName, required.name) {
				continue
			}
			if operationsContain(grant.Operations, required.operation) {
				return true
			}
		}
	case requiredScopeResource:
		for _, grant := range scope.ResourceGrants {
			if patternCovers(grant.URIPattern, required.name) &&
				operationsContain(grant.Operations, required.operation) {
				return true
			}
		}
	case requiredScopePrompt:
		for _, grant := range scope.PromptGrants {
			if patternCovers(grant.PromptName, required.name) &&
				operationsContain(grant.Operations, required.operation) {
				return true
			}
		}
	}
	return false
}

func operationsContain(operations []string, target string) bool {
	for _, op := range operations {
		if strings.EqualFold(op, target) {
			return true
		}
	}
	return false
}

func patternCovers(parent, child string) bool {
	if parent == "*" {
		return true
	}
	if strings.HasSuffix(parent, "*") {
		return strings.HasPrefix(child, strings.TrimSuffix(parent, "*"))
	}
	return parent == child
}

func decodeFixedHex(raw string, size int) ([]byte, error) {
	trimmed := strings.TrimPrefix(raw, "0x")
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, err
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("expected %d bytes, got %d", size, len(decoded))
	}
	return decoded, nil
}

func normalizePublicKeyHex(raw string) (string, error) {
	decoded, err := decodeFixedHex(raw, ed25519.PublicKeySize)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(decoded), nil
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if typed {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case json.Number:
		buf.WriteString(typed.String())
	case float64:
		buf.WriteString(strconv.FormatFloat(typed, 'g', -1, 64))
	case []any:
		buf.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodedKey, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(encodedKey)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, typed[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		var reparsed any
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if err := decoder.Decode(&reparsed); err != nil {
			return err
		}
		return writeCanonicalJSON(buf, reparsed)
	}
	return nil
}
