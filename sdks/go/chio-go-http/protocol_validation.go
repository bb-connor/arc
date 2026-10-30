package chio

// These decoders protect signed wire representation. They are not signature
// verifiers, admission authorities, or a replacement for the canonical schemas.
// Integer fields use the generated int64 domain and reject overflow. Opaque JSON
// numbers use json.Number so decoding never rounds an authenticated payload.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxSecurityWireBytes = 1 << 20

var errSecurityWireTooLarge = errors.New("security wire artifact exceeds one MiB")

// readProtocolValue retains exact numbers and rejects duplicate keys at every
// depth, including otherwise opaque objects. The bounded profile permits up to
// 64 nested objects/arrays and one MiB per artifact.
func readProtocolValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("security wire nesting exceeds 64")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("security wire property must be a string")
			}
			if _, exists := object[name]; exists {
				return nil, fmt.Errorf("duplicate security wire property")
			}
			value, err := readProtocolValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return nil, fmt.Errorf("invalid security wire object")
		}
		return object, nil
	case json.Delim('['):
		array := make([]any, 0)
		for decoder.More() {
			value, err := readProtocolValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return nil, fmt.Errorf("invalid security wire array")
		}
		return array, nil
	case json.Delim('}'), json.Delim(']'):
		return nil, fmt.Errorf("unexpected security wire closing token")
	default:
		return token, nil
	}
}

// checkProtocolShape derives required/optional properties from generated JSON
// tags, including anonymous nested structs. Extensible generated objects and
// raw unions retain their own representation; this does not reinterpret them.
func checkProtocolShape(value any, shape reflect.Type) error {
	for shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	if shape.Kind() == reflect.Interface || shape == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if value == nil {
		if shape == reflect.TypeOf(KernelCallerDeliveryReport_Report_RealizedCost{}) {
			return nil // This required field has an explicit nullable schema branch.
		}
		return fmt.Errorf("security properties must be omitted instead of null")
	}
	switch shape.Kind() {
	case reflect.Struct:
		if shape.NumField() == 1 && shape.Field(0).Name == "union" {
			return nil // Generated raw union, preserved without reinterpretation.
		}
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("security wire value must be an object")
		}
		allowed := make(map[string]bool)
		extensible := false
		for index := 0; index < shape.NumField(); index++ {
			field := shape.Field(index)
			if field.Name == "AdditionalProperties" {
				extensible = true
				continue
			}
			parts := strings.Split(field.Tag.Get("json"), ",")
			name := parts[0]
			if name == "" || name == "-" {
				continue
			}
			allowed[name] = true
			item, present := object[name]
			if !present {
				if len(parts) == 1 || parts[1] != "omitempty" {
					return fmt.Errorf("missing required security wire property %q", name)
				}
				continue
			}
			// Only these required caller launch fields have nullable schema branches.
			if item == nil && shape == reflect.TypeOf(KernelCallerDispatchAuthorizationCallerDispatchLaunch{}) &&
				(name == "native_launch" || name == "worker_profile") {
				continue
			}
			if err := checkProtocolShape(item, field.Type); err != nil {
				return err
			}
		}
		for name := range object {
			if !allowed[name] && !extensible {
				return fmt.Errorf("unknown security wire property")
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("security wire value must be an array")
		}
		for _, item := range array {
			if err := checkProtocolShape(item, shape.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeProtocolObject(data []byte, target any) error {
	if len(data) > maxSecurityWireBytes {
		return errSecurityWireTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readProtocolValue(decoder, 0)
	if err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after security wire artifact")
	}
	if err := checkProtocolShape(value, reflect.TypeOf(target)); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func (n *KernelExecutionNonce) UnmarshalJSON(data []byte) error {
	type wire KernelExecutionNonce
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if (decoded.Nonce.Schema != "chio.execution_nonce.v1" && decoded.Nonce.Schema != "chio.operation_execution_nonce.v1") || decoded.Nonce.IssuedAt < 0 || decoded.Nonce.ExpiresAt < 0 {
		return fmt.Errorf("invalid execution nonce domain")
	}
	*n = KernelExecutionNonce(decoded)
	return nil
}

// UnmarshalJSON preserves the closed signed origin vocabulary. It does not
// establish a trusted signer, verify a receipt, or grant execution authority.
func (origin *ReceiptRecordToolOrigin) UnmarshalJSON(data []byte) error {
	var decoded string
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	value := ReceiptRecordToolOrigin(decoded)
	switch value {
	case ReceiptRecordToolOriginCallerExecuted,
		ReceiptRecordToolOriginHostExecutedProviderReported,
		ReceiptRecordToolOriginHostExecutedUnmediated,
		ReceiptRecordToolOriginChioInternal:
		*origin = value
		return nil
	default:
		return fmt.Errorf("unknown receipt tool origin")
	}
}

func (p *CapabilityThresholdApprovalProposal) UnmarshalJSON(data []byte) error {
	type wire CapabilityThresholdApprovalProposal
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if decoded.Schema != "chio.threshold-approval-proposal.v1" || decoded.Threshold < 1 || decoded.Threshold > 32 || decoded.ProposalCreatedAt < 0 || decoded.ProposalDeadline < 1 {
		return fmt.Errorf("invalid threshold proposal domain")
	}
	*p = CapabilityThresholdApprovalProposal(decoded)
	return nil
}

func (a *CapabilityGovernedApprovalToken) UnmarshalJSON(data []byte) error {
	type wire CapabilityGovernedApprovalToken
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if (decoded.Decision != "approved" && decoded.Decision != "denied") || decoded.IssuedAt < 0 || decoded.ExpiresAt < 0 {
		return fmt.Errorf("invalid governed approval domain")
	}
	*a = CapabilityGovernedApprovalToken(decoded)
	return nil
}

func (a *AgentActiveResponseGovernedIntent) UnmarshalJSON(data []byte) error {
	type wire AgentActiveResponseGovernedIntent
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if decoded.PlanSchema != "chio.response-plan.v1" || decoded.ExpiresAt < 1 || decoded.OperatorCapabilityExpiresAt < 1 || len(decoded.OrderedEffects) < 1 || len(decoded.OrderedEffects) > 5 {
		return fmt.Errorf("invalid governed response domain")
	}
	if !boundedPlanIdentifier(decoded.PlanId) || !boundedPlanIdentifier(decoded.OperatorCapabilityId) {
		return fmt.Errorf("invalid governed response identifier")
	}
	seen := make(map[AgentActiveResponseGovernedIntentOrderedEffects]bool, len(decoded.OrderedEffects))
	for _, effect := range decoded.OrderedEffects {
		switch effect {
		case "throttle_session", "restrict_egress", "suspend_session", "suspend_capability_set", "freeze_issuance":
		default:
			return fmt.Errorf("unknown governed response effect")
		}
		if seen[effect] {
			return fmt.Errorf("duplicate governed response effect")
		}
		seen[effect] = true
	}
	_, camelHash := decoded.CanonicalPlanBody["planHash"]
	_, snakeHash := decoded.CanonicalPlanBody["plan_hash"]
	if len(decoded.CanonicalPlanBody) == 0 || camelHash || snakeHash || len(decoded.TargetBinding) == 0 || len(decoded.RollbackBinding) == 0 {
		return fmt.Errorf("invalid governed response binding")
	}
	*a = AgentActiveResponseGovernedIntent(decoded)
	return nil
}

// boundedPlanIdentifier holds 1 to 256 UTF-8 bytes with no control character
// and no surrounding whitespace, matching the native response-plan validator.
func boundedPlanIdentifier(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

func (m *KernelCombinedCaptureMetadata) UnmarshalJSON(data []byte) error {
	type wire KernelCombinedCaptureMetadata
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if decoded.Schema != "chio.admission-capture-metadata.v1" || decoded.BudgetCommitIndex < 1 || decoded.RevocationCommitIndex < 1 || decoded.LeaderEpoch < 1 || len(decoded.QuotaKeys) < 1 || len(decoded.QuotaKeys) > 8 {
		return fmt.Errorf("invalid combined capture domain")
	}
	for index, key := range decoded.QuotaKeys {
		if key.Profile == "" || key.OwnerId == "" || (key.GrantIndex != nil && (*key.GrantIndex < 0 || *key.GrantIndex > 4294967295)) {
			return fmt.Errorf("invalid combined capture quota key")
		}
		for _, previous := range decoded.QuotaKeys[:index] {
			if reflect.DeepEqual(key, previous) {
				return fmt.Errorf("duplicate combined capture quota key")
			}
		}
	}
	*m = KernelCombinedCaptureMetadata(decoded)
	return nil
}

func (s *CapabilitySupplementalAuthorization) UnmarshalJSON(data []byte) error {
	type wire CapabilitySupplementalAuthorization
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if decoded.SignedExtension == "" {
		return fmt.Errorf("empty signed extension")
	}
	*s = CapabilitySupplementalAuthorization(decoded)
	return nil
}

func (r *ResultPendingApproval) UnmarshalJSON(data []byte) error {
	type wire ResultPendingApproval
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if decoded.Status != "pending_approval" {
		return fmt.Errorf("invalid pending approval status")
	}
	*r = ResultPendingApproval(decoded)
	return nil
}

func (b *CapabilityAggregateInvocationBudget0) UnmarshalJSON(data []byte) error {
	type wire CapabilityAggregateInvocationBudget0
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"scope", "max_invocations"}, nil); err != nil {
		return err
	}
	if decoded.Scope != "capability" || decoded.MaxInvocations < 0 || decoded.MaxInvocations > 4294967295 {
		return fmt.Errorf("invalid direct aggregate budget")
	}
	*b = CapabilityAggregateInvocationBudget0(decoded)
	return nil
}

func (b *CapabilityAggregateInvocationBudget1) UnmarshalJSON(data []byte) error {
	type wire CapabilityAggregateInvocationBudget1
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if decoded.Scope != "delegation_family" || decoded.MaxInvocations < 0 || decoded.MaxInvocations > 4294967295 {
		return fmt.Errorf("invalid family aggregate budget")
	}
	*b = CapabilityAggregateInvocationBudget1(decoded)
	return nil
}

func (t *CapabilityToken) UnmarshalJSON(data []byte) error {
	type wire CapabilityToken
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if decoded.Schema != "chio.capability.v1" {
		return fmt.Errorf("invalid capability schema domain")
	}
	*t = CapabilityToken(decoded)
	return nil
}

// validateAggregateBudgetJSON is invoked by the generated union decoder before
// retaining new bytes. A raw union must not evade its branch's wire contract.
func validateAggregateBudgetJSON(data []byte) error {
	var discriminator struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(data, &discriminator); err != nil {
		return err
	}
	switch discriminator.Scope {
	case "capability":
		var budget CapabilityAggregateInvocationBudget0
		return json.Unmarshal(data, &budget)
	case "delegation_family":
		var budget CapabilityAggregateInvocationBudget1
		return json.Unmarshal(data, &budget)
	default:
		return fmt.Errorf("unknown aggregate budget scope")
	}
}

var revocationEntryMembers = []string{"schema", "entry_id", "target_kind", "target_value", "revoked_at", "reason"}

// validateRevocationEntryJSON is invoked by the generated union decoder before
// retaining new bytes. It refuses what chio.revocation-entry.v1 refuses: a
// closed member set, the schema constant, a closed reason, a target value whose
// shape follows its kind, and an entry id other than the one its target derives.
func validateRevocationEntryJSON(data []byte) error {
	var entry struct {
		Schema      string `json:"schema"`
		EntryID     string `json:"entry_id"`
		TargetKind  string `json:"target_kind"`
		TargetValue string `json:"target_value"`
		RevokedAt   int64  `json:"revoked_at"`
		Reason      string `json:"reason"`
	}
	if err := decodeManifestObject(data, &entry, revocationEntryMembers, nil); err != nil {
		return err
	}
	if entry.Schema != "chio.revocation-entry.v1" {
		return fmt.Errorf("invalid revocation entry schema")
	}
	if entry.RevokedAt < 1 {
		return fmt.Errorf("invalid revocation time")
	}
	switch entry.Reason {
	case "operator_request", "credential_compromise", "principal_offboarded",
		"tenant_offboarded", "policy_withdrawn", "incident_response":
	default:
		return fmt.Errorf("unknown revocation reason")
	}
	switch entry.TargetKind {
	case "capability_id", "root_policy_rule":
		length := utf8.RuneCountInString(entry.TargetValue)
		if !utf8.ValidString(entry.TargetValue) || length < 1 || length > 512 || strings.ContainsRune(entry.TargetValue, 0) {
			return fmt.Errorf("invalid revocation target identifier")
		}
	case "anchor_subject", "tenant_tag", "replay_key":
		if !isLowercaseHexDigest(entry.TargetValue) {
			return fmt.Errorf("revocation target digest is not 64 lowercase hex")
		}
	default:
		return fmt.Errorf("unknown revocation target kind")
	}
	// Kinds and values are NUL-free, so the NUL-separated preimage is injective.
	digest := sha256.Sum256([]byte("chio.revocation-entry-id.v1\x00" + entry.TargetKind + "\x00" + entry.TargetValue))
	if entry.EntryID != "rev_"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("revocation entry id is not the id its target derives")
	}
	return nil
}

func isLowercaseHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
