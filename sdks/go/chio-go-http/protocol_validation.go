package chio

// These decoders protect signed wire representation. They are not signature
// verifiers, admission authorities, or a replacement for the canonical schemas.
// Integer fields use the generated int64 domain and reject overflow. Opaque JSON
// numbers use json.Number so decoding never rounds an authenticated payload.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"unicode"
)

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
	if len(data) > 1<<20 {
		return fmt.Errorf("security wire artifact exceeds one MiB")
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

// recordNestingLimit equals encoding/json's own nesting limit, so the default
// record decoder adds no depth bound that json.Unmarshal lacks.
const recordNestingLimit = 10000

// decodeRecordObject is the default decoder of every closed generated record
// type. It refuses a repeated property name at any depth, a property that the
// record's struct types do not declare, and trailing data. Presence, null and
// number handling are those of encoding/json; primitives that need stricter
// rules decode through decodeProtocolObject instead.
func decodeRecordObject(data []byte, target any) error {
	scanner := json.NewDecoder(bytes.NewReader(data))
	scanner.UseNumber()
	if err := rejectDuplicateKeys(scanner, 0); err != nil {
		return err
	}
	if _, err := scanner.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after Chio record")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// checkRecordMembers refuses a repeated property name at any depth, a
// top-level member outside allowed, and trailing data. Generated decoders of
// closed records, whose branches encoding/json cannot check, call it first.
func checkRecordMembers(data []byte, allowed ...string) error {
	scanner := json.NewDecoder(bytes.NewReader(data))
	scanner.UseNumber()
	if err := rejectDuplicateKeys(scanner, 0); err != nil {
		return err
	}
	if _, err := scanner.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after Chio record")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	for name := range members {
		if !slices.Contains(allowed, name) {
			return fmt.Errorf("unknown chio record property")
		}
	}
	return nil
}

// rejectDuplicateKeys reads one JSON value and refuses a repeated property
// name in any object within it. It retains nothing.
func rejectDuplicateKeys(decoder *json.Decoder, depth int) error {
	if depth > recordNestingLimit {
		return fmt.Errorf("chio record nesting exceeds %d", recordNestingLimit)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("chio record property must be a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate chio record property")
			}
			seen[name] = struct{}{}
			if err := rejectDuplicateKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for decoder.More() {
			if err := rejectDuplicateKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = decoder.Token()
	return err
}

func (n *KernelExecutionNonce) UnmarshalJSON(data []byte) error {
	type wire KernelExecutionNonce
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	if (decoded.Nonce.Schema != "chio.execution_nonce.v1" && decoded.Nonce.Schema != "chio.execution_nonce.v2") || decoded.Nonce.IssuedAt < 0 || decoded.Nonce.ExpiresAt < 0 {
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
	if decoded.Schema != nil && *decoded.Schema != "chio.capability.v1" {
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
