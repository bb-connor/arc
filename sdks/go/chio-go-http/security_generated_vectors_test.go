package chio

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

const securityJCSMaxSafeInteger int64 = 9007199254740991

func stripSecurityFixtureLF(raw []byte) []byte {
	if len(raw) != 0 && raw[len(raw)-1] == '\n' {
		return raw[:len(raw)-1]
	}
	return raw
}

func canonicalizeSecurityJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("canonical JSON contains invalid UTF-8")
	}
	if err := validateSecurityJCSUnicode(raw); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode canonical JSON input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("canonical JSON input contains multiple values")
		}
		return nil, fmt.Errorf("decode canonical JSON trailing input: %w", err)
	}

	var canonical bytes.Buffer
	if err := writeSecurityJCSValue(&canonical, value); err != nil {
		return nil, err
	}
	return canonical.Bytes(), nil
}

func validateSecurityJCSUnicode(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		current := raw[index]
		if !inString {
			if current == '"' {
				inString = true
			}
			continue
		}
		switch current {
		case '"':
			inString = false
		case '\\':
			index++
			if index >= len(raw) {
				return fmt.Errorf("canonical JSON string has an incomplete escape")
			}
			escape := raw[index]
			if escape != 'u' {
				if !strings.ContainsRune(`"\\/bfnrt`, rune(escape)) {
					return fmt.Errorf("canonical JSON string has invalid escape \\%c", escape)
				}
				continue
			}
			unit, err := parseSecurityJCSUTF16Unit(raw, index+1)
			if err != nil {
				return err
			}
			index += 4
			switch {
			case unit >= 0xd800 && unit <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return fmt.Errorf("canonical JSON string has an unpaired high surrogate")
				}
				low, err := parseSecurityJCSUTF16Unit(raw, index+3)
				if err != nil {
					return err
				}
				if low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("canonical JSON string has an unpaired high surrogate")
				}
				index += 6
			case unit >= 0xdc00 && unit <= 0xdfff:
				return fmt.Errorf("canonical JSON string has an unpaired low surrogate")
			}
		default:
			if current < 0x20 {
				return fmt.Errorf("canonical JSON string has an unescaped control character")
			}
		}
	}
	return nil
}

func parseSecurityJCSUTF16Unit(raw []byte, start int) (uint16, error) {
	if start+4 > len(raw) {
		return 0, fmt.Errorf("canonical JSON string has an incomplete Unicode escape")
	}
	var unit uint16
	for _, digit := range raw[start : start+4] {
		unit <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			unit |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			unit |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			unit |= uint16(digit-'A') + 10
		default:
			return 0, fmt.Errorf("canonical JSON string has an invalid Unicode escape")
		}
	}
	return unit, nil
}

func writeSecurityJCSValue(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		if err := writeSecurityJCSString(output, typed); err != nil {
			return err
		}
	case json.Number:
		rendered, err := canonicalizeSecurityJCSInteger(typed)
		if err != nil {
			return err
		}
		output.WriteString(rendered)
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := writeSecurityJCSValue(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if !utf8.ValidString(key) {
				return fmt.Errorf("canonical JSON object key contains invalid UTF-8")
			}
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool {
			return compareSecurityJCSUTF16(keys[left], keys[right]) < 0
		})
		output.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := writeSecurityJCSString(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := writeSecurityJCSValue(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON does not support %T", value)
	}
	return nil
}

func canonicalizeSecurityJCSInteger(number json.Number) (string, error) {
	raw := number.String()
	if strings.ContainsAny(raw, ".eE") {
		return "", fmt.Errorf("bounded canonical JSON rejects non-integral number %q", raw)
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return "", fmt.Errorf("bounded canonical JSON rejects invalid integer %q", raw)
	}
	if parsed < -securityJCSMaxSafeInteger || parsed > securityJCSMaxSafeInteger {
		return "", fmt.Errorf("bounded canonical JSON rejects unsafe integer %q", raw)
	}
	return strconv.FormatInt(parsed, 10), nil
}

func writeSecurityJCSString(output *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("canonical JSON string contains invalid UTF-8")
	}
	const hexadecimal = "0123456789abcdef"
	output.WriteByte('"')
	for _, current := range value {
		switch current {
		case '"':
			output.WriteString(`\"`)
		case '\\':
			output.WriteString(`\\`)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if current < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hexadecimal[byte(current)>>4])
				output.WriteByte(hexadecimal[byte(current)&0x0f])
			} else {
				output.WriteRune(current)
			}
		}
	}
	output.WriteByte('"')
	return nil
}

func compareSecurityJCSUTF16(left, right string) int {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] < rightUnits[index] {
			return -1
		}
		if leftUnits[index] > rightUnits[index] {
			return 1
		}
	}
	if len(leftUnits) < len(rightUnits) {
		return -1
	}
	if len(leftUnits) > len(rightUnits) {
		return 1
	}
	return 0
}

func assertSecurityCanonicalReencoding(
	t *testing.T,
	relativePath string,
	raw []byte,
	reencoded []byte,
) {
	t.Helper()
	payload := stripSecurityFixtureLF(raw)
	fixtureCanonical, err := canonicalizeSecurityJSON(payload)
	if err != nil {
		t.Fatalf("canonicalize fixture %s: %v", relativePath, err)
	}
	if !bytes.Equal(fixtureCanonical, payload) {
		t.Fatalf("security vector %s is not exact RFC 8785 JSON", relativePath)
	}
	typedCanonical, err := canonicalizeSecurityJSON(reencoded)
	if err != nil {
		t.Fatalf("canonicalize generated Go encoding %s: %v", relativePath, err)
	}
	if !bytes.Equal(typedCanonical, payload) {
		t.Fatalf("generated Go type changed exact RFC 8785 bytes for %s", relativePath)
	}
}

func assertSecurityGeneratedRoundTrip[T any](t *testing.T, relativePath string) {
	t.Helper()
	path := filepath.Join(
		"..", "..", "..", "tests", "bindings", "vectors", "security",
		filepath.FromSlash(relativePath),
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var decoded T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("generated Go type rejected %s: %v", relativePath, err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("generated Go type failed to encode %s: %v", relativePath, err)
	}
	assertSecurityCanonicalReencoding(t, relativePath, raw, reencoded)

	var sourceValue map[string]any
	if err := json.Unmarshal(raw, &sourceValue); err != nil {
		t.Fatalf("decode source %s: %v", relativePath, err)
	}
	sourceValue["unknown"] = true
	unknown, err := json.Marshal(sourceValue)
	if err != nil {
		t.Fatalf("encode unknown-field mutation for %s: %v", relativePath, err)
	}
	var rejected T
	strict := json.NewDecoder(bytes.NewReader(unknown))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&rejected); err == nil {
		t.Fatalf("generated Go type accepted unknown field for %s", relativePath)
	}
}

func TestGeneratedActiveDefenseTypesDecodeReencodeAndReject(t *testing.T) {
	assertSecurityGeneratedRoundTrip[SecuritySecurityEventBodyV1](
		t,
		"active-defense/positive/security-event-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityCorrelatedFindingV1](
		t,
		"active-defense/positive/correlated-finding-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponsePlanV1](
		t,
		"active-defense/positive/response-plan-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponseEffectV1](
		t,
		"active-defense/positive/response-effect-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponseStateTransitionReceiptBodyV1](
		t,
		"active-defense/positive/response-state-transition-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponseStateTransitionReceiptBodyV1](
		t,
		"active-defense/positive/response-state-transition-receipt-body-renewal-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityEffectTransitionReceiptBodyV1](
		t,
		"active-defense/positive/effect-transition-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityEffectTransitionReceiptBodyV1](
		t,
		"active-defense/positive/effect-transition-receipt-body-legacy-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityDetectorHealthReceiptBodyV1](
		t,
		"active-defense/positive/detector-health-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityDetectorHealthReceiptBodyV1](
		t,
		"active-defense/positive/detector-health-receipt-body-contradictory-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityDetectorHealthReceiptBodyV1](
		t,
		"active-defense/positive/detector-health-receipt-body-unknown-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityFlowDenialReceiptBodyV1](
		t,
		"active-defense/positive/flow-denial-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityDeclassificationConsumptionReceiptBodyV1](
		t,
		"active-defense/positive/declassification-consumption-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityDeclassificationOutcomeReceiptBodyV1](
		t,
		"active-defense/positive/declassification-outcome-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityTripwireObservationReceiptBodyV1](
		t,
		"active-defense/positive/tripwire-observation-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityCorrelatedFindingReceiptBodyV1](
		t,
		"active-defense/positive/correlated-finding-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponsePlanReceiptBodyV1](
		t,
		"active-defense/positive/response-plan-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponsePlanReceiptBodyV1](
		t,
		"active-defense/positive/response-plan-receipt-body-two-effects-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponseCompletionReceiptBodyV1](
		t,
		"active-defense/positive/response-completion-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponseCompletionReceiptBodyV1](
		t,
		"active-defense/positive/response-completion-receipt-body-failed-before-effect-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityResponseCompletionReceiptBodyV1](
		t,
		"active-defense/positive/response-completion-receipt-body-failed-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityLiftRollbackCompletionReceiptBodyV1](
		t,
		"active-defense/positive/lift-rollback-completion-receipt-body-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecurityLiftRollbackCompletionReceiptBodyV1](
		t,
		"active-defense/positive/lift-rollback-completion-receipt-body-nonreversible-v1.json",
	)
	assertSecurityGeneratedRoundTrip[SecuritySchedulerHealthReceiptBodyV1](
		t,
		"active-defense/positive/scheduler-health-receipt-body-v1.json",
	)
}

func TestDetectorHealthTaggedKnowledgeRejectsInvalidVariants(t *testing.T) {
	path := filepath.Join(
		"..", "..", "..", "tests", "bindings", "vectors", "security",
		"active-defense", "positive", "detector-health-receipt-body-v1.json",
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	cases := map[string]func(map[string]any){
		"unknown group kind": func(value map[string]any) {
			value["group_binding"].(map[string]any)["kind"] = "future_group"
		},
		"missing resolved hash": func(value map[string]any) {
			delete(value["group_binding"].(map[string]any), "group_key_hash")
		},
		"unknown group member": func(value map[string]any) {
			value["group_binding"].(map[string]any)["unknown"] = true
		},
		"unknown watermark kind": func(value map[string]any) {
			value["watermark"].(map[string]any)["kind"] = "future_watermark"
		},
		"missing committed time": func(value map[string]any) {
			delete(value["watermark"].(map[string]any), "unix_ms")
		},
		"unknown watermark member": func(value map[string]any) {
			value["watermark"].(map[string]any)["unknown"] = true
		},
		"unresolved committed watermark": func(value map[string]any) {
			value["group_binding"] = map[string]any{"kind": "unresolved"}
		},
		"future committed watermark": func(value map[string]any) {
			value["watermark"].(map[string]any)["unix_ms"] = float64(501)
		},
		"unsafe observation time": func(value map[string]any) {
			value["header"].(map[string]any)["occurred_at_unix_ms"] =
				float64(9007199254740992)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatalf("decode detector health source: %v", err)
			}
			mutate(value)
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("encode detector health mutation: %v", err)
			}
			var decoded SecurityDetectorHealthReceiptBodyV1
			decoder := json.NewDecoder(bytes.NewReader(mutated))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&decoded); err == nil {
				t.Fatal("generated Go type accepted invalid detector health knowledge")
			}
		})
	}

	contradictoryPath := filepath.Join(
		"..", "..", "..", "tests", "bindings", "vectors", "security",
		"active-defense", "positive", "detector-health-receipt-body-contradictory-v1.json",
	)
	contradictoryRaw, err := os.ReadFile(contradictoryPath)
	if err != nil {
		t.Fatalf("read %s: %v", contradictoryPath, err)
	}
	contradictoryCases := map[string]func(map[string]any){
		"missing contradictory claim": func(value map[string]any) {
			delete(value["watermark"].(map[string]any), "claimed_unix_ms")
		},
		"unknown contradictory member": func(value map[string]any) {
			value["watermark"].(map[string]any)["unknown"] = true
		},
		"numeric contradictory claim": func(value map[string]any) {
			value["watermark"].(map[string]any)["claimed_unix_ms"] = float64(501)
		},
		"noncanonical contradictory claim": func(value map[string]any) {
			value["watermark"].(map[string]any)["claimed_unix_ms"] = "0501"
		},
		"overflowing contradictory claim": func(value map[string]any) {
			value["watermark"].(map[string]any)["claimed_unix_ms"] = "18446744073709551616"
		},
		"unresolved contradictory claim": func(value map[string]any) {
			value["group_binding"] = map[string]any{"kind": "unresolved"}
		},
		"contradictory claim with wrong health kind": func(value map[string]any) {
			value["health_kind"] = "store_unavailable"
		},
		"claim that is a valid committed watermark": func(value map[string]any) {
			value["watermark"].(map[string]any)["claimed_unix_ms"] = "499"
		},
	}
	for name, mutate := range contradictoryCases {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(contradictoryRaw, &value); err != nil {
				t.Fatalf("decode contradictory detector health source: %v", err)
			}
			mutate(value)
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("encode contradictory detector health mutation: %v", err)
			}
			var decoded SecurityDetectorHealthReceiptBodyV1
			decoder := json.NewDecoder(bytes.NewReader(mutated))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&decoded); err == nil {
				t.Fatal("generated Go type accepted invalid contradictory detector watermark")
			}
		})
	}
}

func applySecurityJSONMutation(value map[string]any, operation, pointer string, replacement any) error {
	segments := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		return fmt.Errorf("mutation path is empty")
	}
	var parent any = value
	for _, segment := range segments[:len(segments)-1] {
		switch container := parent.(type) {
		case map[string]any:
			parent = container[segment]
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(container) {
				return fmt.Errorf("mutation path %q has invalid array index", pointer)
			}
			parent = container[index]
		default:
			return fmt.Errorf("mutation path %q is not a container path", pointer)
		}
	}
	target := segments[len(segments)-1]
	switch container := parent.(type) {
	case map[string]any:
		switch operation {
		case "add", "replace":
			container[target] = replacement
		case "remove":
			delete(container, target)
		default:
			return fmt.Errorf("unsupported mutation operation %q", operation)
		}
	case []any:
		index, err := strconv.Atoi(target)
		if err != nil || index < 0 || index >= len(container) {
			return fmt.Errorf("mutation path %q has invalid array index", pointer)
		}
		switch operation {
		case "add", "replace":
			container[index] = replacement
		case "remove":
			container = append(container[:index], container[index+1:]...)
			return replaceSecurityJSONArrayParent(value, segments[:len(segments)-1], container)
		default:
			return fmt.Errorf("unsupported mutation operation %q", operation)
		}
	default:
		return fmt.Errorf("mutation path %q has a non-container parent", pointer)
	}
	return nil
}

func replaceSecurityJSONArrayParent(value map[string]any, segments []string, replacement []any) error {
	if len(segments) == 0 {
		return fmt.Errorf("cannot replace root array")
	}
	var parent any = value
	for _, segment := range segments[:len(segments)-1] {
		switch container := parent.(type) {
		case map[string]any:
			parent = container[segment]
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(container) {
				return fmt.Errorf("invalid array index %q", segment)
			}
			parent = container[index]
		default:
			return fmt.Errorf("array parent path is not a container")
		}
	}
	target := segments[len(segments)-1]
	switch container := parent.(type) {
	case map[string]any:
		container[target] = replacement
	case []any:
		index, err := strconv.Atoi(target)
		if err != nil || index < 0 || index >= len(container) {
			return fmt.Errorf("invalid array index %q", target)
		}
		container[index] = replacement
	default:
		return fmt.Errorf("array parent path is not a container")
	}
	return nil
}

func generatedReceiptMutationRejected(stem string, raw []byte) (bool, error) {
	var target any
	switch stem {
	case "flow-denial-receipt-body-v1.json":
		target = &SecurityFlowDenialReceiptBodyV1{}
	case "declassification-consumption-receipt-body-v1.json":
		target = &SecurityDeclassificationConsumptionReceiptBodyV1{}
	case "declassification-outcome-receipt-body-v1.json":
		target = &SecurityDeclassificationOutcomeReceiptBodyV1{}
	case "tripwire-observation-receipt-body-v1.json":
		target = &SecurityTripwireObservationReceiptBodyV1{}
	case "correlated-finding-receipt-body-v1.json":
		target = &SecurityCorrelatedFindingReceiptBodyV1{}
	case "response-plan-receipt-body-v1.json", "response-plan-receipt-body-two-effects-v1.json":
		target = &SecurityResponsePlanReceiptBodyV1{}
	case "response-state-transition-receipt-body-v1.json", "response-state-transition-receipt-body-renewal-v1.json":
		target = &SecurityResponseStateTransitionReceiptBodyV1{}
	case "effect-transition-receipt-body-v1.json", "effect-transition-receipt-body-legacy-v1.json":
		target = &SecurityEffectTransitionReceiptBodyV1{}
	case "response-completion-receipt-body-v1.json", "response-completion-receipt-body-failed-v1.json":
		target = &SecurityResponseCompletionReceiptBodyV1{}
	case "lift-rollback-completion-receipt-body-v1.json", "lift-rollback-completion-receipt-body-nonreversible-v1.json":
		target = &SecurityLiftRollbackCompletionReceiptBodyV1{}
	case "scheduler-health-receipt-body-v1.json":
		target = &SecuritySchedulerHealthReceiptBodyV1{}
	default:
		return false, fmt.Errorf("receipt mutation has no exact generated type: %s", stem)
	}
	return json.Unmarshal(raw, target) != nil, nil
}

func TestGeneratedReceiptTypesCoverSemanticMutationCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	checker := exec.Command("python3", filepath.Join(root, "scripts", "check-security-wire-vectors.py"))
	if output, err := checker.CombinedOutput(); err != nil {
		t.Fatalf("semantic checker rejected receipt corpus: %v: %s", err, output)
	}
	vectorDir := filepath.Join(root, "tests", "bindings", "vectors", "security", "active-defense")
	corpusRaw, err := os.ReadFile(filepath.Join(vectorDir, "receipt-body-mutations-v1.json"))
	if err != nil {
		t.Fatalf("read receipt mutation corpus: %v", err)
	}
	var corpus struct {
		Cases []struct {
			Base     string `json:"base"`
			ID       string `json:"id"`
			Mutation struct {
				Operation string `json:"op"`
				Path      string `json:"path"`
				Value     any    `json:"value"`
			} `json:"mutation"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(corpusRaw, &corpus); err != nil {
		t.Fatalf("decode receipt mutation corpus: %v", err)
	}
	requiredGeneratedRejections := map[string]struct{}{
		"correlated_finding_receipt_unsafe_first_event_time": {},
		"correlated_finding_receipt_unsafe_last_event_time":  {},
		"response_plan_receipt_unsafe_header_time":           {},
		"response_plan_receipt_unsafe_expiry":                {},
		"response_plan_receipt_unsafe_created_time":          {},
		"response_state_transition_unsafe_generation":        {},
		"response_state_transition_unsafe_applying_lease":    {},
		"effect_transition_zero_generation":                  {},
		"effect_transition_unsafe_generation":                {},
		"effect_transition_unsafe_fencing_token":             {},
		"scheduler_health_unsafe_first_failure":              {},
		"scheduler_health_attempts_overflow_u32":             {},
		"scheduler_health_unsafe_fencing_token":              {},
	}
	seenRequiredRejections := make(map[string]struct{}, len(requiredGeneratedRejections))
	for _, testCase := range corpus.Cases {
		baseRaw, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(testCase.Base)))
		if err != nil {
			t.Fatalf("read mutation base %s: %v", testCase.ID, err)
		}
		var value map[string]any
		if err := json.Unmarshal(baseRaw, &value); err != nil {
			t.Fatalf("decode mutation base %s: %v", testCase.ID, err)
		}
		if err := applySecurityJSONMutation(value, testCase.Mutation.Operation, testCase.Mutation.Path, testCase.Mutation.Value); err != nil {
			t.Fatalf("apply mutation %s: %v", testCase.ID, err)
		}
		mutated, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encode mutation %s: %v", testCase.ID, err)
		}
		rejected, err := generatedReceiptMutationRejected(filepath.Base(testCase.Base), mutated)
		if err != nil {
			t.Fatalf("select exact generated type for %s: %v", testCase.ID, err)
		}
		if _, required := requiredGeneratedRejections[testCase.ID]; required {
			seenRequiredRejections[testCase.ID] = struct{}{}
			if !rejected {
				t.Fatalf("generated Go type accepted required integer mutation %s", testCase.ID)
			}
		}
	}
	if len(seenRequiredRejections) != len(requiredGeneratedRejections) {
		for id := range requiredGeneratedRejections {
			if _, seen := seenRequiredRejections[id]; !seen {
				t.Fatalf("receipt mutation corpus is missing required generated rejection %s", id)
			}
		}
	}
}

func assertSecurityReceiptMarshalRejects[T any](
	t *testing.T,
	relativePath string,
	mutate func(*T),
) {
	t.Helper()
	path := filepath.Join(
		"..", "..", "..", "tests", "bindings", "vectors", "security",
		"active-defense", "positive", filepath.FromSlash(relativePath),
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var decoded T
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode valid receipt %s: %v", relativePath, err)
	}
	mutate(&decoded)
	if _, err := json.Marshal(decoded); err == nil {
		t.Fatalf("generated Go type emitted invalid receipt mutation from %s", relativePath)
	}
}

func TestGeneratedReceiptEmittersRejectUnsafePortableIntegers(t *testing.T) {
	const unsafeJSONInteger int64 = 9007199254740992

	t.Run("correlated finding first event time", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityCorrelatedFindingReceiptBodyV1](
			t,
			"correlated-finding-receipt-body-v1.json",
			func(value *SecurityCorrelatedFindingReceiptBodyV1) {
				value.FirstEventTimeUnixMs = unsafeJSONInteger
			},
		)
	})
	t.Run("correlated finding last event time", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityCorrelatedFindingReceiptBodyV1](
			t,
			"correlated-finding-receipt-body-v1.json",
			func(value *SecurityCorrelatedFindingReceiptBodyV1) {
				value.LastEventTimeUnixMs = unsafeJSONInteger
			},
		)
	})
	t.Run("response plan observation time", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityResponsePlanReceiptBodyV1](
			t,
			"response-plan-receipt-body-v1.json",
			func(value *SecurityResponsePlanReceiptBodyV1) {
				value.Header.OccurredAtUnixMs = unsafeJSONInteger
			},
		)
	})
	t.Run("response plan expiry", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityResponsePlanReceiptBodyV1](
			t,
			"response-plan-receipt-body-v1.json",
			func(value *SecurityResponsePlanReceiptBodyV1) {
				value.Response.PlanExpiresAtUnixMs = unsafeJSONInteger
			},
		)
	})
	t.Run("response plan creation time", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityResponsePlanReceiptBodyV1](
			t,
			"response-plan-receipt-body-v1.json",
			func(value *SecurityResponsePlanReceiptBodyV1) {
				value.PlanCreatedAtUnixMs = unsafeJSONInteger
			},
		)
	})
	t.Run("response state generation", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityResponseStateTransitionReceiptBodyV1](
			t,
			"response-state-transition-receipt-body-v1.json",
			func(value *SecurityResponseStateTransitionReceiptBodyV1) {
				value.Generation = unsafeJSONInteger
			},
		)
	})
	t.Run("response state applying lease", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityResponseStateTransitionReceiptBodyV1](
			t,
			"response-state-transition-receipt-body-v1.json",
			func(value *SecurityResponseStateTransitionReceiptBodyV1) {
				lease := unsafeJSONInteger
				value.ApplyingLeaseExpiresAtUnixMs = &lease
			},
		)
	})
	t.Run("effect transition zero generation", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityEffectTransitionReceiptBodyV1](
			t,
			"effect-transition-receipt-body-v1.json",
			func(value *SecurityEffectTransitionReceiptBodyV1) {
				value.Generation = 0
			},
		)
	})
	t.Run("effect transition unsafe generation", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityEffectTransitionReceiptBodyV1](
			t,
			"effect-transition-receipt-body-v1.json",
			func(value *SecurityEffectTransitionReceiptBodyV1) {
				value.Generation = unsafeJSONInteger
			},
		)
	})
	t.Run("effect transition fencing token", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecurityEffectTransitionReceiptBodyV1](
			t,
			"effect-transition-receipt-body-v1.json",
			func(value *SecurityEffectTransitionReceiptBodyV1) {
				value.SchedulerFencingToken = unsafeJSONInteger
			},
		)
	})
	t.Run("scheduler health first failure", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecuritySchedulerHealthReceiptBodyV1](
			t,
			"scheduler-health-receipt-body-v1.json",
			func(value *SecuritySchedulerHealthReceiptBodyV1) {
				value.FirstFailureAtUnixMs = unsafeJSONInteger
			},
		)
	})
	t.Run("scheduler health attempts", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecuritySchedulerHealthReceiptBodyV1](
			t,
			"scheduler-health-receipt-body-v1.json",
			func(value *SecuritySchedulerHealthReceiptBodyV1) {
				value.Attempts = 4294967296
			},
		)
	})
	t.Run("scheduler health fencing token", func(t *testing.T) {
		assertSecurityReceiptMarshalRejects[SecuritySchedulerHealthReceiptBodyV1](
			t,
			"scheduler-health-receipt-body-v1.json",
			func(value *SecuritySchedulerHealthReceiptBodyV1) {
				value.SchedulerFencingToken = unsafeJSONInteger
			},
		)
	})
}

func TestDetectorHealthGeneratedTypeRejectsMutationCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	vectorDir := filepath.Join(root, "tests", "bindings", "vectors", "security", "active-defense")
	corpusRaw, err := os.ReadFile(filepath.Join(vectorDir, "mutations-v1.json"))
	if err != nil {
		t.Fatalf("read detector health mutation corpus: %v", err)
	}
	var corpus struct {
		Cases []struct {
			Base     string `json:"base"`
			ID       string `json:"id"`
			Mutation struct {
				Operation string `json:"op"`
				Path      string `json:"path"`
				Value     any    `json:"value"`
			} `json:"mutation"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(corpusRaw, &corpus); err != nil {
		t.Fatalf("decode detector health mutation corpus: %v", err)
	}
	for _, testCase := range corpus.Cases {
		if !strings.HasPrefix(testCase.ID, "detector_health_") {
			continue
		}
		t.Run(testCase.ID, func(t *testing.T) {
			baseRaw, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(testCase.Base)))
			if err != nil {
				t.Fatalf("read mutation base: %v", err)
			}
			var value map[string]any
			if err := json.Unmarshal(baseRaw, &value); err != nil {
				t.Fatalf("decode mutation base: %v", err)
			}
			if err := applySecurityJSONMutation(
				value,
				testCase.Mutation.Operation,
				testCase.Mutation.Path,
				testCase.Mutation.Value,
			); err != nil {
				t.Fatalf("apply mutation: %v", err)
			}
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("encode mutation: %v", err)
			}
			var decoded SecurityDetectorHealthReceiptBodyV1
			if err := json.Unmarshal(mutated, &decoded); err == nil {
				t.Fatal("generated Go type accepted detector health mutation")
			}
		})
	}
}

func TestDetectorHealthGeneratedEmittersRejectInvalidState(t *testing.T) {
	zeroDigest := make([]int64, 32)
	resolvedZero := SecurityDetectorHealthReceiptBodyV1GroupBinding1{
		GroupKeyHash: zeroDigest,
		Kind:         SecurityDetectorHealthReceiptBodyV1GroupBinding1KindResolved,
	}
	var group SecurityDetectorHealthReceiptBodyV1GroupBinding
	if err := group.FromSecurityDetectorHealthReceiptBodyV1GroupBinding1(resolvedZero); err == nil {
		t.Fatal("resolved group constructor accepted an all-zero hash")
	}
	if err := group.MergeSecurityDetectorHealthReceiptBodyV1GroupBinding1(resolvedZero); err == nil {
		t.Fatal("resolved group merge accepted an all-zero hash")
	}

	unsafeCommitted := SecurityDetectorHealthReceiptBodyV1Watermark1{
		Kind:   SecurityDetectorHealthReceiptBodyV1Watermark1KindCommitted,
		UnixMs: 9007199254740992,
	}
	var watermark SecurityDetectorHealthReceiptBodyV1Watermark
	if err := watermark.FromSecurityDetectorHealthReceiptBodyV1Watermark1(unsafeCommitted); err == nil {
		t.Fatal("committed watermark constructor accepted an unsafe time")
	}
	if err := watermark.MergeSecurityDetectorHealthReceiptBodyV1Watermark1(unsafeCommitted); err == nil {
		t.Fatal("committed watermark merge accepted an unsafe time")
	}

	path := filepath.Join(
		"..", "..", "..", "tests", "bindings", "vectors", "security",
		"active-defense", "positive", "detector-health-receipt-body-v1.json",
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read detector health source: %v", err)
	}
	var valid SecurityDetectorHealthReceiptBodyV1
	if err := json.Unmarshal(raw, &valid); err != nil {
		t.Fatalf("decode detector health source: %v", err)
	}
	valid.Policy.PolicyHash = zeroDigest
	if _, err := json.Marshal(valid); err == nil {
		t.Fatal("detector health marshal accepted an all-zero policy hash")
	}

	if err := json.Unmarshal(raw, &valid); err != nil {
		t.Fatalf("restore detector health source: %v", err)
	}
	valid.Header.OccurredAtUnixMs = 9007199254740992
	if _, err := json.Marshal(valid); err == nil {
		t.Fatal("detector health marshal accepted an unsafe observation time")
	}

	if err := json.Unmarshal(raw, &valid); err != nil {
		t.Fatalf("restore detector health source: %v", err)
	}
	var unresolved SecurityDetectorHealthReceiptBodyV1GroupBinding
	if err := unresolved.FromSecurityDetectorHealthReceiptBodyV1GroupBinding0(
		SecurityDetectorHealthReceiptBodyV1GroupBinding0{
			Kind: SecurityDetectorHealthReceiptBodyV1GroupBinding0KindUnresolved,
		},
	); err != nil {
		t.Fatalf("construct unresolved detector group: %v", err)
	}
	valid.GroupBinding = unresolved
	if _, err := json.Marshal(valid); err == nil {
		t.Fatal("detector health marshal accepted unresolved committed knowledge")
	}
}

func TestGeneratedProtocolTypesPreserveApprovalAndAggregateBudgetFields(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	vectorDir := filepath.Join(root, "tests", "bindings", "vectors", "security", "protocol-primitives")
	indexRaw, err := os.ReadFile(filepath.Join(vectorDir, "index.json"))
	if err != nil {
		t.Fatalf("read protocol vector index: %v", err)
	}
	var index struct {
		Positive []struct {
			File string `json:"file"`
			ID   string `json:"id"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		t.Fatalf("decode protocol vector index: %v", err)
	}
	if len(index.Positive) != 26 {
		t.Fatalf("positive protocol inventory has %d entries, want 26", len(index.Positive))
	}
	identifiers := make(map[string]struct{}, len(index.Positive))
	files := make(map[string]struct{}, len(index.Positive))
	for _, entry := range index.Positive {
		if _, exists := identifiers[entry.ID]; exists {
			t.Fatalf("duplicate positive protocol ID %s", entry.ID)
		}
		if _, exists := files[entry.File]; exists {
			t.Fatalf("duplicate positive protocol file %s", entry.File)
		}
		identifiers[entry.ID] = struct{}{}
		files[entry.File] = struct{}{}
		assertProtocolGeneratedRoundTrip(t, vectorDir, entry.ID, entry.File)
	}
}

func protocolGeneratedTarget(identifier string) (any, error) {
	switch identifier {
	case "aggregate_root_commitment":
		return &CapabilityAggregateBudgetRootCommitment{}, nil
	case "aggregate_root_binding_body":
		return &CapabilityAggregateBudgetRootBindingBody{}, nil
	case "aggregate_root_binding":
		return &CapabilityAggregateBudgetRootBinding{}, nil
	case "aggregate_invocation_budget":
		return &CapabilityAggregateInvocationBudget{}, nil
	case "capability_list_delegation_family":
		return &KernelCapabilityList{}, nil
	case "aggregate_family_preservation":
		return &CapabilityAggregateFamilyPreservationEvidence{}, nil
	case "threshold_proposal_body":
		return &CapabilityThresholdApprovalProposalBody{}, nil
	case "threshold_proposal":
		return &CapabilityThresholdApprovalProposal{}, nil
	case "governed_token_body_alice", "governed_token_body_bob":
		return &CapabilityGovernedApprovalTokenBody{}, nil
	case "governed_token_alice", "governed_token_bob":
		return &CapabilityGovernedApprovalToken{}, nil
	case "governed_active_response_intent":
		return &CapabilityGovernedTransactionIntent1{}, nil
	case "tool_call_request_singular_approval", "tool_call_request_list_approval", "tool_call_request_full_security":
		return &AgentToolCallRequest{}, nil
	case "verified_approval_set":
		return &CapabilityVerifiedApprovalSet{}, nil
	case "admission_request_binding":
		return &TrustControlAdmissionRequestBinding{}, nil
	case "budget_admission_evidence":
		return &TrustControlBudgetInvocationAdmissionEvidence{}, nil
	case "admission_capture_metadata":
		return &TrustControlAdmissionCaptureMetadata{}, nil
	case "partition_escrow_quota_commitment":
		return &TrustControlPartitionEscrowQuotaCommitment{}, nil
	case "partition_escrow_allocation_set":
		return &TrustControlPartitionEscrowAllocationSet{}, nil
	case "partition_escrow_admission_evidence":
		return &TrustControlPartitionEscrowAdmissionEvidence{}, nil
	case "partition_escrow_receipt_metadata":
		return &TrustControlPartitionEscrowReceiptMetadata{}, nil
	case "budget_admission_evidence_partition_escrow":
		return &TrustControlBudgetInvocationAdmissionEvidence{}, nil
	case "admission_capture_metadata_partition_escrow":
		return &TrustControlAdmissionCaptureMetadata{}, nil
	default:
		return nil, fmt.Errorf("protocol inventory has no generated type for %s", identifier)
	}
}

func assertProtocolGeneratedRoundTrip(
	t *testing.T,
	vectorDir string,
	identifier string,
	relativePath string,
) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(relativePath)))
	if err != nil {
		t.Fatalf("read protocol positive %s: %v", identifier, err)
	}
	target, err := protocolGeneratedTarget(identifier)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("generated Go type rejected protocol positive %s: %v", identifier, err)
	}
	reencoded, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("generated Go type failed to encode protocol positive %s: %v", identifier, err)
	}
	assertSecurityCanonicalReencoding(t, relativePath, raw, reencoded)
	assertProtocolSecurityFields(t, identifier, target)

	var sourceValue map[string]any
	if err := json.Unmarshal(raw, &sourceValue); err != nil {
		t.Fatalf("decode protocol source %s: %v", identifier, err)
	}
	sourceValue["unknown"] = true
	unknown, err := json.Marshal(sourceValue)
	if err != nil {
		t.Fatalf("encode unknown-field protocol mutation %s: %v", identifier, err)
	}
	rejected, err := protocolGeneratedTarget(identifier)
	if err != nil {
		t.Fatal(err)
	}
	strict := json.NewDecoder(bytes.NewReader(unknown))
	strict.DisallowUnknownFields()
	if err := strict.Decode(rejected); err == nil {
		t.Fatalf("generated Go type accepted unknown protocol field for %s", identifier)
	}
}

func assertProtocolSecurityFields(t *testing.T, identifier string, target any) {
	t.Helper()
	switch identifier {
	case "governed_active_response_intent":
		intent, ok := target.(*CapabilityGovernedTransactionIntent1)
		if !ok {
			t.Fatalf("protocol positive %s used the wrong generated Go type", identifier)
		}
		if string(intent.Kind) != "active_response_plan" {
			t.Fatalf("protocol positive %s has governed kind %q", identifier, intent.Kind)
		}
	case "tool_call_request_full_security":
		request, ok := target.(*AgentToolCallRequest)
		if !ok {
			t.Fatalf("protocol positive %s used the wrong generated Go type", identifier)
		}
		if request.CapabilityToken.AggregateInvocationBudget == nil {
			t.Fatal("full security request omitted aggregate invocation budget")
		}
		if request.SupplementalAuthorization == nil {
			t.Fatal("full security request omitted supplemental authorization")
		}
		if request.GovernedIntent == nil {
			t.Fatal("full security request omitted governed intent")
		}
		governed, err := request.GovernedIntent.AsCapabilityGovernedTransactionIntent0()
		if err != nil {
			t.Fatalf("decode full security request governed intent: %v", err)
		}
		if string(governed.Kind) != "tool_invocation" {
			t.Fatalf("full security request governed kind is %q", governed.Kind)
		}
		if request.ApprovalTokens == nil || len(*request.ApprovalTokens) != 2 {
			t.Fatal("full security request must carry exactly two approval tokens")
		}
		if request.ApprovalToken != nil {
			t.Fatal("full security request carried the singular approval form")
		}
		if request.ThresholdApprovalProposal == nil {
			t.Fatal("full security request omitted threshold approval proposal")
		}
		if request.DeclassificationGrant == nil {
			t.Fatal("full security request omitted declassification grant")
		}
	}
}

func TestSecurityJCSUsesUTF16PropertyOrder(t *testing.T) {
	canonical, err := canonicalizeSecurityJSON([]byte("{\"\ue000\":1,\"\U0001f600\":2}"))
	if err != nil {
		t.Fatalf("canonicalize non-BMP property ordering proof: %v", err)
	}
	want := []byte("{\"\U0001f600\":2,\"\ue000\":1}")
	if !bytes.Equal(canonical, want) {
		t.Fatalf("UTF-16 property order is %q, want %q", canonical, want)
	}
}

func TestSecurityJCSRejectsValuesOutsideBoundedCorpus(t *testing.T) {
	tests := map[string][]byte{
		"float":          []byte(`{"value":1.5}`),
		"unsafe integer": []byte(`{"value":9007199254740992}`),
		"high surrogate": []byte(`{"value":"\ud800"}`),
		"low surrogate":  []byte(`{"value":"\udc00"}`),
		"invalid UTF-8":  {'{', '"', 'v', '"', ':', '"', 0xff, '"', '}'},
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalizeSecurityJSON(raw); err == nil {
				t.Fatal("bounded canonical JSON accepted an unsupported value")
			}
		})
	}
}

func TestProtocolSchemaAndGeneratedTypesCoverExactNegativeCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	// Generated Go shapes and the authoritative JSON Schema validator form the
	// Go conformance pipeline. Schema-valid cases must still decode.
	checker := exec.Command(
		"python3",
		filepath.Join(root, "scripts", "check-protocol-primitives-vectors.py"),
		"--report-json",
	)
	validationRaw, err := checker.CombinedOutput()
	if err != nil {
		output := validationRaw
		t.Fatalf("protocol vector checker failed: %v: %s", err, output)
	}
	var validationReport struct {
		Direct struct {
			ID              string `json:"id"`
			JSONParseValid  bool   `json:"json_parse_valid"`
			JSONSchemaValid bool   `json:"json_schema_valid"`
			SemanticValid   bool   `json:"semantic_valid"`
		} `json:"direct"`
		Cases []struct {
			ID              string `json:"id"`
			JSONParseValid  bool   `json:"json_parse_valid"`
			JSONSchemaValid bool   `json:"json_schema_valid"`
			SemanticValid   bool   `json:"semantic_valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(validationRaw, &validationReport); err != nil {
		t.Fatalf("decode protocol schema validation report: %v", err)
	}
	if validationReport.Direct.ID != "tool_call_request_both_approval_forms" ||
		!validationReport.Direct.JSONParseValid ||
		validationReport.Direct.JSONSchemaValid ||
		validationReport.Direct.SemanticValid {
		t.Fatalf("direct protocol negative did not receive an authoritative schema rejection")
	}
	validatedByID := make(map[string]struct {
		JSONParseValid  bool
		JSONSchemaValid bool
		SemanticValid   bool
	}, len(validationReport.Cases))
	for _, result := range validationReport.Cases {
		validatedByID[result.ID] = struct {
			JSONParseValid  bool
			JSONSchemaValid bool
			SemanticValid   bool
		}{
			JSONParseValid:  result.JSONParseValid,
			JSONSchemaValid: result.JSONSchemaValid,
			SemanticValid:   result.SemanticValid,
		}
	}
	vectorDir := filepath.Join(root, "tests", "bindings", "vectors", "security", "protocol-primitives")
	indexRaw, err := os.ReadFile(filepath.Join(vectorDir, "index.json"))
	if err != nil {
		t.Fatalf("read protocol vector index: %v", err)
	}
	var index struct {
		Positive []struct {
			File string `json:"file"`
			ID   string `json:"id"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		t.Fatalf("decode protocol vector index: %v", err)
	}
	identifierByBase := make(map[string]string, len(index.Positive))
	for _, entry := range index.Positive {
		identifierByBase[entry.File] = entry.ID
	}
	corpusRaw, err := os.ReadFile(filepath.Join(vectorDir, "mutations-v1.json"))
	if err != nil {
		t.Fatalf("read protocol mutation corpus: %v", err)
	}
	var corpus struct {
		Cases []struct {
			Base     string `json:"base"`
			Expected struct {
				JSONParseValid  bool `json:"json_parse_valid"`
				JSONSchemaValid bool `json:"json_schema_valid"`
				SemanticValid   bool `json:"semantic_valid"`
			} `json:"expected"`
			ID       string `json:"id"`
			Mutation struct {
				Operation string `json:"op"`
				Path      string `json:"path"`
				Value     any    `json:"value"`
				Hex       string `json:"hex"`
			} `json:"mutation"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(corpusRaw, &corpus); err != nil {
		t.Fatalf("decode protocol mutation corpus: %v", err)
	}
	if len(corpus.Cases) != 43 {
		t.Fatalf("protocol mutation corpus has %d cases, want 43", len(corpus.Cases))
	}
	caseIDs := make(map[string]struct{}, len(corpus.Cases))
	structuralRejections := 1
	semanticRejections := 0
	for _, testCase := range corpus.Cases {
		if _, exists := caseIDs[testCase.ID]; exists {
			t.Fatalf("duplicate protocol mutation ID %s", testCase.ID)
		}
		caseIDs[testCase.ID] = struct{}{}
		if !testCase.Expected.JSONParseValid || testCase.Expected.SemanticValid {
			t.Fatalf("protocol mutation %s has invalid classification", testCase.ID)
		}
		baseRaw, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(testCase.Base)))
		if err != nil {
			t.Fatalf("read protocol mutation base %s: %v", testCase.ID, err)
		}
		mutated := baseRaw
		var value map[string]any
		if testCase.Mutation.Operation == "append_bytes" {
			suffix, err := hex.DecodeString(testCase.Mutation.Hex)
			if err != nil {
				t.Fatalf("decode protocol byte mutation %s: %v", testCase.ID, err)
			}
			mutated = append(append([]byte(nil), baseRaw...), suffix...)
			if err := json.Unmarshal(mutated, &value); err != nil {
				t.Fatalf("decode byte-mutated protocol vector %s: %v", testCase.ID, err)
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("re-encode byte-mutated protocol vector %s: %v", testCase.ID, err)
			}
			if bytes.Equal(canonical, mutated) {
				t.Fatalf("byte mutation %s remained canonical after suffix append", testCase.ID)
			}
		} else {
			if err := json.Unmarshal(baseRaw, &value); err != nil {
				t.Fatalf("decode protocol mutation base %s: %v", testCase.ID, err)
			}
			if err := applySecurityJSONMutation(
				value,
				testCase.Mutation.Operation,
				testCase.Mutation.Path,
				testCase.Mutation.Value,
			); err != nil {
				t.Fatalf("apply protocol mutation %s: %v", testCase.ID, err)
			}
			mutated, err = json.Marshal(value)
			if err != nil {
				t.Fatalf("encode protocol mutation %s: %v", testCase.ID, err)
			}
		}
		validated, exists := validatedByID[testCase.ID]
		if !exists {
			t.Fatalf("protocol mutation %s has no authoritative schema result", testCase.ID)
		}
		if validated.JSONParseValid != testCase.Expected.JSONParseValid ||
			validated.JSONSchemaValid != testCase.Expected.JSONSchemaValid ||
			validated.SemanticValid != testCase.Expected.SemanticValid {
			t.Fatalf("protocol validator classification drifted for %s", testCase.ID)
		}
		if testCase.Expected.JSONSchemaValid {
			semanticRejections++
			identifier, exists := identifierByBase[testCase.Base]
			if !exists {
				t.Fatalf("protocol mutation base is absent from positive inventory: %s", testCase.Base)
			}
			target, err := protocolGeneratedTarget(identifier)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(mutated))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(target); err != nil {
				t.Fatalf("generated Go type rejected schema-valid semantic mutation %s: %v", testCase.ID, err)
			}
		} else {
			structuralRejections++
		}
	}
	if structuralRejections != 16 || semanticRejections != 28 {
		t.Fatalf(
			"protocol negative partition is structural=%d semantic=%d, want 16 and 28",
			structuralRejections,
			semanticRejections,
		)
	}
	if structuralRejections+semanticRejections != 44 {
		t.Fatalf("protocol negative corpus has %d cases, want 44", structuralRejections+semanticRejections)
	}
}

func TestBothApprovalFormsVectorTracksAuthoritativeExclusion(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	schemaPath := filepath.Join(
		root,
		"spec", "schemas", "chio-wire", "v1", "agent", "tool_call_request.schema.json",
	)
	schemaRaw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}
	var schema struct {
		Not struct {
			Required []string `json:"required"`
		} `json:"not"`
	}
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		t.Fatalf("decode %s: %v", schemaPath, err)
	}

	vectorPath := filepath.Join(
		root,
		"tests", "bindings", "vectors", "security", "protocol-primitives", "negative",
		"tool-call-request-both-approval-forms-v1.json",
	)
	vectorRaw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorPath, err)
	}
	var vector map[string]any
	if err := json.Unmarshal(vectorRaw, &vector); err != nil {
		t.Fatalf("decode %s: %v", vectorPath, err)
	}

	if len(schema.Not.Required) != 2 ||
		schema.Not.Required[0] != "approval_token" ||
		schema.Not.Required[1] != "approval_tokens" {
		t.Fatalf("unexpected approval exclusion: %v", schema.Not.Required)
	}
	for _, field := range schema.Not.Required {
		if _, present := vector[field]; !present {
			t.Fatalf("negative vector is missing %s", field)
		}
	}
}
