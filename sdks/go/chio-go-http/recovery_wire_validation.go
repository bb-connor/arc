package chio

// These handwritten decoders cover the fourteen shared recovery wire contracts.
// They preserve closed, bounded foundation data and lossless opaque tool JSON.
// Successful decoding establishes neither a trusted signer nor freshness,
// execution authority or effect truth.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const recoveryMaxSafeInteger int64 = 9007199254740991

// recoveryWirePreflight mirrors the native allocation-free recovery profile:
// 64 KiB wire bytes, depth 16, 4096 values/keys, 32 KiB encoded string content
// and 256 entries per container. Foundation recovery numbers are unsigned safe
// integers. Command results use the same resource accounting with a scoped
// I-JSON profile for arbitrary receipt metadata and parameters, below.
func recoveryWirePreflight(data []byte) error {
	return recoveryWireProfile(data, recoveryUnsignedNumber)
}

// A nil number rule checks resources only. Its caller must already have parsed
// the input and separately enforce the numeric profile of every retained value.
func recoveryWireProfile(data []byte, numberRule func(string) error) error {
	if len(data) == 0 || len(data) > 65536 || !utf8.Valid(data) {
		return fmt.Errorf("recovery wire exceeds its byte or UTF-8 profile")
	}
	var entries [16]int
	depth, nodes, stringBytes := 0, 0, 0
	for cursor := 0; cursor < len(data); {
		switch data[cursor] {
		case ' ', '\n', '\r', '\t', ':':
			cursor++
		case '{', '[':
			nodes++
			if depth == len(entries) {
				return fmt.Errorf("recovery wire nesting exceeds 16")
			}
			entries[depth] = 1
			depth++
			cursor++
		case '}', ']':
			if depth == 0 {
				return fmt.Errorf("invalid recovery closing token")
			}
			depth--
			cursor++
		case ',':
			if depth == 0 {
				return fmt.Errorf("invalid recovery separator")
			}
			entries[depth-1]++
			if entries[depth-1] > 256 {
				return fmt.Errorf("recovery container exceeds 256 entries")
			}
			cursor++
		case '"':
			nodes++
			cursor++
			start := cursor
			for cursor < len(data) && data[cursor] != '"' {
				if data[cursor] == '\\' {
					cursor += 2
				} else {
					cursor++
				}
			}
			if cursor >= len(data) {
				return fmt.Errorf("unterminated recovery string")
			}
			stringBytes += cursor - start
			if stringBytes > 32768 {
				return fmt.Errorf("recovery strings exceed 32 KiB")
			}
			cursor++
		default:
			nodes++
			start := cursor
			for cursor < len(data) && !strings.ContainsRune(",}] \n\r\t", rune(data[cursor])) {
				cursor++
			}
			token := string(data[start:cursor])
			if token != "true" && token != "false" && token != "null" && numberRule != nil {
				if err := numberRule(token); err != nil {
					return err
				}
			}
		}
		if nodes > 4096 {
			return fmt.Errorf("recovery wire exceeds 4096 values and keys")
		}
	}
	if depth != 0 {
		return fmt.Errorf("unclosed recovery wire container")
	}
	return nil
}

func decodeRecoveryObject(data []byte, target any, contract string) error {
	if contract == "command_result" {
		// Opaque native tool JSON must not inherit the foundation integer,
		// string, node or container ceilings. Bound the full response before
		// the duplicate-rejecting parser allocates; that parser caps depth 64.
		if len(data) == 0 || len(data) > 262144 || !utf8.Valid(data) {
			return fmt.Errorf("recovery response exceeds its byte or UTF-8 profile")
		}
	} else {
		if err := recoveryWirePreflight(data); err != nil {
			return err
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readProtocolValue(decoder, 0)
	if err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing recovery wire data")
	}
	if contract == "command_result" {
		projection := recoveryCommandResultFoundation(value)
		if err := recoveryWireProfile(recoveryCanonicalJSON(nil, projection), nil); err != nil {
			return err
		}
		if err := recoveryCommandResultNumbers(projection, "", false); err != nil {
			return err
		}
	}
	rule, found := recoveryWireRules[contract]
	if !found {
		return fmt.Errorf("unsupported recovery wire contract")
	}
	if err := rule(value); err != nil {
		return err
	}
	// The generated v2 grant target_label wrapper combines Kind with a raw
	// union. The shared shape helper treats such a wrapper as a plain struct,
	// unlike single-field raw unions. Its complete shape is checked by the
	// closed grant/claims/known-label rules above before typed decoding.
	if contract != "grant" {
		if err := checkProtocolShape(value, reflect.TypeOf(target)); err != nil {
			return err
		}
	}
	canonical := recoveryCanonicalJSON(nil, value)
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("recovery wire is not exact canonical JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// Preserve every foundation property, including unknown properties, so the
// closed shape rules still reject it. Only the actual tool result is replaced;
// a missing result remains missing, and the original lossless tree is unchanged.
func recoveryCommandResultFoundation(value any) any {
	object, ok := value.(map[string]any)
	if !ok {
		return value
	}
	projection := make(map[string]any, len(object))
	for key, item := range object {
		projection[key] = item
	}
	if original, ok := object["original_response"].(map[string]any); ok {
		response := make(map[string]any, len(original))
		for key, item := range original {
			response[key] = item
		}
		if _, exists := response["result"]; exists {
			response["result"] = nil
		}
		projection["original_response"] = response
	}
	return projection
}

func recoveryUnsignedNumber(token string) error {
	integer, err := strconv.ParseInt(token, 10, 64)
	if err != nil || integer < 0 || integer > recoveryMaxSafeInteger || strconv.FormatInt(integer, 10) != token {
		return fmt.Errorf("recovery number is not an unsigned canonical safe integer")
	}
	return nil
}

// Only these two native receipt Value fields admit signed I-JSON numbers.
// Recovery status, typed receipt integers and every other foundation subtree
// keep unsigned safe integer tokens. The opaque result is already projected out.
func recoveryCommandResultNumbers(value any, path string, receiptJSON bool) error {
	switch value := value.(type) {
	case json.Number:
		if receiptJSON {
			return recoveryReceiptNumber(value.String())
		}
		return recoveryUnsignedNumber(value.String())
	case []any:
		for _, item := range value {
			if err := recoveryCommandResultNumbers(item, path+"[]", receiptJSON); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, item := range value {
			next := key
			if path != "" {
				next = path + "." + key
			}
			signed := receiptJSON || next == "original_response.receipt.metadata" || next == "original_response.receipt.action.parameters"
			if err := recoveryCommandResultNumbers(item, next, signed); err != nil {
				return err
			}
		}
	}
	return nil
}

// Match the raw signed I-JSON domain without replacing the retained json.Number.
// Integer literals must be exact and safe. Fractions must be finite, genuinely
// fractional and already the shortest RFC 8785 double representation, so a
// precision-losing or integer-valued float token cannot silently change on sign.
func recoveryReceiptNumber(token string) error {
	if !strings.ContainsAny(token, ".eE") {
		integer, err := strconv.ParseInt(token, 10, 64)
		if err != nil || integer < -recoveryMaxSafeInteger || integer > recoveryMaxSafeInteger || strconv.FormatInt(integer, 10) != token {
			return fmt.Errorf("receipt JSON integer is outside the canonical I-JSON domain")
		}
		return nil
	}
	value, err := strconv.ParseFloat(token, 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) || value == math.Trunc(value) {
		return fmt.Errorf("receipt JSON float is non-finite or integer-valued")
	}
	var canonical string
	if absolute := math.Abs(value); absolute >= 1e-6 && absolute < 1e21 {
		canonical = strconv.FormatFloat(value, 'f', -1, 64)
	} else {
		mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(value, 'e', -1, 64), "e")
		power, err := strconv.Atoi(exponent)
		if err != nil {
			return fmt.Errorf("invalid receipt JSON exponent")
		}
		sign := ""
		if power >= 0 {
			sign = "+"
		}
		canonical = mantissa + "e" + sign + strconv.Itoa(power)
	}
	if token != canonical {
		return fmt.Errorf("receipt JSON fraction is not exact canonical I-JSON")
	}
	return nil
}

// Foundation numbers have already passed their scoped canonical numeric rules.
// Opaque tool results retain their original JSON number lexemes, without
// conversion to float64. Strings use RFC 8785 escaping; keys sort by UTF-16 units.
func recoveryCanonicalJSON(output []byte, value any) []byte {
	switch value := value.(type) {
	case nil:
		return append(output, "null"...)
	case bool:
		return strconv.AppendBool(output, value)
	case json.Number:
		return append(output, value.String()...)
	case string:
		output = append(output, '"')
		for _, char := range value {
			switch char {
			case '"', '\\':
				output = append(output, '\\', byte(char))
			case '\b':
				output = append(output, '\\', 'b')
			case '\f':
				output = append(output, '\\', 'f')
			case '\n':
				output = append(output, '\\', 'n')
			case '\r':
				output = append(output, '\\', 'r')
			case '\t':
				output = append(output, '\\', 't')
			default:
				if char < 0x20 {
					const hex = "0123456789abcdef"
					output = append(output, '\\', 'u', '0', '0', hex[char>>4], hex[char&15])
				} else {
					output = utf8.AppendRune(output, char)
				}
			}
		}
		return append(output, '"')
	case []any:
		output = append(output, '[')
		for index, item := range value {
			if index != 0 {
				output = append(output, ',')
			}
			output = recoveryCanonicalJSON(output, item)
		}
		return append(output, ']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			left, right := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for index := 0; index < len(left) && index < len(right); index++ {
				if left[index] != right[index] {
					return left[index] < right[index]
				}
			}
			return len(left) < len(right)
		})
		output = append(output, '{')
		for index, key := range keys {
			if index != 0 {
				output = append(output, ',')
			}
			output = recoveryCanonicalJSON(output, key)
			output = append(output, ':')
			output = recoveryCanonicalJSON(output, value[key])
		}
		return append(output, '}')
	}
	return output // The duplicate-rejecting parser only produces the types above.
}

type recoveryRule func(any) error

func recoveryObject(required, optional map[string]recoveryRule) recoveryRule {
	return func(value any) error {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("recovery value must be an object")
		}
		for name, rule := range required {
			item, exists := object[name]
			if !exists {
				return fmt.Errorf("missing required recovery property %q", name)
			}
			if err := rule(item); err != nil {
				return fmt.Errorf("recovery property %q: %w", name, err)
			}
		}
		for name, item := range object {
			if _, exists := required[name]; exists {
				continue
			}
			rule, exists := optional[name]
			if !exists {
				return fmt.Errorf("unknown recovery property %q", name)
			}
			if err := rule(item); err != nil {
				return fmt.Errorf("recovery property %q: %w", name, err)
			}
		}
		return nil
	}
}

func recoveryText(minimum, maximum int) recoveryRule {
	return func(value any) error {
		text, ok := value.(string)
		if !ok || utf8.RuneCountInString(text) < minimum || utf8.RuneCountInString(text) > maximum {
			return fmt.Errorf("recovery string outside its length domain")
		}
		return nil
	}
}

// Native ProtectedText bounds are UTF-8 byte ceilings, rather than JSON Schema
// scalar counts. Its enclosing recovery profile also charges encoded escapes.
func recoveryProtectedText(maximum int) recoveryRule {
	return func(value any) error {
		text, ok := value.(string)
		if !ok || len(text) == 0 || len(text) > maximum {
			return fmt.Errorf("recovery protected text outside its UTF-8 byte domain")
		}
		return nil
	}
}

func recoveryInteger(minimum, maximum int64) recoveryRule {
	return func(value any) error {
		number, ok := value.(json.Number)
		if !ok {
			return fmt.Errorf("recovery value must be an integer")
		}
		integer, err := number.Int64()
		if err != nil || integer < minimum || integer > maximum {
			return fmt.Errorf("recovery integer outside its domain")
		}
		return nil
	}
}

func recoveryEnum(values ...string) recoveryRule {
	return func(value any) error {
		text, ok := value.(string)
		for _, allowed := range values {
			if ok && text == allowed {
				return nil
			}
		}
		return fmt.Errorf("unknown recovery vocabulary value")
	}
}

func recoveryArray(item recoveryRule, minimum, maximum int, unique bool) recoveryRule {
	return func(value any) error {
		array, ok := value.([]any)
		if !ok || len(array) < minimum || len(array) > maximum {
			return fmt.Errorf("recovery array outside its length domain")
		}
		for index, value := range array {
			if err := item(value); err != nil {
				return err
			}
			if unique {
				for _, prior := range array[:index] {
					if reflect.DeepEqual(prior, value) {
						return fmt.Errorf("duplicate recovery array member")
					}
				}
			}
		}
		return nil
	}
}

func recoveryTagged(name string, variants map[string]recoveryRule) recoveryRule {
	return func(value any) error {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("recovery tagged value must be an object")
		}
		tag, ok := object[name].(string)
		rule, found := variants[tag]
		if !ok || !found {
			return fmt.Errorf("unknown recovery discriminator")
		}
		return rule(value)
	}
}

func recoveryHex(value any, size int) error {
	text, ok := value.(string)
	if !ok || len(text) == 0 || len(text)%2 != 0 || (size > 0 && len(text) != size) {
		return fmt.Errorf("invalid recovery hex representation")
	}
	for _, char := range text {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return fmt.Errorf("invalid recovery hex representation")
		}
	}
	return nil
}

func recoveryCryptoText(signature bool) recoveryRule {
	return func(value any) error {
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("recovery cryptographic representation must be a string")
		}
		if strings.HasPrefix(text, "hybrid:") {
			body := strings.TrimPrefix(text, "hybrid:")
			last := strings.LastIndexByte(body, ':')
			if last < 0 {
				return fmt.Errorf("invalid hybrid recovery representation")
			}
			algorithm := body[last+1:]
			body = body[:last]
			last = strings.LastIndexByte(body, ':')
			if last < 0 {
				return fmt.Errorf("invalid hybrid recovery representation")
			}
			classical, quantum := body[:last], body[last+1:]
			if strings.HasPrefix(classical, "hybrid:") {
				return fmt.Errorf("nested hybrid recovery representation is unsupported")
			}
			quantumSize := 3904
			if signature {
				quantumSize = 6618
			}
			if err := recoveryHex(quantum, quantumSize); err != nil {
				return err
			}
			classicalAlgorithm := "ed25519"
			if strings.HasPrefix(classical, "p256:") {
				classicalAlgorithm = "p256"
			} else if strings.HasPrefix(classical, "p384:") {
				classicalAlgorithm = "p384"
			}
			if algorithm != classicalAlgorithm+"+mldsa65" {
				return fmt.Errorf("hybrid recovery representation algorithm mismatch")
			}
			return recoveryCryptoText(signature)(classical)
		}
		size := 64
		if signature {
			size = 128
		}
		for _, prefix := range []string{"p256:", "p384:"} {
			if strings.HasPrefix(text, prefix) {
				text = strings.TrimPrefix(text, prefix)
				size = 130
				if prefix == "p384:" {
					size = 194
				}
				if signature {
					size = 0
				}
				break
			}
		}
		return recoveryHex(text, size)
	}
}

var recoveryWireRules = newRecoveryWireRules()

func newRecoveryWireRules() map[string]recoveryRule {
	anyValue := recoveryRule(func(any) error { return nil })
	boolean := recoveryRule(func(value any) error {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("recovery value must be boolean")
		}
		return nil
	})
	opaquePattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	opaque := recoveryRule(func(value any) error {
		text, ok := value.(string)
		if !ok || !opaquePattern.MatchString(text) {
			return fmt.Errorf("invalid recovery identifier")
		}
		return nil
	})
	flow := recoveryRule(func(value any) error {
		text, ok := value.(string)
		if !ok || len(text) == 0 || len(text) > 256 || strings.TrimSpace(text) != text {
			return fmt.Errorf("invalid recovery flow identifier")
		}
		for _, char := range text {
			if unicode.IsControl(char) {
				return fmt.Errorf("invalid recovery flow identifier")
			}
		}
		return nil
	})
	integer := recoveryInteger(0, recoveryMaxSafeInteger)
	positive := recoveryInteger(1, recoveryMaxSafeInteger)
	version := recoveryInteger(1, 1)
	digest := recoveryArray(recoveryInteger(0, 255), 32, 32, false)
	hexDigest := recoveryRule(func(value any) error { return recoveryHex(value, 64) })
	scope := recoveryObject(map[string]recoveryRule{"authority_domain": opaque, "tenant_id": opaque, "process_id": opaque}, nil)
	operation := recoveryObject(map[string]recoveryRule{"operation_id": opaque, "native_admission_digest": digest, "operation_version": positive}, nil)
	owners := recoveryRule(func(value any) error {
		object, ok := value.(map[string]any)
		if !ok || len(object) > 64 {
			return fmt.Errorf("invalid recovery label owner map")
		}
		for owner, readers := range object {
			if err := flow(owner); err != nil {
				return err
			}
			if err := recoveryArray(flow, 0, 256, true)(readers); err != nil {
				return err
			}
		}
		return nil
	})
	knownLabel := recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("known"), "owners": owners, "compartments": recoveryArray(flow, 0, 64, true)}, nil)
	label := recoveryTagged("kind", map[string]recoveryRule{"known": knownLabel, "top": recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("top")}, nil)})
	obligationVariants := map[string]recoveryRule{}
	for kind, principal := range map[string]string{"owner_release": "owner", "compartment_release": "compartment", "user_acceptance": "principal", "integrity_endorsement": "principal"} {
		obligationVariants[kind] = recoveryObject(map[string]recoveryRule{"kind": recoveryEnum(kind), principal: flow}, nil)
	}
	obligations := recoveryArray(recoveryTagged("kind", obligationVariants), 1, 64, false)
	requirements := recoveryObject(map[string]recoveryRule{
		"schema": recoveryEnum("chio.recovery.authorization-requirements.v1"), "version": version, "scope": scope,
		"source_label": label, "admitted_target": label, "source_join": digest, "influence_basis": digest,
		"recipient": flow, "purpose": flow, "obligations": obligations, "issuer_scope": digest,
		"validity_ceiling_unix_ms": integer, "attachment_profile": recoveryEnum("ordinary", "operation_owned_nonce"),
	}, nil)
	action := recoveryObject(map[string]recoveryRule{
		"schema": recoveryEnum("chio.recovery.action-intent.v1"), "version": version, "scope": scope,
		"workflow_id": opaque, "step_id": opaque, "continuation_id": opaque, "request_id": opaque,
		"isolation_lineage": opaque, "capability_id": flow, "authorization_requirements": requirements,
		"request_namespace": digest, "capability_body": digest, "semantic_request": digest, "policy_digest": digest,
		"contract_digest": digest, "authority_scope": digest, "basis": digest, "output_disposition": digest,
		"source_generation": integer, "isolation_epoch": integer,
	}, map[string]recoveryRule{"origin": recoveryObject(map[string]recoveryRule{"operation": operation, "request_id": opaque, "closure": opaque}, nil)})
	binding := recoveryObject(map[string]recoveryRule{
		"schema": recoveryEnum("chio.recovery.grant-binding.v1"), "version": version, "authority_domain": opaque,
		"workflow_id": opaque, "step_id": opaque, "continuation_id": opaque, "process_id": opaque, "request_id": opaque,
		"isolation_lineage": opaque, "approval_intent": opaque, "challenge": opaque, "request_namespace": digest,
		"action_intent": digest, "authorization_requirements": digest, "selected_offer": digest, "approved_plan": digest,
		"policy_digest": digest, "contract_digest": digest, "authority_scope": digest, "output_disposition": digest,
		"coverage_digest": digest, "isolation_epoch": positive,
	}, nil)
	approval := recoveryObject(map[string]recoveryRule{
		"schema": recoveryEnum("chio.recovery.approval-intent.v1"), "version": version, "approval_intent": opaque,
		"challenge": opaque, "scope": scope, "action_intent": digest, "authorization_requirements": digest,
		"offer": digest, "plan": digest, "preview": digest, "recipient": flow, "purpose": flow, "reviewer": flow,
		"obligations": obligations, "issued_at_unix_ms": integer, "expires_at_unix_ms": integer,
	}, nil)
	claims := recoveryObject(map[string]recoveryRule{
		"domain_version": version, "grant_id": flow, "capability_id": flow, "tenant_id": flow,
		"subject_id": flow, "agent_id": flow, "session_id": flow, "source_label_hash": digest,
		"target_label": knownLabel, "destination_id": flow, "tool_name": flow, "purpose": flow,
		"request_hash": digest, "issued_at_unix_seconds": integer, "expires_at_unix_seconds": integer,
		"authority_key_id": flow,
	}, nil)
	signed := func(body recoveryRule) recoveryRule {
		return recoveryObject(map[string]recoveryRule{"body": body, "authority_key": recoveryCryptoText(false), "algorithm": recoveryEnum("ed25519", "p256", "p384", "hybrid"), "signature": recoveryCryptoText(true)}, nil)
	}
	grant := signed(recoveryObject(map[string]recoveryRule{"schema": recoveryEnum("chio.declassification-grant.v2"), "domain_version": recoveryInteger(2, 2), "claims": claims, "recovery": binding}, nil))
	coverage := signed(recoveryObject(map[string]recoveryRule{
		"schema": recoveryEnum("chio.recovery.authority-coverage.v1"), "version": version, "approval_intent": opaque,
		"challenge": opaque, "scope": scope, "action_intent": digest, "authorization_requirements": digest,
		"obligations": obligations, "issued_at_unix_ms": integer, "expires_at_unix_ms": integer,
		"source_basis": digest, "issuer_id": opaque, "principal": flow,
	}, nil))
	provider := recoveryObject(map[string]recoveryRule{
		"schema": recoveryEnum("chio.recovery.provider-finality.v1"), "version": version, "workflow_id": opaque,
		"continuation_id": opaque, "operation_id": opaque, "attempt_id": opaque, "scope": scope,
		"native_admission_digest": digest, "provider": flow, "account": flow, "resource_digest": digest,
		"contract_digest": digest, "observed_at_unix_ms": integer, "expires_at_unix_ms": integer,
		"disposition": recoveryEnum("succeeded", "partially_applied", "failed_after_effect"), "applied_effects": recoveryInteger(1, 1),
	}, nil)
	commandVariants := map[string]recoveryRule{
		"create_workflow":  recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("create_workflow"), "creation_key": opaque, "template": recoveryEnum("support_ticket_public_issue"), "request_seed": recoveryProtectedText(32768)}, nil),
		"inspect_workflow": recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("inspect_workflow"), "workflow_id": opaque}, nil),
		"select_offer":     recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("select_offer"), "workflow_id": opaque, "expected_revision": integer, "offer_id": opaque}, nil),
		"submit_approval":  recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("submit_approval"), "workflow_id": opaque, "expected_revision": integer, "approval": recoveryProtectedText(32768)}, nil),
		"report_decision":  recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("report_decision"), "workflow_id": opaque, "expected_revision": integer, "decision": recoveryEnum("accepted", "declined", "needs_review")}, nil),
	}
	for _, kind := range []string{"resume_workflow", "cancel_workflow"} {
		commandVariants[kind] = recoveryObject(map[string]recoveryRule{"kind": recoveryEnum(kind), "workflow_id": opaque, "expected_revision": integer}, nil)
	}
	command := recoveryObject(map[string]recoveryRule{"schema": recoveryEnum("chio.recovery.command.v1"), "version": version, "command_id": opaque, "command": recoveryTagged("kind", commandVariants)}, nil)
	effectVariants := map[string]recoveryRule{
		"never_admitted":       recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("never_admitted")}, nil),
		"admission_unresolved": recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("admission_unresolved"), "admission_intent": opaque}, nil),
		"closed_before_effect": recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("closed_before_effect"), "operation": operation, "closure": opaque}, nil),
		"complete":             recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("complete"), "operation": operation, "effect_count": integer}, nil),
	}
	for _, kind := range []string{"awaiting_approval", "in_flight", "awaiting_caller_report", "unknown"} {
		effectVariants[kind] = recoveryObject(map[string]recoveryRule{"kind": recoveryEnum(kind), "operation": operation}, nil)
	}
	for _, kind := range []string{"partial", "failed_after_effect"} {
		effectVariants[kind] = recoveryObject(map[string]recoveryRule{"kind": recoveryEnum(kind), "operation": operation, "applied_effects": positive}, nil)
	}
	refusal := recoveryEnum("invalid_evidence", "unsupported_profile", "stale_basis", "revoked", "expired", "budget_unavailable", "unknown_effect", "audience_denied", "resource_exhausted")
	releaseVariants := map[string]recoveryRule{
		"not_available": recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("not_available")}, nil),
		"withheld":      recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("withheld"), "evidence": opaque}, nil),
		"denied":        recoveryObject(map[string]recoveryRule{"kind": recoveryEnum("denied"), "reason": refusal}, nil),
	}
	for _, kind := range []string{"pending", "released"} {
		releaseVariants[kind] = recoveryObject(map[string]recoveryRule{"kind": recoveryEnum(kind), "release_id": opaque}, nil)
	}
	response := recoveryObject(map[string]recoveryRule{
		"command_id": opaque, "workflow_id": opaque, "revision": integer,
		"control": recoveryEnum("active", "cancel_requested", "cancelled", "quarantined"),
		"effect":  recoveryTagged("kind", effectVariants), "release": recoveryTagged("kind", releaseVariants),
	}, nil)
	decisionVariants := map[string]recoveryRule{
		"allow": recoveryObject(map[string]recoveryRule{"verdict": recoveryEnum("allow")}, nil),
		"deny":  recoveryObject(map[string]recoveryRule{"verdict": recoveryEnum("deny"), "reason": recoveryText(0, 32768), "guard": recoveryText(0, 32768)}, nil),
	}
	for _, kind := range []string{"cancelled", "incomplete"} {
		decisionVariants[kind] = recoveryObject(map[string]recoveryRule{"verdict": recoveryEnum(kind), "reason": recoveryText(0, 32768)}, nil)
	}
	bbs := recoveryObject(map[string]recoveryRule{
		"schema": recoveryEnum("chio.receipt.bbs_signature.v1"), "projection_version": recoveryEnum("chio.bbs-projection.receipt.v1"),
		"algorithm": recoveryEnum("bbs"), "ciphersuite": recoveryEnum("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"),
		"issuer_fingerprint": func(value any) error {
			text, ok := value.(string)
			if !ok || len(text) > 128 || !regexp.MustCompile(`^[A-Za-z0-9._:-]+$`).MatchString(text) {
				return fmt.Errorf("invalid BBS issuer fingerprint")
			}
			return nil
		},
		"issuer_public_key_hex": func(value any) error { return recoveryHex(value, 192) },
		"message_count":         recoveryInteger(14, 14), "signature_hex": func(value any) error { return recoveryHex(value, 0) },
	}, nil)
	receiptShape := recoveryObject(map[string]recoveryRule{
		"id": hexDigest, "timestamp": integer, "capability_id": recoveryText(1, 32768),
		"tool_server": recoveryText(1, 32768), "tool_name": recoveryText(1, 32768),
		"action":         recoveryObject(map[string]recoveryRule{"parameters": anyValue, "parameter_hash": hexDigest}, nil),
		"receipt_kind":   recoveryEnum("mediated_decision", "trace_observation", "advisory_evaluation"),
		"boundary_class": recoveryEnum("prevent", "detect_only", "advisory_only"),
		"tool_origin":    recoveryEnum("caller_executed", "host_executed_provider_reported", "host_executed_unmediated", "chio_internal"),
		"redaction_mode": recoveryEnum("none", "summary", "redacted"), "content_hash": hexDigest,
		"policy_hash": recoveryText(1, 32768), "trust_level": recoveryEnum("mediated", "verified", "advisory"),
		"kernel_key": recoveryCryptoText(false), "signature": recoveryCryptoText(true),
	}, map[string]recoveryRule{
		"decision": recoveryTagged("verdict", decisionVariants), "observation_outcome": recoveryEnum("observed", "evaluated", "dropped"),
		"actor_chain": recoveryArray(recoveryObject(map[string]recoveryRule{"actor_id": recoveryText(1, 32768)}, map[string]recoveryRule{"actor_kind": recoveryText(1, 32768)}), 0, 256, false),
		"evidence":    recoveryArray(recoveryObject(map[string]recoveryRule{"guard_name": recoveryText(1, 32768), "verdict": boolean}, map[string]recoveryRule{"details": recoveryText(0, 32768)}), 0, 256, false),
		"metadata":    anyValue, "tenant_id": recoveryText(1, 32768),
		"bbs_projection_version": recoveryEnum("chio.bbs-projection.receipt.v1"), "bbs_signature": bbs,
		"algorithm": recoveryEnum("ed25519", "p256", "p384", "hybrid"),
	})
	receipt := recoveryRule(func(value any) error {
		if err := receiptShape(value); err != nil {
			return err
		}
		object := value.(map[string]any)
		_, decision := object["decision"]
		_, observation := object["observation_outcome"]
		_, bbsVersion := object["bbs_projection_version"]
		_, bbsSignature := object["bbs_signature"]
		if bbsVersion != bbsSignature {
			return fmt.Errorf("receipt BBS fields require each other")
		}
		switch object["receipt_kind"] {
		case "mediated_decision":
			if !decision || observation || object["boundary_class"] != "prevent" || object["trust_level"] != "mediated" {
				return fmt.Errorf("invalid mediated receipt shape")
			}
		case "trace_observation":
			if decision || !observation || object["boundary_class"] != "detect_only" || object["trust_level"] != "verified" {
				return fmt.Errorf("invalid trace receipt shape")
			}
		case "advisory_evaluation":
			if decision || !observation || object["boundary_class"] != "advisory_only" || object["trust_level"] != "advisory" {
				return fmt.Errorf("invalid advisory receipt shape")
			}
		}
		return nil
	})
	return map[string]recoveryRule{
		"action": action, "requirements": requirements, "grant_binding": binding, "approval_intent": approval,
		"grant": grant, "coverage": coverage, "provider_finality": signed(provider), "provider_body": provider, "command": command,
		"support_issue_effect": recoveryObject(map[string]recoveryRule{
			"schema": recoveryEnum("chio.recovery.support-issue-effect.v1"), "provider": flow, "account": flow,
			"resource": recoveryProtectedText(2048), "observation_key": recoveryCryptoText(false), "max_response_bytes": recoveryInteger(1, 65536),
		}, nil),
		"support_issue_input": recoveryObject(map[string]recoveryRule{"title": recoveryProtectedText(256), "body": recoveryProtectedText(16384)}, nil),
		"command_response":    response,
		"command_result": recoveryObject(map[string]recoveryRule{"status": response}, map[string]recoveryRule{
			"original_response": recoveryObject(map[string]recoveryRule{"receipt": receipt, "result": anyValue}, nil),
		}),
		"review_document": recoveryObject(map[string]recoveryRule{"intent": approval, "canonical_preview": recoveryProtectedText(32768)}, nil),
	}
}

func (value *RecoveryActionIntent) UnmarshalJSON(data []byte) error {
	type wire RecoveryActionIntent
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "action"); err != nil {
		return err
	}
	*value = RecoveryActionIntent(decoded)
	return nil
}
func (value *RecoveryAuthorizationRequirements) UnmarshalJSON(data []byte) error {
	type wire RecoveryAuthorizationRequirements
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "requirements"); err != nil {
		return err
	}
	*value = RecoveryAuthorizationRequirements(decoded)
	return nil
}
func (value *RecoveryGrantBinding) UnmarshalJSON(data []byte) error {
	type wire RecoveryGrantBinding
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "grant_binding"); err != nil {
		return err
	}
	*value = RecoveryGrantBinding(decoded)
	return nil
}
func (value *RecoveryApprovalIntent) UnmarshalJSON(data []byte) error {
	type wire RecoveryApprovalIntent
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "approval_intent"); err != nil {
		return err
	}
	*value = RecoveryApprovalIntent(decoded)
	return nil
}
func (value *RecoverySignedGrantV2) UnmarshalJSON(data []byte) error {
	type wire RecoverySignedGrantV2
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "grant"); err != nil {
		return err
	}
	*value = RecoverySignedGrantV2(decoded)
	return nil
}
func (value *RecoverySignedAuthorityCoverage) UnmarshalJSON(data []byte) error {
	type wire RecoverySignedAuthorityCoverage
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "coverage"); err != nil {
		return err
	}
	*value = RecoverySignedAuthorityCoverage(decoded)
	return nil
}
func (value *RecoverySignedProviderFinality) UnmarshalJSON(data []byte) error {
	type wire RecoverySignedProviderFinality
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "provider_finality"); err != nil {
		return err
	}
	*value = RecoverySignedProviderFinality(decoded)
	return nil
}
func (value *RecoveryProviderFinality) UnmarshalJSON(data []byte) error {
	type wire RecoveryProviderFinality
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "provider_body"); err != nil {
		return err
	}
	*value = RecoveryProviderFinality(decoded)
	return nil
}
func (value *RecoveryCommand) UnmarshalJSON(data []byte) error {
	type wire RecoveryCommand
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "command"); err != nil {
		return err
	}
	*value = RecoveryCommand(decoded)
	return nil
}
func (value *RecoverySupportIssueEffect) UnmarshalJSON(data []byte) error {
	type wire RecoverySupportIssueEffect
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "support_issue_effect"); err != nil {
		return err
	}
	*value = RecoverySupportIssueEffect(decoded)
	return nil
}
func (value *RecoverySupportIssueInput) UnmarshalJSON(data []byte) error {
	type wire RecoverySupportIssueInput
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "support_issue_input"); err != nil {
		return err
	}
	*value = RecoverySupportIssueInput(decoded)
	return nil
}
func (value *RecoveryCommandResponse) UnmarshalJSON(data []byte) error {
	type wire RecoveryCommandResponse
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "command_response"); err != nil {
		return err
	}
	*value = RecoveryCommandResponse(decoded)
	return nil
}
func (value *RecoveryCommandResult) UnmarshalJSON(data []byte) error {
	// The standalone ReceiptRecord helper decodes its interface fields without
	// UseNumber. This local alias preserves checked signed JSON lexemes while
	// retaining the receipt's semantic validation before publishing the value.
	type receiptWire ReceiptRecord
	var decoded struct {
		OriginalResponse *struct {
			Receipt receiptWire `json:"receipt"`
			Result  interface{} `json:"result"`
		} `json:"original_response,omitempty"`
		Status RecoveryCommandResponse `json:"status"`
	}
	if err := decodeRecoveryObject(data, &decoded, "command_result"); err != nil {
		return err
	}
	result := RecoveryCommandResult{Status: decoded.Status}
	if original := decoded.OriginalResponse; original != nil {
		receipt := ReceiptRecord(original.Receipt)
		if err := receipt.ValidateSemantics(); err != nil {
			return err
		}
		result.OriginalResponse = &struct {
			Receipt ReceiptRecord `json:"receipt"`
			Result  interface{}   `json:"result"`
		}{Receipt: receipt, Result: original.Result}
	}
	*value = result
	return nil
}
func (value *RecoveryReviewDocument) UnmarshalJSON(data []byte) error {
	type wire RecoveryReviewDocument
	var decoded wire
	if err := decodeRecoveryObject(data, &decoded, "review_document"); err != nil {
		return err
	}
	*value = RecoveryReviewDocument(decoded)
	return nil
}
