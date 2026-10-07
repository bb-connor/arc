package chio

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

func recoveryPositive(t *testing.T, contract string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../../spec/vectors/recovery/v1/authority-positive.json")
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	fixture := values[contract]
	if contract == "grant_binding" && len(fixture) == 0 {
		var grant struct {
			Body struct {
				Recovery json.RawMessage `json:"recovery"`
			} `json:"body"`
		}
		if err := json.Unmarshal(values["grant"], &grant); err != nil {
			t.Fatal(err)
		}
		fixture = grant.Body.Recovery
	}
	var value any
	if err := json.Unmarshal(fixture, &value); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mutateRecovery(t *testing.T, wire []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(wire, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRecoveryActionIntentRejectsNoncanonicalWire(t *testing.T) {
	fresh := recoveryPositive(t, "action")
	var original map[string]json.RawMessage
	if err := json.Unmarshal(fresh, &original); err != nil {
		t.Fatal(err)
	}
	origin := string(original["origin"])
	cases := map[string][]byte{
		"explicit null origin":  mutateRecovery(t, fresh, func(v map[string]any) { v["origin"] = nil }),
		"duplicate origin":      []byte(string(fresh[:len(fresh)-1]) + `,"origin":` + origin + `}`),
		"unknown action field":  mutateRecovery(t, fresh, func(v map[string]any) { v["unknown"] = true }),
		"case variant origin":   mutateRecovery(t, fresh, func(v map[string]any) { v["ORIGIN"] = v["origin"]; delete(v, "origin") }),
		"unknown origin field":  mutateRecovery(t, fresh, func(v map[string]any) { v["origin"].(map[string]any)["unknown"] = true }),
		"missing origin member": mutateRecovery(t, fresh, func(v map[string]any) { delete(v["origin"].(map[string]any), "closure") }),
		"zero operation version": mutateRecovery(t, fresh, func(v map[string]any) {
			v["origin"].(map[string]any)["operation"].(map[string]any)["operation_version"] = 0
		}),
		"unsafe integer":     bytes.Replace(fresh, []byte(`"isolation_epoch":1`), []byte(`"isolation_epoch":9007199254740992`), 1),
		"negative zero":      bytes.Replace(fresh, []byte(`"isolation_epoch":1`), []byte(`"isolation_epoch":-0`), 1),
		"exponent integer":   bytes.Replace(fresh, []byte(`"isolation_epoch":1`), []byte(`"isolation_epoch":1e0`), 1),
		"fractional integer": bytes.Replace(fresh, []byte(`"isolation_epoch":1`), []byte(`"isolation_epoch":1.0`), 1),
		"wrong domain":       mutateRecovery(t, fresh, func(v map[string]any) { v["schema"] = "chio.recovery.action-intent.v99" }),
		"wrong version":      mutateRecovery(t, fresh, func(v map[string]any) { v["version"] = 99 }),
		"short digest":       mutateRecovery(t, fresh, func(v map[string]any) { v["basis"] = []any{1} }),
		"invalid identifier": mutateRecovery(t, fresh, func(v map[string]any) { v["workflow_id"] = " bad" }),
		"unknown obligation": mutateRecovery(t, fresh, func(v map[string]any) {
			v["authorization_requirements"].(map[string]any)["obligations"] = []any{map[string]any{"kind": "unknown", "principal": "reader"}}
		}),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			var value RecoveryActionIntent
			if err := json.Unmarshal(wire, &value); err == nil {
				t.Fatal("closed action decoder accepted noncanonical or out-of-domain input")
			}
		})
	}
}

func recoveryTarget(contract string) any {
	switch contract {
	case "action":
		return &RecoveryActionIntent{}
	case "requirements":
		return &RecoveryAuthorizationRequirements{}
	case "grant_binding":
		return &RecoveryGrantBinding{}
	case "approval_intent":
		return &RecoveryApprovalIntent{}
	case "grant":
		return &RecoverySignedGrantV2{}
	case "coverage":
		return &RecoverySignedAuthorityCoverage{}
	case "provider_finality":
		return &RecoverySignedProviderFinality{}
	case "provider_body":
		return &RecoveryProviderFinality{}
	case "command":
		return &RecoveryCommand{}
	case "support_issue_effect":
		return &RecoverySupportIssueEffect{}
	case "support_issue_input":
		return &RecoverySupportIssueInput{}
	case "command_response":
		return &RecoveryCommandResponse{}
	case "command_result":
		return &RecoveryCommandResult{}
	case "review_document":
		return &RecoveryReviewDocument{}
	default:
		return nil
	}
}

func recoveryCorpusPath() string {
	if candidate := os.Getenv("CHIO_RECOVERY_CORPUS_PATH"); candidate != "" {
		return candidate
	}
	return "../../../spec/vectors/recovery/v1/authority-contracts.json"
}

// This fixture-only verifier deliberately handles the shared Ed25519 corpus.
// Decoding is not a trusted-key or context-authority decision.
func recoveryFixtureSignature(contract string, wire []byte) bool {
	domain, signed := map[string]string{
		"grant":             "chio:declassification-grant:v2",
		"coverage":          "chio:recovery-authority-coverage:v1",
		"provider_finality": "chio:recovery-provider-finality:v1",
	}[contract]
	if !signed {
		return true
	}
	var envelope struct {
		Algorithm    string          `json:"algorithm"`
		AuthorityKey string          `json:"authority_key"`
		Body         json.RawMessage `json:"body"`
		Signature    string          `json:"signature"`
	}
	if json.Unmarshal(wire, &envelope) != nil || envelope.Algorithm != "ed25519" {
		return false
	}
	key, keyErr := hex.DecodeString(envelope.AuthorityKey)
	signature, sigErr := hex.DecodeString(envelope.Signature)
	if keyErr != nil || sigErr != nil || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(key, append([]byte(domain+"\x00"), envelope.Body...), signature)
}

func TestRecoverySharedAuthorityCorpus(t *testing.T) {
	data, err := os.ReadFile(recoveryCorpusPath())
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FormatVersion int `json:"format_version"`
		Vectors       []struct {
			Name        string `json:"name"`
			Contract    string `json:"contract"`
			Wire        string `json:"wire"`
			Valid       bool   `json:"valid"`
			SchemaValid bool   `json:"schema_valid"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 || len(corpus.Vectors) == 0 {
		t.Fatal("unsupported or empty shared recovery corpus")
	}
	contracts := map[string]bool{}
	for _, vector := range corpus.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			target := recoveryTarget(vector.Contract)
			if target == nil {
				t.Fatalf("uncovered recovery contract %q", vector.Contract)
			}
			contracts[vector.Contract] = true
			wire := []byte(vector.Wire)
			decodeErr := json.Unmarshal(wire, target)
			decoded := decodeErr == nil
			// Schema validation sees already-parsed values. The signed decoder
			// must additionally refuse duplicate and noncanonical raw tokens.
			structural := vector.Valid || (vector.SchemaValid && strings.HasSuffix(vector.Name, "-invalid-signature"))
			if decoded != structural {
				t.Fatalf("closed wire acceptance = %v, want %v (error: %v)", decoded, structural, decodeErr)
			}
			if valid := decoded && recoveryFixtureSignature(vector.Contract, wire); valid != vector.Valid {
				t.Fatalf("wire plus fixture signature acceptance = %v, want %v", valid, vector.Valid)
			}
		})
	}
	if len(contracts) != 14 {
		t.Fatalf("shared corpus covered %d contracts, want all 14", len(contracts))
	}
}

func recoveryReceiptJSONWire(t *testing.T, field, payload string) []byte {
	t.Helper()
	wire := mutateRecovery(t, recoveryPositive(t, "command_result"), func(v map[string]any) {
		receipt := v["original_response"].(map[string]any)["receipt"].(map[string]any)
		if field == "parameters" {
			receipt["action"].(map[string]any)[field] = "signed-json-placeholder"
		} else {
			receipt[field] = "signed-json-placeholder"
		}
	})
	return bytes.Replace(wire, []byte(`"signed-json-placeholder"`), []byte(payload), 1)
}

func TestRecoveryCommandResultPreservesSignedReceiptJSON(t *testing.T) {
	payload := `{"confidence":0.5,"delta":-1,"nested":[-9007199254740991,9007199254740991,-1.25,1e-7,0.000001,0.12345678901234566,5e-324],"unicode":"日本😀"}`
	for _, field := range []string{"metadata", "parameters"} {
		t.Run(field, func(t *testing.T) {
			var value RecoveryCommandResult
			if err := json.Unmarshal(recoveryReceiptJSONWire(t, field, payload), &value); err != nil {
				t.Fatal("native signed receipt JSON refused:", err)
			}
			var retained any = value.OriginalResponse.Receipt.Action.Parameters
			if field == "metadata" {
				if value.OriginalResponse.Receipt.Metadata == nil {
					t.Fatal("signed receipt metadata was discarded")
				}
				retained = *value.OriginalResponse.Receipt.Metadata
			}
			object, ok := retained.(map[string]any)
			if !ok {
				t.Fatalf("signed receipt JSON retained as %T, want object", retained)
			}
			for name, token := range map[string]string{"confidence": "0.5", "delta": "-1"} {
				if number, ok := object[name].(json.Number); !ok || number.String() != token {
					t.Fatalf("signed %s lexeme = %#v, want %q", name, object[name], token)
				}
			}
			for index, token := range []string{"-9007199254740991", "9007199254740991", "-1.25", "1e-7", "0.000001", "0.12345678901234566", "5e-324"} {
				nested := object["nested"].([]any)[index]
				if number, ok := nested.(json.Number); !ok || number.String() != token {
					t.Fatalf("nested signed numeric lexeme = %#v, want %q", nested, token)
				}
			}
			if object["unicode"] != "日本😀" {
				t.Fatal("signed receipt Unicode changed")
			}
		})
		for _, token := range []string{"-1", "-9007199254740991", "9007199254740991", "-0.5", "0.5", "0.000001", "1e-7", "1.2345e-10", "-5e-324"} {
			t.Run(field+" scalar "+token, func(t *testing.T) {
				var value RecoveryCommandResult
				if err := value.UnmarshalJSON(recoveryReceiptJSONWire(t, field, token)); err != nil {
					t.Fatal("canonical I-JSON scalar refused:", err)
				}
			})
		}
	}
}

func TestRecoveryDecoderBoundsSignedReceiptJSONBeforeRetention(t *testing.T) {
	var nested any = true
	for depth := 0; depth < 17; depth++ {
		nested = []any{nested}
	}
	nodes := make([]any, 17)
	for index := range nodes {
		nodes[index] = make([]any, 256)
	}
	cases := map[string]any{
		"depth":                  nested,
		"container entries":      make([]any, 257),
		"aggregate nodes":        nodes,
		"aggregate string bytes": strings.Repeat("a", 32769),
		"wire bytes":             strings.Repeat("a", 65537),
	}
	for _, field := range []string{"metadata", "parameters"} {
		for name, payload := range cases {
			t.Run(field+" "+name, func(t *testing.T) {
				encoded, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				var value RecoveryCommandResult
				if err := json.Unmarshal(recoveryReceiptJSONWire(t, field, string(encoded)), &value); err == nil {
					t.Fatal("out-of-profile signed receipt JSON was retained")
				}
			})
		}
		for _, token := range []string{"-0", "-0.0", "1.0", "1e0", "0.5000", "5e-1", "1e-6", "1E-7", "1e-07", "1e+21", "9007199254740992", "-9007199254740992", "9007199254740991.1", "1e309", "1e-400", "0.123456789012345678901", "0.12345678901234567"} {
			t.Run(field+" number "+token, func(t *testing.T) {
				var value RecoveryCommandResult
				if err := json.Unmarshal(recoveryReceiptJSONWire(t, field, token), &value); err == nil {
					t.Fatal("non-interoperable or noncanonical signed raw number was accepted")
				}
			})
		}
	}
}

func TestRecoverySignedReceiptJSONKeepsUnsignedTypedFields(t *testing.T) {
	wire := recoveryReceiptJSONWire(t, "metadata", `{"confidence":0.5,"delta":-1}`)
	var fixture map[string]any
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	timestamp := fixture["original_response"].(map[string]any)["receipt"].(map[string]any)["timestamp"].(json.Number).String()
	for _, field := range []string{`"timestamp":` + timestamp, `"revision":13`, `"operation_version":8`} {
		for _, token := range []string{"-1", "0.5", "1.0", "1e0", "9007199254740992"} {
			t.Run(field+" "+token, func(t *testing.T) {
				bad := bytes.Replace(wire, []byte(field), []byte(strings.Split(field, ":")[0]+":"+token), 1)
				if bytes.Equal(bad, wire) {
					t.Fatalf("expected typed field %s missing", field)
				}
				var value RecoveryCommandResult
				if err := value.UnmarshalJSON(bad); err == nil {
					t.Fatal("arbitrary receipt JSON relaxed a typed unsigned field")
				}
			})
		}
	}
}

func TestRecoverySignedReceiptJSONRejectsAmbiguousOrInvalidText(t *testing.T) {
	for _, field := range []string{"metadata", "parameters"} {
		for _, payload := range []string{`{"delta":-1,"delta":0.5}`, `{"delta":-1,"\u0064elta":0.5}`, `{"a":"\ud800"}`, `{"\udc00":0.5}`, `NaN`, `Infinity`, `-Infinity`} {
			t.Run(field+" "+payload, func(t *testing.T) {
				var value RecoveryCommandResult
				if err := value.UnmarshalJSON(recoveryReceiptJSONWire(t, field, payload)); err == nil {
					t.Fatal("signed receipt JSON escaped duplicate, Unicode or syntax checks")
				}
			})
		}
		bad := bytes.Replace(recoveryReceiptJSONWire(t, field, `"invalid-utf8-marker"`), []byte("invalid-utf8-marker"), []byte{0xff}, 1)
		var value RecoveryCommandResult
		if err := value.UnmarshalJSON(bad); err == nil {
			t.Fatal("signed receipt JSON accepted invalid UTF-8")
		}
	}
}

func TestRecoverySignedReceiptJSONRetainsFoundationByteBound(t *testing.T) {
	row := "[" + strings.TrimSuffix(strings.Repeat("-9007199254740991,", 256), ",") + "]"
	for _, field := range []string{"metadata", "parameters"} {
		for _, rows := range []int{13, 14} {
			t.Run(field+" "+strconv.Itoa(rows)+" rows", func(t *testing.T) {
				payload := "[" + strings.TrimSuffix(strings.Repeat(row+",", rows), ",") + "]"
				wire := recoveryReceiptJSONWire(t, field, payload)
				if (len(wire) <= 65536) != (rows == 13) || len(wire) > 262144 {
					t.Fatalf("numeric receipt fixture has unexpected size %d", len(wire))
				}
				var value RecoveryCommandResult
				err := value.UnmarshalJSON(wire)
				if rows == 13 && err != nil {
					t.Fatal("bounded canonical signed integer array refused:", err)
				}
				if rows == 14 && (err == nil || !strings.Contains(err.Error(), "byte")) {
					t.Fatalf("foundation numeric-byte ceiling was not enforced: %v", err)
				}
			})
		}
	}
}

func TestRecoveryCommandResultPreservesReceiverOnSignedJSONRefusal(t *testing.T) {
	for _, field := range []string{"metadata", "parameters"} {
		t.Run(field, func(t *testing.T) {
			var value RecoveryCommandResult
			if err := value.UnmarshalJSON(recoveryReceiptJSONWire(t, field, `{"confidence":0.5,"delta":-1}`)); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := value.UnmarshalJSON(recoveryReceiptJSONWire(t, field, `{"confidence":0.5,"delta":-9007199254740992}`)); err == nil {
				t.Fatal("unsafe signed receipt JSON accepted")
			}
			after, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("signed JSON refusal changed the retained command result")
			}
		})
	}
}

func recoveryResultWire(t *testing.T, payload string) []byte {
	t.Helper()
	foundation := mutateRecovery(t, recoveryPositive(t, "command_result"), func(v map[string]any) {
		v["original_response"].(map[string]any)["result"] = "opaque-result-placeholder"
	})
	return bytes.Replace(foundation, []byte(`"opaque-result-placeholder"`), []byte(payload), 1)
}

func TestRecoveryCommandResultPreservesOpaqueToolNumberLexemes(t *testing.T) {
	payload := `{"decimal":1.25,"exponent":1e-3,"negative":-9007199254740993,"nested":[{"huge":9007199254740993,"negative_zero":-0,"uint64":18446744073709551615}],"unicode":"日本😀"}`
	var value RecoveryCommandResult
	if err := json.Unmarshal(recoveryResultWire(t, payload), &value); err != nil {
		t.Fatal("valid opaque native tool payload refused:", err)
	}
	result, ok := value.OriginalResponse.Result.(map[string]any)
	if !ok {
		t.Fatalf("tool result retained as %T, want lossless object", value.OriginalResponse.Result)
	}
	for name, token := range map[string]string{"decimal": "1.25", "exponent": "1e-3", "negative": "-9007199254740993"} {
		if number, ok := result[name].(json.Number); !ok || number.String() != token {
			t.Fatalf("%s numeric lexeme = %#v, want %q", name, result[name], token)
		}
	}
	nested := result["nested"].([]any)[0].(map[string]any)
	for name, token := range map[string]string{"huge": "9007199254740993", "negative_zero": "-0", "uint64": "18446744073709551615"} {
		if number, ok := nested[name].(json.Number); !ok || number.String() != token {
			t.Fatalf("nested %s numeric lexeme = %#v, want %q", name, nested[name], token)
		}
	}
	if result["unicode"] != "日本😀" {
		t.Fatal("opaque tool Unicode changed")
	}
	for _, token := range []string{"-42", "1.0", "1e0", "-1.5e+2", "0.123456789012345678901", "9007199254740993", "18446744073709551615", "1e309"} {
		t.Run(token, func(t *testing.T) {
			var result RecoveryCommandResult
			if err := json.Unmarshal(recoveryResultWire(t, token), &result); err != nil {
				t.Fatal("valid opaque numeric token refused:", err)
			}
			number, ok := result.OriginalResponse.Result.(json.Number)
			if !ok || number.String() != token {
				t.Fatalf("opaque numeric lexeme = %#v, want %q", result.OriginalResponse.Result, token)
			}
		})
	}
}

func TestRecoveryCommandResultUsesSeparateOpaqueResponseByteProfile(t *testing.T) {
	for _, size := range []int{65537, 262144} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			empty := recoveryResultWire(t, `""`)
			payload := `"` + strings.Repeat("a", size-len(empty)) + `"`
			wire := recoveryResultWire(t, payload)
			if len(wire) != size {
				t.Fatalf("response fixture = %d bytes, want %d", len(wire), size)
			}
			var value RecoveryCommandResult
			if err := value.UnmarshalJSON(wire); err != nil {
				t.Fatal("bounded native tool response refused:", err)
			}
			if value.OriginalResponse.Result != payload[1:len(payload)-1] {
				t.Fatal("large opaque tool payload changed")
			}
		})
	}
	tooLarge := recoveryResultWire(t, `"`+strings.Repeat("a", 262144)+`"`)
	var value RecoveryCommandResult
	if err := value.UnmarshalJSON(tooLarge); err == nil {
		t.Fatal("response beyond 256 KiB was accepted")
	}
}

func TestRecoveryOpaqueResultCannotRelaxSignedFoundation(t *testing.T) {
	wire := recoveryResultWire(t, `{"large":9007199254740993,"negative":-1,"real":1.5}`)
	for _, from := range []string{`"revision":13`, `"operation_version":8`} {
		bad := bytes.Replace(wire, []byte(from), []byte(strings.Split(from, ":")[0]+`:9007199254740993`), 1)
		if bytes.Equal(bad, wire) {
			t.Fatalf("expected signed foundation field %s missing", from)
		}
		var value RecoveryCommandResult
		if err := value.UnmarshalJSON(bad); err == nil {
			t.Fatal("opaque result relaxed a signed foundation integer")
		}
	}
	for _, payload := range []string{`{"dup":1,"dup":2}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), `NaN`, `Infinity`, `-Infinity`} {
		var value RecoveryCommandResult
		if err := value.UnmarshalJSON(recoveryResultWire(t, payload)); err == nil {
			t.Fatal("opaque tool payload escaped duplicate, depth or JSON-number grammar checks")
		}
	}
	invalidUTF8 := recoveryResultWire(t, `"opaque-byte-marker"`)
	invalidUTF8 = bytes.Replace(invalidUTF8, []byte("opaque-byte-marker"), []byte{0xff}, 1)
	var value RecoveryCommandResult
	if err := value.UnmarshalJSON(invalidUTF8); err == nil {
		t.Fatal("opaque tool payload accepted invalid UTF-8")
	}
}

func TestRecoveryOpaqueResultDoesNotUseFoundationContainerLimits(t *testing.T) {
	payloads := []string{
		"[" + strings.Repeat("0,", 4999) + "0]",
		strings.Repeat("[", 20) + "-1.25e+2" + strings.Repeat("]", 20),
		`{"😀":-1,"":9007199254740993}`,
	}
	for _, payload := range payloads {
		var value RecoveryCommandResult
		if err := value.UnmarshalJSON(recoveryResultWire(t, payload)); err != nil {
			t.Fatal("opaque tool result inherited foundation container or depth limits:", err)
		}
		if value.OriginalResponse.Result == nil {
			t.Fatal("opaque tool result was discarded")
		}
	}
}

func TestRecoveryActionDecoderPreservesReceiverOnRefusal(t *testing.T) {
	var value RecoveryActionIntent
	if err := json.Unmarshal(recoveryPositive(t, "action"), &value); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	bad := mutateRecovery(t, recoveryPositive(t, "action"), func(v map[string]any) { v["version"] = 99 })
	if err := json.Unmarshal(bad, &value); err == nil {
		t.Fatal("out-of-domain action was accepted")
	}
	after, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused wire changed the retained action")
	}
}

func TestRecoveryPositiveContractsPreserveNativeWireBytes(t *testing.T) {
	data, err := os.ReadFile(recoveryCorpusPath())
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Name     string `json:"name"`
			Contract string `json:"contract"`
			Wire     string `json:"wire"`
			Valid    bool   `json:"valid"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		if !vector.Valid {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			target := recoveryTarget(vector.Contract)
			if err := target.(json.Unmarshaler).UnmarshalJSON([]byte(vector.Wire)); err != nil {
				t.Fatal(err)
			}
			output, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(output) != vector.Wire {
				t.Fatal("typed decoding changed the native positive fixture bytes")
			}
		})
	}
	fresh := recoveryPositive(t, "action")
	var action RecoveryActionIntent
	if err := action.UnmarshalJSON(fresh); err != nil {
		t.Fatal(err)
	}
	if action.Origin == nil || action.Origin.Operation.OperationVersion < 1 {
		t.Fatal("fresh action lost its positive original operation claim")
	}
	legacy, err := os.ReadFile("../../../spec/vectors/recovery/v1/legacy-action-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := action.UnmarshalJSON(bytes.TrimSpace(legacy)); err != nil {
		t.Fatal(err)
	}
	if action.Origin != nil {
		t.Fatal("legacy action gained an origin")
	}
}

func TestRecoveryRawDecoderRequiresWholeCanonicalInput(t *testing.T) {
	wire := recoveryPositive(t, "action")
	for _, data := range [][]byte{append([]byte(" "), wire...), append(append([]byte(nil), wire...), '\n'), []byte("null")} {
		var action RecoveryActionIntent
		if err := action.UnmarshalJSON(data); err == nil {
			t.Fatal("raw decoder accepted noncanonical whole-input bytes")
		}
	}
}

func TestRecoverySignedDecoderRejectsNestedHybridRepresentation(t *testing.T) {
	wire := recoveryPositive(t, "grant")
	classical := strings.Repeat("a", 64)
	quantum := strings.Repeat("b", 3904)
	inner := "hybrid:" + classical + ":" + quantum + ":ed25519+mldsa65"
	data := mutateRecovery(t, wire, func(v map[string]any) { v["authority_key"] = "hybrid:" + inner + ":" + quantum + ":ed25519+mldsa65" })
	var grant RecoverySignedGrantV2
	if err := grant.UnmarshalJSON(data); err == nil {
		t.Fatal("nested hybrid key escaped the closed cryptographic wire grammar")
	}
}

func TestRecoveryCommandAndResponseFiniteBranches(t *testing.T) {
	commands := []string{
		`{"creation_key":"creation","kind":"create_workflow","request_seed":"seed","template":"support_ticket_public_issue"}`,
		`{"kind":"inspect_workflow","workflow_id":"workflow"}`,
		`{"expected_revision":0,"kind":"select_offer","offer_id":"offer","workflow_id":"workflow"}`,
		`{"approval":"approval","expected_revision":1,"kind":"submit_approval","workflow_id":"workflow"}`,
		`{"expected_revision":1,"kind":"resume_workflow","workflow_id":"workflow"}`,
		`{"expected_revision":1,"kind":"cancel_workflow","workflow_id":"workflow"}`,
		`{"decision":"accepted","expected_revision":1,"kind":"report_decision","workflow_id":"workflow"}`,
	}
	for _, command := range commands {
		wire := []byte(`{"command":` + command + `,"command_id":"command","schema":"chio.recovery.command.v1","version":1}`)
		var decoded RecoveryCommand
		if err := decoded.UnmarshalJSON(wire); err != nil {
			t.Fatalf("legal command branch %s: %v", command, err)
		}
		bad := bytes.Replace(wire, []byte(`"kind":`), []byte(`"UNKNOWN":`), 1)
		if err := decoded.UnmarshalJSON(bad); err == nil {
			t.Fatal("command branch accepted a missing discriminator")
		}
	}
	operation := `{"native_admission_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"operation_id":"operation","operation_version":1}`
	effects := []string{
		`{"kind":"never_admitted"}`,
		`{"admission_intent":"intent","kind":"admission_unresolved"}`,
		`{"closure":"closure","kind":"closed_before_effect","operation":` + operation + `}`,
		`{"kind":"awaiting_approval","operation":` + operation + `}`,
		`{"kind":"in_flight","operation":` + operation + `}`,
		`{"kind":"awaiting_caller_report","operation":` + operation + `}`,
		`{"kind":"unknown","operation":` + operation + `}`,
		`{"effect_count":1,"kind":"complete","operation":` + operation + `}`,
		`{"applied_effects":1,"kind":"partial","operation":` + operation + `}`,
		`{"applied_effects":1,"kind":"failed_after_effect","operation":` + operation + `}`,
	}
	releases := []string{
		`{"kind":"not_available"}`,
		`{"kind":"pending","release_id":"release"}`,
		`{"evidence":"evidence","kind":"withheld"}`,
		`{"kind":"released","release_id":"release"}`,
		`{"kind":"denied","reason":"audience_denied"}`,
	}
	for _, effect := range effects {
		for _, release := range releases {
			wire := []byte(`{"command_id":"command","control":"active","effect":` + effect + `,"release":` + release + `,"revision":0,"workflow_id":"workflow"}`)
			var response RecoveryCommandResponse
			if err := response.UnmarshalJSON(wire); err != nil {
				t.Fatalf("legal effect/release %s/%s: %v", effect, release, err)
			}
			bad := bytes.Replace(wire, []byte(`"kind":`), []byte(`"UNKNOWN":`), 1)
			if err := response.UnmarshalJSON(bad); err == nil {
				t.Fatal("effect branch accepted a missing discriminator")
			}
		}
	}
}

func TestRecoveryProtectedTextUsesUTF8ByteCeilings(t *testing.T) {
	cases := []struct {
		name     string
		contract string
		field    string
		value    string
		valid    bool
	}{
		{"title ASCII ceiling", "support_issue_input", "title", strings.Repeat("a", 256), true},
		{"title ASCII overflow", "support_issue_input", "title", strings.Repeat("a", 257), false},
		{"title UTF-8 ceiling", "support_issue_input", "title", strings.Repeat("é", 128), true},
		{"title UTF-8 overflow", "support_issue_input", "title", strings.Repeat("é", 128) + "a", false},
		{"body ASCII ceiling", "support_issue_input", "body", strings.Repeat("a", 16384), true},
		{"body ASCII overflow", "support_issue_input", "body", strings.Repeat("a", 16385), false},
		{"body UTF-8 ceiling", "support_issue_input", "body", strings.Repeat("é", 8192), true},
		{"body UTF-8 overflow", "support_issue_input", "body", strings.Repeat("é", 8192) + "a", false},
		{"resource ASCII ceiling", "support_issue_effect", "resource", strings.Repeat("a", 2048), true},
		{"resource ASCII overflow", "support_issue_effect", "resource", strings.Repeat("a", 2049), false},
		{"resource UTF-8 ceiling", "support_issue_effect", "resource", strings.Repeat("é", 1024), true},
		{"resource UTF-8 overflow", "support_issue_effect", "resource", strings.Repeat("é", 1024) + "a", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			wire := mutateRecovery(t, recoveryPositive(t, test.contract), func(v map[string]any) { v[test.field] = test.value })
			err := json.Unmarshal(wire, recoveryTarget(test.contract))
			if (err == nil) != test.valid {
				t.Fatalf("%s: %d UTF-8 bytes decoded = %v, want %v (error: %v)", test.field, len(test.value), err == nil, test.valid, err)
			}
		})
	}
}

func TestRecoveryCommandProtectedTextKeepsAggregateByteCeiling(t *testing.T) {
	for _, kind := range []string{"create_workflow", "submit_approval"} {
		for _, test := range []struct {
			name  string
			text  string
			valid bool
		}{
			{"ASCII within aggregate", strings.Repeat("a", 32000), true},
			{"UTF-8 within aggregate", strings.Repeat("é", 16000), true},
			{"ASCII field ceiling exceeds aggregate", strings.Repeat("a", 32768), false},
			{"UTF-8 field ceiling exceeds aggregate", strings.Repeat("é", 16384), false},
			{"UTF-8 field overflow", strings.Repeat("é", 16384) + "a", false},
		} {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				command := map[string]any{"kind": kind}
				if kind == "create_workflow" {
					command["creation_key"] = "creation"
					command["template"] = "support_ticket_public_issue"
					command["request_seed"] = test.text
				} else {
					command["workflow_id"] = "workflow"
					command["expected_revision"] = 1
					command["approval"] = test.text
				}
				wire := mutateRecovery(t, recoveryPositive(t, "command"), func(v map[string]any) { v["command"] = command })
				var result RecoveryCommand
				err := json.Unmarshal(wire, &result)
				if (err == nil) != test.valid {
					t.Fatalf("command %d-byte payload decoded = %v, want %v (error: %v)", len(test.text), err == nil, test.valid, err)
				}
			})
		}
	}
}

func TestRecoveryGrantBindingRejectsZeroIsolationEpoch(t *testing.T) {
	wire := mutateRecovery(t, recoveryPositive(t, "grant_binding"), func(v map[string]any) { v["isolation_epoch"] = 0 })
	var binding RecoveryGrantBinding
	if err := json.Unmarshal(wire, &binding); err == nil {
		t.Fatal("zero isolation epoch escaped the recovery grant binding")
	}
	grant := mutateRecovery(t, recoveryPositive(t, "grant"), func(v map[string]any) {
		v["body"].(map[string]any)["recovery"].(map[string]any)["isolation_epoch"] = 0
	})
	var signed RecoverySignedGrantV2
	if err := json.Unmarshal(grant, &signed); err == nil {
		t.Fatal("zero isolation epoch escaped the enclosing v2 grant")
	}
}

func TestRecoveryHistoricalActionKeepsZeroSafeIntegerData(t *testing.T) {
	legacy, err := os.ReadFile("../../../spec/vectors/recovery/v1/legacy-action-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, fields := range [][]string{{"source_generation"}, {"isolation_epoch"}, {"source_generation", "isolation_epoch"}} {
		t.Run(strings.Join(fields, "+"), func(t *testing.T) {
			wire := mutateRecovery(t, bytes.TrimSpace(legacy), func(v map[string]any) {
				for _, field := range fields {
					v[field] = 0
				}
			})
			var action RecoveryActionIntent
			if err := json.Unmarshal(wire, &action); err != nil {
				t.Fatal("retained historical action data was refused:", err)
			}
			if action.Origin != nil {
				t.Fatal("historical data gained a native authorization origin")
			}
			for _, field := range fields {
				if (field == "source_generation" && action.SourceGeneration != 0) || (field == "isolation_epoch" && action.IsolationEpoch != 0) {
					t.Fatal("retained zero SafeInteger data changed")
				}
			}
		})
	}
}

func TestRecoveryActionCountersKeepZeroDataWithOrigin(t *testing.T) {
	wire := mutateRecovery(t, recoveryPositive(t, "action"), func(v map[string]any) {
		v["source_generation"] = 0
		v["isolation_epoch"] = 0
	})
	var action RecoveryActionIntent
	if err := json.Unmarshal(wire, &action); err != nil {
		t.Fatal("raw action SafeInteger data was refused:", err)
	}
	if action.Origin == nil || action.SourceGeneration != 0 || action.IsolationEpoch != 0 {
		t.Fatal("raw action counters or origin changed")
	}
}
