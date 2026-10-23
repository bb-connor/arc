package invariants_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
)

const vectorRoot = "../../../../tests/bindings/vectors"

type canonicalVectors struct {
	Cases []struct {
		CanonicalJSON string `json:"canonical_json"`
		ID            string `json:"id"`
		InputJSON     string `json:"input_json"`
	} `json:"cases"`
}

type hashingVectors struct {
	Cases []struct {
		ID        string `json:"id"`
		InputUTF8 string `json:"input_utf8"`
		SHA256Hex string `json:"sha256_hex"`
	} `json:"cases"`
}

type signingVectors struct {
	JSONCases []struct {
		CanonicalJSON  string `json:"canonical_json"`
		ExpectedVerify bool   `json:"expected_verify"`
		ID             string `json:"id"`
		InputJSON      string `json:"input_json"`
		PublicKeyHex   string `json:"public_key_hex"`
		SignatureHex   string `json:"signature_hex"`
	} `json:"json_cases"`
	SigningKeySeedHex string `json:"signing_key_seed_hex"`
	UTF8Cases         []struct {
		ExpectedVerify bool   `json:"expected_verify"`
		ID             string `json:"id"`
		InputUTF8      string `json:"input_utf8"`
		PublicKeyHex   string `json:"public_key_hex"`
		SignatureHex   string `json:"signature_hex"`
	} `json:"utf8_cases"`
}

type receiptVectors struct {
	Cases []struct {
		Expected                 invariants.ReceiptVerification `json:"expected"`
		ID                       string                         `json:"id"`
		Receipt                  map[string]any                 `json:"receipt"`
		ReceiptBodyCanonicalJSON string                         `json:"receipt_body_canonical_json"`
	} `json:"cases"`
	SigningKeySeedHex string `json:"signing_key_seed_hex"`
}

type capabilityVectors struct {
	Cases []struct {
		Capability                     map[string]any                     `json:"capability"`
		CapabilitySigningBodyCanonical string                             `json:"capability_signing_body_canonical_json"`
		Expected                       invariants.CapabilityVerification  `json:"expected"`
		ExpectedWithMaxDelegationDepth *invariants.CapabilityVerification `json:"expected_with_max_delegation_depth"`
		ID                             string                             `json:"id"`
		MaxDelegationDepth             *int                               `json:"max_delegation_depth"`
		VerifyAt                       int64                              `json:"verify_at"`
	} `json:"cases"`
}

func TestCanonicalVectors(t *testing.T) {
	var vectors canonicalVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "canonical", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			rendered, err := invariants.CanonicalizeJSONString(testCase.InputJSON)
			if err != nil {
				t.Fatalf("CanonicalizeJSONString returned error: %v", err)
			}
			if rendered != testCase.CanonicalJSON {
				t.Fatalf("unexpected canonical json: %s", rendered)
			}
		})
	}
}

func TestCanonicalStringsPassDELAndC1ControlsThrough(t *testing.T) {
	const controls = "\u007f\u009f"

	value, err := invariants.CanonicalizeJSON(controls)
	if err != nil {
		t.Fatalf("CanonicalizeJSON value returned error: %v", err)
	}
	if value != `"`+controls+`"` {
		t.Fatalf("unexpected canonical string value: %s", value)
	}

	object, err := invariants.CanonicalizeJSON(map[string]any{controls: controls})
	if err != nil {
		t.Fatalf("CanonicalizeJSON object returned error: %v", err)
	}
	if object != `{"`+controls+`":"`+controls+`"}` {
		t.Fatalf("unexpected canonical string key/value: %s", object)
	}
}

func TestHashingVectors(t *testing.T) {
	var vectors hashingVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "hashing", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			rendered := invariants.SHA256HexUTF8(testCase.InputUTF8)
			if rendered != testCase.SHA256Hex {
				t.Fatalf("unexpected sha256: %s", rendered)
			}
		})
	}
}

func TestSigningVectors(t *testing.T) {
	var vectors signingVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "signing", "v1.json"), &vectors)
	for _, testCase := range vectors.UTF8Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			verified, err := invariants.VerifyUTF8MessageEd25519(
				testCase.InputUTF8,
				testCase.PublicKeyHex,
				testCase.SignatureHex,
			)
			if err != nil {
				t.Fatalf("VerifyUTF8MessageEd25519 returned error: %v", err)
			}
			if verified != testCase.ExpectedVerify {
				t.Fatalf("unexpected utf8 verification result: %v", verified)
			}
		})
	}
	for _, testCase := range vectors.JSONCases {
		t.Run(testCase.ID, func(t *testing.T) {
			rendered, err := invariants.CanonicalizeJSONString(testCase.InputJSON)
			if err != nil {
				t.Fatalf("CanonicalizeJSONString returned error: %v", err)
			}
			if rendered != testCase.CanonicalJSON {
				t.Fatalf("unexpected canonical json: %s", rendered)
			}
			verified, err := invariants.VerifyJSONStringSignatureEd25519(
				testCase.InputJSON,
				testCase.PublicKeyHex,
				testCase.SignatureHex,
			)
			if err != nil {
				t.Fatalf("VerifyJSONStringSignatureEd25519 returned error: %v", err)
			}
			if verified != testCase.ExpectedVerify {
				t.Fatalf("unexpected json verification result: %v", verified)
			}
		})
	}
	signedUTF8, err := invariants.SignUTF8MessageEd25519("hello chio", vectors.SigningKeySeedHex)
	if err != nil {
		t.Fatalf("SignUTF8MessageEd25519 returned error: %v", err)
	}
	if signedUTF8.PublicKeyHex != vectors.UTF8Cases[0].PublicKeyHex || signedUTF8.SignatureHex != vectors.UTF8Cases[0].SignatureHex {
		t.Fatalf("unexpected utf8 signing output: %#v", signedUTF8)
	}
	signedJSON, err := invariants.SignJSONStringEd25519(vectors.JSONCases[0].InputJSON, vectors.SigningKeySeedHex)
	if err != nil {
		t.Fatalf("SignJSONStringEd25519 returned error: %v", err)
	}
	if signedJSON.CanonicalJSON != vectors.JSONCases[0].CanonicalJSON || signedJSON.PublicKeyHex != vectors.JSONCases[0].PublicKeyHex || signedJSON.SignatureHex != vectors.JSONCases[0].SignatureHex {
		t.Fatalf("unexpected json signing output: %#v", signedJSON)
	}
}

func TestReceiptVectors(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			renderedBody, err := invariants.ReceiptBodyCanonicalJSON(testCase.Receipt)
			if err != nil {
				t.Fatalf("ReceiptBodyCanonicalJSON returned error: %v", err)
			}
			if renderedBody != testCase.ReceiptBodyCanonicalJSON {
				t.Fatalf("unexpected receipt body: %s", renderedBody)
			}
			verification, err := invariants.VerifyReceipt(testCase.Receipt)
			if err != nil {
				t.Fatalf("VerifyReceipt returned error: %v", err)
			}
			var verificationJSON map[string]any
			verificationBytes, err := json.Marshal(verification)
			if err != nil {
				t.Fatalf("Marshal receipt verification returned error: %v", err)
			}
			if err := json.Unmarshal(verificationBytes, &verificationJSON); err != nil {
				t.Fatalf("Unmarshal receipt verification returned error: %v", err)
			}
			if verificationJSON["trust_level"] != testCase.Receipt["trust_level"] {
				t.Fatalf("unexpected receipt trust level: %#v", verificationJSON)
			}
			if verification != testCase.Expected {
				t.Fatalf("unexpected receipt verification: %#v", verification)
			}
		})
	}
}

func TestReceiptVectorsSupportTrustedSigners(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		if testCase.ID != "allow_receipt" {
			continue
		}
		kernelKey, ok := testCase.Receipt["kernel_key"].(string)
		if !ok {
			t.Fatalf("allow receipt missing kernel_key")
		}
		verification, err := invariants.VerifyReceiptWithTrustedSigners(testCase.Receipt, []string{kernelKey})
		if err != nil {
			t.Fatalf("VerifyReceiptWithTrustedSigners returned error: %v", err)
		}
		if !verification.SignerTrusted || !verification.Ok || !verification.Authorized {
			t.Fatalf("trusted signer verification did not authorize: %#v", verification)
		}
		return
	}
	t.Fatalf("allow_receipt vector not found")
}

func TestReceiptSemanticsIgnoreLegacyMetadataPayloads(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		if testCase.ID != "allow_receipt" {
			continue
		}
		receipt := cloneMap(t, testCase.Receipt)
		receipt["metadata"] = map[string]any{
			"receipt_semantics": map[string]any{
				"receiptKind":   "trace_observation",
				"boundaryClass": "detect_only",
			},
		}
		kernelKey, ok := receipt["kernel_key"].(string)
		if !ok {
			t.Fatalf("allow receipt missing kernel_key")
		}
		verification, err := invariants.VerifyReceiptWithTrustedSigners(receipt, []string{kernelKey})
		if err != nil {
			t.Fatalf("VerifyReceipt returned error: %v", err)
		}
		if verification.ReceiptKind != "mediated_decision" || verification.BoundaryClass != "prevent" {
			t.Fatalf("legacy metadata semantics affected verification: %#v", verification)
		}
		if verification.ReceiptIDValid || verification.SignatureValid || verification.Authorized {
			t.Fatalf("mutated signed metadata unexpectedly remained authoritative: %#v", verification)
		}
		return
	}
	t.Fatalf("allow_receipt vector not found")
}

func TestReceiptSignatureValidFailsWhenContentAddressedIDMismatches(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		if testCase.ID != "allow_receipt" {
			continue
		}
		receipt := cloneMap(t, testCase.Receipt)
		receipt["id"] = "0000000000000000000000000000000000000000000000000000000000000000"
		body, err := invariants.ReceiptSigningBodyCanonicalJSON(receipt)
		if err != nil {
			t.Fatalf("ReceiptSigningBodyCanonicalJSON returned error: %v", err)
		}
		signed, err := invariants.SignJSONStringEd25519(body, vectors.SigningKeySeedHex)
		if err != nil {
			t.Fatalf("SignJSONStringEd25519 returned error: %v", err)
		}
		receipt["signature"] = signed.SignatureHex
		verification, err := invariants.VerifyReceipt(receipt)
		if err != nil {
			t.Fatalf("VerifyReceipt returned error: %v", err)
		}
		if verification.ReceiptIDValid || verification.SignatureValid || verification.Ok {
			t.Fatalf("mismatched receipt id must invalidate signature status: %#v", verification)
		}
		return
	}
	t.Fatalf("allow_receipt vector not found")
}

func TestCapabilityVectors(t *testing.T) {
	var vectors capabilityVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "capability", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			renderedBody, err := invariants.CapabilitySigningBodyCanonicalJSON(testCase.Capability)
			if err != nil {
				t.Fatalf("CapabilitySigningBodyCanonicalJSON returned error: %v", err)
			}
			if renderedBody != testCase.CapabilitySigningBodyCanonical {
				t.Fatalf("unexpected capability signing body: %s", renderedBody)
			}
			verification, err := invariants.VerifyCapability(testCase.Capability, testCase.VerifyAt)
			if err != nil {
				t.Fatalf("VerifyCapability returned error: %v", err)
			}
			if verification != testCase.Expected {
				t.Fatalf("unexpected capability verification: %#v", verification)
			}
			if testCase.ExpectedWithMaxDelegationDepth != nil {
				if testCase.MaxDelegationDepth == nil {
					t.Fatalf("expected_with_max_delegation_depth requires max_delegation_depth")
				}
				withDepth, err := invariants.VerifyCapabilityWithMaxDelegationDepth(
					testCase.Capability,
					testCase.VerifyAt,
					*testCase.MaxDelegationDepth,
				)
				if err != nil {
					t.Fatalf("VerifyCapabilityWithMaxDelegationDepth returned error: %v", err)
				}
				if withDepth != *testCase.ExpectedWithMaxDelegationDepth {
					t.Fatalf("unexpected max-depth capability verification: %#v", withDepth)
				}
			}
		})
	}
}

func cloneMap(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("failed to marshal clone input: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("failed to unmarshal clone output: %v", err)
	}
	return output
}

func loadVectorFile(t *testing.T, path string, target any) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("failed to decode %s: %v", path, err)
	}
}

func TestCapabilityWithoutV1SchemaIsRefused(t *testing.T) {
	for _, payload := range []string{`{"id":"cap"}`, `{"id":"cap","schema":"chio.capability.v2"}`} {
		if _, err := invariants.ParseCapabilityJSON(payload); err == nil || !strings.Contains(err.Error(), `capability schema must be "chio.capability.v1"`) {
			t.Fatalf("expected schema refusal for %s, got %v", payload, err)
		}
	}
	if _, err := invariants.CapabilitySigningBodyCanonicalJSON(map[string]any{"id": "cap"}); err == nil {
		t.Fatalf("expected signing body refusal without schema")
	}
}

func paddedReceipt(t *testing.T, receipt map[string]any, pointer string) map[string]any {
	t.Helper()
	switch pointer {
	case "/actor_chain/0":
		receipt["actor_chain"] = []any{map[string]any{"actor_id": "agent-1", "pad": float64(0)}}
		return receipt
	case "/bbs_signature":
		receipt["bbs_signature"] = map[string]any{"pad": float64(0)}
		return receipt
	}
	var target any = receipt
	for _, part := range strings.Split(pointer, "/")[1:] {
		switch node := target.(type) {
		case map[string]any:
			target = node[part]
		case []any:
			target = node[0]
		}
	}
	object, ok := target.(map[string]any)
	if !ok {
		t.Fatalf("pointer %q does not name an object", pointer)
	}
	object["pad"] = float64(0)
	return receipt
}

func assertReceiptMemberRefused(t *testing.T, receipt map[string]any, member string) {
	t.Helper()
	kernelKey, _ := receipt["kernel_key"].(string)
	_, err := invariants.VerifyReceiptWithTrustedSigners(receipt, []string{kernelKey})
	invariantErr, ok := err.(*invariants.InvariantError)
	if !ok {
		t.Fatalf("%s: expected InvariantError, got %v", member, err)
	}
	if invariantErr.Code != "receipt" || invariantErr.Message != "unknown receipt member: "+member {
		t.Fatalf("%s: unexpected refusal %#v", member, invariantErr)
	}
}

func TestEveryReceiptRecordRefusesAnUnknownMember(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	byID := map[string]map[string]any{}
	for _, testCase := range vectors.Cases {
		byID[testCase.ID] = testCase.Receipt
	}
	for _, padding := range []struct{ caseID, pointer string }{
		{"allow_receipt", ""},
		{"allow_receipt", "/action"},
		{"allow_receipt", "/decision"},
		{"deny_receipt", "/decision"},
		{"allow_receipt", "/evidence/0"},
		{"allow_receipt", "/actor_chain/0"},
		{"allow_receipt", "/bbs_signature"},
	} {
		source, ok := byID[padding.caseID]
		if !ok {
			t.Fatalf("%s vector not found", padding.caseID)
		}
		receipt := paddedReceipt(t, cloneMap(t, source), padding.pointer)
		assertReceiptMemberRefused(t, receipt, padding.pointer+"/pad")
	}
	allow := cloneMap(t, byID["allow_receipt"])
	allow["schema"] = "chio.receipt.v1"
	assertReceiptMemberRefused(t, allow, "/schema")
}

func TestProtocolPrimitivesUnknownFieldReceiptIsRefused(t *testing.T) {
	var corpus struct {
		Cases []struct {
			Name     string         `json:"name"`
			Valid    bool           `json:"valid"`
			Instance map[string]any `json:"instance"`
		} `json:"cases"`
	}
	loadVectorFile(t, "../../../../tests/bindings/fixtures/protocol-primitives-v1.json", &corpus)
	for _, testCase := range corpus.Cases {
		if testCase.Name != "receipt-unknown-field" {
			continue
		}
		if testCase.Valid {
			t.Fatalf("receipt-unknown-field must be an invalid case")
		}
		assertReceiptMemberRefused(t, testCase.Instance, "/unsigned_extension")
		return
	}
	t.Fatalf("receipt-unknown-field case not found")
}
