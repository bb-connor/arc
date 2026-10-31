package invariants_test

import (
	"encoding/json"
	"errors"
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
		SchemaID       string `json:"schema_id"`
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
	for _, testCase := range vectors.JSONCases {
		if testCase.SchemaID == "" {
			t.Skip("signing vectors carry no schema_id until they regenerate")
		}
	}
	if len(vectors.UTF8Cases) != 0 {
		t.Fatalf("signing vectors must not carry utf8_cases")
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
			err = invariants.VerifyWrappedJSON(testCase.SchemaID, testCase.InputJSON, testCase.PublicKeyHex, testCase.SignatureHex)
			if (err == nil) != testCase.ExpectedVerify {
				t.Fatalf("unexpected wrapped verification result: %v", err)
			}
			if !testCase.ExpectedVerify {
				return
			}
			signed, err := invariants.SignWrappedJSONEd25519(testCase.SchemaID, testCase.InputJSON, vectors.SigningKeySeedHex)
			if err != nil {
				t.Fatalf("SignWrappedJSONEd25519 returned error: %v", err)
			}
			if signed.CanonicalJSON != testCase.CanonicalJSON || signed.PublicKeyHex != testCase.PublicKeyHex || signed.SignatureHex != testCase.SignatureHex {
				t.Fatalf("unexpected wrapped signing output: %#v", signed)
			}
		})
	}
	publicKey, err := invariants.PublicKeyFromSeedEd25519(vectors.SigningKeySeedHex)
	if err != nil {
		t.Fatalf("PublicKeyFromSeedEd25519 returned error: %v", err)
	}
	signed, err := invariants.SignWrappedJSONEd25519(invariants.ReceiptSchema, `{"b":1,"a":2}`, vectors.SigningKeySeedHex)
	if err != nil || signed.PublicKeyHex != publicKey {
		t.Fatalf("unexpected wrapped signing identity: %#v %v", signed, err)
	}
}

func TestUnregisteredSchemaIDIsRefused(t *testing.T) {
	seed := strings.Repeat("01", 32)
	_, err := invariants.SignWrappedJSONEd25519("chio.unregistered-fixture.v1", `{"a":1}`, seed)
	assertInvariantError(t, err, "unregistered_schema_id", "unregistered signed-artifact schema id: chio.unregistered-fixture.v1")
	signed, err := invariants.SignWrappedJSONEd25519(invariants.ReceiptSchema, `{"a":1}`, seed)
	if err != nil {
		t.Fatalf("SignWrappedJSONEd25519 returned error: %v", err)
	}
	err = invariants.VerifyWrappedJSON("chio.unregistered-fixture.v1", `{"a":1}`, signed.PublicKeyHex, signed.SignatureHex)
	assertInvariantError(t, err, "unregistered_schema_id", "unregistered signed-artifact schema id: chio.unregistered-fixture.v1")
	err = invariants.VerifyWrappedJSON(invariants.CapabilitySchema, `{"a":1}`, signed.PublicKeyHex, signed.SignatureHex)
	assertInvariantError(t, err, "signature_rejected", "signature rejected")
}

func TestCapabilityWithAlgorithmMemberIsRefused(t *testing.T) {
	var vectors capabilityVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "capability", "v1.json"), &vectors)
	for _, algorithm := range []string{"ed25519", "p256"} {
		capability := cloneMap(t, vectors.Cases[0].Capability)
		capability["algorithm"] = algorithm
		encoded, err := json.Marshal(capability)
		if err != nil {
			t.Fatalf("marshal capability: %v", err)
		}
		_, err = invariants.ParseCapabilityJSON(string(encoded))
		assertInvariantError(t, err, "json", "capability has unknown member algorithm")
	}
}

func rootAnchorFixture() map[string]any {
	return map[string]any{
		"kind":               "oidc_jwt",
		"context_digest":     "sha256:" + strings.Repeat("a", 64),
		"root_policy_digest": "sha256:" + strings.Repeat("b", 64),
		"anchored_at":        json.Number("1700000000"),
		"assertion_exp":      json.Number("1700000600"),
	}
}

func anchoredCapabilityJSON(t *testing.T, anchor any) string {
	t.Helper()
	var vectors capabilityVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "capability", "v1.json"), &vectors)
	capability := cloneMap(t, vectors.Cases[0].Capability)
	capability["root_anchor"] = anchor
	encoded, err := json.Marshal(capability)
	if err != nil {
		t.Fatalf("marshal capability: %v", err)
	}
	return string(encoded)
}

func TestRootAnchorDecodesEveryKindAndEntersTheSigningBody(t *testing.T) {
	for _, kind := range []string{
		"oauth_id_jag", "entra_jwt", "entra_agent_id", "oidc_jwt",
		"oauth_introspection", "chio_local_as", "chio_operator_key", "operator_static_bearer",
	} {
		anchor := rootAnchorFixture()
		anchor["kind"] = kind
		capability, err := invariants.ParseCapabilityJSON(anchoredCapabilityJSON(t, anchor))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		canonical, err := invariants.CapabilitySigningBodyCanonicalJSON(capability)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		want := `"root_anchor":{"anchored_at":1700000000,"assertion_exp":1700000600,` +
			`"context_digest":"sha256:` + strings.Repeat("a", 64) + `","kind":"` + kind +
			`","root_policy_digest":"sha256:` + strings.Repeat("b", 64) + `"}`
		if !strings.Contains(canonical, want) {
			t.Fatalf("%s: signing body lost root_anchor bytes: %s", kind, canonical)
		}
	}
}

func TestRootAnchorRefusesMalformedValues(t *testing.T) {
	with := func(member string, value any) map[string]any {
		anchor := rootAnchorFixture()
		anchor[member] = value
		return anchor
	}
	without := func(member string) map[string]any {
		anchor := rootAnchorFixture()
		delete(anchor, member)
		return anchor
	}
	cases := []struct {
		anchor  any
		message string
	}{
		{"oidc_jwt", "root_anchor must be a JSON object"},
		{nil, "root_anchor must be a JSON object"},
		{with("padding", "x"), "root_anchor has unknown member padding"},
		{without("kind"), "root_anchor is missing member kind"},
		{without("assertion_exp"), "root_anchor is missing member assertion_exp"},
		{with("kind", "spiffe"), "root_anchor kind is not a known anchor kind"},
		{with("kind", json.Number("1")), "root_anchor kind is not a known anchor kind"},
		{with("context_digest", "sha256:"+strings.Repeat("A", 64)), "root_anchor context_digest must be a sha256 digest"},
		{with("root_policy_digest", strings.Repeat("b", 64)), "root_anchor root_policy_digest must be a sha256 digest"},
		{with("anchored_at", json.Number("-1")), "root_anchor anchored_at must be an unsigned integer"},
		{with("assertion_exp", "1700000600"), "root_anchor assertion_exp must be an unsigned integer"},
		{with("assertion_exp", json.Number("9007199254740992")), "root_anchor assertion_exp must be an unsigned integer"},
	}
	for _, testCase := range cases {
		_, err := invariants.ParseCapabilityJSON(anchoredCapabilityJSON(t, testCase.anchor))
		assertInvariantError(t, err, "json", testCase.message)
	}
}

type wrapperVectors struct {
	SignatureCases []struct {
		Algorithm      string `json:"algorithm"`
		CanonicalBody  string `json:"canonical_body"`
		ExpectedVerify bool   `json:"expected_verify"`
		ID             string `json:"id"`
		PublicKey      string `json:"public_key"`
		Signature      string `json:"signature"`
		VerifySchemaID string `json:"verify_schema_id"`
	} `json:"signature_cases"`
}

func TestSigningWrapperVectors(t *testing.T) {
	var vectors wrapperVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "signing", "wrapper", "v1.json"), &vectors)
	skipped := map[string]struct{}{}
	for _, testCase := range vectors.SignatureCases {
		if testCase.Algorithm != "ed25519" {
			skipped[testCase.Algorithm] = struct{}{}
			continue
		}
		t.Run(testCase.ID, func(t *testing.T) {
			err := invariants.VerifyWrappedJSON(testCase.VerifySchemaID, testCase.CanonicalBody, testCase.PublicKey, testCase.Signature)
			if (err == nil) != testCase.ExpectedVerify {
				t.Fatalf("unexpected wrapper verification result: %v", err)
			}
		})
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped algorithms must be exactly p256 and p384: %v", skipped)
	}
	for _, algorithm := range []string{"p256", "p384"} {
		if _, ok := skipped[algorithm]; !ok {
			t.Fatalf("skipped algorithms must be exactly p256 and p384: %v", skipped)
		}
	}
}

func assertInvariantError(t *testing.T, err error, code string, message string) {
	t.Helper()
	var invariantError *invariants.InvariantError
	if !errors.As(err, &invariantError) || invariantError.Code != code || invariantError.Message != message {
		t.Fatalf("expected %s error %q, got %v", code, message, err)
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
		signed, err := invariants.SignWrappedJSONEd25519(invariants.ReceiptSchema, body, vectors.SigningKeySeedHex)
		if err != nil {
			t.Fatalf("SignWrappedJSONEd25519 returned error: %v", err)
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
