package invariants_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
)

const vectorRoot = "../../../../tests/bindings/vectors"
const watermarkVectorRoot = "../../../../crates/tooling/chio-conformance/vectors/security/watermark"
const maxWatermarkSafeInteger int64 = (1 << 53) - 1

var watermarkPayloadFields = []string{
	"application_id",
	"encoding",
	"expires_at_unix_ms",
	"issued_at_unix_ms",
	"key_id",
	"marker_ref",
	"sequence",
	"session_id",
	"source_receipt_id",
	"tenant_id",
	"tool_id",
}

var watermarkNumericFields = []string{
	"expires_at_unix_ms",
	"issued_at_unix_ms",
	"sequence",
}

var declassificationEnvelopeFields = []string{
	"algorithm",
	"authority_key",
	"body",
	"signature",
}

var declassificationBodyFields = []string{
	"agent_id",
	"authority_key_id",
	"capability_id",
	"destination_id",
	"domain_version",
	"expires_at_unix_seconds",
	"grant_id",
	"issued_at_unix_seconds",
	"purpose",
	"request_hash",
	"session_id",
	"source_label_hash",
	"subject_id",
	"target_label",
	"tenant_id",
	"tool_name",
}

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

type declassificationVectors struct {
	Positive struct {
		CanonicalBodyJSON string `json:"canonical_body_json"`
		Grant             struct {
			Algorithm    string         `json:"algorithm"`
			AuthorityKey string         `json:"authority_key"`
			Body         map[string]any `json:"body"`
			Signature    string         `json:"signature"`
		} `json:"grant"`
		ID             string `json:"id"`
		SigningSeedHex string `json:"signing_seed_hex"`
	} `json:"positive"`
}

type watermarkVectors struct {
	Cases []struct {
		CanonicalEnvelopeJSON string         `json:"canonical_envelope_json"`
		CanonicalPayloadJSON  string         `json:"canonical_payload_json"`
		EncodedPayload        string         `json:"encoded_payload"`
		Envelope              map[string]any `json:"envelope"`
		ID                    string         `json:"id"`
		Payload               map[string]any `json:"payload"`
		PublicKeyHex          string         `json:"public_key_hex"`
		SignatureHex          string         `json:"signature_hex"`
		SigningMessageHex     string         `json:"signing_message_hex"`
		Token                 string         `json:"token"`
	} `json:"cases"`
	Schema            string `json:"schema"`
	SigningDomain     string `json:"signing_domain"`
	SigningKeySeedHex string `json:"signing_key_seed_hex"`
}

type watermarkRejectionVectors struct {
	Cases []struct {
		CanonicalPayloadJSON string `json:"canonical_payload_json"`
		ExpectedError        string `json:"expected_error"`
		Field                string `json:"field"`
		ID                   string `json:"id"`
		InputPayloadJSON     string `json:"input_payload_json"`
		ValueDecimal         string `json:"value_decimal"`
	} `json:"cases"`
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
		CapabilityBodyCanonicalJSON    string                             `json:"capability_body_canonical_json"`
		Expected                       invariants.CapabilityVerification  `json:"expected"`
		ExpectedWithMaxDelegationDepth *invariants.CapabilityVerification `json:"expected_with_max_delegation_depth"`
		ID                             string                             `json:"id"`
		MaxDelegationDepth             *int                               `json:"max_delegation_depth"`
		VerifyAt                       int64                              `json:"verify_at"`
	} `json:"cases"`
}

type manifestVectors struct {
	Cases []struct {
		Expected                  invariants.ManifestVerification `json:"expected"`
		ID                        string                          `json:"id"`
		ManifestBodyCanonicalJSON string                          `json:"manifest_body_canonical_json"`
		SignedManifest            map[string]any                  `json:"signed_manifest"`
	} `json:"cases"`
}

type manifestCanonicalRejectionVectors struct {
	Cases []struct {
		Field       string `json:"field"`
		ID          string `json:"id"`
		Replacement any    `json:"replacement"`
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

func TestDeclassificationVector(t *testing.T) {
	var vectors declassificationVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "declassification", "v1.json"), &vectors)
	testCase := vectors.Positive
	grant := map[string]any{
		"algorithm":     testCase.Grant.Algorithm,
		"authority_key": testCase.Grant.AuthorityKey,
		"body":          testCase.Grant.Body,
		"signature":     testCase.Grant.Signature,
	}
	assertExactObjectKeys(t, grant, declassificationEnvelopeFields)
	assertExactObjectKeys(t, testCase.Grant.Body, declassificationBodyFields)
	if testCase.Grant.Algorithm != "ed25519" {
		t.Fatalf("unexpected declassification algorithm: %s", testCase.Grant.Algorithm)
	}
	bodyJSON, err := json.Marshal(testCase.Grant.Body)
	if err != nil {
		t.Fatalf("marshal declassification body: %v", err)
	}
	canonicalBody, err := invariants.CanonicalizeJSONString(string(bodyJSON))
	if err != nil {
		t.Fatalf("canonicalize declassification body: %v", err)
	}
	if canonicalBody != testCase.CanonicalBodyJSON {
		t.Fatalf("unexpected declassification canonical body: %s", canonicalBody)
	}
	signingMessage := "chio:declassification-grant:v1\x00" + canonicalBody
	signed, err := invariants.SignUTF8MessageEd25519(signingMessage, testCase.SigningSeedHex)
	if err != nil {
		t.Fatalf("sign declassification body: %v", err)
	}
	if signed.PublicKeyHex != testCase.Grant.AuthorityKey || signed.SignatureHex != testCase.Grant.Signature {
		t.Fatalf("unexpected declassification signature: %#v", signed)
	}
	verified, err := invariants.VerifyUTF8MessageEd25519(
		signingMessage,
		testCase.Grant.AuthorityKey,
		testCase.Grant.Signature,
	)
	if err != nil || !verified {
		t.Fatalf("verify declassification signature: verified=%v error=%v", verified, err)
	}
	withoutDomain, err := invariants.VerifyUTF8MessageEd25519(
		canonicalBody,
		testCase.Grant.AuthorityKey,
		testCase.Grant.Signature,
	)
	if err != nil {
		t.Fatalf("verify declassification domain separation: %v", err)
	}
	if withoutDomain {
		t.Fatal("declassification signature verified without its domain")
	}
}

func TestWatermarkVectors(t *testing.T) {
	var vectors watermarkVectors
	loadVectorFile(t, filepath.Join(watermarkVectorRoot, "v1.json"), &vectors)
	if vectors.Schema != "chio.signed-watermark-vectors.v1" {
		t.Fatalf("unexpected watermark vector schema: %s", vectors.Schema)
	}
	if vectors.SigningDomain != "chio.signed-watermark.v1\x00" {
		t.Fatalf("unexpected watermark signing domain: %q", vectors.SigningDomain)
	}

	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			assertExactObjectKeys(t, testCase.Payload, watermarkPayloadFields)
			if requireString(t, testCase.Payload, "encoding") != "base64_url_canonical_json" {
				t.Fatal("unexpected watermark encoding")
			}
			for _, field := range watermarkNumericFields {
				number, ok := testCase.Payload[field].(json.Number)
				if !ok {
					t.Fatalf("watermark field %s is not a JSON number", field)
				}
				value, err := number.Int64()
				if err != nil || value < 0 || value > maxWatermarkSafeInteger {
					t.Fatalf("watermark field %s is not an interoperable integer: %v", field, number)
				}
			}
			if testCase.Payload["sequence"].(json.Number).String() != "9007199254740991" {
				t.Fatal("positive watermark vector must pin the maximum safe integer")
			}

			canonicalPayload, err := invariants.CanonicalizeJSON(testCase.Payload)
			if err != nil {
				t.Fatalf("CanonicalizeJSON payload returned error: %v", err)
			}
			if canonicalPayload != testCase.CanonicalPayloadJSON {
				t.Fatalf("unexpected canonical watermark payload: %s", canonicalPayload)
			}
			signingMessage := vectors.SigningDomain + canonicalPayload
			if hex.EncodeToString([]byte(signingMessage)) != testCase.SigningMessageHex {
				t.Fatal("unexpected watermark signing-message bytes")
			}
			signed, err := invariants.SignUTF8MessageEd25519(signingMessage, vectors.SigningKeySeedHex)
			if err != nil {
				t.Fatalf("SignUTF8MessageEd25519 returned error: %v", err)
			}
			if signed.PublicKeyHex != testCase.PublicKeyHex || signed.SignatureHex != testCase.SignatureHex {
				t.Fatalf("unexpected watermark signing output: %#v", signed)
			}
			verified, err := invariants.VerifyUTF8MessageEd25519(
				signingMessage,
				testCase.PublicKeyHex,
				testCase.SignatureHex,
			)
			if err != nil || !verified {
				t.Fatalf("watermark signature verification failed: verified=%v err=%v", verified, err)
			}
			verifiedWithoutDomain, err := invariants.VerifyUTF8MessageEd25519(
				canonicalPayload,
				testCase.PublicKeyHex,
				testCase.SignatureHex,
			)
			if err != nil || verifiedWithoutDomain {
				t.Fatalf("watermark signature was not domain separated: verified=%v err=%v", verifiedWithoutDomain, err)
			}

			if strings.Contains(testCase.EncodedPayload, "=") {
				t.Fatal("watermark payload base64url contains padding")
			}
			if base64.RawURLEncoding.EncodeToString([]byte(canonicalPayload)) != testCase.EncodedPayload {
				t.Fatal("unexpected base64url-encoded watermark payload")
			}
			decodedPayload, err := base64.RawURLEncoding.DecodeString(testCase.EncodedPayload)
			if err != nil {
				t.Fatalf("failed to decode watermark payload: %v", err)
			}
			if string(decodedPayload) != canonicalPayload {
				t.Fatal("decoded watermark payload is not canonical payload JSON")
			}
			if base64.RawURLEncoding.EncodeToString(decodedPayload) != testCase.EncodedPayload {
				t.Fatal("watermark payload base64url is not canonical")
			}

			assertExactObjectKeys(t, testCase.Envelope, []string{"encoded_payload", "payload", "schema", "signature"})
			if requireString(t, testCase.Envelope, "schema") != "chio.signed-watermark-envelope.v1" {
				t.Fatal("unexpected signed watermark envelope schema")
			}
			if requireString(t, testCase.Envelope, "encoded_payload") != testCase.EncodedPayload {
				t.Fatal("envelope encoded payload does not match pinned payload")
			}
			if requireString(t, testCase.Envelope, "signature") != testCase.SignatureHex {
				t.Fatal("envelope signature does not match pinned signature")
			}
			envelopePayload, ok := testCase.Envelope["payload"].(map[string]any)
			if !ok {
				t.Fatal("envelope payload is not an object")
			}
			canonicalEnvelopePayload, err := invariants.CanonicalizeJSON(envelopePayload)
			if err != nil || canonicalEnvelopePayload != canonicalPayload {
				t.Fatalf("envelope payload does not match pinned payload: %v", err)
			}
			canonicalEnvelope, err := invariants.CanonicalizeJSON(testCase.Envelope)
			if err != nil {
				t.Fatalf("CanonicalizeJSON envelope returned error: %v", err)
			}
			if canonicalEnvelope != testCase.CanonicalEnvelopeJSON {
				t.Fatalf("unexpected canonical watermark envelope: %s", canonicalEnvelope)
			}

			if !strings.HasPrefix(testCase.Token, "[[chio-wm1:") || !strings.HasSuffix(testCase.Token, "]]") {
				t.Fatal("watermark token wrapper is malformed")
			}
			encodedEnvelope := strings.TrimSuffix(strings.TrimPrefix(testCase.Token, "[[chio-wm1:"), "]]")
			if strings.Contains(encodedEnvelope, "=") {
				t.Fatal("watermark envelope base64url contains padding")
			}
			decodedEnvelope, err := base64.RawURLEncoding.DecodeString(encodedEnvelope)
			if err != nil {
				t.Fatalf("failed to decode watermark envelope: %v", err)
			}
			if string(decodedEnvelope) != canonicalEnvelope {
				t.Fatal("decoded watermark envelope is not canonical envelope JSON")
			}
			if base64.RawURLEncoding.EncodeToString(decodedEnvelope) != encodedEnvelope {
				t.Fatal("watermark envelope base64url is not canonical")
			}
			canonicalDecodedEnvelope, err := invariants.CanonicalizeJSONString(string(decodedEnvelope))
			if err != nil || canonicalDecodedEnvelope != string(decodedEnvelope) {
				t.Fatalf("decoded watermark envelope failed canonical validation: %v", err)
			}
		})
	}
}

func TestWatermarkVectorsRejectUnsafeInteger(t *testing.T) {
	var vectors watermarkRejectionVectors
	loadVectorFile(t, filepath.Join(watermarkVectorRoot, "v1-rejections.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			canonicalPayload, err := invariants.CanonicalizeJSONString(testCase.InputPayloadJSON)
			if err != nil {
				t.Fatalf("CanonicalizeJSONString returned error: %v", err)
			}
			if canonicalPayload != testCase.CanonicalPayloadJSON {
				t.Fatalf("unexpected canonical rejection payload: %s", canonicalPayload)
			}
			decoder := json.NewDecoder(strings.NewReader(testCase.InputPayloadJSON))
			decoder.UseNumber()
			var payload map[string]any
			if err := decoder.Decode(&payload); err != nil {
				t.Fatalf("failed to decode rejection payload: %v", err)
			}
			assertExactObjectKeys(t, payload, watermarkPayloadFields)
			number, ok := payload[testCase.Field].(json.Number)
			if !ok || number.String() != testCase.ValueDecimal {
				t.Fatalf("unexpected rejection integer: %v", payload[testCase.Field])
			}
			value, err := number.Int64()
			if err != nil || value <= maxWatermarkSafeInteger || value != 1<<53 {
				t.Fatalf("rejection vector is not the first unsafe integer: %v", number)
			}
			if testCase.ExpectedError != "unsafe_integer" {
				t.Fatalf("unexpected rejection reason: %s", testCase.ExpectedError)
			}
		})
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
			renderedBody, err := invariants.CapabilityBodyCanonicalJSON(testCase.Capability)
			if err != nil {
				t.Fatalf("CapabilityBodyCanonicalJSON returned error: %v", err)
			}
			if renderedBody != testCase.CapabilityBodyCanonicalJSON {
				t.Fatalf("unexpected capability body: %s", renderedBody)
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

func TestManifestVectors(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		var vectors manifestVectors
		loadVectorFile(t, filepath.Join(vectorRoot, "manifest", version+".json"), &vectors)
		for _, testCase := range vectors.Cases {
			t.Run(version+"/"+testCase.ID, func(t *testing.T) {
				renderedBody, err := invariants.SignedManifestBodyCanonicalJSON(testCase.SignedManifest)
				if err != nil {
					t.Fatalf("SignedManifestBodyCanonicalJSON returned error: %v", err)
				}
				if renderedBody != testCase.ManifestBodyCanonicalJSON {
					t.Fatalf("unexpected manifest body: %s", renderedBody)
				}
				verification, err := invariants.VerifySignedManifest(testCase.SignedManifest)
				if err != nil {
					t.Fatalf("VerifySignedManifest returned error: %v", err)
				}
				if verification != testCase.Expected {
					t.Fatalf("unexpected manifest verification: %#v", verification)
				}
			})
		}
	}
}

func TestManifestV2CanonicalRejectionVectors(t *testing.T) {
	var manifests manifestVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "manifest", "v2.json"), &manifests)
	var vectors manifestCanonicalRejectionVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "manifest", "v2-canonical-rejections.json"), &vectors)
	var baseline map[string]any
	for _, testCase := range manifests.Cases {
		if testCase.ID == "valid_signed_manifest" {
			baseline = testCase.SignedManifest
			break
		}
	}
	if baseline == nil {
		t.Fatal("valid v2 manifest vector not found")
	}
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			envelope := cloneMap(t, baseline)
			manifest := envelope["manifest"].(map[string]any)
			permissions := manifest["required_permissions"].(map[string]any)
			switch testCase.Field {
			case "network_destinations.0.host":
				destinations := permissions["network_destinations"].([]any)
				destinations[0].(map[string]any)["host"] = testCase.Replacement
			case "read_paths.0":
				permissions["read_paths"].([]any)[0] = testCase.Replacement
			default:
				permissions[testCase.Field] = testCase.Replacement
			}
			verification, err := invariants.VerifySignedManifest(envelope)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatal("canonical alias was accepted")
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

func assertExactObjectKeys(t *testing.T, object map[string]any, expected []string) {
	t.Helper()
	if len(object) != len(expected) {
		t.Fatalf("unexpected object keys: %#v", object)
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			t.Fatalf("object is missing key %q", key)
		}
	}
}

func requireString(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("object field %q is not a string", key)
	}
	return value
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
