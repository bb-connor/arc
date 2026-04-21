package invariants_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/backbay/chio/packages/sdk/chio-go/invariants"
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
		Expected struct {
			Decision           string `json:"decision"`
			ParameterHashValid bool   `json:"parameter_hash_valid"`
			SignatureValid     bool   `json:"signature_valid"`
		} `json:"expected"`
		ID                       string         `json:"id"`
		Receipt                  map[string]any `json:"receipt"`
		ReceiptBodyCanonicalJSON string         `json:"receipt_body_canonical_json"`
	} `json:"cases"`
}

type capabilityVectors struct {
	Cases []struct {
		Capability                  map[string]any                    `json:"capability"`
		CapabilityBodyCanonicalJSON string                            `json:"capability_body_canonical_json"`
		Expected                    invariants.CapabilityVerification `json:"expected"`
		ID                          string                            `json:"id"`
		VerifyAt                    int64                             `json:"verify_at"`
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
	signedUTF8, err := invariants.SignUTF8MessageEd25519("hello arc", vectors.SigningKeySeedHex)
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
			if verification != (invariants.ReceiptVerification{
				Decision:           testCase.Expected.Decision,
				ParameterHashValid: testCase.Expected.ParameterHashValid,
				SignatureValid:     testCase.Expected.SignatureValid,
			}) {
				t.Fatalf("unexpected receipt verification: %#v", verification)
			}
		})
	}
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
		})
	}
}

func TestManifestVectors(t *testing.T) {
	var vectors manifestVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "manifest", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
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
