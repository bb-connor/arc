package invariants_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
)

type committedCase struct {
	ID                string         `json:"id"`
	Receipt           map[string]any `json:"receipt"`
	Disclosure        any            `json:"disclosure"`
	DelegationContext any            `json:"delegation_context"`
	Expected          struct {
		Parameters      string `json:"parameters"`
		Content         string `json:"content"`
		DisclosureValid bool   `json:"disclosure_valid"`
	} `json:"expected"`
	Preimages struct {
		ParametersCanonical string `json:"parameters_canonical"`
		ContentPreimageHex  string `json:"content_preimage_hex"`
	} `json:"preimages"`
}

func loadCommittedCases(t *testing.T) []committedCase {
	t.Helper()
	var document struct {
		Cases []committedCase `json:"cases"`
	}
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "committed", "v1.json"), &document)
	return document.Cases
}

// decodeRefusedCases are the committed vectors whose disclosure carries a salt outside the
// canonical b64u form of 32 bytes. Every other vector decodes.
var decodeRefusedCases = map[string]bool{
	"salt_31_bytes":          true,
	"salt_padded_b64u":       true,
	"salt_noncanonical_tail": true,
}

func TestOpenCommitmentsReproducesCommittedVectors(t *testing.T) {
	cases := loadCommittedCases(t)
	refused := 0
	for _, vector := range cases {
		action := vector.Receipt["action"].(map[string]any)
		parameterCommitment := action["parameter_commitment"].(map[string]any)
		contentCommitment := vector.Receipt["content_commitment"].(map[string]any)
		ownParameters, err := invariants.ParseJSONText(vector.Preimages.ParametersCanonical)
		if err != nil {
			t.Fatalf("%s: parameters: %v", vector.ID, err)
		}
		ownContent, err := hex.DecodeString(vector.Preimages.ContentPreimageHex)
		if err != nil {
			t.Fatalf("%s: content preimage: %v", vector.ID, err)
		}
		disclosure, err := invariants.ParseReceiptDisclosure(vector.Disclosure)
		if (err != nil) != decodeRefusedCases[vector.ID] {
			t.Fatalf("%s: decode error %v, refusal expected %v", vector.ID, err, decodeRefusedCases[vector.ID])
		}
		report := invariants.OpeningReport{Parameters: invariants.FieldRejected, Content: invariants.FieldRejected}
		if err != nil {
			refused++
		} else {
			report = invariants.OpenCommitments(
				vector.Receipt["id"].(string),
				parameterCommitment,
				contentCommitment,
				disclosure,
				ownParameters,
				append([]byte{}, ownContent...),
			)
		}
		if string(report.Parameters) != vector.Expected.Parameters || string(report.Content) != vector.Expected.Content {
			t.Fatalf("%s: got %+v, expected %+v", vector.ID, report, vector.Expected)
		}
		if vector.DelegationContext == nil && report.DisclosureValid != vector.Expected.DisclosureValid {
			t.Fatalf("%s: disclosure_valid %v, expected %v", vector.ID, report.DisclosureValid, vector.Expected.DisclosureValid)
		}
	}
	if refused != len(decodeRefusedCases) {
		t.Fatalf("committed vectors carry %d of the %d decode-refused cases", refused, len(decodeRefusedCases))
	}
}

func TestParseReceiptDisclosureFollowsSchemaExamples(t *testing.T) {
	examples := filepath.Join(vectorRoot, "..", "..", "..", "spec", "schemas", "chio-wire", "v1", "root_authority", "examples")
	var valid any
	loadVectorFile(t, filepath.Join(examples, "valid", "disclosure.json"), &valid)
	if _, err := invariants.ParseReceiptDisclosure(valid); err != nil {
		t.Fatalf("valid disclosure example refused: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(examples, "invalid"))
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "disclosure.") {
			continue
		}
		text, err := os.ReadFile(filepath.Join(examples, "invalid", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		value, err := invariants.ParseJSONText(string(text))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := invariants.ParseReceiptDisclosure(value); err == nil {
			t.Fatalf("%s decoded", entry.Name())
		}
		refused++
	}
	if refused != 7 {
		t.Fatalf("refused %d invalid disclosure examples, expected 7", refused)
	}
}

func TestDecodeSaltIsStrict(t *testing.T) {
	canonical := "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA"
	if _, err := invariants.DecodeSalt(canonical); err != nil {
		t.Fatalf("canonical salt refused: %v", err)
	}
	for _, encoded := range []string{
		canonical + "=",
		"b64u:" + strings.Repeat("A", 42) + "B",
		"b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEA",
		"EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
	} {
		if _, err := invariants.DecodeSalt(encoded); err == nil {
			t.Fatalf("%q decoded", encoded)
		}
	}
}
