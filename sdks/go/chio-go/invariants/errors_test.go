package invariants_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
)

func TestParseJSONTextRefusesDuplicateKeys(t *testing.T) {
	for _, input := range []string{
		`{"a":1,"a":1}`,
		`{"a":{"b":true,"b":false}}`,
		`[{"a":1},{"b":2,"b":2}]`,
	} {
		if _, err := invariants.ParseJSONText(input); err == nil {
			t.Fatalf("%s parsed", input)
		}
	}
	if _, err := invariants.ParseJSONText(`{"a":{"b":1},"b":{"a":1},"c":[{"a":1},{"a":2}]}`); err != nil {
		t.Fatalf("distinct keys refused: %v", err)
	}
}

func TestParseJSONTextRefusesTrailingData(t *testing.T) {
	for _, input := range []string{`{} {}`, `1 2`, `{}x`, `[]]`} {
		if _, err := invariants.ParseJSONText(input); err == nil {
			t.Fatalf("%q parsed", input)
		}
	}
	if _, err := invariants.ParseJSONText(" {} \n"); err != nil {
		t.Fatalf("surrounding whitespace refused: %v", err)
	}
}

func TestParseJSONTextAcceptsOutOfRangeNumbers(t *testing.T) {
	if _, err := invariants.ParseJSONText(`{"a":1e400,"b":[1e400]}`); err != nil {
		t.Fatalf("out-of-range number refused: %v", err)
	}
}

func TestReceiptDisclosureTextRefusesDuplicateKeys(t *testing.T) {
	examples := filepath.Join(vectorRoot, "..", "..", "..", "spec", "schemas", "chio-wire", "v1", "root_authority", "examples")
	text, err := os.ReadFile(filepath.Join(examples, "valid", "disclosure.json"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := invariants.ParseJSONText(string(text))
	if err != nil {
		t.Fatal(err)
	}
	receiptID := value.(map[string]any)["receipt_id"].(string)
	duplicated := strings.Replace(string(text), `"receipt_id"`, `"receipt_id": "`+receiptID+`", "receipt_id"`, 1)
	if _, err := invariants.ParseJSONText(duplicated); err == nil {
		t.Fatal("disclosure with a duplicate receipt_id parsed")
	}
}
