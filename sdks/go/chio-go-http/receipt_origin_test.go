package chio

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReceiptOriginRejectsInvalidValuesWithoutReplacingPriorValue(t *testing.T) {
	for _, origin := range []ReceiptRecordToolOrigin{
		ReceiptRecordToolOriginCallerExecuted,
		ReceiptRecordToolOriginHostExecutedProviderReported,
		ReceiptRecordToolOriginHostExecutedUnmediated,
		ReceiptRecordToolOriginChioInternal,
	} {
		encoded, err := json.Marshal(origin)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ReceiptRecordToolOrigin
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != origin {
			t.Fatalf("origin round trip changed: %q, %v", decoded, err)
		}
	}
	for _, invalid := range []string{`"untrusted_future_origin"`, `""`, `null`, `1`, `true`, `{}`, `[]`, `"chio_internal" "caller_executed"`} {
		prior := ReceiptRecordToolOriginCallerExecuted
		if err := json.Unmarshal([]byte(invalid), &prior); err == nil {
			t.Fatalf("accepted invalid origin: %s", invalid)
		}
		if prior != ReceiptRecordToolOriginCallerExecuted {
			t.Fatalf("invalid origin replaced prior value: %q", prior)
		}
	}
}

func TestReceiptRecordRejectsUnknownFieldsAndDuplicateKeys(t *testing.T) {
	corpusBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "bindings", "fixtures", "protocol-primitives-v1.json"))
	if err != nil {
		t.Fatalf("read protocol-primitives fixture corpus: %v", err)
	}
	var corpus struct {
		Cases []protocolPrimitiveFixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(corpusBytes, &corpus); err != nil {
		t.Fatalf("parse protocol-primitives fixture corpus: %v", err)
	}
	var valid []byte
	for _, fixture := range corpus.Cases {
		if fixture.SchemaFile == "receipt/record.schema.json" && fixture.Valid {
			valid = bytes.TrimSpace(fixture.Instance)
			break
		}
	}
	if len(valid) < 2 || valid[0] != '{' {
		t.Fatal("corpus has no valid receipt object")
	}
	var accepted ReceiptRecord
	if err := json.Unmarshal(valid, &accepted); err != nil {
		t.Fatalf("valid corpus receipt rejected: %v", err)
	}
	for name, mutated := range map[string][]byte{
		"unknown field": append([]byte(`{"unexpected":true,`), valid[1:]...),
		// The duplicate comes first, so last-wins parsing would keep the original id.
		"duplicate key": append([]byte(`{"id":"`+strings.Repeat("0", 64)+`",`), valid[1:]...),
	} {
		var decoded ReceiptRecord
		if err := json.Unmarshal(mutated, &decoded); err == nil {
			t.Fatalf("%s receipt accepted", name)
		}
	}
}
