package chio

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const unexpectedRecordProperty = "chio_unexpected_property"

type recordSample struct {
	source string
	data   []byte
}

// closedRecordSamples gathers valid instances of closed wire schemas, keyed by
// schema path relative to spec/schemas/chio-wire/v1: every positive security
// wire vector and every valid protocol-primitives fixture.
func closedRecordSamples(t *testing.T) map[string][]recordSample {
	t.Helper()
	samples := make(map[string][]recordSample)
	indexes, err := filepath.Glob(filepath.Join("..", "..", "..", "tests", "bindings", "vectors", "security", "*", "index.json"))
	if err != nil || len(indexes) == 0 {
		t.Fatalf("find security vector indexes: %v", err)
	}
	for _, indexPath := range indexes {
		raw, err := os.ReadFile(indexPath)
		if err != nil {
			t.Fatalf("read %s: %v", indexPath, err)
		}
		var index struct {
			Positive []struct {
				File     string `json:"file"`
				SchemaID string `json:"schema_id"`
			} `json:"positive"`
		}
		if err := json.Unmarshal(raw, &index); err != nil {
			t.Fatalf("parse %s: %v", indexPath, err)
		}
		for _, entry := range index.Positive {
			rel, ok := strings.CutPrefix(entry.SchemaID, "https://chio.world/schemas/chio-wire/v1/")
			if !ok {
				continue
			}
			data, err := os.ReadFile(filepath.Join(filepath.Dir(indexPath), entry.File))
			if err != nil {
				t.Fatalf("read vector %s: %v", entry.File, err)
			}
			samples[rel] = append(samples[rel], recordSample{source: entry.File, data: data})
		}
	}
	var receipt json.RawMessage
	for _, fixture := range loadProtocolPrimitiveCorpus(t).Cases {
		if fixture.Valid {
			samples[fixture.SchemaFile] = append(samples[fixture.SchemaFile], recordSample{source: fixture.Name, data: fixture.Instance})
		}
		if fixture.Name == "receipt-internal-origin" {
			receipt = fixture.Instance
		}
	}
	for _, signed := range samples["security/signed-tool-manifest-v2.schema.json"] {
		var envelope struct {
			Manifest json.RawMessage `json:"manifest"`
		}
		if err := json.Unmarshal(signed.data, &envelope); err != nil {
			t.Fatalf("parse signed manifest vector: %v", err)
		}
		samples["security/tool-manifest-v2.schema.json"] = append(samples["security/tool-manifest-v2.schema.json"], recordSample{source: signed.source + " manifest", data: envelope.Manifest})
	}
	for rel, data := range map[string]string{
		"jsonrpc/request.schema.json":      `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`,
		"jsonrpc/notification.schema.json": `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		"jsonrpc/response.schema.json":     `{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}`,
		"provenance/verdict-link.schema.json": `{"verdict":"deny","requestId":"req-1","chainId":"chain-1",` +
			`"renderedAt":1710000200,"reason":"scope","guard":"ForbiddenPathGuard"}`,
		"kernel/tool_call_response.schema.json": `{"type":"tool_call_response","id":"req-1",` +
			`"result":{"status":"ok","value":{"text":"hi"}},"receipt":` + string(receipt) + `}`,
	} {
		samples[rel] = append(samples[rel], recordSample{source: "constructed", data: []byte(data)})
	}
	return samples
}

// withLeadingMember inserts one member before the first member of an object.
func withLeadingMember(t *testing.T, data []byte, member string) []byte {
	t.Helper()
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		t.Fatalf("record sample is not a JSON object")
	}
	rest := bytes.TrimSpace(trimmed[1:])
	if rest[0] == '}' {
		return []byte("{" + member + "}")
	}
	return append([]byte("{"+member+","), rest...)
}

// firstMember returns one existing member of an object, encoded as name:value.
func firstMember(t *testing.T, data []byte) string {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || len(object) == 0 {
		t.Fatalf("record sample has no members: %v", err)
	}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	name, err := json.Marshal(names[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(name) + ":" + string(object[names[0]])
}

func isUnknownPropertyError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, `unknown field "`+unexpectedRecordProperty+`"`) ||
		strings.Contains(message, "unknown chio record property") ||
		strings.Contains(message, "unknown security wire property") ||
		strings.Contains(message, "unknown or duplicate manifest property")
}

func isDuplicatePropertyError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "duplicate chio record property") ||
		strings.Contains(message, "duplicate security wire property") ||
		strings.Contains(message, "unknown or duplicate manifest property")
}

func TestClosedRecordTypesDecodeEveryValidSample(t *testing.T) {
	decoded := 0
	for rel, samples := range closedRecordSamples(t) {
		construct, ok := closedRecordTypes[rel]
		if !ok {
			continue
		}
		for _, sample := range samples {
			if err := json.Unmarshal(sample.data, construct()); err != nil {
				t.Errorf("%s (%s): valid sample refused: %v", rel, sample.source, err)
			}
			decoded++
		}
	}
	if decoded < 90 {
		t.Fatalf("only %d valid record samples decoded", decoded)
	}
}

// Every closed record type refuses an undeclared property and a repeated
// property through the ordinary json.Unmarshal entry point. A type without a
// corpus sample is checked from its zero value when that value decodes.
func TestClosedRecordTypesRefuseUnknownAndDuplicateProperties(t *testing.T) {
	samples := closedRecordSamples(t)
	var unchecked []string
	for rel, construct := range closedRecordTypes {
		cases := samples[rel]
		if len(cases) == 0 {
			zero, err := json.Marshal(construct())
			if err == nil && json.Unmarshal(zero, construct()) == nil && !bytes.Equal(zero, []byte("{}")) {
				cases = []recordSample{{source: "zero value", data: zero}}
			}
		}
		if len(cases) == 0 {
			unchecked = append(unchecked, rel)
			continue
		}
		for _, sample := range cases {
			unknown := withLeadingMember(t, sample.data, `"`+unexpectedRecordProperty+`":0`)
			if err := json.Unmarshal(unknown, construct()); !isUnknownPropertyError(err) {
				t.Errorf("%s (%s): unknown property not refused: %v", rel, sample.source, err)
			}
			duplicate := withLeadingMember(t, sample.data, firstMember(t, sample.data))
			if err := json.Unmarshal(duplicate, construct()); !isDuplicatePropertyError(err) {
				t.Errorf("%s (%s): duplicate property not refused: %v", rel, sample.source, err)
			}
		}
	}
	sort.Strings(unchecked)
	if len(unchecked) > 0 {
		t.Fatalf("closed record types without a decodable sample: %s", strings.Join(unchecked, ", "))
	}
}

func TestDefaultRecordDecoderRefusesNestedUnknownProperties(t *testing.T) {
	valid := `{"id":"intent-1","server_id":"tools","tool_name":"read","purpose":"read",` +
		`"max_amount":{"units":5,"currency":"USD"}}`
	var intent AgentGovernedTransactionIntent
	if err := json.Unmarshal([]byte(valid), &intent); err != nil {
		t.Fatalf("valid governed intent refused: %v", err)
	}
	nested := strings.Replace(valid, `"currency":"USD"`, `"currency":"USD","`+unexpectedRecordProperty+`":1`, 1)
	err := json.Unmarshal([]byte(nested), &AgentGovernedTransactionIntent{})
	if !isUnknownPropertyError(err) {
		t.Fatalf("nested unknown property not refused: %v", err)
	}
	trailing := valid + `{}`
	if err := json.Unmarshal([]byte(trailing), &AgentGovernedTransactionIntent{}); err == nil {
		t.Fatal("trailing data accepted")
	}
	if err := decodeRecordObject([]byte(trailing), &struct{}{}); err == nil || err.Error() != "trailing data after Chio record" {
		t.Fatalf("record decoder accepted trailing data: %v", err)
	}
}
