package chio

import (
	"encoding/json"
	"reflect"
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
	corpus := loadProtocolPrimitiveCorpus(t)
	payloads := make(map[string][]byte)
	for _, fixture := range corpus.Cases {
		payloads[fixture.Name] = fixture.Instance
	}
	for _, fixture := range corpus.RawCases {
		payloads[fixture.Name] = []byte(fixture.InstanceText)
	}
	var decoded ReceiptRecord
	if err := json.Unmarshal(payloads["receipt-internal-origin"], &decoded); err != nil {
		t.Fatalf("valid corpus receipt rejected: %v", err)
	}
	accepted := decoded
	for _, name := range []string{"receipt-unknown-field", "receipt-duplicate-id", "receipt-duplicate-parameter"} {
		payload, ok := payloads[name]
		if !ok {
			t.Fatalf("corpus is missing receipt fixture %s", name)
		}
		if err := json.Unmarshal(payload, &decoded); err == nil {
			t.Fatalf("%s receipt accepted", name)
		}
		if !reflect.DeepEqual(decoded, accepted) {
			t.Fatalf("%s replaced the previously decoded receipt", name)
		}
	}
}
