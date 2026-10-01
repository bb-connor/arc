package chio

import (
	"encoding/json"
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
