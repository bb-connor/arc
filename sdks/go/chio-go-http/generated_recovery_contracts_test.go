package chio

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Adding a closed explanation state must retain the existing public gap helper.
// Its wire meaning cannot silently change when the schema gains another branch.
func TestExplanationGapHelperRetainsItsWireMeaning(t *testing.T) {
	input := []byte(`{"kind":"gap","reason":"not_consulted"}`)
	var state RecoveryExplanationSnapshotObservationsState1
	if err := json.Unmarshal(input, &state); err != nil {
		t.Fatal(err)
	}
	var projection RecoveryExplanationSnapshot_Observations_State
	if err := projection.FromRecoveryExplanationSnapshotObservationsState1(state); err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	if err := json.Unmarshal(input, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("existing explanation gap helper changed wire meaning: got %s, want %s", output, input)
	}
}
