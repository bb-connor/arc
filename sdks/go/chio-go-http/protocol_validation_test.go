package chio

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func protocolFixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "bindings", "fixtures", "protocol-primitives-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []protocolPrimitiveFixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(payload, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range corpus.Cases {
		if fixture.Name == name && fixture.Valid {
			return fixture.Instance
		}
	}
	t.Fatalf("missing valid fixture %s", name)
	return nil
}

func TestProtocolPublicDecoderRejectsMutationsWithoutReplacingPriorValue(t *testing.T) {
	valid := protocolFixture(t, "operation-execution-nonce")
	var nonce KernelExecutionNonce
	if err := json.Unmarshal(valid, &nonce); err != nil {
		t.Fatal(err)
	}
	original := nonce
	cases := map[string][]byte{
		"unknown":     bytes.Replace(valid, []byte(`"nonce":`), []byte(`"caller_quota":100,"nonce":`), 1),
		"duplicate":   bytes.Replace(valid, []byte(`"issued_at":`), []byte(`"issued_at":1,"issued_at":`), 1),
		"escaped-key": bytes.Replace(valid, []byte(`"issued_at":`), []byte(`"issued_at":1,"\u0069ssued_at":`), 1),
		"null":        []byte(`{"nonce":null,"signature":"unused"}`),
		"missing":     []byte(`{"signature":"unused"}`),
		"trailing":    append(append([]byte{}, valid...), []byte(` {}`)...),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(payload, valid) {
				t.Fatal("mutation did not change the fixture")
			}
			if err := json.Unmarshal(payload, &nonce); err == nil {
				t.Fatal("public decoder accepted mutation")
			}
			if !reflect.DeepEqual(nonce, original) {
				t.Fatal("failed decoder replaced previously validated value")
			}
		})
	}
}

func TestProtocolNumbersPreserveOpaqueValuesAndRejectTypedOverflow(t *testing.T) {
	payload := protocolFixture(t, "active-response-intent")
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	object["canonical_plan_body"] = json.RawMessage(`{"exact":9007199254740993}`)
	object["expires_at"] = json.RawMessage(`9223372036854775807`)
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var intent AgentActiveResponseGovernedIntent
	if err := json.Unmarshal(encoded, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.CanonicalPlanBody["exact"] != json.Number("9007199254740993") {
		t.Fatal("opaque signed number was rounded")
	}
	for _, number := range []string{"9223372036854775808", "1.5", "true", `"1"`} {
		object["expires_at"] = json.RawMessage(number)
		encoded, err = json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &intent); err == nil {
			t.Fatalf("accepted invalid integer %s", number)
		}
	}
}

func TestAggregatePublicUnionRejectsUnknownAndForbiddenRootProperties(t *testing.T) {
	for _, payload := range []string{
		`{"scope":"capability","max_invocations":3,"caller_quota":4}`,
		`{"scope":"capability","max_invocations":3,"\u0072oot_binding":null}`,
		`{"scope":"capability","max_invocations":4294967296}`,
		`{"scope":"delegation_family","max_invocations":3}`,
	} {
		var budget CapabilityAggregateInvocationBudget
		if err := json.Unmarshal([]byte(payload), &budget); err == nil {
			t.Fatal("raw aggregate union bypassed branch validation")
		}
	}
}

func TestProtocolWireBoundsAndOpaqueDuplicatesReject(t *testing.T) {
	checkCallerWireMutations(t)
	for _, payload := range []string{
		`{"value":1,"value":2}`,
		strings.Repeat(`[`, 66) + `0` + strings.Repeat(`]`, 66),
	} {
		decoder := json.NewDecoder(strings.NewReader(payload))
		decoder.UseNumber()
		if _, err := readProtocolValue(decoder, 0); err == nil {
			t.Fatal("accepted duplicate or excessive nesting")
		}
	}
	var extension CapabilitySupplementalAuthorization
	if err := json.Unmarshal([]byte(`{"signed_extension":"`+strings.Repeat("a", 1<<20)+`"}`), &extension); err == nil {
		t.Fatal("accepted oversized security artifact")
	}
}

func checkCallerWireMutations(t *testing.T) {
	t.Helper()
	for _, name := range []string{"caller-dispatch-authorization", "caller-delivery-report-realized-cost"} {
		t.Run(name, func(t *testing.T) {
			valid := protocolFixture(t, name)
			var target any = &KernelCallerDeliveryReport{}
			if name == "caller-dispatch-authorization" {
				target = &KernelCallerDispatchAuthorization{}
			}
			if err := json.Unmarshal(valid, target); err != nil {
				t.Fatal(err)
			}
			original, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			mutations := [][]byte{
				bytes.Replace(valid, []byte(`"key_epoch": 1`), []byte(`"key_epoch": 0`), 1),
				bytes.Replace(valid, []byte(`"key_epoch": 1`), []byte(`"key_epoch": 9007199254740992`), 1),
				bytes.Replace(valid, []byte(`.v1"`), []byte(`.v2"`), 1),
				bytes.Replace(valid, []byte(`"executor_id":`), []byte(`"key_epoch":1,"executor_id":`), 1),
			}
			if name == "caller-dispatch-authorization" {
				// encoding/json strips surrounding whitespace before UnmarshalJSON.
				// Pad inside the object to exercise the public artifact-size bound.
				mutations = append(mutations, bytes.Replace(valid, []byte("{"),
					append([]byte("{"), bytes.Repeat([]byte(" "), 32768)...), 1))
			} else {
				mutations = append(mutations,
					bytes.Replace(valid, []byte(`"units": 7`), []byte(`"units": -1`), 1),
					bytes.Replace(valid, []byte(`"units": 7`), []byte(`"units": 9007199254740992`), 1),
					bytes.Replace(valid, []byte(`"currency": "USD"`), []byte(`"currency": ""`), 1),
					bytes.Replace(valid, []byte(`"units": 7`), []byte(`"units": 7,"quota":99`), 1),
				)
			}
			for index, payload := range mutations {
				if bytes.Equal(payload, valid) {
					t.Fatal("caller mutation did not change fixture")
				}
				if err := json.Unmarshal(payload, target); err == nil {
					t.Fatalf("caller public decoder accepted malformed artifact %d", index)
				}
				retained, err := json.Marshal(target)
				if err != nil || !bytes.Equal(original, retained) {
					t.Fatal("caller decoder replaced prior value on failure")
				}
			}
		})
	}
}
