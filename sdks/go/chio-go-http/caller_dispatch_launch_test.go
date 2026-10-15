package chio

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const callerNativeLaunch = `{"receipt_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`
const callerWorkerProfile = `{"kind":"container","launch_attempt":1,"launch_ref":{"record_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","record_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}`
const callerObjectLaunch = `{"native_launch":` + callerNativeLaunch + `,"worker_profile":` + callerWorkerProfile + `}`

// A nil replacement deletes the property; the bytes "null" retain an explicit null.
func replaceCallerWireProperty(t *testing.T, payload []byte, path []string, replacement json.RawMessage) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	if len(path) == 1 {
		if replacement == nil {
			delete(object, path[0])
		} else {
			object[path[0]] = replacement
		}
	} else {
		object[path[0]] = replaceCallerWireProperty(t, object[path[0]], path[1:], replacement)
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func callerWithDispatchLaunch(t *testing.T, launch string) []byte {
	t.Helper()
	return replaceCallerWireProperty(t, protocolFixture(t, "caller-dispatch-authorization"),
		[]string{"authorization", "committed", "dispatch_commit", "dispatch_launch"}, json.RawMessage(launch))
}

func TestCallerDispatchLaunchNullableRoundTrip(t *testing.T) {
	cases := []struct{ name, launch string }{
		{"both-null", `{"native_launch":null,"worker_profile":null}`},
		{"native-only", `{"native_launch":` + callerNativeLaunch + `,"worker_profile":null}`},
		{"worker-only", `{"native_launch":null,"worker_profile":` + callerWorkerProfile + `}`},
		{"both-objects", callerObjectLaunch},
		{"maximum-attempt", strings.Replace(callerObjectLaunch, `"launch_attempt":1`, `"launch_attempt":4294967295`, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var target KernelCallerDispatchAuthorization
			if err := json.Unmarshal(callerWithDispatchLaunch(t, tc.launch), &target); err != nil {
				t.Fatalf("valid dispatch launch refused: %v", err)
			}
			encoded, err := json.Marshal(target.Authorization.Committed.DispatchCommit.DispatchLaunch)
			if err != nil {
				t.Fatal(err)
			}
			var got, want map[string]any
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.launch), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("launch representation changed: got %s, want %s", encoded, tc.launch)
			}
			wire, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip KernelCallerDispatchAuthorization
			if err := json.Unmarshal(wire, &roundTrip); err != nil {
				t.Fatalf("encoded authorization refused: %v", err)
			}
			if !reflect.DeepEqual(target, roundTrip) {
				t.Fatal("authorization changed across round trip")
			}
		})
	}
}

func TestCallerDispatchLaunchRefusalsPreserveReceiver(t *testing.T) {
	cases := []struct {
		name, path string
		value      json.RawMessage
		want       string
	}{
		{"missing-launch", "", nil, `missing required security wire property "dispatch_launch"`},
		{"null-launch", "", json.RawMessage(`null`), "security properties must be omitted instead of null"},
		{"missing-native", "native_launch", nil, `missing required security wire property "native_launch"`},
		{"missing-worker", "worker_profile", nil, `missing required security wire property "worker_profile"`},
		{"missing-receipt-id", "native_launch.receipt_id", nil, `missing required security wire property "receipt_id"`},
		{"missing-receipt-digest", "native_launch.receipt_sha256", nil, `missing required security wire property "receipt_sha256"`},
		{"missing-kind", "worker_profile.kind", nil, `missing required security wire property "kind"`},
		{"missing-attempt", "worker_profile.launch_attempt", nil, `missing required security wire property "launch_attempt"`},
		{"missing-reference", "worker_profile.launch_ref", nil, `missing required security wire property "launch_ref"`},
		{"missing-record-id", "worker_profile.launch_ref.record_id", nil, `missing required security wire property "record_id"`},
		{"missing-record-digest", "worker_profile.launch_ref.record_sha256", nil, `missing required security wire property "record_sha256"`},
		{"native-array", "native_launch", json.RawMessage(`[]`), "security wire value must be an object"},
		{"worker-array", "worker_profile", json.RawMessage(`[]`), "security wire value must be an object"},
		{"null-receipt-digest", "native_launch.receipt_sha256", json.RawMessage(`null`), "security properties must be omitted instead of null"},
		{"null-reference", "worker_profile.launch_ref", json.RawMessage(`null`), "security properties must be omitted instead of null"},
		{"unknown-launch-field", "extra", json.RawMessage(`1`), "unknown security wire property"},
		{"unknown-native-field", "native_launch.extra", json.RawMessage(`1`), "unknown security wire property"},
		{"unknown-worker-field", "worker_profile.extra", json.RawMessage(`1`), "unknown security wire property"},
		{"unknown-reference-field", "worker_profile.launch_ref.extra", json.RawMessage(`1`), "unknown security wire property"},
		{"negative-attempt", "worker_profile.launch_attempt", json.RawMessage(`-1`), "invalid caller worker profile domain"},
		{"zero-attempt", "worker_profile.launch_attempt", json.RawMessage(`0`), "invalid caller worker profile domain"},
		{"over-u32-attempt", "worker_profile.launch_attempt", json.RawMessage(`4294967296`), "invalid caller worker profile domain"},
		{"unknown-kind", "worker_profile.kind", json.RawMessage(`"direct"`), "invalid caller worker profile domain"},
		{"uppercase-kind", "worker_profile.kind", json.RawMessage(`"Container"`), "invalid caller worker profile domain"},
		{"empty-receipt-id", "native_launch.receipt_id", json.RawMessage(`""`), "invalid caller native launch domain"},
		{"short-receipt-id", "native_launch.receipt_id", json.RawMessage(`"` + strings.Repeat("a", 63) + `"`), "invalid caller native launch domain"},
		{"long-receipt-digest", "native_launch.receipt_sha256", json.RawMessage(`"` + strings.Repeat("b", 65) + `"`), "invalid caller native launch domain"},
		{"uppercase-receipt-digest", "native_launch.receipt_sha256", json.RawMessage(`"` + strings.Repeat("B", 64) + `"`), "invalid caller native launch domain"},
		{"nonhex-record-id", "worker_profile.launch_ref.record_id", json.RawMessage(`"` + strings.Repeat("g", 64) + `"`), "invalid caller worker profile domain"},
		{"uppercase-record-digest", "worker_profile.launch_ref.record_sha256", json.RawMessage(`"` + strings.Repeat("D", 64) + `"`), "invalid caller worker profile domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := []string{"authorization", "committed", "dispatch_commit", "dispatch_launch"}
			if tc.path != "" {
				path = append(path, strings.Split(tc.path, ".")...)
			}
			payload := replaceCallerWireProperty(t, callerWithDispatchLaunch(t, callerObjectLaunch), path, tc.value)
			var target KernelCallerDispatchAuthorization
			target.Signature = "retained receiver"
			original := target
			err := json.Unmarshal(payload, &target)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got error %v, want %q", err, tc.want)
			}
			if !reflect.DeepEqual(target, original) {
				t.Fatal("refusal replaced the receiver")
			}
		})
	}
}

func TestCallerDispatchLaunchAttemptRejectsNonIntegers(t *testing.T) {
	for _, tc := range []struct{ wire, value string }{
		{`1.5`, "number 1.5"},
		{`"1"`, "string"},
		{`true`, "bool"},
		{`9223372036854775808`, "number 9223372036854775808"},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			payload := replaceCallerWireProperty(t, callerWithDispatchLaunch(t, callerObjectLaunch),
				[]string{"authorization", "committed", "dispatch_commit", "dispatch_launch", "worker_profile", "launch_attempt"}, json.RawMessage(tc.wire))
			var target KernelCallerDispatchAuthorization
			target.Signature = "retained receiver"
			original := target
			err := json.Unmarshal(payload, &target)
			var mismatch *json.UnmarshalTypeError
			if !errors.As(err, &mismatch) || mismatch.Value != tc.value || mismatch.Type != reflect.TypeOf(int64(0)) ||
				mismatch.Field != "authorization.committed.dispatch_commit.dispatch_launch.worker_profile.launch_attempt" {
				t.Fatalf("got error %#v, want int64 type error for launch_attempt with value %q", err, tc.value)
			}
			if !reflect.DeepEqual(target, original) {
				t.Fatal("type refusal replaced the receiver")
			}
		})
	}
}

func TestCallerDispatchLaunchNullDoesNotRelaxOtherPointerFields(t *testing.T) {
	payload := replaceCallerWireProperty(t, protocolFixture(t, "operation-execution-nonce"),
		[]string{"nonce", "reserved_hold_id"}, json.RawMessage(`null`))
	var target KernelExecutionNonce
	target.Signature = "retained receiver"
	original := target
	err := json.Unmarshal(payload, &target)
	if err == nil || err.Error() != "security properties must be omitted instead of null" {
		t.Fatalf("got error %v, want exact optional-pointer null refusal", err)
	}
	if !reflect.DeepEqual(target, original) {
		t.Fatal("optional-pointer null refusal replaced the receiver")
	}
}
