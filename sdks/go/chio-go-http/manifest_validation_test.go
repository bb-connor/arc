package chio

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestManifestSizeRefusesBeforeAllowedFieldCopy(t *testing.T) {
	// The allowed value would be copied before the missing-field check unless
	// the public decoder refuses the whole artifact before preflight starts.
	payload := []byte(`{"manifest":{"input_schema":"` + strings.Repeat("x", maxSecurityWireBytes) + `"}}`)
	manifest := SecuritySignedToolManifestV1{SignerKey: "retained-key"}
	want := manifest
	err := manifest.UnmarshalJSON(payload)
	if !errors.Is(err, errSecurityWireTooLarge) {
		t.Fatalf("expected size refusal before field decoding, got %v", err)
	}
	if !reflect.DeepEqual(manifest, want) {
		t.Fatal("oversized manifest changed its destination")
	}
}

func TestManifestExactSizeBoundaryPreservesValidFields(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tests", "bindings", "fixtures", "manifest-consumers.json")
	payload, err := os.ReadFile(path)
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
		if !fixture.Valid {
			continue
		}
		var want, manifest SecuritySignedToolManifestV1
		if err := json.Unmarshal(fixture.Instance, &want); err != nil {
			t.Fatal(err)
		}
		padded := append(bytes.Clone(fixture.Instance), bytes.Repeat([]byte(" "), (maxSecurityWireBytes)-len(fixture.Instance))...)
		if err := manifest.UnmarshalJSON(padded); err != nil {
			t.Fatalf("exact one MiB valid manifest was refused: %v", err)
		}
		if !reflect.DeepEqual(manifest, want) {
			t.Fatal("size-boundary decoding changed manifest fields")
		}
		if err := manifest.UnmarshalJSON(append(padded, ' ')); !errors.Is(err, errSecurityWireTooLarge) {
			t.Fatalf("expected exact size refusal above one MiB, got %v", err)
		}
		if !reflect.DeepEqual(manifest, want) {
			t.Fatal("size refusal changed retained manifest fields")
		}
		return
	}
	t.Fatal("manifest corpus has no valid size-boundary control")
}

func TestGeneratedManifestRuntimeCorpus(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tests", "bindings", "fixtures", "manifest-consumers.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []protocolPrimitiveFixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(payload, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 14 {
		t.Fatalf("expected 14 manifest cases, got %d", len(corpus.Cases))
	}
	vector, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "bindings", "vectors", "security", "cage", "positive", "signed-tool-manifest-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			var manifest SecuritySignedToolManifestV1
			// Exercise the public type's ordinary decoder, not a test-only
			// strict wrapper which could conceal security-field loss by callers.
			err := json.Unmarshal(fixture.Instance, &manifest)
			if (err == nil) != fixture.Valid {
				t.Fatalf("runtime acceptance mismatch: %v", err)
			}
			if !fixture.Valid {
				return
			}
			roundTrip, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			var want, got any
			if err := json.Unmarshal(fixture.Instance, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(roundTrip, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("public manifest decoding changed security fields")
			}
			// The shared canonical vector has ASCII strings and small integers.
			// Preserve number spellings even in this bounded test projection.
			decoder := json.NewDecoder(bytes.NewReader(roundTrip))
			decoder.UseNumber()
			var canonicalValue any
			if err := decoder.Decode(&canonicalValue); err != nil {
				t.Fatal(err)
			}
			canonical, err := json.Marshal(canonicalValue)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical, vector) {
				t.Fatal("current manifest canonical form differs from the frozen vector")
			}
		})
	}
}
