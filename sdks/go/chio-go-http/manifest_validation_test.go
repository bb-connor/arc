package chio

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGeneratedManifestV2RuntimeCorpus(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tests", "bindings", "fixtures", "manifest-v2-consumers.json")
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
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			var manifest SecuritySignedToolManifestV2
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
			if fmt.Sprintf("%x", sha256.Sum256(canonical)) != "4f9a91d6859c909e118bc89d1645d20da15fc3ac90aae26c4d796e3c56e8d603" {
				t.Fatal("current manifest canonical vector hash changed")
			}
		})
	}
}
