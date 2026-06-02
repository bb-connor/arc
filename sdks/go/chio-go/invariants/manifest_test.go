package invariants_test

import (
	"strings"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
)

func pricedSignedManifest() map[string]any {
	return map[string]any{
		"manifest": map[string]any{
			"schema":    "chio.manifest.v1",
			"server_id": "srv-priced",
			"name":      "Priced Server",
			"version":   "1.0.0",
			"tools": []any{
				map[string]any{
					"name":             "greet",
					"description":      "Returns a greeting",
					"input_schema":     map[string]any{"type": "object"},
					"has_side_effects": false,
				},
			},
			"public_key": strings.Repeat("22", 32),
		},
		"signature":  strings.Repeat("33", 64),
		"signer_key": strings.Repeat("11", 32),
	}
}

func TestManifestStructureDoesNotIncludeEmbeddedPublicKeyValidity(t *testing.T) {
	signedManifest := pricedSignedManifest()
	signedManifest["manifest"].(map[string]any)["public_key"] = "demo-placeholder"

	verification, err := invariants.VerifySignedManifest(signedManifest)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error: %v", err)
	}
	if !verification.StructureValid {
		t.Fatalf("malformed embedded public key must not invalidate manifest structure")
	}
	if verification.EmbeddedPublicKeyValid {
		t.Fatalf("malformed embedded public key must be reported separately")
	}
	if verification.EmbeddedPublicKeyMatchesSigner {
		t.Fatalf("malformed embedded public key must not match signer")
	}
}

func TestManifestStructureRejectsEmptyOrPaddedToolNames(t *testing.T) {
	for _, name := range []string{"", " greet", "greet "} {
		t.Run(name, func(t *testing.T) {
			signedManifest := pricedSignedManifest()
			tool := signedManifest["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)
			tool["name"] = name

			verification, err := invariants.VerifySignedManifest(signedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatalf("name %q must be structurally invalid", name)
			}
		})
	}
}

func TestManifestStructureRejectsNonObjectToolSchemas(t *testing.T) {
	badInputSchema := pricedSignedManifest()
	badInputSchema["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["input_schema"] = []any{}
	inputVerification, err := invariants.VerifySignedManifest(badInputSchema)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for input schema: %v", err)
	}
	if inputVerification.StructureValid {
		t.Fatalf("array input_schema must be structurally invalid")
	}

	badOutputSchema := pricedSignedManifest()
	badOutputSchema["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["output_schema"] = "not an object"
	outputVerification, err := invariants.VerifySignedManifest(badOutputSchema)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for output schema: %v", err)
	}
	if outputVerification.StructureValid {
		t.Fatalf("string output_schema must be structurally invalid")
	}
}
