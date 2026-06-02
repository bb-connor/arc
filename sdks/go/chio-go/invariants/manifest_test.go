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

func TestManifestStructureRejectsEmptyOrPaddedIdentityFields(t *testing.T) {
	cases := []struct {
		field string
		value string
	}{
		{"server_id", ""},
		{"server_id", " srv-priced"},
		{"server_id", "srv-priced "},
		{"name", ""},
		{"name", " Priced Server"},
		{"name", "Priced Server "},
		{"version", ""},
		{"version", " 1.0.0"},
		{"version", "1.0.0 "},
	}
	for _, tc := range cases {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			signedManifest := pricedSignedManifest()
			signedManifest["manifest"].(map[string]any)[tc.field] = tc.value

			verification, err := invariants.VerifySignedManifest(signedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatalf("%s value %q must be structurally invalid", tc.field, tc.value)
			}
			if verification.SignatureValid {
				t.Fatalf("mutated identity field should invalidate the signature")
			}
			if !verification.EmbeddedPublicKeyValid {
				t.Fatalf("embedded public key validity must remain independent")
			}
		})
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

func TestManifestStructureAcceptsValidRequiredPermissions(t *testing.T) {
	signedManifest := pricedSignedManifest()
	signedManifest["manifest"].(map[string]any)["required_permissions"] = map[string]any{
		"read_paths":            []any{"/tmp/in"},
		"write_paths":           []any{"/tmp/out"},
		"network_hosts":         []any{"api.example.com"},
		"environment_variables": []any{"TOKEN"},
	}

	verification, err := invariants.VerifySignedManifest(signedManifest)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error: %v", err)
	}
	if !verification.StructureValid {
		t.Fatalf("valid required_permissions must remain structurally valid")
	}
	if verification.SignatureValid {
		t.Fatalf("mutated required_permissions should invalidate the signature")
	}
	if !verification.EmbeddedPublicKeyValid {
		t.Fatalf("embedded public key validity must remain independent")
	}
}

func TestManifestStructureRejectsInvalidRequiredPermissions(t *testing.T) {
	cases := []struct {
		field  string
		values []any
	}{
		{"read_paths", []any{""}},
		{"write_paths", []any{" /tmp/out"}},
		{"network_hosts", []any{"api.example.com "}},
		{"environment_variables", []any{"TOKEN", "TOKEN"}},
		{"read_paths", []any{123}},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			signedManifest := pricedSignedManifest()
			signedManifest["manifest"].(map[string]any)["required_permissions"] = map[string]any{
				tc.field: tc.values,
			}

			verification, err := invariants.VerifySignedManifest(signedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatalf("%s values %#v must be structurally invalid", tc.field, tc.values)
			}
			if verification.SignatureValid {
				t.Fatalf("mutated required_permissions should invalidate the signature")
			}
			if !verification.EmbeddedPublicKeyValid {
				t.Fatalf("embedded public key validity must remain independent")
			}
		})
	}
}

func TestManifestStructureRejectsMalformedRequiredPermissionsObject(t *testing.T) {
	unknownField := pricedSignedManifest()
	unknownField["manifest"].(map[string]any)["required_permissions"] = map[string]any{
		"unknown": []any{"/tmp"},
	}
	unknownVerification, err := invariants.VerifySignedManifest(unknownField)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for unknown field: %v", err)
	}
	if unknownVerification.StructureValid {
		t.Fatalf("unknown required_permissions field must be structurally invalid")
	}

	nonArrayValues := pricedSignedManifest()
	nonArrayValues["manifest"].(map[string]any)["required_permissions"] = map[string]any{
		"read_paths": "/tmp",
	}
	nonArrayVerification, err := invariants.VerifySignedManifest(nonArrayValues)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for non-array value: %v", err)
	}
	if nonArrayVerification.StructureValid {
		t.Fatalf("non-array required_permissions value must be structurally invalid")
	}
}
