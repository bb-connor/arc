package invariants

import "strings"

var requiredPermissionFields = map[string]struct{}{
	"read_paths":            {},
	"write_paths":           {},
	"network_hosts":         {},
	"environment_variables": {},
}

type ManifestVerification struct {
	EmbeddedPublicKeyMatchesSigner bool `json:"embedded_public_key_matches_signer"`
	EmbeddedPublicKeyValid         bool `json:"embedded_public_key_valid"`
	SignatureValid                 bool `json:"signature_valid"`
	StructureValid                 bool `json:"structure_valid"`
}

func ParseSignedManifestJSON(input string) (map[string]any, error) {
	value, err := ParseJSONText(input)
	if err != nil {
		return nil, err
	}
	signedManifest, ok := value.(map[string]any)
	if !ok {
		return nil, newInvariantError("json", "signed manifest must be a JSON object")
	}
	return signedManifest, nil
}

func SignedManifestBodyCanonicalJSON(signedManifest map[string]any) (string, error) {
	manifest, err := mapField(signedManifest, "manifest")
	if err != nil {
		return "", err
	}
	return CanonicalizeJSON(manifest)
}

func VerifySignedManifest(signedManifest map[string]any) (ManifestVerification, error) {
	manifest, err := mapField(signedManifest, "manifest")
	if err != nil {
		return ManifestVerification{}, err
	}
	signature, err := stringField(signedManifest, "signature")
	if err != nil {
		return ManifestVerification{}, err
	}
	signerKey, err := stringField(signedManifest, "signer_key")
	if err != nil {
		return ManifestVerification{}, err
	}
	body, err := SignedManifestBodyCanonicalJSON(signedManifest)
	if err != nil {
		return ManifestVerification{}, err
	}
	signatureValid, err := VerifyUTF8MessageEd25519(body, signerKey, signature)
	if err != nil {
		return ManifestVerification{}, err
	}
	embeddedPublicKey, err := stringField(manifest, "public_key")
	if err != nil {
		return ManifestVerification{}, err
	}
	embeddedPublicKeyValid := IsValidEd25519PublicKeyHex(embeddedPublicKey)
	return ManifestVerification{
		EmbeddedPublicKeyMatchesSigner: embeddedPublicKeyValid && PublicKeyHexMatches(embeddedPublicKey, signerKey),
		EmbeddedPublicKeyValid:         embeddedPublicKeyValid,
		SignatureValid:                 signatureValid,
		StructureValid:                 validateManifestStructure(manifest),
	}, nil
}

func VerifySignedManifestJSON(input string) (ManifestVerification, error) {
	signedManifest, err := ParseSignedManifestJSON(input)
	if err != nil {
		return ManifestVerification{}, err
	}
	return VerifySignedManifest(signedManifest)
}

func validateManifestStructure(manifest map[string]any) bool {
	schema, ok := manifest["schema"].(string)
	if !ok || schema != "chio.manifest.v1" {
		return false
	}
	if !isValidManifestTextField(manifest["server_id"]) ||
		!isValidManifestTextField(manifest["name"]) ||
		!isValidManifestTextField(manifest["version"]) {
		return false
	}
	tools, ok := manifest["tools"].([]any)
	if !ok || len(tools) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(tools))
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		name, ok := tool["name"].(string)
		if !ok || !isValidToolName(name) {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
		if !isJSONObject(tool["input_schema"]) {
			return false
		}
		if outputSchema, exists := tool["output_schema"]; exists && outputSchema != nil && !isJSONObject(outputSchema) {
			return false
		}
	}
	return validateRequiredPermissions(manifest["required_permissions"])
}

func isValidManifestTextField(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	trimmed := strings.TrimSpace(text)
	return trimmed != "" && trimmed == text
}

func isValidToolName(name string) bool {
	return isValidManifestTextField(name)
}

func isJSONObject(value any) bool {
	_, ok := value.(map[string]any)
	return ok
}

func validateRequiredPermissions(value any) bool {
	if value == nil {
		return true
	}
	permissions, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for field := range permissions {
		if _, ok := requiredPermissionFields[field]; !ok {
			return false
		}
	}
	for field := range requiredPermissionFields {
		if !validateRequiredPermissionValues(permissions[field]) {
			return false
		}
	}
	return true
}

func validateRequiredPermissionValues(value any) bool {
	if value == nil {
		return true
	}
	values, ok := value.([]any)
	if !ok {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, entry := range values {
		text, ok := entry.(string)
		if !ok || !isValidManifestTextField(text) {
			return false
		}
		if _, exists := seen[text]; exists {
			return false
		}
		seen[text] = struct{}{}
	}
	return true
}
