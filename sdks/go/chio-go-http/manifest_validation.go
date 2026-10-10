package chio

// The generated manifest shapes are transport types, not publisher signature
// verifiers or native launch authorities. Their public JSON decoder must still
// reject omitted, duplicated or silently discarded security properties.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// decodeManifestObject validates the wire object's presence contract before
// decoding into an alias of its generated type. Each nested security object has
// the same decoder, while arbitrary input/output JSON Schemas remain opaque.
func decodeManifestObject(data []byte, target any, required, optional []string) error {
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = true
	}
	for _, name := range optional {
		allowed[name] = true
	}
	seen := make(map[string]bool, len(allowed))
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return fmt.Errorf("manifest wire value must be an object")
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok || !allowed[name] || seen[name] {
			return fmt.Errorf("unknown or duplicate manifest property")
		}
		seen[name] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("manifest properties must be omitted instead of null")
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return fmt.Errorf("invalid manifest object closing token")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after manifest object")
	}
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("missing required manifest property %q", name)
		}
	}
	return decodeProtocolObject(data, target)
}

func (m *SecuritySignedToolManifestV2) UnmarshalJSON(data []byte) error {
	type wire SecuritySignedToolManifestV2
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"manifest", "signature", "signer_key"}, nil); err != nil {
		return err
	}
	*m = SecuritySignedToolManifestV2(decoded)
	return nil
}

func (m *SecurityToolManifestV2) UnmarshalJSON(data []byte) error {
	type wire SecurityToolManifestV2
	var decoded wire
	if err := decodeManifestObject(data, &decoded,
		[]string{"schema", "server_id", "name", "version", "tools", "public_key"},
		[]string{"description", "server_tools", "required_permissions"}); err != nil {
		return err
	}
	if decoded.Schema != "chio.manifest.v2" || decoded.ServerId == "" || decoded.Name == "" || decoded.Version == "" || decoded.PublicKey == "" || len(decoded.Tools) == 0 {
		return fmt.Errorf("invalid manifest schema or empty required field")
	}
	if decoded.ServerTools != nil {
		seen := make(map[SecurityToolManifestV2ServerTools]bool)
		if len(*decoded.ServerTools) == 0 {
			return fmt.Errorf("server_tools must be omitted instead of empty")
		}
		for _, tool := range *decoded.ServerTools {
			if (tool != "computer_use" && tool != "bash" && tool != "text_editor") || seen[tool] {
				return fmt.Errorf("unknown or duplicate server tool")
			}
			seen[tool] = true
		}
	}
	*m = SecurityToolManifestV2(decoded)
	return nil
}

func (t *SecurityToolManifestV2ToolDefinition) UnmarshalJSON(data []byte) error {
	type wire SecurityToolManifestV2ToolDefinition
	var decoded wire
	if err := decodeManifestObject(data, &decoded,
		[]string{"name", "description", "input_schema", "annotations"},
		[]string{"output_schema", "pricing", "latency_hint", "flow"}); err != nil {
		return err
	}
	if decoded.Name == "" {
		return fmt.Errorf("manifest tool name must not be empty")
	}
	if decoded.LatencyHint != nil {
		switch *decoded.LatencyHint {
		case "instant", "fast", "moderate", "slow":
		default:
			return fmt.Errorf("unknown manifest latency hint")
		}
	}
	*t = SecurityToolManifestV2ToolDefinition(decoded)
	return nil
}

func (a *SecurityToolManifestV2ToolAnnotations) UnmarshalJSON(data []byte) error {
	type wire SecurityToolManifestV2ToolAnnotations
	var decoded wire
	if err := decodeManifestObject(data, &decoded,
		[]string{"read_only", "destructive", "idempotent", "requires_approval"}, nil); err != nil {
		return err
	}
	*a = SecurityToolManifestV2ToolAnnotations(decoded)
	return nil
}

func (f *SecurityToolFlowDeclaration) UnmarshalJSON(data []byte) error {
	type wire SecurityToolFlowDeclaration
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"egress"},
		[]string{"output_label", "input_clearance", "declassification_purposes"}); err != nil {
		return err
	}
	if decoded.DeclassificationPurposes != nil && len(*decoded.DeclassificationPurposes) == 0 {
		return fmt.Errorf("declassification purposes must be omitted instead of empty")
	}
	*f = SecurityToolFlowDeclaration(decoded)
	return nil
}

func (l *SecurityToolFlowDeclarationKnownLabel) UnmarshalJSON(data []byte) error {
	type wire SecurityToolFlowDeclarationKnownLabel
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"kind", "owners", "compartments"}, nil); err != nil {
		return err
	}
	if decoded.Kind != "known" {
		return fmt.Errorf("manifest flow label must be known")
	}
	*l = SecurityToolFlowDeclarationKnownLabel(decoded)
	return nil
}

func (p *SecurityToolManifestV2RequiredPermissions) UnmarshalJSON(data []byte) error {
	type wire SecurityToolManifestV2RequiredPermissions
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"native_syscall_profile"},
		[]string{"read_paths", "write_paths", "network_destinations", "environment_variables"}); err != nil {
		return err
	}
	switch decoded.NativeSyscallProfile {
	case "native_minimal_v1", "native_standard_v1", "brokered_native_v1":
	default:
		return fmt.Errorf("unknown native syscall profile")
	}
	*p = SecurityToolManifestV2RequiredPermissions(decoded)
	return nil
}

func (d *SecurityToolManifestV2NetworkDestination) UnmarshalJSON(data []byte) error {
	type wire SecurityToolManifestV2NetworkDestination
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"host", "port"}, nil); err != nil {
		return err
	}
	if decoded.Host == "" || decoded.Port < 1 || decoded.Port > 65535 {
		return fmt.Errorf("invalid manifest network destination")
	}
	*d = SecurityToolManifestV2NetworkDestination(decoded)
	return nil
}

func (p *SecurityToolManifestV2ToolPricing) UnmarshalJSON(data []byte) error {
	type wire SecurityToolManifestV2ToolPricing
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"pricing_model"},
		[]string{"base_price", "unit_price", "billing_unit"}); err != nil {
		return err
	}
	switch decoded.PricingModel {
	case "flat", "per_invocation", "per_unit", "hybrid":
	default:
		return fmt.Errorf("unknown manifest pricing model")
	}
	*p = SecurityToolManifestV2ToolPricing(decoded)
	return nil
}

func (a *SecurityToolManifestV2MonetaryAmount) UnmarshalJSON(data []byte) error {
	type wire SecurityToolManifestV2MonetaryAmount
	var decoded wire
	if err := decodeManifestObject(data, &decoded, []string{"units", "currency"}, nil); err != nil {
		return err
	}
	if decoded.Units < 0 || len(decoded.Currency) != 3 {
		return fmt.Errorf("invalid manifest monetary amount")
	}
	for _, character := range decoded.Currency {
		if character < 'A' || character > 'Z' {
			return fmt.Errorf("manifest currency must be uppercase ASCII")
		}
	}
	*a = SecurityToolManifestV2MonetaryAmount(decoded)
	return nil
}
