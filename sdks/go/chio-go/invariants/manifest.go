package invariants

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode"
)

var requiredPermissionFields = map[string]struct{}{
	"read_paths":            {},
	"write_paths":           {},
	"network_hosts":         {},
	"environment_variables": {},
}

var pricingModels = map[string]struct{}{
	"flat":           {},
	"per_invocation": {},
	"per_unit":       {},
	"hybrid":         {},
}

var signedManifestFields = map[string]struct{}{
	"manifest":   {},
	"signature":  {},
	"signer_key": {},
}

var manifestFields = map[string]struct{}{
	"schema":               {},
	"server_id":            {},
	"name":                 {},
	"description":          {},
	"version":              {},
	"tools":                {},
	"server_tools":         {},
	"required_permissions": {},
	"public_key":           {},
}

var toolFields = map[string]struct{}{
	"name":             {},
	"description":      {},
	"input_schema":     {},
	"output_schema":    {},
	"pricing":          {},
	"has_side_effects": {},
	"latency_hint":     {},
}

var v2ToolFields = map[string]struct{}{
	"name": {}, "description": {}, "input_schema": {}, "output_schema": {},
	"pricing": {}, "annotations": {}, "latency_hint": {}, "flow": {},
}

var v2AnnotationFields = map[string]struct{}{
	"read_only": {}, "destructive": {}, "idempotent": {}, "requires_approval": {},
}

var v2PermissionFields = map[string]struct{}{
	"read_paths": {}, "write_paths": {}, "network_destinations": {},
	"environment_variables": {}, "native_syscall_profile": {},
}

var flowFields = map[string]struct{}{
	"output_label": {}, "input_clearance": {}, "egress": {}, "declassification_purposes": {},
}

var nativeProfiles = map[string]struct{}{
	"native_minimal_v1": {}, "native_standard_v1": {}, "brokered_native_v1": {},
}

var forbiddenEnvironmentPrefixes = []string{"LD_", "DYLD_", "BASH_FUNC_", "MALLOC_"}

var forbiddenEnvironmentNames = map[string]struct{}{
	"BASH_ENV":              {},
	"DOCKER_CONFIG":         {},
	"ENV":                   {},
	"GCONV_PATH":            {},
	"GEM_HOME":              {},
	"GEM_PATH":              {},
	"GIT_ASKPASS":           {},
	"GLIBC_TUNABLES":        {},
	"GPG_AGENT_INFO":        {},
	"IFS":                   {},
	"JAVA_TOOL_OPTIONS":     {},
	"JDK_JAVA_OPTIONS":      {},
	"KRB5CCNAME":            {},
	"LOCPATH":               {},
	"NETRC":                 {},
	"NLSPATH":               {},
	"NODE_OPTIONS":          {},
	"NODE_PATH":             {},
	"NPM_CONFIG_USERCONFIG": {},
	"PERL5OPT":              {},
	"PERL5LIB":              {},
	"PYTHONHOME":            {},
	"PYTHONINSPECT":         {},
	"PYTHONPATH":            {},
	"PYTHONSTARTUP":         {},
	"RUBYLIB":               {},
	"RUBYOPT":               {},
	"RUSTC_WRAPPER":         {},
	"SSLKEYLOGFILE":         {},
	"SSL_CERT_DIR":          {},
	"SSL_CERT_FILE":         {},
	"SSH_AUTH_SOCK":         {},
	"SUDO_ASKPASS":          {},
	"ZDOTDIR":               {},
	"_JAVA_OPTIONS":         {},
}

var credentialEnvironmentMarkers = []string{
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"CREDENTIAL",
	"API_KEY",
	"PRIVATE_KEY",
	"ACCESS_KEY",
	"AUTHORIZATION",
}

var pricingFields = map[string]struct{}{
	"pricing_model": {},
	"base_price":    {},
	"unit_price":    {},
	"billing_unit":  {},
}

var serverTools = map[string]struct{}{
	"computer_use": {},
	"bash":         {},
	"text_editor":  {},
}

var latencyHints = map[string]struct{}{
	"instant":  {},
	"fast":     {},
	"moderate": {},
	"slow":     {},
}

const maxUint64ExclusiveAsFloat = 18446744073709551616.0

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
	envelopeValid := validateSignedManifestEnvelope(signedManifest)
	manifest, manifestValid := signedManifest["manifest"].(map[string]any)
	signature, signatureValidShape := signedManifest["signature"].(string)
	signerKey, signerKeyValidShape := signedManifest["signer_key"].(string)
	embeddedPublicKey, embeddedPublicKeyShapeValid := manifest["public_key"].(string)
	embeddedPublicKeyValid := IsValidEd25519PublicKeyHex(embeddedPublicKey)
	signatureValid := false
	if envelopeValid && manifestValid && signatureValidShape && signerKeyValidShape {
		body, err := CanonicalizeJSON(manifest)
		if err == nil {
			signatureValid, _ = VerifyUTF8MessageEd25519(body, signerKey, signature)
		}
	}
	return ManifestVerification{
		EmbeddedPublicKeyMatchesSigner: embeddedPublicKeyValid && signerKeyValidShape && PublicKeyHexMatches(embeddedPublicKey, signerKey),
		EmbeddedPublicKeyValid:         embeddedPublicKeyShapeValid && embeddedPublicKeyValid,
		SignatureValid:                 signatureValid,
		StructureValid:                 envelopeValid && validateManifestStructure(manifest),
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
	if !hasOnlyKnownKeys(manifest, manifestFields) {
		return false
	}
	schema, ok := manifest["schema"].(string)
	if !ok {
		return false
	}
	if schema == "chio.manifest.v2" {
		return validateManifestV2(manifest)
	}
	if schema != "chio.manifest.v1" {
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
	if _, ok := manifest["public_key"].(string); !ok {
		return false
	}
	if !validateServerTools(manifest["server_tools"]) {
		return false
	}
	seen := make(map[string]struct{}, len(tools))
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		if !hasOnlyKnownKeys(tool, toolFields) {
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
		if _, ok := tool["description"].(string); !ok {
			return false
		}
		if _, ok := tool["has_side_effects"].(bool); !ok {
			return false
		}
		if outputSchema, exists := tool["output_schema"]; exists && outputSchema != nil && !isJSONObject(outputSchema) {
			return false
		}
		if !validateToolPricing(tool["pricing"]) {
			return false
		}
		if latencyHint, exists := tool["latency_hint"]; exists && latencyHint != nil {
			text, ok := latencyHint.(string)
			if !ok {
				return false
			}
			if _, ok := latencyHints[text]; !ok {
				return false
			}
		}
	}
	return validateRequiredPermissions(manifest["required_permissions"])
}

func validateManifestV2(manifest map[string]any) bool {
	if !isValidManifestTextField(manifest["server_id"]) ||
		!isValidManifestTextField(manifest["name"]) ||
		!isValidManifestTextField(manifest["version"]) {
		return false
	}
	if _, ok := manifest["public_key"].(string); !ok {
		return false
	}
	if description, exists := manifest["description"]; exists {
		if _, ok := description.(string); !ok {
			return false
		}
	}
	if serverToolValue, exists := manifest["server_tools"]; exists {
		serverToolList, ok := serverToolValue.([]any)
		if !ok || len(serverToolList) == 0 || !validateServerTools(serverToolValue) {
			return false
		}
	}
	if permissions, exists := manifest["required_permissions"]; exists && !validateRequiredPermissionsV2(permissions) {
		return false
	}
	tools, ok := manifest["tools"].([]any)
	if !ok || len(tools) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(tools))
	for _, candidate := range tools {
		tool, ok := candidate.(map[string]any)
		if !ok || !hasOnlyKnownKeys(tool, v2ToolFields) {
			return false
		}
		name, ok := tool["name"].(string)
		if !ok || !isValidToolName(name) {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
		if _, ok := tool["description"].(string); !ok || !isJSONObject(tool["input_schema"]) {
			return false
		}
		if output, exists := tool["output_schema"]; exists && !isJSONObject(output) {
			return false
		}
		if pricing, exists := tool["pricing"]; exists && (pricing == nil || !validateToolPricing(pricing)) {
			return false
		}
		if !validateAnnotationsV2(tool["annotations"]) {
			return false
		}
		if hint, exists := tool["latency_hint"]; exists {
			text, ok := hint.(string)
			if !ok {
				return false
			}
			if _, ok := latencyHints[text]; !ok {
				return false
			}
		}
		if flow, exists := tool["flow"]; exists && !validateFlowV2(flow) {
			return false
		}
	}
	return true
}

func validateAnnotationsV2(value any) bool {
	annotations, ok := value.(map[string]any)
	if !ok || len(annotations) != len(v2AnnotationFields) || !hasOnlyKnownKeys(annotations, v2AnnotationFields) {
		return false
	}
	for field := range v2AnnotationFields {
		if _, ok := annotations[field].(bool); !ok {
			return false
		}
	}
	return true
}

func validateFlowV2(value any) bool {
	flow, ok := value.(map[string]any)
	if !ok || !hasOnlyKnownKeys(flow, flowFields) {
		return false
	}
	if _, ok := flow["egress"].(bool); !ok {
		return false
	}
	for _, field := range []string{"output_label", "input_clearance"} {
		if label, exists := flow[field]; exists && !validateKnownLabel(label) {
			return false
		}
	}
	if value, exists := flow["declassification_purposes"]; exists {
		purposes, ok := value.([]any)
		if !ok || len(purposes) == 0 || !validateUniqueIdentifiers(purposes, 0) {
			return false
		}
	}
	return true
}

func validateKnownLabel(value any) bool {
	label, ok := value.(map[string]any)
	knownFields := map[string]struct{}{"kind": {}, "owners": {}, "compartments": {}}
	if !ok || len(label) != len(knownFields) || !hasOnlyKnownKeys(label, knownFields) || label["kind"] != "known" {
		return false
	}
	owners, ok := label["owners"].(map[string]any)
	if !ok || len(owners) > 64 {
		return false
	}
	compartments, ok := label["compartments"].([]any)
	if !ok || len(compartments) > 64 || !validateUniqueIdentifiers(compartments, 0) {
		return false
	}
	for owner, rawReaders := range owners {
		if !isValidIdentifier(owner) {
			return false
		}
		readers, ok := rawReaders.([]any)
		if !ok || len(readers) > 256 || !validateUniqueIdentifiers(readers, 0) {
			return false
		}
		containsOwner := false
		for _, reader := range readers {
			containsOwner = containsOwner || reader == owner
		}
		if !containsOwner {
			return false
		}
	}
	return true
}

func validateUniqueIdentifiers(values []any, minimum int) bool {
	if len(values) < minimum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || !isValidIdentifier(text) {
			return false
		}
		if _, duplicate := seen[text]; duplicate {
			return false
		}
		seen[text] = struct{}{}
	}
	return true
}

func isValidIdentifier(value string) bool {
	return len(value) > 0 && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func validateRequiredPermissionsV2(value any) bool {
	permissions, ok := value.(map[string]any)
	if !ok || !hasOnlyKnownKeys(permissions, v2PermissionFields) {
		return false
	}
	profile, ok := permissions["native_syscall_profile"].(string)
	if !ok {
		return false
	}
	if _, ok := nativeProfiles[profile]; !ok {
		return false
	}
	for _, field := range []string{"read_paths", "write_paths"} {
		if paths, exists := permissions[field]; exists && !validatePathList(paths) {
			return false
		}
	}
	if variables, exists := permissions["environment_variables"]; exists && !validateEnvironmentList(variables) {
		return false
	}
	if destinations, exists := permissions["network_destinations"]; exists && !validateNetworkDestinations(destinations) {
		return false
	}
	return true
}

func validatePathList(value any) bool {
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		path, ok := raw.(string)
		if !ok || !strings.HasPrefix(path, "/") || path == "/" || strings.TrimSpace(path) != path ||
			strings.ContainsFunc(path, unicode.IsControl) {
			return false
		}
		for index, component := range strings.Split(path, "/") {
			if index > 0 && (component == "" || component == "." || component == "..") {
				return false
			}
		}
		if _, duplicate := seen[path]; duplicate {
			return false
		}
		seen[path] = struct{}{}
	}
	return true
}

func validateEnvironmentList(value any) bool {
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		name, ok := raw.(string)
		if !ok || !isEnvironmentName(name) || isForbiddenEnvironmentName(name) {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func isForbiddenEnvironmentName(name string) bool {
	for _, prefix := range forbiddenEnvironmentPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	if _, forbidden := forbiddenEnvironmentNames[name]; forbidden {
		return true
	}
	for _, marker := range credentialEnvironmentMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func isEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, char := range value {
		if index == 0 {
			if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || char == '_') {
				return false
			}
		} else if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}
	return true
}

func validateNetworkDestinations(value any) bool {
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		destination, ok := raw.(map[string]any)
		fields := map[string]struct{}{"host": {}, "port": {}}
		if !ok || len(destination) != 2 || !hasOnlyKnownKeys(destination, fields) {
			return false
		}
		host, ok := destination["host"].(string)
		if !ok || host == "" || len(host) > 253 || host != strings.ToLower(host) || strings.ContainsAny(host, "*/ \t\r\n") {
			return false
		}
		port, ok := jsonUint16(destination["port"])
		if !ok || port == 0 {
			return false
		}
		key := host + ":" + strconv.FormatUint(uint64(port), 10)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func jsonUint16(value any) (uint16, bool) {
	switch number := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseUint(number.String(), 10, 16)
		return uint16(parsed), err == nil
	case float64:
		if number < 0 || number > 65535 || math.Trunc(number) != number {
			return 0, false
		}
		return uint16(number), true
	case int:
		if number < 0 || number > 65535 {
			return 0, false
		}
		return uint16(number), true
	default:
		return 0, false
	}
}

func validateSignedManifestEnvelope(signedManifest map[string]any) bool {
	if signedManifest == nil {
		return false
	}
	if len(signedManifest) != len(signedManifestFields) {
		return false
	}
	for field := range signedManifest {
		if _, ok := signedManifestFields[field]; !ok {
			return false
		}
	}
	return true
}

func hasOnlyKnownKeys(value map[string]any, knownKeys map[string]struct{}) bool {
	if value == nil {
		return false
	}
	for field := range value {
		if _, ok := knownKeys[field]; !ok {
			return false
		}
	}
	return true
}

func isValidManifestTextField(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	trimmed := strings.TrimSpace(text)
	return trimmed != "" && trimmed == text && !strings.ContainsFunc(text, unicode.IsControl)
}

func isValidToolName(name string) bool {
	return isValidManifestTextField(name)
}

func isJSONObject(value any) bool {
	_, ok := value.(map[string]any)
	return ok
}

func validateToolPricing(value any) bool {
	if value == nil {
		return true
	}
	pricing, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if !hasOnlyKnownKeys(pricing, pricingFields) {
		return false
	}
	model, ok := pricing["pricing_model"].(string)
	if !ok {
		return false
	}
	if _, ok := pricingModels[model]; !ok {
		return false
	}
	switch model {
	case "flat":
		if !requirePricingAmount(pricing["base_price"]) {
			return false
		}
	case "per_invocation", "per_unit":
		if !requirePricingAmount(pricing["unit_price"]) ||
			!isValidManifestTextField(pricing["billing_unit"]) {
			return false
		}
	case "hybrid":
		if !requirePricingAmount(pricing["base_price"]) ||
			!requirePricingAmount(pricing["unit_price"]) ||
			!isValidManifestTextField(pricing["billing_unit"]) {
			return false
		}
	}
	if !validateOptionalPricingAmount(pricing["base_price"]) {
		return false
	}
	if !validateOptionalPricingAmount(pricing["unit_price"]) {
		return false
	}
	if billingUnit, exists := pricing["billing_unit"]; exists && billingUnit != nil && !isValidManifestTextField(billingUnit) {
		return false
	}
	return true
}

func validateServerTools(value any) bool {
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
		if !ok {
			return false
		}
		if _, ok := serverTools[text]; !ok {
			return false
		}
		if _, exists := seen[text]; exists {
			return false
		}
		seen[text] = struct{}{}
	}
	return true
}

func requirePricingAmount(value any) bool {
	return value != nil && validatePricingAmount(value)
}

func validateOptionalPricingAmount(value any) bool {
	if value == nil {
		return true
	}
	return validatePricingAmount(value)
}

func validatePricingAmount(value any) bool {
	amount, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if !isNonNegativeInteger(amount["units"]) {
		return false
	}
	currency, ok := amount["currency"].(string)
	return ok && isISO4217CurrencyCode(currency)
}

func isNonNegativeInteger(value any) bool {
	switch units := value.(type) {
	case int:
		return units >= 0
	case int64:
		return units >= 0
	case float64:
		return units >= 0 && math.Trunc(units) == units && units < maxUint64ExclusiveAsFloat
	case json.Number:
		_, err := strconv.ParseUint(units.String(), 10, 64)
		return err == nil
	default:
		return false
	}
}

func isISO4217CurrencyCode(currency string) bool {
	if len(currency) != 3 {
		return false
	}
	for _, char := range currency {
		if char < 'A' || char > 'Z' {
			return false
		}
	}
	return true
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
