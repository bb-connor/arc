package invariants

type CapabilityTimeStatus string

const (
	CapabilityTimeStatusValid       CapabilityTimeStatus = "valid"
	CapabilityTimeStatusNotYetValid CapabilityTimeStatus = "not_yet_valid"
	CapabilityTimeStatusExpired     CapabilityTimeStatus = "expired"
)

type CapabilityVerification struct {
	DelegationChainShapeValid bool                 `json:"delegation_chain_shape_valid"`
	SignatureValid            bool                 `json:"signature_valid"`
	TimeStatus                CapabilityTimeStatus `json:"time_status"`
	TimeValid                 bool                 `json:"time_valid"`
}

// ErrorCodeDelegationRootUnresolved is the InvariantError code for a delegated capability
// verified without a verifier-supplied parent subject.
const ErrorCodeDelegationRootUnresolved = "delegation_root_unresolved"

// CapabilitySchema is the only accepted capability token schema and its wrapper id.
const CapabilitySchema = "chio.capability.v1"

// DelegationLinkSchema is the wrapper id of a delegation link signature.
const DelegationLinkSchema = "chio.delegation-link.v1"

var capabilityMembers = map[string]struct{}{
	"schema": {}, "id": {}, "issuer": {}, "subject": {}, "scope": {}, "issued_at": {},
	"expires_at": {}, "delegation_chain": {}, "aggregate_invocation_budget": {}, "caveats": {},
	"scope_attenuations": {}, "attenuation_proof": {}, "budget_share_bps": {}, "signature": {},
}

var delegationLinkMembers = map[string]struct{}{
	"capability_id": {}, "delegator": {}, "delegatee": {}, "attenuations": {}, "timestamp": {},
	"scope_hash": {}, "aggregate_budget": {}, "cumulative_approval": {}, "signature": {},
}

func rejectUnknownMembers(value map[string]any, allowed map[string]struct{}, kind string) error {
	for key := range value {
		if _, ok := allowed[key]; !ok {
			return newInvariantError("json", kind+" has unknown member "+key)
		}
	}
	return nil
}

func ParseCapabilityJSON(input string) (map[string]any, error) {
	value, err := ParseJSONText(input)
	if err != nil {
		return nil, err
	}
	capability, ok := value.(map[string]any)
	if !ok {
		return nil, newInvariantError("json", "capability must be a JSON object")
	}
	if err := validateCapabilitySchema(capability); err != nil {
		return nil, err
	}
	return capability, nil
}

func validateCapabilitySchema(capability map[string]any) error {
	if schema, ok := capability["schema"].(string); !ok || schema != CapabilitySchema {
		return newInvariantError("json", `capability schema must be "chio.capability.v1"`)
	}
	return rejectUnknownMembers(capability, capabilityMembers, "capability")
}

func capabilityBody(capability map[string]any) map[string]any {
	omitted := map[string]struct{}{
		"attenuation_proof":  {},
		"budget_share_bps":   {},
		"caveats":            {},
		"schema":             {},
		"scope_attenuations": {},
		"signature":          {},
	}
	body := make(map[string]any, len(capability))
	for key, value := range capability {
		if _, ok := omitted[key]; ok {
			continue
		}
		body[key] = value
	}
	return body
}

func isNonEmptyArray(value any) bool {
	array, ok := value.([]any)
	return ok && len(array) > 0
}

func CapabilitySigningBody(capability map[string]any) map[string]any {
	body := capabilityBody(capability)
	signingBody := make(map[string]any, len(body)+4)
	if schema, ok := capability["schema"]; ok {
		signingBody["schema"] = schema
	}
	for key, value := range body {
		if key == "delegation_chain" && !isNonEmptyArray(value) {
			continue
		}
		signingBody[key] = value
	}
	if isNonEmptyArray(capability["caveats"]) {
		signingBody["caveats"] = capability["caveats"]
	}
	if isNonEmptyArray(capability["scope_attenuations"]) {
		signingBody["scope_attenuations"] = capability["scope_attenuations"]
	}
	if value, ok := capability["attenuation_proof"]; ok && value != nil {
		signingBody["attenuation_proof"] = value
	}
	if value, ok := capability["budget_share_bps"]; ok && value != nil {
		signingBody["budget_share_bps"] = value
	}
	return signingBody
}

func CapabilitySigningBodyCanonicalJSON(capability map[string]any) (string, error) {
	if err := validateCapabilitySchema(capability); err != nil {
		return "", err
	}
	return CanonicalizeJSON(CapabilitySigningBody(capability))
}

// VerifyCapability checks a capability token. rootDelegatorHex is the subject key of the
// parent capability the delegation chain starts from; a delegated token verified without it
// is refused with the delegation_root_unresolved error code.
func VerifyCapability(capability map[string]any, rootDelegatorHex string, now int64) (CapabilityVerification, error) {
	return verifyCapability(capability, rootDelegatorHex, now, nil)
}

func VerifyCapabilityWithMaxDelegationDepth(capability map[string]any, rootDelegatorHex string, now int64, maxDelegationDepth int) (CapabilityVerification, error) {
	return verifyCapability(capability, rootDelegatorHex, now, &maxDelegationDepth)
}

func verifyCapability(capability map[string]any, rootDelegatorHex string, now int64, maxDelegationDepth *int) (CapabilityVerification, error) {
	issuedAt, err := int64Field(capability, "issued_at")
	if err != nil {
		return CapabilityVerification{}, err
	}
	expiresAt, err := int64Field(capability, "expires_at")
	if err != nil {
		return CapabilityVerification{}, err
	}
	timeStatus := CapabilityTimeStatusValid
	switch {
	case now < issuedAt:
		timeStatus = CapabilityTimeStatusNotYetValid
	case now >= expiresAt:
		timeStatus = CapabilityTimeStatusExpired
	}

	body, err := CapabilitySigningBodyCanonicalJSON(capability)
	if err != nil {
		return CapabilityVerification{}, err
	}
	issuer, err := stringField(capability, "issuer")
	if err != nil {
		return CapabilityVerification{}, err
	}
	signature, err := stringField(capability, "signature")
	if err != nil {
		return CapabilityVerification{}, err
	}
	signatureValid, err := wrappedSignatureValid(CapabilitySchema, body, issuer, signature)
	if err != nil {
		return CapabilityVerification{}, err
	}
	delegationChainValid, err := verifyDelegationChain(capability["delegation_chain"], rootDelegatorHex, maxDelegationDepth)
	if err != nil {
		return CapabilityVerification{}, err
	}

	return CapabilityVerification{
		DelegationChainShapeValid: delegationChainValid,
		SignatureValid:            signatureValid,
		TimeStatus:                timeStatus,
		TimeValid:                 timeStatus == CapabilityTimeStatusValid,
	}, nil
}

func VerifyCapabilityJSON(input string, rootDelegatorHex string, now int64) (CapabilityVerification, error) {
	capability, err := ParseCapabilityJSON(input)
	if err != nil {
		return CapabilityVerification{}, err
	}
	return VerifyCapability(capability, rootDelegatorHex, now)
}

func VerifyCapabilityJSONWithMaxDelegationDepth(input string, rootDelegatorHex string, now int64, maxDelegationDepth int) (CapabilityVerification, error) {
	capability, err := ParseCapabilityJSON(input)
	if err != nil {
		return CapabilityVerification{}, err
	}
	return VerifyCapabilityWithMaxDelegationDepth(capability, rootDelegatorHex, now, maxDelegationDepth)
}

func verifyDelegationChain(raw any, rootDelegatorHex string, maxDelegationDepth *int) (bool, error) {
	if rootDelegatorHex != "" && !IsValidEd25519PublicKeyHex(rootDelegatorHex) {
		return false, newInvariantError("invalid_public_key", "root delegator is not a valid Ed25519 public key")
	}
	if raw == nil {
		return true, nil
	}
	entries, ok := raw.([]any)
	if !ok {
		return false, newInvariantError("json", "delegation_chain must be an array")
	}
	if len(entries) == 0 {
		return true, nil
	}
	if rootDelegatorHex == "" {
		return false, newInvariantError(
			ErrorCodeDelegationRootUnresolved,
			"delegation chain root delegator was not supplied by the verifier",
		)
	}
	if maxDelegationDepth != nil && len(entries) > *maxDelegationDepth {
		return false, nil
	}
	expectedDelegator := rootDelegatorHex
	var previous map[string]any
	for _, entry := range entries {
		current, ok := entry.(map[string]any)
		if !ok {
			return false, newInvariantError("json", "delegation_chain entries must be objects")
		}
		if err := rejectUnknownMembers(current, delegationLinkMembers, "delegation link"); err != nil {
			return false, err
		}
		delegator, err := stringField(current, "delegator")
		if err != nil {
			return false, err
		}
		if !PublicKeyHexMatches(delegator, expectedDelegator) {
			return false, nil
		}
		body, err := CanonicalizeJSON(copyWithoutKey(current, "signature"))
		if err != nil {
			return false, err
		}
		signature, err := stringField(current, "signature")
		if err != nil {
			return false, err
		}
		signatureValid, err := wrappedSignatureValid(DelegationLinkSchema, body, expectedDelegator, signature)
		if err != nil {
			return false, err
		}
		if !signatureValid {
			return false, nil
		}
		if previous != nil {
			previousTimestamp, err := int64Field(previous, "timestamp")
			if err != nil {
				return false, err
			}
			currentTimestamp, err := int64Field(current, "timestamp")
			if err != nil {
				return false, err
			}
			if currentTimestamp < previousTimestamp {
				return false, nil
			}
		}
		expectedDelegator, err = stringField(current, "delegatee")
		if err != nil {
			return false, err
		}
		previous = current
	}
	return true, nil
}
