package invariants

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
)

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

// CapabilitySchema is the only accepted capability token schema and its wrapper id.
const CapabilitySchema = "chio.capability.v1"

// DelegationLinkSchema is the wrapper id of a delegation link signature.
const DelegationLinkSchema = "chio.delegation-link.v1"

var capabilityMembers = map[string]struct{}{
	"schema": {}, "id": {}, "issuer": {}, "subject": {}, "scope": {}, "issued_at": {},
	"expires_at": {}, "delegation_chain": {}, "aggregate_invocation_budget": {}, "caveats": {},
	"scope_attenuations": {}, "attenuation_proof": {}, "budget_share_bps": {}, "root_anchor": {},
	"signature": {},
}

var delegationLinkMembers = map[string]struct{}{
	"capability_id": {}, "delegator": {}, "delegatee": {}, "attenuations": {}, "timestamp": {},
	"scope_hash": {}, "aggregate_budget": {}, "cumulative_approval": {}, "signature": {},
}

var rootAnchorMembers = map[string]struct{}{
	"kind": {}, "context_digest": {}, "root_policy_digest": {}, "anchored_at": {}, "assertion_exp": {},
}

var rootAnchorKinds = map[string]struct{}{
	"oauth_id_jag": {}, "entra_jwt": {}, "entra_agent_id": {}, "oidc_jwt": {},
	"oauth_introspection": {}, "chio_local_as": {}, "chio_operator_key": {}, "operator_static_bearer": {},
}

var rootAnchorDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const maxRootAnchorInteger = 1<<53 - 1

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
	if err := rejectUnknownMembers(capability, capabilityMembers, "capability"); err != nil {
		return err
	}
	if anchor, ok := capability["root_anchor"]; ok {
		return validateRootAnchor(anchor)
	}
	return nil
}

func validateRootAnchor(value any) error {
	anchor, ok := value.(map[string]any)
	if !ok {
		return newInvariantError("json", "root_anchor must be a JSON object")
	}
	if err := rejectUnknownMembers(anchor, rootAnchorMembers, "root_anchor"); err != nil {
		return err
	}
	for _, member := range []string{"kind", "context_digest", "root_policy_digest", "anchored_at", "assertion_exp"} {
		if _, ok := anchor[member]; !ok {
			return newInvariantError("json", "root_anchor is missing member "+member)
		}
	}
	kind, ok := anchor["kind"].(string)
	if _, known := rootAnchorKinds[kind]; !ok || !known {
		return newInvariantError("json", "root_anchor kind is not a known anchor kind")
	}
	for _, member := range []string{"context_digest", "root_policy_digest"} {
		digest, ok := anchor[member].(string)
		if !ok || !rootAnchorDigest.MatchString(digest) {
			return newInvariantError("json", "root_anchor "+member+" must be a sha256 digest")
		}
	}
	for _, member := range []string{"anchored_at", "assertion_exp"} {
		if !isRootAnchorInteger(anchor[member]) {
			return newInvariantError("json", "root_anchor "+member+" must be an unsigned integer")
		}
	}
	return nil
}

func isRootAnchorInteger(value any) bool {
	if number, ok := value.(json.Number); ok {
		parsed, err := strconv.ParseUint(number.String(), 10, 64)
		return err == nil && parsed <= maxRootAnchorInteger
	}
	integer := reflect.ValueOf(value)
	switch {
	case integer.CanInt():
		return integer.Int() >= 0 && uint64(integer.Int()) <= maxRootAnchorInteger
	case integer.CanUint():
		return integer.Uint() <= maxRootAnchorInteger
	}
	return false
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

func VerifyCapability(capability map[string]any, now int64) (CapabilityVerification, error) {
	return verifyCapability(capability, now, nil)
}

func VerifyCapabilityWithMaxDelegationDepth(capability map[string]any, now int64, maxDelegationDepth int) (CapabilityVerification, error) {
	return verifyCapability(capability, now, &maxDelegationDepth)
}

func verifyCapability(capability map[string]any, now int64, maxDelegationDepth *int) (CapabilityVerification, error) {
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
	delegationChainValid, err := verifyDelegationChain(capability["delegation_chain"], maxDelegationDepth)
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

func VerifyCapabilityJSON(input string, now int64) (CapabilityVerification, error) {
	capability, err := ParseCapabilityJSON(input)
	if err != nil {
		return CapabilityVerification{}, err
	}
	return VerifyCapability(capability, now)
}

func VerifyCapabilityJSONWithMaxDelegationDepth(input string, now int64, maxDelegationDepth int) (CapabilityVerification, error) {
	capability, err := ParseCapabilityJSON(input)
	if err != nil {
		return CapabilityVerification{}, err
	}
	return VerifyCapabilityWithMaxDelegationDepth(capability, now, maxDelegationDepth)
}

func verifyDelegationChain(raw any, maxDelegationDepth *int) (bool, error) {
	if raw == nil {
		return true, nil
	}
	entries, ok := raw.([]any)
	if !ok {
		return false, newInvariantError("json", "delegation_chain must be an array")
	}
	if maxDelegationDepth != nil && len(entries) > *maxDelegationDepth {
		return false, nil
	}
	var previous map[string]any
	for _, entry := range entries {
		current, ok := entry.(map[string]any)
		if !ok {
			return false, newInvariantError("json", "delegation_chain entries must be objects")
		}
		if err := rejectUnknownMembers(current, delegationLinkMembers, "delegation link"); err != nil {
			return false, err
		}
		body, err := CanonicalizeJSON(copyWithoutKey(current, "signature"))
		if err != nil {
			return false, err
		}
		delegator, err := stringField(current, "delegator")
		if err != nil {
			return false, err
		}
		signature, err := stringField(current, "signature")
		if err != nil {
			return false, err
		}
		signatureValid, err := wrappedSignatureValid(DelegationLinkSchema, body, delegator, signature)
		if err != nil {
			return false, err
		}
		if !signatureValid {
			return false, nil
		}
		if previous != nil {
			previousDelegatee, err := stringField(previous, "delegatee")
			if err != nil {
				return false, err
			}
			if previousDelegatee != delegator {
				return false, nil
			}
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
		previous = current
	}
	return true, nil
}
