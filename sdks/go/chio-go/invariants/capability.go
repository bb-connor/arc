package invariants

type CapabilityTimeStatus string

const (
	CapabilityTimeStatusValid       CapabilityTimeStatus = "valid"
	CapabilityTimeStatusNotYetValid CapabilityTimeStatus = "not_yet_valid"
	CapabilityTimeStatusExpired     CapabilityTimeStatus = "expired"
)

type CapabilityVerification struct {
	DelegationChainValid bool                 `json:"delegation_chain_valid"`
	SignatureValid       bool                 `json:"signature_valid"`
	TimeStatus           CapabilityTimeStatus `json:"time_status"`
	TimeValid            bool                 `json:"time_valid"`
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
	return capability, nil
}

func CapabilityBodyCanonicalJSON(capability map[string]any) (string, error) {
	return CanonicalizeJSON(copyWithoutKey(capability, "signature"))
}

func VerifyCapability(capability map[string]any, now int64) (CapabilityVerification, error) {
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

	body, err := CapabilityBodyCanonicalJSON(capability)
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
	signatureValid, err := VerifyUTF8MessageEd25519(body, issuer, signature)
	if err != nil {
		return CapabilityVerification{}, err
	}
	delegationChainValid, err := verifyDelegationChain(capability["delegation_chain"])
	if err != nil {
		return CapabilityVerification{}, err
	}

	return CapabilityVerification{
		DelegationChainValid: delegationChainValid,
		SignatureValid:       signatureValid,
		TimeStatus:           timeStatus,
		TimeValid:            timeStatus == CapabilityTimeStatusValid,
	}, nil
}

func VerifyCapabilityJSON(input string, now int64) (CapabilityVerification, error) {
	capability, err := ParseCapabilityJSON(input)
	if err != nil {
		return CapabilityVerification{}, err
	}
	return VerifyCapability(capability, now)
}

func verifyDelegationChain(raw any) (bool, error) {
	if raw == nil {
		return true, nil
	}
	entries, ok := raw.([]any)
	if !ok {
		return false, newInvariantError("json", "delegation_chain must be an array")
	}
	var previous map[string]any
	for _, entry := range entries {
		current, ok := entry.(map[string]any)
		if !ok {
			return false, newInvariantError("json", "delegation_chain entries must be objects")
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
		signatureValid, err := VerifyUTF8MessageEd25519(body, delegator, signature)
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
