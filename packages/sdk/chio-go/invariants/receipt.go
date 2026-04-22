package invariants

type ReceiptVerification struct {
	Decision           string `json:"decision"`
	ParameterHashValid bool   `json:"parameter_hash_valid"`
	SignatureValid     bool   `json:"signature_valid"`
}

func ParseReceiptJSON(input string) (map[string]any, error) {
	value, err := ParseJSONText(input)
	if err != nil {
		return nil, err
	}
	receipt, ok := value.(map[string]any)
	if !ok {
		return nil, newInvariantError("json", "receipt must be a JSON object")
	}
	return receipt, nil
}

func ReceiptBodyCanonicalJSON(receipt map[string]any) (string, error) {
	return CanonicalizeJSON(copyWithoutKey(receipt, "signature"))
}

func VerifyReceipt(receipt map[string]any) (ReceiptVerification, error) {
	body, err := ReceiptBodyCanonicalJSON(receipt)
	if err != nil {
		return ReceiptVerification{}, err
	}
	kernelKey, err := stringField(receipt, "kernel_key")
	if err != nil {
		return ReceiptVerification{}, err
	}
	signature, err := stringField(receipt, "signature")
	if err != nil {
		return ReceiptVerification{}, err
	}
	signatureValid, err := VerifyUTF8MessageEd25519(body, kernelKey, signature)
	if err != nil {
		return ReceiptVerification{}, err
	}
	action, err := mapField(receipt, "action")
	if err != nil {
		return ReceiptVerification{}, err
	}
	parameters, err := mapField(action, "parameters")
	if err != nil {
		return ReceiptVerification{}, err
	}
	renderedParameters, err := CanonicalizeJSON(parameters)
	if err != nil {
		return ReceiptVerification{}, err
	}
	expectedParameterHash := SHA256HexUTF8(renderedParameters)
	actualParameterHash, err := stringField(action, "parameter_hash")
	if err != nil {
		return ReceiptVerification{}, err
	}
	decision, err := mapField(receipt, "decision")
	if err != nil {
		return ReceiptVerification{}, err
	}
	verdict, err := stringField(decision, "verdict")
	if err != nil {
		return ReceiptVerification{}, err
	}
	return ReceiptVerification{
		Decision:           verdict,
		ParameterHashValid: actualParameterHash == expectedParameterHash,
		SignatureValid:     signatureValid,
	}, nil
}

func VerifyReceiptJSON(input string) (ReceiptVerification, error) {
	receipt, err := ParseReceiptJSON(input)
	if err != nil {
		return ReceiptVerification{}, err
	}
	return VerifyReceipt(receipt)
}
