package invariants

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// SigningWrapperPrefix opens every Chio signing wrapper; byte 23 is 0x00.
const SigningWrapperPrefix = "chio.signing-wrapper.v1\x00"

// WrappedSignature is an Ed25519 signature over the signing wrapper of a canonical JSON body.
type WrappedSignature struct {
	SchemaID      string
	CanonicalJSON string
	PublicKeyHex  string
	SignatureHex  string
}

func IsValidEd25519PublicKeyHex(value string) bool {
	_, err := decodeFixedHex(value, 32, "invalid_public_key")
	return err == nil
}

func IsValidEd25519SignatureHex(value string) bool {
	_, err := decodeFixedHex(value, 64, "invalid_signature")
	return err == nil
}

func PublicKeyHexMatches(left string, right string) bool {
	return normalizeHex(left) == normalizeHex(right)
}

// IsRegisteredSchemaID reports whether the wrapper may sign or verify under schemaID.
func IsRegisteredSchemaID(schemaID string) bool {
	_, ok := knownSignedArtifactSchemas[schemaID]
	return ok
}

// SigningWrapper returns the 88 bytes a Chio signature covers for schemaID and canonicalJSON.
func SigningWrapper(schemaID string, canonicalJSON string) ([]byte, error) {
	if !IsRegisteredSchemaID(schemaID) {
		return nil, newInvariantError("unregistered_schema_id", "unregistered signed-artifact schema id: "+schemaID)
	}
	schemaDigest := sha256.Sum256([]byte(schemaID))
	bodyDigest := sha256.Sum256([]byte(canonicalJSON))
	wrapper := make([]byte, 0, 88)
	wrapper = append(wrapper, SigningWrapperPrefix...)
	wrapper = append(wrapper, schemaDigest[:]...)
	wrapper = append(wrapper, bodyDigest[:]...)
	return wrapper, nil
}

func PublicKeyFromSeedEd25519(seedHex string) (string, error) {
	seed, err := decodeFixedHex(seedHex, 32, "invalid_hex")
	if err != nil {
		return "", err
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return hex.EncodeToString(publicKey), nil
}

func SignWrappedJSONEd25519(schemaID string, input string, seedHex string) (WrappedSignature, error) {
	canonicalJSON, err := CanonicalizeJSONString(input)
	if err != nil {
		return WrappedSignature{}, err
	}
	wrapper, err := SigningWrapper(schemaID, canonicalJSON)
	if err != nil {
		return WrappedSignature{}, err
	}
	seed, err := decodeFixedHex(seedHex, 32, "invalid_hex")
	if err != nil {
		return WrappedSignature{}, err
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return WrappedSignature{
		SchemaID:      schemaID,
		CanonicalJSON: canonicalJSON,
		PublicKeyHex:  hex.EncodeToString(publicKey),
		SignatureHex:  hex.EncodeToString(ed25519.Sign(privateKey, wrapper)),
	}, nil
}

// VerifyWrappedJSON verifies signatureHex over the wrapper of input under schemaID. The pinned
// key's encoding alone selects the algorithm; a signature encoded for another algorithm is
// refused before any cryptographic check.
func VerifyWrappedJSON(schemaID string, input string, publicKeyHex string, signatureHex string) error {
	canonicalJSON, err := CanonicalizeJSONString(input)
	if err != nil {
		return err
	}
	return verifyWrappedCanonical(schemaID, canonicalJSON, publicKeyHex, signatureHex)
}

func verifyWrappedCanonical(schemaID string, canonicalJSON string, publicKeyHex string, signatureHex string) error {
	wrapper, err := SigningWrapper(schemaID, canonicalJSON)
	if err != nil {
		return err
	}
	keyAlgorithm := encodedAlgorithm(publicKeyHex)
	signatureAlgorithm := encodedAlgorithm(signatureHex)
	if keyAlgorithm != signatureAlgorithm {
		return newInvariantError(
			"signature_algorithm_mismatch",
			"signature algorithm "+signatureAlgorithm+" does not match the pinned key algorithm "+keyAlgorithm,
		)
	}
	if keyAlgorithm != "ed25519" {
		return newInvariantError("unsupported_algorithm", "signature algorithm "+keyAlgorithm+" is not supported by this SDK")
	}
	publicKey, err := decodeFixedHex(publicKeyHex, 32, "invalid_public_key")
	if err != nil {
		return err
	}
	signature, err := decodeFixedHex(signatureHex, 64, "invalid_signature")
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), wrapper, signature) {
		return newInvariantError("signature_rejected", "signature rejected")
	}
	return nil
}

// wrappedSignatureValid maps a rejected signature to false and keeps every other refusal an error.
func wrappedSignatureValid(schemaID string, canonicalJSON string, publicKeyHex string, signatureHex string) (bool, error) {
	err := verifyWrappedCanonical(schemaID, canonicalJSON, publicKeyHex, signatureHex)
	if err == nil {
		return true, nil
	}
	var invariantError *InvariantError
	if errors.As(err, &invariantError) && invariantError.Code == "signature_rejected" {
		return false, nil
	}
	return false, err
}

func encodedAlgorithm(value string) string {
	for _, prefix := range []string{"p256", "p384", "hybrid"} {
		if strings.HasPrefix(value, prefix+":") {
			return prefix
		}
	}
	return "ed25519"
}

func normalizeHex(value string) string {
	normalized := strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	return strings.ToLower(normalized)
}

func decodeFixedHex(value string, expectedBytes int, code string) ([]byte, error) {
	normalized := normalizeHex(value)
	if len(normalized) != expectedBytes*2 {
		return nil, newInvariantError(code, "value has an unexpected hexadecimal length")
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, newInvariantError(code, "value is not valid hexadecimal")
	}
	return decoded, nil
}
