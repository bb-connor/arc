package invariants

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"regexp"
)

const ReceiptDisclosureSchema = "chio.receipt-disclosure.v1"

const maxDisclosureOpenings = 64

var (
	parametersCommitmentDomain = []byte("chio.receipt.parameters.v1\x00")
	contentCommitmentDomain    = []byte("chio.receipt.content.v1\x00")
	disclosureReceiptIDPattern = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
	saltRefPattern             = regexp.MustCompile(`\A[a-z][a-z0-9_]*(\.[a-z0-9_]+)*\z`)
	saltPattern                = regexp.MustCompile(`\Ab64u:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\z`)
	disclosureMembers          = memberSet("schema", "receipt_id", "openings")
	openingMembers             = memberSet("salt_ref", "salt", "payload")
	commitmentMembers          = memberSet("alg", "value", "salt_ref")
)

// FieldVerdict is the opening result for one committed field.
type FieldVerdict string

const (
	FieldVerified     FieldVerdict = "verified"
	FieldRejected     FieldVerdict = "rejected"
	FieldUnverifiable FieldVerdict = "unverifiable"
)

// Opening is one salt opening. Payload is opaque to the opener; nil is a salt-only opening.
type Opening struct {
	SaltRef string
	Salt    []byte
	Payload any
}

// ReceiptDisclosure is a decoded chio.receipt-disclosure.v1 document.
type ReceiptDisclosure struct {
	ReceiptID string
	Openings  []Opening
}

// OpeningReport is false in DisclosureValid exactly when the document is tampered disclosure.
// It covers only the parameter and content commitments: the delegation-context anchor
// commitments (anchor_subject, anchor_tenant) are outside it, and a disclosure that opens them
// is accepted only after they are judged separately.
type OpeningReport struct {
	Parameters      FieldVerdict `json:"parameters"`
	Content         FieldVerdict `json:"content"`
	DisclosureValid bool         `json:"disclosure_valid"`
}

// DecodeSalt accepts only the canonical b64u form of 32 bytes.
func DecodeSalt(encoded string) ([]byte, error) {
	if !saltPattern.MatchString(encoded) {
		return nil, newInvariantError("disclosure", "salt is not the canonical b64u form of 32 bytes")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded[len("b64u:"):])
	if err != nil || len(raw) != 32 {
		return nil, newInvariantError("disclosure", "salt is not the canonical b64u form of 32 bytes")
	}
	return raw, nil
}

// ParseReceiptDisclosure decodes a disclosure document from its parsed JSON value and refuses
// any member, schema, receipt id, opening count, salt_ref or salt outside the wire form.
func ParseReceiptDisclosure(value any) (ReceiptDisclosure, error) {
	refuse := func(message string) (ReceiptDisclosure, error) {
		return ReceiptDisclosure{}, newInvariantError("disclosure", message)
	}
	document, ok := value.(map[string]any)
	if !ok {
		return refuse("disclosure must be a JSON object")
	}
	if err := requireExactMembers(document, disclosureMembers, ""); err != nil {
		return ReceiptDisclosure{}, err
	}
	if schema, ok := document["schema"].(string); !ok || schema != ReceiptDisclosureSchema {
		return refuse("schema is not chio.receipt-disclosure.v1")
	}
	receiptID, ok := document["receipt_id"].(string)
	if !ok || !disclosureReceiptIDPattern.MatchString(receiptID) {
		return refuse("receipt_id is not 64 lowercase hex characters")
	}
	entries, ok := document["openings"].([]any)
	if !ok || len(entries) == 0 || len(entries) > maxDisclosureOpenings {
		return refuse("openings must hold 1 to 64 entries")
	}
	openings := make([]Opening, 0, len(entries))
	for _, entry := range entries {
		opening, ok := entry.(map[string]any)
		if !ok {
			return refuse("opening must be a JSON object")
		}
		if err := requireExactMembers(opening, openingMembers, "/openings"); err != nil {
			return ReceiptDisclosure{}, err
		}
		saltRef, ok := opening["salt_ref"].(string)
		if !ok || len(saltRef) > 64 || !saltRefPattern.MatchString(saltRef) {
			return refuse("salt_ref is not a valid salt reference")
		}
		encoded, ok := opening["salt"].(string)
		if !ok {
			return refuse("salt must be a string")
		}
		salt, err := DecodeSalt(encoded)
		if err != nil {
			return ReceiptDisclosure{}, err
		}
		openings = append(openings, Opening{SaltRef: saltRef, Salt: salt, Payload: opening["payload"]})
	}
	return ReceiptDisclosure{ReceiptID: receiptID, Openings: openings}, nil
}

func requireExactMembers(object map[string]any, members map[string]struct{}, path string) error {
	if err := requireMembers(object, members, path); err != nil {
		return newInvariantError("disclosure", err.Error())
	}
	for member := range members {
		if _, ok := object[member]; !ok {
			return newInvariantError("disclosure", "missing member: "+path+"/"+member)
		}
	}
	return nil
}

func structurallyValid(receiptID string, disclosure ReceiptDisclosure) bool {
	if disclosure.ReceiptID != receiptID {
		return false
	}
	for index, opening := range disclosure.Openings {
		for _, other := range disclosure.Openings[index+1:] {
			if opening.SaltRef == other.SaltRef || subtle.ConstantTimeCompare(opening.Salt, other.Salt) == 1 {
				return false
			}
		}
	}
	return true
}

func openField(disclosure ReceiptDisclosure, commitment map[string]any, position string, domain []byte, preimage []byte, havePreimage bool) FieldVerdict {
	if requireExactMembers(commitment, commitmentMembers, "") != nil ||
		commitment["alg"] != "sha256-salted" || commitment["salt_ref"] != position {
		return FieldRejected
	}
	var opening *Opening
	for index := range disclosure.Openings {
		if disclosure.Openings[index].SaltRef == position {
			opening = &disclosure.Openings[index]
			break
		}
	}
	if opening == nil || !havePreimage {
		return FieldUnverifiable
	}
	value, ok := commitment["value"].(string)
	if !ok {
		return FieldRejected
	}
	digest := sha256.Sum256(bytes.Join([][]byte{domain, opening.Salt, preimage}, nil))
	expected := []byte("sha256:" + hex.EncodeToString(digest[:]))
	if subtle.ConstantTimeCompare(expected, []byte(value)) == 1 {
		return FieldVerified
	}
	return FieldRejected
}

// OpenCommitments opens a receipt's parameter and content commitments with disclosure over the
// caller's own arguments and content preimage; a payload never supplies a preimage. A nil
// ownParameters or ownContent leaves that field unverifiable. A document for another receipt,
// a repeated salt_ref or a salt shared by two openings rejects every field; any rejected field
// marks the disclosure invalid.
func OpenCommitments(
	receiptID string,
	parameterCommitment map[string]any,
	contentCommitment map[string]any,
	disclosure ReceiptDisclosure,
	ownParameters any,
	ownContent []byte,
) OpeningReport {
	if !structurallyValid(receiptID, disclosure) {
		return OpeningReport{Parameters: FieldRejected, Content: FieldRejected, DisclosureValid: false}
	}
	parameters := FieldUnverifiable
	if ownParameters != nil {
		canonical, err := CanonicalizeJSON(ownParameters)
		if err != nil {
			parameters = FieldRejected
		} else {
			parameters = openField(disclosure, parameterCommitment, "params", parametersCommitmentDomain, []byte(canonical), true)
		}
	} else {
		parameters = openField(disclosure, parameterCommitment, "params", parametersCommitmentDomain, nil, false)
	}
	content := openField(disclosure, contentCommitment, "content", contentCommitmentDomain, ownContent, ownContent != nil)
	return OpeningReport{
		Parameters:      parameters,
		Content:         content,
		DisclosureValid: parameters != FieldRejected && content != FieldRejected,
	}
}
