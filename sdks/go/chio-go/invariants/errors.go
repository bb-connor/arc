package invariants

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

type InvariantError struct {
	Code    string
	Message string
}

func (error *InvariantError) Error() string {
	return error.Message
}

func newInvariantError(code string, message string) error {
	return &InvariantError{
		Code:    code,
		Message: message,
	}
}

// ParseJSONText decodes exactly one JSON value and refuses trailing data and duplicate object
// keys anywhere in the document.
func ParseJSONText(input string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, invalidJSON()
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, invalidJSON()
	}
	keys := json.NewDecoder(strings.NewReader(input))
	keys.UseNumber()
	if err := requireUniqueKeys(keys); err != nil {
		return nil, err
	}
	return value, nil
}

func invalidJSON() error {
	return newInvariantError("json", "input is not valid JSON")
}

// requireUniqueKeys walks one value that Decode already accepted, so its nesting depth is
// bounded by the decoder's own limit.
func requireUniqueKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return invalidJSON()
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		if delim == '{' {
			keyToken, err := decoder.Token()
			if err != nil {
				return invalidJSON()
			}
			key, isKey := keyToken.(string)
			if !isKey {
				return invalidJSON()
			}
			if _, duplicate := seen[key]; duplicate {
				return newInvariantError("json", "input contains duplicate object key: "+key)
			}
			seen[key] = struct{}{}
		}
		if err := requireUniqueKeys(decoder); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return invalidJSON()
	}
	return nil
}
