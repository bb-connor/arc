//go:build tools

// Package tools pins the generator dependency graph without adding it to the SDK.
package tools

import _ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
