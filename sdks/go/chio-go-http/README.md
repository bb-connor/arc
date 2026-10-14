# chio-go-http

Go `net/http` middleware for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps any `http.Handler` with capability-based access control and
receipt-signed responses served by the Chio sidecar kernel.

## Overview

`chio-go-http` is the drop-in Go HTTP adapter for Chio. It is aimed at
service authors who already expose a `net/http` handler and want to gate
every request through a capability token plus a policy-evaluated
verdict, without rewriting their routing layer. The middleware is
fail-closed by default: if the sidecar is unreachable, requests are
denied, and allowed requests carry an `X-Chio-Receipt-Id` header pointing
at the signed receipt.

## Install

```bash
go get github.com/backbay-labs/chio/sdks/go/chio-go-http
```

Requires Go 1.21 or newer and a running Chio sidecar (defaults to
`http://127.0.0.1:9090`).

## Quickstart

```go
package main

import (
    "fmt"
    "net/http"

    chio "github.com/backbay-labs/chio/sdks/go/chio-go-http"
)

func handlePets(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, `{"pets":[]}`)
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/pets", handlePets)

    protected := chio.Protect(mux, chio.ConfigFile("chio.yaml"))
    http.ListenAndServe(":8080", protected)
}
```

Denied requests receive a structured JSON error; allowed requests flow
through to your inner handler with the receipt ID attached to the
response headers.

## Configuration

Options are passed via functional `chio.Option` values:

| Option                     | Purpose                                                             |
| -------------------------- | ------------------------------------------------------------------- |
| `ConfigFile(path)`         | Path to `chio.yaml` (routes and policies).                          |
| `WithSidecarURL(url)`      | Override sidecar base URL.                                          |
| `WithTimeout(seconds)`     | Sidecar HTTP timeout (default 5).                                   |
| `WithIdentityExtractor(f)` | Custom caller extraction; defaults to Bearer/API key/Cookie lookup. |
| `WithRouteResolver(f)`     | Map `(method, path)` to a route pattern (e.g. `/pets/{petId}`).     |

Environment variable `CHIO_SIDECAR_URL` is honoured when no explicit
sidecar URL is provided.

## Example

A slightly richer example using a custom route resolver and a shared
sidecar URL:

```go
resolver := func(method, path string) string {
    if strings.HasPrefix(path, "/pets/") {
        return "/pets/{petId}"
    }
    return path
}

protected := chio.Protect(
    mux,
    chio.ConfigFile("chio.yaml"),
    chio.WithSidecarURL("http://127.0.0.1:9090"),
    chio.WithRouteResolver(resolver),
)
```

For a full runnable flow, pair this package with the `examples/hello-tool`
tool server and drive traffic via the Chio CLI or any Chio client.

## Recovery wire contracts

`json.Unmarshal` uses closed, canonical decoders for these shared contracts:
`RecoveryActionIntent`, `RecoveryAuthorizationRequirements`,
`RecoveryGrantBinding`, `RecoveryApprovalIntent`, `RecoverySignedGrantV2`,
`RecoverySignedAuthorityCoverage`, `RecoverySignedProviderFinality`,
`RecoveryProviderFinality`, `RecoveryCommand`, `RecoverySupportIssueEffect`,
`RecoverySupportIssueInput`, `RecoveryCommandResponse`,
`RecoveryCommandResult`, and `RecoveryReviewDocument`.

These decoders reject duplicate and unknown properties, case variants,
explicit null for typed properties, invalid tagged branches, unsupported
versions, malformed identifiers and digests, and noncanonical number tokens.
Recovery intake permits unsigned integers through `2^53 - 1`, 64 KiB of wire
bytes, 32 KiB of aggregate encoded string content, nesting depth 16, 4,096
values and keys, and 256 entries per container. These foundation bounds apply
to status and the signed receipt. Within the receipt's arbitrary JSON
`metadata` and `action.parameters`, canonical I-JSON also permits negative
safe integers and finite fractions in their exact shortest RFC 8785 form.
Unsafe integers, non-finite values, precision-losing fractions and float
tokens that normalize to integers are refused. These numbers remain
`json.Number`; typed receipt and recovery counters keep the unsigned domain.
Historical actions may omit
`origin`; an explicitly null origin is refused. Native authorization still
requires a verified current origin, trusted keys and context binding.
Raw action `source_generation` and `isolation_epoch` retain the native
`SafeInteger` zero value as historical data. Fresh authorization remains a
native context decision; recovery grant bindings require a positive epoch.

Native protected text ceilings count UTF-8 bytes: issue titles permit 256,
issue bodies 16,384, sink resources 2,048, and command text and review previews
32,768. The enclosing aggregate encoded-string budget also applies.

`RecoveryCommandResult` uses a separate 256 KiB/depth-64 full response profile
for its opaque `original_response.result`. That tool JSON may contain negative
or fractional numbers, exponent tokens, integers above `2^53 - 1`, and larger
strings or containers. Every number is retained as `json.Number`, including
nested numbers, so decoding never converts tool data through `float64`.
Use `json.Number.String()` to retain the exact numeric lexeme. Converting it
to an application numeric type is an explicit consumer decision. Duplicate
keys, invalid UTF-8 and invalid JSON remain refused throughout the full response.
The foundation projection substitutes only the tool result with null before
checking the stricter status and receipt limits. Arbitrary receipt JSON keeps
the foundation allocation limits even though its numeric domain is broader
than recovery counters.

Successful decoding validates data representation. It does not verify any
signature, receipt identity, authority assignment, freshness, provider claim,
or permission to execute or release. The host performs those checks. Other
generated recovery declarations are informational structural types; direct
decoding of a nested generated union does not apply these enclosing-contract
checks. Preserve original canonical bytes when verifying signed artifacts;
Go's ordinary `json.Marshal` is not an RFC 8785 signer.

For exact whole-input canonical validation, invoke the enclosing type's
`UnmarshalJSON(wire)` method directly. The standard `json.Unmarshal` wrapper
consumes leading and trailing whitespace before calling that method.

## Regenerate Go types

Prepare the checksum-pinned generator cache once:

```bash
cd sdks/go/chio-go-http/scripts/tools
go mod download
```

From the workspace root, regeneration runs offline with the committed tools
module and a readonly module graph. Every schema reference must resolve to a
local file or an exact locally declared schema ID. A missing generator cache
or unresolved remote reference refuses generation.

```bash
bash sdks/go/chio-go-http/scripts/regen-types.sh
python3 -B sdks/go/chio-go-http/scripts/regen-types.test.py
```

Use `--output /absolute/path/types.go` to stage generated bytes for comparison.
The script completes generation, hardening and formatting in a temporary
directory before writing the chosen destination. The xtask check uses this
interface to preserve the maintained file throughout a drift check.

## Status

Version `0.1.0`, pre-1.0. Wire formats track the Chio `0.1.x` sidecar
contract. The API surface may evolve in minor versions before the `1.0`
stability freeze.
