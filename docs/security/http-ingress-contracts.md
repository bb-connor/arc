# HTTP ingress and shared-reader contracts

The direct Serde decoder count is not the size of the remaining input-security
problem. `check-trust-boundaries.py` also inventories request extractors, transport
response decoders, non-JSON formats, original JSON readers and their resolved
free-function consumers. The approved observations remain in
`trust-boundary-inventory.json`; semantic request and format dispositions are in
`http-ingress-contracts.json`.

The CA3 source inventory has 106 JSON request extractors and three form request
extractors. Of these, 104 JSON extractors belong to the control plane: 97 on the
trust-control router and seven on the separate FROST coordinator router. JSON
response construction is excluded. Empty `.json()` and `.into_json()` calls are
transport response readers; `.json(&request)` serialization is excluded.

## Control-plane request contract

The two production routers install `trust_control::json_ingress::validate`.
Its explicit method and matched-path table covers every control-plane JSON
request extractor. The gate compares that table with actual router bindings and
checks the middleware installation, numeric mode and body limit. Reviewed builder
hashes also pin route/layer ordering, merges and literal route aliases. A new
route, changed method, moved layer, mode downgrade or changed bound needs review.
Axum's framework-owned `NestedPath` removes outer mount prefixes from
`MatchedPath`, preserving the contract through nested and parameterized routers.

The middleware collects bounded original bytes before the existing `Json<T>`
extractor can discard duplicate keys, ignored fields or numeric spelling. It
rejects invalid UTF-8, malformed JSON and duplicate keys at any nesting depth.
Signed and authoritative requests use `UntrustedJsonText::decode_signed`, which
preserves native integer widths and rejects lossy or noncanonical numeric
spellings. This includes unsigned wrappers around signed artifacts, such as
certification network publication, federation policy records and presentation
verification requests. It is not signature verification. Existing authentication,
signature, path-identity, policy, fencing and semantic checks still own admission.

Five unsigned document routes use `decode_document`: finding search, certification
consumption selection, evidence export selection, underwriting simulation and
bonded-execution simulation. Their ordinary Serde numeric conversions remain
valid; for example, an unsigned hypothetical underwriting policy can use `0.50`.
Duplicate keys still reject before typed projection. Simulation does not sign or
persist a decision. A signed verifier policy using a changed numeric spelling
such as `0.10` must pass the stricter signed-input contract instead.

| Request family | Maximum original body |
| --- | ---: |
| Authority key-log synchronization | 4 KiB |
| Evidence import | 64 MiB |
| Tool and child receipt append | 128 MiB |
| Other classified control-plane JSON requests | 1 MiB |

The standard 1 MiB limit already applied in `serve_async` server hygiene. The
middleware also applies it when the router is built directly. The existing
larger receipt/import route exceptions remain effective. Raw `Bytes` request
routes, including authentication-before-read admission and digest-addressed
finding inputs, retain their existing readers and limits.

Malformed original input returns HTTP 400; an oversized stream returns 413;
transport read failure returns 400. Typed shape errors remain Axum's 422, and
media-type rejection remains Axum's 415. JSON suffix media types remain supported.
The reader stops consuming an oversized stream before dispatching the handler.
Body and parser error sources are retained internally; public errors do not echo
untrusted parser or transport details.

## Evidence and remaining work

The actual production-router regression cases first establish honest signed
certification and verifier-policy writes. They then reject top-level and nested
duplicate keys, changed signed numeric spellings and invalid signatures while
checking retained registry bytes. Additional cases exercise a nested signed
certification wrapper, an unsigned decimal simulation, method selection, service
authentication, content types, malformed JSON, explicit body exceptions, stream
termination at the bound and transport failure. The nested network-publication
fixture has no configured peers; it qualifies input dispatch, not remote fan-out.
The shared validator and source bindings cover the other handlers; these cases do
not replace every handler's protocol and mutation tests or qualify hosted service
operation.

The inventory explicitly retains two API-protect threshold-approval JSON
extractors as remaining original-byte gaps. Three form extractors use their
existing URL-encoded and protocol-specific validation: control-plane OID4VP and
MCP OAuth approval/token exchange. They are not counted as strict JSON readers.
Transport response decoders and YAML/TOML/CBOR configuration or attestation inputs
have separate per-file semantics and remaining-risk records. None is promoted by
the control-plane middleware.

Shared-reader consumers remain visible when a parser is moved into a local helper,
another module or a re-exported cross-crate free function. Ordinary module and
reader-type import aliases are resolved, including cyclic glob imports and
same-named module/function reexports. Their call sites do not
prove caller provenance, authentication or complete Rust dataflow. The inventory
does not resolve dynamic dispatch, arbitrary macros, generated routes or every
associated-method alias. Those limitations remain review responsibilities.

The direct census remains 253 files, including 45 `raw-input-baseline` files.
Neither number includes all framework, format or shared-reader risks, and this
packet does not reduce or increase that debt baseline. Expanded observations are
additional scope, not evidence that every observed boundary is qualified.
