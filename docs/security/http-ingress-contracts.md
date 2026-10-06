# HTTP ingress and shared-reader contracts

The direct Serde decoder count is not the size of the remaining input-security
problem. `check-trust-boundaries.py` also inventories request extractors, transport
response decoders, non-JSON formats, original JSON readers and their resolved
free-function consumers. The approved observations remain in
`trust-boundary-inventory.json`; semantic request and format dispositions are in
`http-ingress-contracts.json`.

The current framework inventory records 107 request extractors: 104 JSON and
three form extractors. All 104 JSON extractors belong to the control plane: 97
on the trust-control router and seven on the separate FROST coordinator router.
Two API-protect manual-reader contracts are recorded separately and are excluded
from this extractor count. JSON response construction is excluded. Empty
`.json()` and `.into_json()` calls are transport response readers;
`.json(&request)` serialization is excluded.

## Control-plane request contract

The two production routers install `trust_control::json_ingress::validate`.
The trust-control router also installs the state-aware `json_ingress::authenticate`
layer outside byte validation, after its route registrations and merges, so
route-specific authentication runs before body reads. The separate FROST router
retains original-byte validation followed by typed extraction and its handler
credential checks. Body-bound FROST roster, lease, role and mutation-fence checks
remain in the control/store operations after extraction.

The explicit method and matched-path table covers every control-plane JSON
request extractor. The gate compares that table with actual router bindings and
checks byte-middleware installation, numeric mode and body limit. Reviewed builder
hashes pin route/layer ordering, merges and literal aliases within the reviewed
owner bodies. These are
source-review tripwires; the lexical check does not prove authentication or Rust
dataflow. A new route, changed method, moved layer, mode downgrade or changed bound
needs semantic review. Axum's framework-owned `NestedPath` removes outer mount
prefixes from `MatchedPath`, preserving the contract through nested and
parameterized routers.

For the trust-control contracts, service credentials, authority service/workload
or forwarded-peer credentials, admin/tenant read principals, cluster-peer
credentials and admin report authority use their existing validators before body
reads. Handlers retain their later checks and request-specific bindings. Public
finding search, the pre-authorized token exchange and public presentation
submission keep their protocol-specific contracts. The parser adds no service
bearer requirement to those three routes.

Wallet credential redemption checks the opaque token's current issued state,
offer/token expiry and normalized configured issuer against the verified registry
before body reads, without refreshing, consuming or saving it. After upload, the
handler reloads that registry and repeats the pure entitlement check before full
issuer metadata or signing seed/DB resolution. The redemption method retains its
later entitlement recheck and credential configuration, subject and format
bindings before signing, consumption and save.

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

Once a request reaches original-byte validation, malformed input returns HTTP
400; an oversized stream returns 413;
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

The inventory records two API-protect threshold-approval manual-reader contracts
separately in `manual_reader_closures`. Their router-level sidecar-control
credential gate runs before `read_body(request, input::decode)`, which bounds the
original body at 1 MiB and uses signed duplicate/numeric validation before
threshold collector mutation. Recorded owning tests include retained original
causes, redacted errors and honest signed proposal/approval admission; these
source records do not establish runtime or hosted acceptance in this control-plane
packet. Three form extractors use their existing URL-encoded and protocol-specific
validation: control-plane OID4VP and MCP OAuth approval/token exchange. They are
not counted as strict JSON readers.
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

The approved direct census records 258 files; the current source scan observes
266 and requires separate catalog reconciliation. The same 45
`raw-input-baseline` file identities and debt classifications remain unchanged.
These counts do not include all framework, format or
shared-reader risks, and this packet does not reduce or increase that debt
baseline. Expanded observations are additional scope, not evidence that every
observed boundary is qualified.
