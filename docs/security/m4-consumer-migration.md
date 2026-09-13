# M4 consumer migration contract

This is the source and wire migration contract for the M4 candidate. It does not
authorize deployment or qualify a platform. Consult the
[support ledger](consumer-support.md) and [launch status](launch-status.md) for
the tested profile and evidence state.

## Manifest v2

`ToolDefinition.annotations.estimated_duration_ms` is no longer a public Rust
field. Manifest v2 already rejected that field in its authoritative schema.
Use the existing `latency_hint` field (`instant`, `fast`, `moderate`, or `slow`).
Do not emit both representations. Only the explicit, private v1 migration
parser accepts the old field and maps it into the v2 representation.

Migration is not signature preservation: a migrated manifest must be reviewed
and signed by the configured publisher before insertion into
`VerifiedManifestRegistry`. Discovery documents and unsigned tool descriptions
cannot replace that registry. Flow declarations remain constrained by the
host's tenant policy, data-owner policy and effective egress topology.

`NetworkDestination` keeps its public `u16` constructor/accessor contract but
stores a nonzero port internally. Deserializing port zero now fails, matching
the existing wire schema. Ports 1 and 65535 remain valid.

## Negotiated authorization

The default peer profile has no extended authorization features. For MCP, the
client offers a versioned profile in the initialization request's
`capabilities.experimental.chioAuthorization` field. The server validates the
offer and retains the intersection with its configured ceiling in session state.
The profile is not a field that a later tool-call request can upgrade.

`PeerCapabilities` has a new optional `authorization` field. Update explicit
Rust literals to `authorization: None` for legacy behavior, or use
`PeerCapabilities::default()` when constructing a baseline profile. Persisted
legacy sessions with no authorization profile retain that baseline on restore.
Malformed or unsupported retained profiles reject; recovery must not silently
replace them with a more permissive current configuration.

Other explicit Rust literals also change: `A2aEdgeConfig` and `AcpEdgeConfig`
carry `peer_capabilities`; `CrossProtocolTargetRequest` carries a borrowed host
profile; and the bridge MCP request carries both `peer_capabilities` and
`dpop_proof`. Use the baseline profile and `None` only when those semantics are
actually absent. Custom target executors must retain the supplied profile and
use the common bound kernel projection. These field additions are intentional
source changes, not a source-compatible migration for downstream literals.

A2A and ACP edges take the profile from trusted edge configuration, one profile
per authenticated peer. Native cross-protocol, Tower `KernelService`, and the
ordinary OpenAI wrapper use their host configuration/builder. Negotiation means
that a wire vocabulary can be carried. It does not install approval custody,
durable budgets, a DPoP verifier, flow control, or release/declassification owners.
The kernel still requires the actual participants for the selected profile.

Complete approval sets, proposals, governed intents, DPoP proofs and supplemental
authorization must reach the common request projection unchanged. Supplemental
authorization remains opaque to the adapter and is verified by its installed
owner. Do not convert it to a caller-provided quota claim.

The provider-fabric `ToolInvocation` envelope cannot carry a complete negotiated
proof set. That ordinary lowering rejects aggregate/cumulative extensions before
returning a kernel request. Use the supported native or mediated protocol
entrypoint for those profiles. Provider provenance is not authorization.

## Host profiles and early rejection

The ordinary remote-MCP and stdio factories reject flow-required manifests before
tool-launch preparation and store acquisition. The ordinary OpenAI constructor
also rejects flow-required unsigned manifests. The verified native/cross-protocol
host owns the supported flow profile; enabling a peer flag is not a substitute.

The separate Tower HTTP middleware's explicit fail-open configuration is
unenforced operation. It is not part of the qualified `KernelService` profile
and must not be selected as fallback after an enforced invocation is denied.
The Drogon middleware is unconditionally fail-closed; the obsolete
`SidecarFailureMode` example setting has been removed.

Raw process, network and tool-server connectors are trusted host effect ports,
not secure agent invocation APIs. Attach them to the kernel. Ordinary examples,
policy probes and benchmark harnesses do not acquire production custody or
confinement guarantees merely because their constructors compile.

## Pending approval and receipt projection

MCP tool results carry kernel receipt information under `_meta.chio`. Kernel
projection owns that namespace, even if a connector supplies a same-named value.
A genuine pending approval has `isError: false`, empty content, and
`structuredContent` containing `status: "pending_approval"` and the complete
signed `proposal`. It is neither successful execution nor a terminal failure.

A2A pending approval uses the nonterminal `working` state with proposal data;
ACP uses the shared pending-result representation. Adapters must not pick only
the first approval or discard the proposal during result translation.

The governed active-response schema uses `chio.response-plan.v1`, matching the
native domain. The obsolete `chio.governed-response-plan.v1` value is not an
alternate accepted domain. Regenerate clients from the current schema registry.

## Language parser boundaries

| Package | Current M4 contract | Not supplied by that contract |
| --- | --- | --- |
| Python `chio-sdk-python` | Generated security models reject extra fields and integer/boolean coercion; schema-nonnullable properties must be omitted instead of null | Signature verification, duplicate-key recovery from an already-parsed dictionary, native custody |
| TypeScript `@chio-protocol/node-http` | Public `createWireSchemaValidator` compiles host-selected schemas at setup and rejects unknown domains, coercion, unsafe integers, non-JSON values and excessive nesting; private conformance tests import the built package export | Raw JSON parsing, signature verification, native custody |
| Go `chio-go-http` | Public security-artifact `json.Unmarshal` retains opaque numbers as `json.Number`, rejects missing/unknown typed properties, duplicate raw keys, schema-forbidden nulls, typed integer overflow and bounded domain violations; updates the receiver only after success | Complete JSON Schema validation of every generated type or cryptographic verification |
| Rust | Native validated types, generated shape tests, authoritative schemas and registered-publisher verification are separate tested layers | A generated type alone is not a trusted publisher or native execution authority |

Go's raw security-artifact profile is bounded to one MiB and 64 nesting levels.
Typed integers retain the generated `int64` domain; narrower fields also enforce
their wire bounds. Opaque numbers are preserved, not rounded through `float64`.
TypeScript rejects integers outside JavaScript's safe-integer domain. Do not
coerce such a value into a supported profile, sign a rounded value, or mistake
parser acceptance for permission to execute.

Signed caller delivery reports require both `output` and `realized_cost`, even
when their values are null. The Python client accepts generated authorization and
report models and preserves these fields in HTTP serialization. Do not serialize
these reports with `exclude_none=True`. Caller integer fields are positive safe
integers; cost units may be zero. The Go authorization decoder also bounds raw
input to 32 KiB. The caller corpus checks wire shape and preservation, not the
authenticity of its illustrative signatures. M3's exact signed custody gate owns
that separate contract.

Legacy invariant packages (`chio-py`, `chio-ts`, and `chio-go`) retain their
explicit manifest-v1 helper contract. Their legacy vector tests are not evidence
of current manifest-v2 verification. Run both the legacy binding lane and the
current four-language consumer corpus when changing shared shapes.

## Caller and recovery ownership

M3's [authenticated caller contract](authenticated-caller-delivery.md) is
unchanged. Reservation is not execution permission. A trusted executor must
obtain authenticated start before effect and deliver the exact signed report.
Retry uses the durable executor ledger, original operation identity and original
execution interval. Uncertain effects are not replayed as fresh work.

Native release-owner and declassification custody remain required and supported
through the trusted Rust host. Python/TypeScript/Go transport helpers do not own
that custody. Request metadata cannot supply host identities, rebind a session,
select an executor pin or turn a historical receipt into current authority.

## Reproducible acceptance

Use `scripts/check-consumer-boundaries.sh` for the exact Rust consumer inventory,
`scripts/check-consumer-sdk-parity.sh` for the current public parser corpus, and
the existing M3, flow, binding and affected C++/FFI gates. Missing, renamed,
ignored, zero-match or skipped required cases are failures, not qualifications.
The Drogon acceptance gate requires its pinned dependencies, nonempty CTest runs
and a freshly built CLI. It does not use the example launcher's optional skip
path or an older default-target binary.

These changes do not complete M5 swarm confinement, M6 enterprise deployment,
M9 publication or M10 exact-candidate release qualification. M1's Linux x86_64
confinement deferral is unchanged.
