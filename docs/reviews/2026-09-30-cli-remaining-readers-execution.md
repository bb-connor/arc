# Remaining CLI reader execution

Source base: `da4086017f`, branch `packet/3-retention-accounting`, checkout
`/tmp/arc-security-launch`. This batch implements the 29-reader queue in the
[preceding handoff](artifacts/2026-09-30-cli-authority-proof-readers/next-readers.json).

## Delivered boundaries

- Finding, attestation and workflow: bounded original documents; explicit private
  signing custody; direct canonical private profile decoding and wiping fields;
  bounded HTTP success bodies and request deadlines. Publish acknowledgements
  bind both finding identity and original artifact digest. Current status floors
  require an operator key; the v1 converter and optional-key fallback are removed.
  Durable trusted time, retractions and epoch equivocation checks remain.
- Buyer, treaty and pheromone: bounded original documents and shared collection
  budgets, including repeated and failed reads. Portable member resolution rejects
  stable intermediate symlinks. Relay and transport seeds use canonical private
  wiping custody. Fallible relay time propagates to commands and transport
  callbacks; reloader clock failures disable admission.
- Assurance archives: compressed bytes have an actual-read bound; expanded bytes
  and members retain owner limits. Namespace validation rejects traversal,
  duplicate names, case collisions, implicit-directory amplification and
  file/directory conflicts before extraction effects. Existing packager/exporter
  verification and report commitments remain the authentication gates.
- MCP, runtime, lineage and market: original decoding precedes projections;
  JSON-RPC wrap/discovery checks message shape before dispatch or discovery
  acceptance. Signed cage policy, manifest admission and enforcing-host checks
  remain mandatory. Selected malformed lineage JSON rejects explicitly. Market
  catalogs reject duplicate references, and retained installation records must
  match the current schema, requested tenant and guard reference.

Limits are 16 MiB per general JSON document, 128 MiB per collection, 4,096 entries
and 64 path levels. Existing tighter finding/cage/transport limits remain.
Opaque supply-chain artifacts use a separate 512 MiB limit. Assurance archives
retain 64 MiB compressed, 256 MiB expanded, 32 MiB per member and 513 tar entries;
the shared namespace cap also counts implicit parent directories. These limits
bound input custody and do not authenticate content.

Private operator profile shapes remain current-schema documents. Internal
Deserialize custody types protect partial failures and transfer secret allocations
into wiping owners. Ordinary public trust profiles contain no private fields.
Initialization replay also uses private wiping custody and rejects exposed or
hard-linked secret files without repairing their mode. Public initialization
artifacts keep their own exact-content and public-mode contract. CLI runtime
credentials derived from these profiles remain their own owners.

## Qualification

The final iroh-enabled build and **266 focused tests pass** (247 CLI unit
controls, 18 integration tests and one private-profile custody test). Trust
inventory, file hygiene, clock, arithmetic, negative-assertion, wire-schema and
changed-file formatting checks pass. Qualification and source identities are recorded in the
[artifact index](artifacts/2026-09-30-cli-remaining-readers/README.md).
The [one independent review](artifacts/2026-09-30-cli-remaining-readers/review-resolutions.md)
identified failed-read budget accounting, profile custody, publish identity and
binary size contracts; each has an explicit resolution. Initial failed build,
fixture/expectation failures and ratchet diagnostics are retained.

The semantic decoder baseline falls from 223 to **194 workspace files**, with
**zero remaining CLI baseline files**. This disposes the lexical reader queue,
not all CLI security debt. The clock and arithmetic ratchets retain their own
configured scopes; 85 semantic arithmetic entries and broader roadmap work remain.

This batch is local. No push, merge, release or external activation occurred.
It does not requalify native host enforcement, cryptographic implementations,
optional TEE quote backends, or exact-candidate hosted/M5 acceptance. Hostile
concurrent replacement of ancestor directories still requires OS isolation.

## Next substantial chunk

Execute the [28 remaining protocol reader owners](artifacts/2026-09-30-cli-remaining-readers/next-readers.json):

1. Provider-adapter-core and egress HTTP: original-byte and response-size limits,
   redacted typed failures, transport deadlines and response identity.
2. Anthropic, Bedrock, Cohere, Gemini, Groq, Mistral and Ollama adapters: bound
   streaming assembly and nested tool arguments; reject ambiguous arguments before
   tool-call construction while retaining provider-specific usage and stop rules.
3. Provider recorder/replay/conformance and tool-call fabric: distinguish captured
   fixture data from authority, bound retained inputs, add owner negative controls
   and update semantic inventory with focused cross-provider qualification.

The larger queue remains other product/platform/trust/guard readers, arithmetic,
structural and declaration work, retention acceptance, sanitizer/formal
correspondence, supply-chain audits and exact-candidate hosted/M5 delivery.
