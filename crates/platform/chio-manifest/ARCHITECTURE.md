# chio-manifest architecture

## Responsibility and boundary

`ToolManifest` describes a server and its tools. `SignedManifest` combines
that document, a signature, and a signer key. `sign_manifest`,
`verify_manifest`, and `validate_manifest` expose distinct signing,
authentication, and structural checks. Trusted server registration chooses
the known public key independently of the document.

`VerifiedManifestRegistry` owns verified entries, compiled input schemas,
topology, and `AdmittedToolSecurity`. `VerifiedCageManifest` is an opaque
registry-issued authorization binding an exact signed manifest and registry
digest for native cage compilation. This library does not install a sandbox
or dispatch tools.

## Structure

`lib.rs` defines verification and includes `lib_parts/part_01.inc`, which
contains manifest, permissions, normalized host/environment-name types,
provider-native tool classification, signing, and unit tests.
`validation.rs` checks identities, annotations, schemas, pricing, and
permissions. `input_schema.rs` compiles Draft 2020-12 schemas and owns the
pinned provider-native tool catalog. `admission.rs` handles registry
construction, flow policy, cage authorization, and existing-file loading.

## Data and control flow

Signing validates the manifest and key agreement before canonical signing.
Verification validates it, compares the envelope key with the registered
key, and verifies the signature. Registry admission then resolves a policy
and topology for each tool and compiles its argument validator. Invocation
argument validation uses those stored validators.

`register_public_only` supplies public clearances and one runtime topology
for all tools. General registration accepts separate tool maps. Native tool
allowlists and their trusted input schemas are admitted alongside ordinary
tools.

## Trust and invariants

Only v2 is supported. Optional manifest fields reject explicit null;
optional server-tool lists reject explicit empty arrays. Typed permission
values normalize hosts and constrain environment variables. Shape validation
checks duplicate tool names and permission entries. Schema compilation
blocks external retrieval and unsupported reference forms.

The existing-file loader checks regular-file metadata, limits the read to 1
MiB plus one detection byte, decodes original JSON through the strict
boundary, and verifies expected server ID and registered key. Unix opens use
no-follow protection. In-memory typed objects cannot reconstruct original
duplicate-field provenance. Operator flow policy and topology remain trusted
inputs.

## Dependencies

`chio-core` supplies manifest vocabulary, keys, canonical signing, and
hashes. `chio-security-types` supplies information labels. `chio-cage-plan`
supplies native syscall profiles. `jsonschema` compiles input contracts.
`url` and `libc` support host normalization and platform file-opening
checks.

## Verification

`tests/integration_smoke.rs` signs and verifies through public APIs.
`manifest_v2.rs` and its JSON-boundary cases check strict fields, admission,
topology, and original signed input. `input_schema.rs` covers local
references and external-reference rejection; `server_tools.rs` covers
native-tool classification and allowlisting. Run `cargo test -p
chio-manifest`. The README uses existing default dependencies and performs
only local signing and verification.
