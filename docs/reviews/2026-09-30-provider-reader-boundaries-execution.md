# Provider reader boundary execution

Base: `82eec927b20ec4dae1fff2a4eb149fef4592c817`, branch
`packet/3-retention-accounting`, checkout `/tmp/arc-security-launch`.
Implements all 28 protocol reader owners pinned by the preceding CLI batch,
plus their shared helpers and direct consumers.

## Completed tasks

1. Shared HTTP/egress and SDK custody: actual response reads are bounded,
   redirects are denied by the shared provider transport, deadlines remain,
   and URL/header/network/SDK causes survive behind redacted public errors.
   Bedrock validates original response bytes before SDK deserialization.
   HTTP failure bodies are not retained. Credentials use sensitive headers;
   recorder curl argv custody is removed.
2. Provider and fabric input: original JSON, wrapped response bodies and nested
   tool-argument strings reject ambiguity before projection. Normalized arguments
   are bounded canonical objects. Fragmented calls retain identity; selected
   provider lifecycle and choice terminators are checked before evaluator calls.
   Every changed stream gate prepares all invocations before evaluating any. Provider
   sidecar admission and allow-without-redaction requirements remain in place.
3. Recorder/replay: bounded nofollow regular fixture files, strict NDJSON and
   typed projections, bounded concurrent subprocess pipe capture, deadlines and
   owned Unix process-group cleanup. Anthropic recording now reconstructs final
   streamed arguments instead of recording the empty start block. Capture and
   replay data grant no live authority.
4. One independent batch review resolved, focused qualification completed,
   semantic inventory and source/evidence hashes recorded, and local delivery
   retained on the existing branch.

The shared external-document ceiling is 16 MiB, nested/assembled tool arguments
are at most 1 MiB, and stream limits are 16,384 records and 1,024 tool calls.
Existing tighter provider frame and contract-egress limits remain. Native signed
receipt/capability numeric domains are not changed by this external-provider
I-JSON policy.

## Evidence and scope

**596 tests pass** across 12 affected packages with all eight provider fixture
features. Trust inventory, file hygiene, negative-assertion, wire-schema and
changed-file formatting checks pass. The [artifact record](artifacts/2026-09-30-provider-reader-boundaries/README.md)
contains commands, terminal results, failed attempts, source identities and
review resolutions. Tests are local, including actual loopback HTTP and the
native AWS SDK with an injected transport; they do not establish live-provider
or hosted qualification.

The decoder baseline falls from 194 to **166 workspace files**, with zero
protocol and CLI raw baseline files. This disposes that reader inventory,
not all security or interoperability work. Broader error taxonomy, 85 semantic
arithmetic entries, other readers, structural/declaration work, retention,
formal/runtime correspondence, supply-chain audits and exact-candidate hosted/M5
acceptance remain separate queues. No push, merge, publication or activation
occurred. The existing Cohere assembled-event and Gemini whole-call contracts
are preserved, and hostile process-group escape/ancestor mutation remain OS
isolation concerns rather than claims of this helper layer.

## Next substantial chunk

Execute the [35 remaining trust readers](artifacts/2026-09-30-provider-reader-boundaries/next-readers.json):

1. Attestation, credentials, buyer proofs and model cards: bound original imports,
   preserve exact signature/digest meaning and native numeric domains, and retain
   native verification/parser causes without exposing payloads.
2. Hardware/mobile custody, TEE frames, remote signing and federation ceremony:
   apply the same boundaries to external responses, proof packages and persisted
   challenge/state readers while preserving authentication and replay checks.
3. Pheromone relay/runtime, treaty and exchanged evidence: bound file/network
   custody, reject ambiguous persisted inputs, and add owner-specific controls
   plus evidence-backed inventory dispositions.

The next batch continues mechanisms B/C and the remaining-security-work reader
queue; it does not declare completion of cryptographic audits or operational gates.
