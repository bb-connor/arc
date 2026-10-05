# Design: lift-bound adapter correlation (opaque adapter context, narrowed)

- Status: PROPOSED (revision 4, 2026-10-05, after Codex review on PR #1174; revision 3 re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:))
- Date: 2026-10-04
- Citations:
  - Unprefixed paths are `main` at `f5a9d2ab2`.
  - `M:` = `origin/integration/process-security-m4` at `19df31ad9`.
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac`.
  - `W:` = the uncommitted working tree of `arc-worktrees/recoverable-agent-runtime-20261002` (recovery P0-P5, built on #1160 checkpoint `f25cd61f4`). Its line refs reflect the working tree on 2026-10-04 and may drift.

  All are treated as shipped for this revision. The fabric contract is byte-identical on `main`, `M:`, `V:`, and `W:` except for the `bridge_security` field (section 5.1).
- Scope: the `chio-tool-call-fabric` lift/lower contract and its provider adapters. No kernel, receipt, or `ToolCallRequest` change.
- Owners: `chio-tool-call-fabric` (contract), `chio-anthropic-tools-adapter`, `chio-openai-adapter`, `chio-bedrock-converse-adapter`, `chio-gemini-tools-adapter`, `chio-ollama-tools-adapter` (implementers), `chio-provider-conformance` (evidence)
- Related: `spec/schemas/chio-wire/v1/provenance/README.md` (provenance stamp and verdict link), `2026-07-12-admission-operation-design.md` (request identity), `spec/errors/registry.yaml` (fabric error codes)
- Origin: lessons from the FTL (nuta/ftl) review
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-authority-faults-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`

## Revision 4 changes

- **The result is bound, not only the verdict.** `ToolResult` was unbound bytes, so a host could pass invocation and verdict B with result A, and every check passed. `lower_bound` now takes a `BoundToolResult` that carries the binding digest, and an `Allow` verdict carries `result_sha256`: the signed receipt's `content_hash` over the canonical output (M: `receipt_support/receipt_content.rs:8-16`). Lowering refuses any result whose bytes or binding do not match (rule 9).
- **The verdict binding comes from the signed receipt.** `verdict_result_from_response(invocation, response)` accepts the two values independently (M: `crates/kernel/chio-kernel/src/provider_verdict.rs:149-180`), so stamping the digest afterward in the bridge would vouch for a mis-paired response. A new kernel-side constructor, `bound_verdict_from_response`, first verifies the receipt's signature and checks that its signed request id, tool name, server and parameter hash match the invocation. Only then does it build the `VerdictResult` and the `BoundToolResult` (rule 10). The old function is deprecated.
- **Synthesized ids are unique across payloads.** `build_tool_call_request` copies `provenance.request_id` into `ToolCallRequest.request_id` (M: `provider_verdict.rs:107`; `main` `:55`), and durable admission retains that replay key for the namespace lifetime. An index restarting on every lift is therefore not enough. Rule 1 adds a per-payload `lift_id`, or a host-supplied conversation and turn, and section 11's open "host mapping" item is resolved.

## Revision 3 changes

- **Section 2.4 now depends on the profile.** Under recovery P4 durable knowledge (`ProcessRuntime::enable_durable_knowledge`, W:`crates/kernel/chio-process/src/knowledge.rs:22-32`), the raw `checkpoint`, `put_blob`, `read_blob`, and `storage` routes refuse, and public snapshots redact the checkpoint value. In that profile, the sanctioned adapter state home is the labeled checkpoint with `ModelContextV1` (new section 2.4.1). Its provider, account, conversation, cache, and side-file binding is the provider-correlation record. The cookie rejection gets stronger again.
- **Lowering into a model is a release under P4.** A model context is a release sink (`ArtifactSinkV1::Model`). Under enforced knowledge, the lowered `ProviderResponse` reaches the provider only through a knowledge-joined release (new rule 8). `InvocationBinding` gains the selected model-context identity, so a verdict cannot be lowered into another conversation (section 5.1).
- **Semantic connectors are out of scope** (section 3, non-goals). They are effect-side `ToolServerConnection`s with no fabric dependency. P3 refuses the model-output channel, so a fabric bridge in a P3 deployment must be inventoried as a channel.

## Revision 2 changes

- **The rejection gets stronger.** Agent processes give adapter state a home outside the kernel: per-process checkpoints, blobs, operation keys, and a caller capability digest (new section 2.4). The kernel-carried cookie is still rejected, now with one more reason.
- **The fabric gap is unchanged on the shipped baseline.** `ProviderAdapter::lower(verdict, result)` still has no correlation input (`M:crates/protocol/chio-tool-call-fabric/src/adapter.rs:37-38`), and `VerdictResult` still cannot name an invocation (`M:.../types.rs:276`). Sections 5 to 10 stand.
- **Gemini citation moved.** The colliding id is now minted at `M:`/`V:crates/protocol/chio-gemini-tools-adapter/src/adapter.rs:263`.
- **`bridge_security` has shipped** (`M:`/`V:.../types.rs:75`). The digest covers it unconditionally.
- **The digest covers the D1 permit** when the delegated-work layout is installed (section 5.1).
- **New `lower_bound` consumers.** Process-hosted provider bridges are named as consumers, and the LangGraph work node is cited as precedent for the changed-body conflict rule.
- **The unrelated D9 finding is resolved on the baseline.** Section 11 is updated.

## 1. Decision summary

The FTL idea was: the kernel stores an opaque per-thread cookie it never interprets and hands it back on every upcall, so the personality finds its state with no lookup. The proposed Chio analog was a size-bounded opaque adapter context that the kernel round-trips per session or per request, so protocol edges can be stateless.

**This design rejects the kernel-carried cookie.** Chio's edges embed the kernel in-process, the kernel keeps its own session map, hosted MCP already persists integrity-tagged session state, and caller-supplied correlation already exists (section 2). A blob that passes through the kernel would not make any deployment stateless. It would add a covert channel and give receipt pollution a new place to happen, right next to an existing opaque field that *is* authorization-bearing (`OpaqueSupplementalAuthorization`).

**The real residual gap is narrower, and it is in the provider fabric, not the kernel.** `ProviderAdapter::lower(verdict, result)` has no correlation input. Each adapter recovers "which tool call is this?" in its own ad hoc way:
- by parsing the provider call id out of the `ToolResult` bytes, which are documented as canonical tool output for auditors;
- from a separate string argument;
- by structural pairing in the stream gate.

Nothing checks that the `VerdictResult` being lowered was rendered for that call. A host that mis-pairs verdicts applies one call's redaction set to another call's output. Separately, the Gemini adapter mints non-unique request ids for repeated calls to the same function in one turn.

The FTL lesson applies here in its accurate form:
- The correlation material the adapter minted at lift time (the `ProvenanceStamp` inside `ToolInvocation`) comes back to the adapter at lower time as a first-class argument.
- The verdict names the invocation it was rendered for, by digest.
- `lower` refuses a mismatch (fail closed).

No new opaque bytes field is added. A genuinely opaque `AdapterContext` is deferred until an adapter needs state that `ToolInvocation` cannot carry, and section 6 fixes its constraints in advance.

## 2. Verified current state

### 2.1 Where adapter state lives today

- **The MCP edge owns its kernel in-process.** `ChioMcpEdge` holds `kernel: ChioKernel` plus deferred tasks in a `BTreeMap` (`crates/protocol/chio-mcp-edge/src/runtime.rs:133-153`), bounded by `MAX_DEFERRED_MCP_TASKS` (`runtime.rs:100`).
- **The A2A and ACP edges are in-process too.** They keep deferred tasks in in-process maps (`crates/protocol/chio-a2a-edge/src/edge.rs:15-24`, `crates/protocol/chio-acp-edge/src/edge.rs:17-23`) and take `kernel: &ChioKernel` on every call (for example `chio-a2a-edge/src/edge.rs:368`, `chio-acp-edge/src/edge.rs:237`).
- **The kernel itself is stateful per session.** It keeps sessions in a `DashMap<SessionId, Arc<Session>>` and fails `UnknownSession` without one (`crates/kernel/chio-kernel/src/request_matching.rs:12-20`).
- **Hosted remote MCP already persists durable session state.**
  - Active and terminal records live in `RemoteSessionLedger` (`crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs:255-260`).
  - Resumable records carry a `resume_integrity_tag` (`session_core.rs:230-246`). The tag is a keyed SHA-256 over a canonical envelope (`remote_mcp/session_resume.rs:213-238`) and is validated fail-closed (`session_resume.rs:240-264`).
  - Records persist to SQLite (`remote_mcp/session_store.rs:22`, `session_store.rs:202`).

**Conclusion:** no deployed Chio surface has a stateless adapter talking to a remote kernel across a boundary a cookie could usefully cross. Where durability matters (hosted MCP), it already exists server-side with integrity.

### 2.2 Correlation that already exists

- `OperationContext` carries `session_id`, `request_id`, `agent_id`, `parent_request_id`, and `progress_token` on every normalized operation (`crates/core/chio-core-types/src/session/operation.rs:73-83`). `ProgressToken` is an untagged string-or-integer correlation token (`session/identifiers.rs:86-91`).
- The MCP edge accepts a caller-supplied stable request id in `_meta.chioRequestId`, capped at 2048 bytes and identifier-validated (`crates/protocol/chio-mcp-edge/src/runtime/protocol/parsing.rs:153-189`).
- Every fabric `ToolInvocation` carries a `ProvenanceStamp` with the provider's `request_id` (`crates/protocol/chio-tool-call-fabric/src/types.rs:58-74`).
- `ToolCallRequest` already has an opaque field, `supplemental_authorization` (`crates/kernel/chio-kernel/src/runtime.rs:85-89`), whose type is documented as an authenticated extension adapters must never interpret (`crates/core/chio-core-types/src/capability/supplemental_authorization.rs:5-13`). A second, non-authorizing opaque field beside it invites confusion between the two.

### 2.3 The fabric lift/lower gap

- **The trait has no correlation input.** It is `lift(raw) -> ToolInvocation` and `lower(verdict, result) -> ProviderResponse` (`crates/protocol/chio-tool-call-fabric/src/adapter.rs:34-43`).
- **`ToolResult` is meant to be tool output only.** It is documented as "canonical-JSON tool output bytes ... so downstream auditors see byte-identical material" (`adapter.rs:18-23`).
- **`VerdictResult` cannot name an invocation.** It carries only `redactions`/`reason` and `receipt_id` (`types.rs:242-251`).
- **The three `ProviderAdapter` implementations require correlation smuggled inside `ToolResult`:**
  - Anthropic requires `tool_use_id` in the result JSON (`crates/protocol/chio-anthropic-tools-adapter/src/adapter.rs:289-316`).
  - OpenAI requires `call_id` or `tool_call_id` (`crates/protocol/chio-openai-adapter/src/adapter.rs:291-300`).
  - Bedrock requires `toolUseId` (`crates/protocol/chio-bedrock-converse-adapter/src/adapter.rs:176-195`).
- **Inherent lowering methods take correlation as a free string instead:**
  - `lower_tool_result_block(tool_use_id, ..)` (`chio-anthropic-tools-adapter/src/adapter.rs:98-103`);
  - `lower_tool_message(tool_name, ..)` (`crates/protocol/chio-ollama-tools-adapter/src/lib.rs:226-240`);
  - `lower_function_response(function_name, ..)` (`crates/protocol/chio-gemini-tools-adapter/src/lib.rs:219-232`).
- **Stream gating pairs structurally,** by handing the verdict closure the `&ToolInvocation` (`chio-ollama-tools-adapter/src/lib.rs:162-168`, `chio-gemini-tools-adapter/src/lib.rs:163`).
- **The conformance replay harness pairs verdicts to results by searching captured verdicts by invocation id** (`crates/protocol/chio-provider-conformance/src/replay/assert.rs:75-87`, used at `assert.rs:126`). There is no in-repo production caller of `ProviderAdapter::lower`; hosts do the pairing.
- **Request-id minting is inconsistent:**
  - Anthropic, OpenAI, and Bedrock use the provider's call id (`chio-anthropic-tools-adapter/src/adapter.rs:85`, `chio-openai-adapter/src/adapter.rs:172`, `chio-bedrock-converse-adapter/src/adapter.rs:162`).
  - Ollama synthesizes an index-qualified id (`chio-ollama-tools-adapter/src/lib.rs:215`, `lib.rs:306-308`).
  - Gemini mints `gemini_{name}_call` (`chio-gemini-tools-adapter/src/lib.rs:207`; on the shipped baseline `M:`/`V:crates/protocol/chio-gemini-tools-adapter/src/adapter.rs:263`), which collides for two calls to the same function in one turn.
  - `validate_identity_field` checks emptiness, whitespace, and control characters but not length (`types.rs:171-194`).

### 2.4 Adapter state homes on the shipped baseline

Agent processes (`M:crates/kernel/chio-process`) give adapter and framework state sanctioned homes. None of them passes through the kernel. The list below holds for processes **without** enforced durable knowledge. Section 2.4.1 covers the enforced profile.

- **Per-process checkpoints.** Up to 1 MiB of JSON with compare-and-swap revisions, plus immutable blobs (1 MiB each, quota shared by the root tree). Both are scoped by the worker credential, not by a caller-selected id (`M:crates/kernel/chio-process/README.md:33-35`; `M:.../WORKER_PROTOCOL.md:154-158`).
- **Correlation.** Request ids derive deterministically from (runtime namespace, process id, operation key), and a changed request under the same key is a conflict (`M:.../README.md:31-32`).
- **Kernel-to-tool context.** Context is carried as identity digests, not opaque bytes. Durable stdio dispatch forwards `_meta.chioCallerCapabilitySha256`, which is not a credential (`M:docs/architecture/ADAPTIVE_PROCESSES.md:20`).
- **Process-hosted bridges.** Provider bridges hosted in processes, such as the mini-SWE adapter and the AI SDK bridge, save provider decisions in checkpoints before releasing commands (`M:docs/architecture/AGENT_PROCESS_DIRECTION.md:75-78`). They are `lower_bound` consumers (section 5).

A kernel cookie would duplicate the checkpoint for the process surface and the correlation ids for every surface.

#### 2.4.1 Under enforced durable knowledge (recovery P4)

- **The switch.** `ProcessRuntime::enable_durable_knowledge` requires a security profile and activates the knowledge journal (W:`crates/kernel/chio-process/src/knowledge.rs:22-32`).
- **Raw routes refuse.** After activation, `put_blob`, `read_blob`, `storage`, and `checkpoint` refuse through `require_raw_knowledge` (W:`crates/kernel/chio-process/src/lib.rs:254-288`, `:572-587`). Public process snapshots redact the checkpoint value (W:`crates/kernel/chio-process/src/store/knowledge.rs:64-70`).
- **The sanctioned home.** It is `NativeKnowledgeRuntime::checkpoint(.., artifacts, models: &[ModelContextV1])` and `restore_into(.., sink)` (W:`crates/platform/chio-control-plane/src/knowledge/checkpoints.rs:3-26`, `:31`).
  - `ModelContextV1` binds the context id, provider, provider account, conversation, cache, side files, and deployment contract (W:`crates/security/chio-security-types/src/knowledge/release.rs:8-16`).
  - Restore joins stronger current knowledge before any frame is delivered.
  - Rotation of provider, account, conversation, cache, or side files refuses the old restore authority (W:`docs/architecture/recoverable-agent-runtime/implementation/p4/OPERATIONS.md:115-123`).
- **A model is a sink.** `ArtifactSinkV1::Model { context }` makes a model context a release sink (W:`release.rs:18-24`). "A receiving process/model context is a sink even when physically local. Provider requests are egress to the configured provider tenant/account" (W:`docs/architecture/recoverable-agent-runtime/06-artifacts-memory.md:33`). Outbound provider prompts "still need the independently selected native effect contract" (W:`.../p4/OPERATIONS.md:121-123`).

In the enforced profile, the labeled model context is the sanctioned provider-correlation record: it identifies exactly which conversation a lowered response belongs to. A kernel cookie would duplicate it, and unlike `ModelContextV1` it would carry no label and no rotation rule.

### 2.5 Logging

`chio-log-redact` redacts by pattern class through `redacted!` and `RedactionLayer` (`crates/observability/chio-log-redact/src/lib.rs:1-6`, `engine.rs:26-56`). An opaque base64 blob matches no pattern class, so any opaque context would rely on never being logged rather than on redaction.

## 3. Goals and non-goals

### Goals

- Give every adapter one correlation contract: `lower` receives the `ToolInvocation` it lifted.
- Make verdict-to-invocation mis-pairing detectable and fail-closed at the adapter.
- Restore `ToolResult` to tool output only.
- Make `provenance.request_id` unique across every lifted payload in the host's request namespace, for every adapter.
- Bind the tool result and the kernel response to the invocation from trusted sources (the verified receipt, or the executor's stamp), never from parsing tool output.

### Non-goals

- A kernel-carried or session-carried opaque cookie (section 4).
- Verdict authenticity against a hostile host. `VerdictResult` is unsigned. Its binding inputs come from the receipt the kernel shim verifies (rule 10), so mis-pairing is detected. A malicious host that forges the `VerdictResult` object itself is out of scope (section 11).
- Changing `ToolCallRequest`, `OperationContext`, receipts, or `request_binding_hash`.
- Changing hosted MCP session persistence.
- **Semantic connectors.**
  - `PinnedSemanticConnector` is an effect-side `ToolServerConnection` (W:`crates/platform/chio-control-plane/src/semantic/connector.rs:183`) with no dependency on `chio-tool-call-fabric`. The fabric is model-side.
  - In a P3 semantic deployment, every package inventories all 13 channels, and the model-output channel refuses (W:`docs/architecture/recoverable-agent-runtime/implementation/p3/OPERATIONS.md:125-129`). A fabric bridge deployed there must therefore be inventoried as a channel. This spec does not enable it.
- Defining knowledge labels or release semantics. Those are recovery P4's; rule 8 only requires the fabric to respect them.

## 4. Rejected: kernel-carried opaque adapter context

The questions the original idea raised, with the answers that led to rejection:

1. **Per-session or per-request.** Per-session state already lives in-process (`ChioMcpEdge`) or durably in `RemoteSessionLedger`. Per-request correlation already exists (`OperationContext`, `_meta.chioRequestId`, `ProvenanceStamp`). A kernel cookie would duplicate one of these at either granularity.
2. **Authorization binding.** If the cookie were bound into `request_binding_hash`, an adapter-chosen value would change operation identity. That breaks the admission-operation rule that the binding covers only immutable normalized fields that can change the operation (`2026-07-12-admission-operation-design.md`, "Identity and retention"). If unbound, the kernel carries bytes it cannot use, which is the FTL design minus FTL's reason for it (the kernel is the only party between the trap and the personality; in Chio the host sits in that position).
3. **Receipts and logs.** Recording the cookie in clear would leak adapter internals into signed, exported, long-retained artifacts. Recording only a digest adds a field with no verifier.
4. **Abuse.** A kernel-relayed blob is a covert channel between whatever writes it and whatever reads it, including across tenants when kernels are shared. A captured blob can be replayed into another session unless every adapter implements binding correctly, and that is exactly the class of per-adapter discipline this design removes.

Conclusion: no kernel or `ToolCallRequest` change.

## 5. Design: lift-bound lowering

### 5.1 Types

```rust
// chio-tool-call-fabric

/// Lowercase hex SHA-256 binding a verdict to the invocation it was rendered for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationDigest(String);

impl ToolInvocation {
    /// Fails closed if `validate()` fails.
    pub fn invocation_digest(&self) -> Result<InvocationDigest, ToolInvocationValidationError>;
}

pub enum VerdictResult {
    Allow {
        redactions: Vec<Redaction>,
        receipt_id: ReceiptId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invocation_digest: Option<InvocationDigest>,
        /// The signed receipt's `content_hash` over the canonical output, when the kernel observed it (rule 10).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result_sha256: Option<String>,
    },
    Deny {
        reason: DenyReason,
        receipt_id: ReceiptId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invocation_digest: Option<InvocationDigest>,
    },
}

/// Tool output plus the binding of the invocation that produced it. The binding is
/// stamped by whoever produced the bytes from that invocation (rule 9), never parsed
/// from the bytes.
pub struct BoundToolResult {
    pub result: ToolResult,
    pub binding_digest: InvocationDigest,
}

/// Host-owned lift context for retry-stable synthesized ids (rule 1). Never read from the payload.
pub struct LiftContext {
    pub conversation_id: String, // identifier-validated, at most 256 bytes
    pub turn_index: u64,
}

pub enum ProviderError {
    // existing variants unchanged
    /// The verdict does not name the invocation being lowered; fail-closed.
    VerdictBindingMismatch { expected: String, observed: Option<String> },
    /// The result's bytes or binding do not match the invocation and verdict; fail-closed.
    ResultBindingMismatch { check: ResultBindingCheck },
}

pub enum ResultBindingCheck { BindingDigest, ContentSha256, DenyCarriesOutput }

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> ProviderId;
    fn api_version(&self) -> &str;
    async fn lift(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError>;
    /// Batch lift; ids are unique across payloads in the namespace (rule 1).
    async fn lift_batch(
        &self,
        raw: ProviderRequest,
        context: Option<&LiftContext>,
    ) -> Result<Vec<ToolInvocation>, ProviderError>;
    async fn lower_bound(
        &self,
        binding: InvocationBinding<'_>, // invocation plus optional permit and model-context digests
        verdict: VerdictResult,
        result: BoundToolResult,
    ) -> Result<ProviderResponse, ProviderError>;
    #[deprecated(note = "use lower_bound; correlation from ToolResult bytes is removed in the next minor")]
    async fn lower(&self, verdict: VerdictResult, result: ToolResult)
        -> Result<ProviderResponse, ProviderError>;
}

// chio-kernel::provider_verdict (the shim already depends on the fabric)

/// Replaces `verdict_result_from_response`, which is deprecated (rule 10).
pub fn bound_verdict_from_response(
    binding: &InvocationBinding<'_>,
    response: &ToolCallResponse,
    trusted_kernel_keys: &[PublicKey],
) -> Result<BoundKernelOutcome, ProviderVerdictError>;

pub struct BoundKernelOutcome {
    pub verdict: VerdictResult,           // invocation_digest and result_sha256 set
    pub result: Option<BoundToolResult>,  // Some for a kernel-observed value output
}

pub enum ProviderVerdictError {
    // existing variants unchanged
    ResponseBindingMismatch { check: ResponseBindingCheck },
}

pub enum ResponseBindingCheck {
    ReceiptSignature, KernelKey, RequestId, ToolName, ToolServer, ParameterHash, ContentHash,
}
```

The digest is computed over the stamp and the already-canonical argument bytes, without re-serializing `arguments` (`types.rs:69-72`):

```text
invocation_digest = hex(SHA256(
  "chio.tool-invocation.v1\0"
  || canonical_json({ provider, tool_name, provenance, bridge_security? })
  || "\0"
  || SHA256(arguments)
))
```

`provenance.received_at` is included, so two lifts of the same provider payload yield different digests. Replay tooling stores the lifted invocation, so it can recompute the digest.

The digest covers every field of `ToolInvocation` except `arguments`, which enters through its own hash. On the shipped baseline that includes `bridge_security: Option<chio_manifest::BridgeSecurityMetadata>` (`M:`/`V:crates/protocol/chio-tool-call-fabric/src/types.rs:75`), which joins the canonical object when present. Two invocations that differ only in admitted bridge metadata must not share a digest. Any later field added to `ToolInvocation` follows the same rule, and a unit test enumerates the struct's fields so that adding one without updating the digest fails the build.

When the delegated-work layout is installed, the sealed D1 permit travels in the governed intent at `governed_intent.context.chioDelegation` (`V:docs/superpowers/specs/2026-10-02-evolving-funded-work-design.md:22`), not in `ToolInvocation`. The verdict binding therefore extends to optional digests that live outside the invocation. Revision 2 defined a permit-only `binding.v1` form, which revision 3 replaces with the `binding.v2` form below, before any implementation.

`lower_bound` takes `InvocationBinding { invocation: &ToolInvocation, delegation_permit_sha256: Option<String>, model_context_sha256: Option<String> }` in place of the bare invocation. The host that submitted the governed request supplies the permit digest. Under enforced knowledge it also supplies the canonical digest of the selected `ModelContextV1` (section 2.4.1). `VerdictResult.invocation_digest` carries `binding_digest`, extended so that each present optional digest is appended in field order under the same domain separator:

```text
binding_digest = hex(SHA256("chio.tool-invocation-binding.v2\0"
                  || invocation_digest
                  || "\0" || (permit_sha256 or "")
                  || "\0" || (model_context_sha256 or "")))   (either optional digest present)
```

When both optional digests are absent, `binding_digest = invocation_digest`, so revision 2 verdicts remain valid. A verdict for one sealed selection then cannot be lowered onto another call with the same tool and arguments under a different permit, and a verdict for one conversation cannot be lowered into another. The work developer surface already enforces the matching rule one layer up: a changed body under a persisted identity conflicts (`V:docs/superpowers/specs/2026-10-03-work-developer-surface-design.md:65`).

### 5.2 Normative rules

1. **Unique ids.** `lift` and `lift_batch` MUST mint `provenance.request_id` values that are unique across every lifted payload in the host's request namespace, not only within one payload.
   - **Why per-namespace.** `build_tool_call_request` copies `provenance.request_id` into `ToolCallRequest.request_id` (M: `crates/kernel/chio-kernel/src/provider_verdict.rs:107`; `main` `:55`). Durable admission retains `(request_namespace_digest, request_id)` for the namespace lifetime (`2026-07-12-admission-operation-design.md`, "Identity and retention"). An id reused by a later payload either replays the earlier terminal result, when the binding matches, or conflicts.
   - **Provider ids.** When the provider supplies a call id, adapters use it.
   - **Synthesized ids.** When it does not (Ollama, Gemini), adapters mint `{provider}_{name}_call_{lift_id}_{index}`. `index` is the call's position in the payload. `lift_id` is 32 lowercase hex characters, unique per lifted payload:
     - by default, 128 bits drawn from a CSPRNG at lift time;
     - when the host passes a `LiftContext`, `lift_id = hex(SHA256("chio.lift-id.v1\0" || conversation_id || "\0" || turn_index))[..32]`. Re-lifting the same turn then yields the same ids, so a retried turn replays its bound terminal result, and different turns never collide. The context is host-owned and never read from the payload.
   - Gemini changes from `gemini_{name}_call` (M:/V: `adapter.rs:263`), and Ollama from `{provider}_{name}_call_{index}` (`chio-ollama-tools-adapter/src/lib.rs:306-308`), to this form.
   - `request_id` is capped at 2048 bytes, matching `_meta.chioRequestId` (`parsing.rs:157`), and the cap is added to `validate_identity_field`. A tool name long enough to push the id over the cap fails the lift with `InvalidIdentity`.
2. **No correlation from tool output.** `lower_bound` MUST take correlation (provider call id, function or tool name, batch index) only from `invocation`. It MUST NOT read correlation keys from `ToolResult` bytes. `ToolResult` is tool output only, restoring `adapter.rs:18-23`.
3. **Digest required.** `lower_bound` MUST recompute the binding digest from its `InvocationBinding` (section 5.1: the invocation digest alone, or the `binding.v2` digest when a delegation permit digest or model-context digest is present) and compare it with the verdict's `invocation_digest`. A missing or different digest returns `VerdictBindingMismatch`, and nothing is lowered. The result is checked against the same digest (rule 9).
4. **Provider and version match.** `lower_bound` MUST check `invocation.provider == self.provider()` and that `invocation.provenance.api_version` equals the adapter's configured version (extending the existing `ensure_supported_api_version` checks).
5. **Who sets the digest.** A kernel decision becomes a `VerdictResult` only through `bound_verdict_from_response` (rule 10), which derives the binding from the verified receipt before it stamps `invocation_digest`. A host bridge never stamps a digest onto a verdict it built itself. The stream gate in `chio-tool-call-fabric/src/stream.rs` calls the same constructor with the `&ToolInvocation` it holds. The replay harness calls it with the recorded receipt and the stored invocation.
6. **Same rules for inherent methods.** Inherent lowering methods that take a free correlation string (`lower_tool_result_block`, `lower_tool_message`, `lower_function_response`) gain `_bound` variants taking `&ToolInvocation`. The string forms are deprecated on the same schedule as `lower`.
7. **Kernel unaffected.** No adapter correlation material is added to `ToolCallRequest`, receipts, or logs. `invocation_digest` is a fabric-local value. It is not a receipt field and plays no part in authorization.
8. **Lowering under enforced knowledge is a release.** When a process-hosted bridge runs with durable knowledge enforced (section 2.4.1), `lower_bound` produces a `ProviderResponse` but does not deliver it.
   - The host delivers it to the provider only through a knowledge-joined release to `ArtifactSinkV1::Model { context }`, whose context digest equals the binding's `model_context_sha256`.
   - A host that has no committed release intent for that context MUST NOT send the lowered bytes.
   - A missing `model_context_sha256` in an enforced deployment is `VerdictBindingMismatch`.
   - The fabric does not compute labels or joins. It refuses to lower without the identity the release needs.
9. **The result is bound.** `lower_bound` MUST check its `BoundToolResult` before lowering, and correlation never comes from the bytes (rule 2):
   - `result.binding_digest` equals the recomputed binding digest;
   - for `Allow` with `result_sha256 = Some(h)`, `SHA256(result.result.0) == h`;
   - for `Allow` with `result_sha256 = None`, the kernel did not observe the output (the receipt's content is the null digest, for example a caller-executed tool). The executor that ran the invocation stamps `binding_digest` from the `ToolInvocation` it executed, at execution time;
   - for `Deny`, `result.result.0` MUST be empty. A deny is lowered from its `reason` alone.

   Any mismatch returns `ResultBindingMismatch`, and nothing is lowered. Passing invocation and verdict B with result A therefore fails: A's binding digest differs, and A's bytes do not hash to B's signed `content_hash`.
10. **The kernel response is bound before the verdict exists.** `bound_verdict_from_response` checks in this order, and constructs nothing until every check passes:
    1. `response.receipt` verifies, and its `kernel_key` is in `trusted_kernel_keys`.
    2. The receipt's signed `metadata.receipt_context.request_id` (M: `kernel/responses/receipt_persistence.rs:138-145`) and `response.request_id` both equal `binding.invocation.provenance.request_id`.
    3. The signed `tool_name` equals the invocation's, and the signed `tool_server` equals the server admitted by `invocation.bridge_security` (the value `build_tool_call_request` checked).
    4. The signed `action.parameter_hash` equals the hash of the canonical arguments, decoded exactly as `build_tool_call_request` decodes `invocation.arguments`.
    5. For an `Allow` with a value output, `SHA256(canonical_json(output))` equals the signed `content_hash` (M: `receipt_support/receipt_content.rs:8-16`). The shim builds the `ToolResult` from those bytes, wraps it in a `BoundToolResult` carrying the binding digest, and sets `result_sha256`. For a streamed output, the shim recomputes the stream digest with the receipt's own function (`receipt_content.rs:29`), and the stream gate emits the final frame only on a match.

    Any failure returns `ResponseBindingMismatch`. If concurrent response B is paired with invocation A, check 2 or 4 fails, and no verdict carrying A's digest is ever produced. `verdict_result_from_response` is deprecated on the schedule of `lower`.

### 5.3 Safety predicates

```text
lowered(response, binding, verdict) ->
  verdict.invocation_digest == binding_digest(binding)
  and binding.invocation.provider == adapter.provider

enforced_knowledge(deployment) and delivered(response, provider) ->
  committed_release(Model { context }) and digest(context) == binding.model_context_sha256

redactions_applied(response) == verdict(invocation).redactions
  (never the redaction set of a different invocation)

for any lift batch B: |{ i.provenance.request_id : i in B }| == |B|

correlation(response) is a function of invocation only,
  never of ToolResult bytes

lowered(response, binding, verdict, result) ->
  result.binding_digest == binding_digest(binding)
  and (verdict = Allow { result_sha256: Some(h) } -> sha256(result.bytes) == h)
  and (verdict = Deny -> result.bytes is empty)

constructed(verdict, binding, kernel_response r) ->
  verified(r.receipt) and r.receipt.kernel_key in trusted_kernel_keys
  and r.receipt.request_id == binding.invocation.provenance.request_id
  and r.receipt.tool_name == binding.invocation.tool_name
  and r.receipt.action.parameter_hash == sha256(canonical(binding.invocation.arguments))

for lifts L1 != L2 in one namespace (not one LiftContext turn):
  ids(L1) and ids(L2) are disjoint
```

## 6. Deferred: opaque `AdapterContext` bytes

Today `ToolInvocation` carries all the correlation every adapter needs: the provider call id or synthesized id, plus the tool or function name. If an adapter later demonstrates a need for adapter-private state it cannot place there (for example a provider message cursor for multi-part streaming), an `AdapterContext` may be added to the lift output, subject to these constraints, fixed in advance:

1. **Per-invocation only.** It is returned beside the `ToolInvocation` and never per-session.
2. **Size.** At most 1024 bytes after encoding; larger contexts fail the lift.
3. **Integrity.** The adapter MACs it with HMAC-SHA256 under an adapter-local key derived by labeled HKDF (not a raw signing seed), and binds the MAC to the invocation digest. This prevents replay into another invocation or session. MAC failure at lower returns `VerdictBindingMismatch`.
4. **Never leaves the host.** It never enters `ToolCallRequest`, receipts, or logs. The kernel never sees it, and if it is ever recorded the record holds only its digest.
5. **Never authority.** It is never an authorization input and is kept distinct in name and type from `OpaqueSupplementalAuthorization`.

## 7. Failure modes and fail-closed behavior

| Condition | Behavior |
|---|---|
| Verdict lacks `invocation_digest` at `lower_bound` | `VerdictBindingMismatch`; nothing lowered |
| Digest mismatch (host mis-paired verdict and result) | `VerdictBindingMismatch`; nothing lowered |
| Invocation fails `validate()` | Digest computation errors; nothing lowered |
| Duplicate `request_id` within a batch | `lift_batch` fails `Malformed`; no invocation is returned |
| CSPRNG unavailable when minting a `lift_id` | Lift fails; no invocation is returned |
| `BoundToolResult` binding digest differs, its bytes do not hash to `result_sha256`, or a `Deny` carries output bytes | `ResultBindingMismatch`; nothing lowered |
| Kernel response fails any rule 10 check (signature, key, request id, tool, server, parameter hash, content hash) | `ResponseBindingMismatch`; no `VerdictResult` is constructed |
| `request_id` over 2048 bytes | `InvalidIdentity`; lift fails |
| Provider or api_version drift between lift and lower | Existing api-version error; nothing lowered |
| Legacy `lower` called with envelope keys | Behaves as today until removal; emits a deprecation metric |
| Enforced-knowledge deployment and no `model_context_sha256` in the binding | `VerdictBindingMismatch`; nothing lowered |
| Lowered response with no committed knowledge release for its model context | Not delivered to the provider (rule 8) |

## 8. Protocol, schema, and wire impact

- **`spec/PROTOCOL.md`:** none. The fabric contract is not specified there.
- **Wire compatibility:**
  - `VerdictResult` gains two optional, skip-if-absent fields (`invocation_digest`, `result_sha256`), so existing serialized verdicts and replay fixtures still parse.
  - New verdicts are readable by old deserializers only if those use `deny_unknown_fields`. They do not today (`types.rs:240-242`).
- **Errors:** `VerdictBindingMismatch` and `ResultBindingMismatch` need fabric error-code entries in `spec/errors/registry.yaml` beside the existing `chio-tool-call-fabric` entries (`registry.yaml:494`, `registry.yaml:640`). `ResponseBindingMismatch` is a kernel shim error.
- **Provenance wire schema:** `spec/schemas/chio-wire/v1/provenance/verdict-link.schema.json` is unchanged. It binds verdicts by `requestId`, and rule 1 makes that id unique across payloads in the namespace.
- **No negotiation is needed.** The change is crate-local; hosts opt in by calling `lower_bound`.

## 9. Rollout and migration

1. **Phase 1.**
   - Add `InvocationDigest`, `invocation_digest()`, the optional verdict field, `VerdictBindingMismatch`, `lift_batch`, and `lower_bound` with default implementations that delegate to each adapter's inherent `_bound` method.
   - Add `BoundToolResult`, `result_sha256`, `ResultBindingMismatch`, `LiftContext`, and `bound_verdict_from_response`, and deprecate `verdict_result_from_response`.
   - Fix the Gemini and Ollama id minting (rule 1).
   - Add the length cap.
2. **Phase 2.** Have the stream gate call `bound_verdict_from_response`, and migrate `chio-provider-conformance` replay to pair by invocation and call `lower_bound`. Captured fixtures must lower byte-identically, because the lowered provider bytes do not include the digest. The harness re-lifts captured payloads with a fixed `LiftContext`, so synthesized ids reproduce.
3. **Phase 3.** Remove envelope-key parsing (`tool_use_id`, `call_id`, `tool_call_id`, `toolUseId`) from `ToolResult`, remove `lower` and the string-correlated inherent methods, and update the SDK bridges that call them.

## 10. Tests and conformance evidence

- **Unit, per adapter:**
  - mis-paired verdict refused;
  - missing digest refused;
  - correlation keys present inside `ToolResult` are ignored by `lower_bound`;
  - two same-name Gemini calls in one payload produce distinct ids, and two payloads with identical calls at the same index produce distinct ids;
  - re-lifting one `LiftContext` turn reproduces its ids, and a different turn does not;
  - invocation and verdict B lowered with result A are refused with `ResultBindingMismatch`, for both the binding-digest and the content-hash check;
  - a `Deny` carrying output bytes is refused;
  - `bound_verdict_from_response` refuses response B paired with invocation A (request id, tool, server and parameter-hash cases), a receipt with a bad signature, and an untrusted kernel key;
  - a verdict bound to one `ModelContextV1` digest is refused for another, and an enforced deployment refuses a binding without one.
- **Proptest in `chio-tool-call-fabric`:**
  - the digest is stable across serde round-trips of `ToolInvocation`;
  - any single-field change (`tool_name`, any provenance field, any argument byte) changes the digest;
  - `lift_batch` ids are unique for generated multi-call payloads.
- **Conformance in `chio-provider-conformance`:**
  - every existing replay fixture lowers byte-identically through `lower_bound`;
  - add negative fixtures for swapped verdicts and duplicate ids.
- **Fuzz:** add a `lower_bound` target taking arbitrary `ToolResult` bytes and a valid invocation. It must not panic, and correlation must not depend on the bytes.

## 11. Residual risks and open decisions

- **Verdict authenticity (open, narrowed).** Rule 10 derives the binding from the verified receipt, so mis-pairing is caught, and `result_sha256` is the receipt's signed content hash. What remains open is a hostile host that forges the `VerdictResult` object passed to `lower_bound`. The stronger form has `lower_bound` itself verify the receipt, which would make the fabric depend on receipt verification keys. That depends on how `2026-10-04-closed-kernel-abi-design.md` defines the verdict surface. Recommendation: decide there, not here.
- **Host mapping of request ids (resolved in revision 4).** The shipped shim already maps `provenance.request_id` into `ToolCallRequest.request_id` (M: `provider_verdict.rs:107`; `main` `:55`), so a reused id collides on the admission replay key `(request_namespace_digest, request_id)`: the same arguments dedupe to the first receipt, and different arguments conflict. Rule 1 therefore requires uniqueness across payloads in the namespace, not only within one.
- **Who selects the model context (open).** Under P4, the host selects `ModelContextV1` for restore and release. This spec assumes the bridge host that calls `lower_bound` is the same host that holds the selected context. If a deployment splits them, the context digest must travel from the knowledge runtime to the bridge as host configuration, never from the provider response.
- **`received_at` in the digest (decided, revisitable).** Including it makes digests per-lift. Excluding it would let a host re-lift and still match, which weakens mis-pair detection for byte-identical repeated calls. Decision: include it.
- **Value check.** If the review finds that host bridges already pair verdicts structurally everywhere (as the stream gate does), phase 3 cleanup alone (rule 2 plus rule 1) captures most of the value, and the verdict digest becomes optional hardening.
- **Unrelated finding (resolved on the shipped baseline).** On `main`, the hosted MCP resume tag uses the authority keypair seed directly as MAC key material (`remote_mcp/session_resume.rs:157-167`). `M:` and `V:` replace this with a dedicated `RemoteSessionHmacKeyring`, with key id, key version, and a v2 envelope that also binds `resume_generation` (`V:crates/protocol/chio-mcp-remote/src/remote_mcp/session_resume.rs:802-824`). No action is needed once the baseline merges.

## Review disposition

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180389972 | Bind each `ToolResult` to the invocation | Fixed now. `BoundToolResult` carries the binding digest, and `Allow` carries the receipt's signed `content_hash` as `result_sha256` | Section 5.1; rules 9 and 10; section 5.3; section 7 |
| 4180389976 | Make synthesized request ids unique across payloads | Fixed now. The synthesized id gains a per-payload `lift_id`, from a CSPRNG or from a host `LiftContext` | Rule 1; section 11 "Host mapping" resolved |
| 4180731770 | Bind the kernel response before constructing the verdict | Fixed now. `bound_verdict_from_response` verifies the receipt and its signed request id, tool, server and parameter hash before it builds the verdict. `verdict_result_from_response` is deprecated | Section 5.1; rules 5 and 10 |

## Appendix A: FTL reference

**What FTL does:**
- `sys_thread_create` takes a `cookie` argument alongside `syscall_pc` and `fault_pc` (`/Users/connor/Medica/backbay/ftl/kernel/src/thread.rs:299-313`).
- The cookie is stored in the arch thread (`kernel/src/arch/x64/thread.rs:66`, `thread.rs:94`).
- The syscall trampoline writes it into the user `SyscallFrame` on every reflected Linux syscall (`kernel/src/arch/x64/syscall.rs:155-159`), and the fault path writes it into `FaultFrame` (`kernel/src/arch/x64/idt.rs:459`).
- LX mints the cookie as a pointer to its per-thread `Cookie` box (`lx/src/thread.rs:54-58`) and recovers its thread with no lookup via `LxThread::from_cookie` (`lx/src/thread.rs:211-213`) in both the syscall path (`lx/src/syscall/mod.rs:183`) and the fault path (`lx/src/fault.rs:15`).

**Where the analogy breaks:**
- **Who sits in the middle.** In FTL the kernel is the only party between the trapping app and the personality, so the cookie must transit the kernel. In Chio the host sits between the adapter's lift and lower, and the kernel is in-process. The cookie therefore travels with the host (as `ToolInvocation`), never through the kernel.
- **Trust.** FTL trusts the cookie as a raw pointer because the app, LX, and the cookie share one trust domain. Chio cannot trust adapter correlation for authority, which is why this design binds verdicts by digest instead of trusting the carried value.
- **Granularity.** FTL's cookie is per thread, which is session-like. The Chio residual gap is per invocation.
