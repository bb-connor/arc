# Cross-Protocol Bridging

**Status:** Draft
**Date:** 2026-04-13

> **Status**: Design proposal. The `CrossProtocolOrchestrator` and
> `CapabilityBridge` trait described here are not yet implemented. This document
> specifies the target architecture for cross-protocol bridging.

---

## 1. Vision

Agent ecosystems are fragmenting across MCP, A2A, and ACP. Each defines its
own tool/skill/capability model, invocation envelope, and trust assumptions.
Tool authors implement three adapters, operators run three control planes,
and audit trails scatter across incompatible formats.

ARC eliminates this by serving as the universal protocol bridge. A tool
published once through ARC is automatically consumable via MCP, A2A, and ACP
surfaces. Every invocation passes through the same kernel -- the same
capability validation, guard pipeline, and signed receipt log.

```
                   +------------------+
                   |   Tool Server    |
                   | (registered once)|
                   +--------+---------+
                            |
                    ARC Kernel (TCB)
                  /    |    |    \
           +-----+ +------+ +------+ +------+
           | MCP | | A2A  | | ACP  | |Native|
           |Edge | |Adapt.| |Adapt.| |Client|
           +-----+ +------+ +------+ +------+
```

One tool, three protocol surfaces, unified security, unified receipts.

---

## 2. Protocol Translation Layer

### 2.1 Concept Alignment

| ARC               | MCP                  | A2A                | ACP                  |
|--------------------|----------------------|--------------------|----------------------|
| Tool               | Tool                 | Skill              | Capability/Function  |
| ToolManifest       | tools/list response  | AgentCard.skills   | capabilities object  |
| ToolCallRequest    | tools/call           | SendMessage        | tool_calls[]         |
| ToolCallResponse   | tools/call result    | Task artifact      | tool_results[]       |
| CapabilityToken    | (none)               | (none)             | (none)               |
| ArcReceipt         | (none)               | (none)             | (none)               |

Capability tokens and receipts have no external equivalents. ARC adds these
security properties transparently at the bridge layer.

### 2.2 MCP <-> A2A

**Discovery (MCP -> A2A):** Each MCP tool becomes an A2A skill in a
synthesized Agent Card.

```rust
fn mcp_tool_to_a2a_skill(tool: &ToolDefinition, server_id: &str) -> A2aSkill {
    A2aSkill {
        id: format!("{}/{}", server_id, tool.name),
        name: tool.name.clone(),
        description: tool.description.clone(),
        input_modes: vec!["application/json".into()],
        output_modes: vec!["application/json".into()],
    }
}
```

**Invocation (A2A -> MCP):** Extract `arc.targetSkillId` from metadata,
parse `DataPart` as MCP arguments, forward as `tools/call`, wrap result as
A2A `Task` with `DataPart` artifact.

### 2.3 MCP <-> ACP

**Discovery (MCP -> ACP):** Each MCP tool becomes an ACP capability.

```rust
fn mcp_tool_to_acp_capability(tool: &ToolDefinition) -> AcpCapability {
    AcpCapability {
        name: tool.name.clone(),
        description: tool.description.clone(),
        parameters: tool.input_schema.clone(),
    }
}
```

**Invocation (ACP -> MCP):** ACP `tool_calls` translates directly to MCP
`tools/call`. Both use JSON Schema for parameters.

### 2.4 A2A <-> ACP

**Discovery (A2A -> ACP):** Each A2A skill becomes an ACP capability.
Skill `inputModes`/`outputModes` are recorded in adapter metadata.

**Invocation (ACP -> A2A):** ACP `tool_calls` repackaged as A2A
`SendMessage` with `DataPart` arguments and `arc.targetSkillId` metadata.

### 2.5 Type Mapping

| MCP Type         | A2A Type            | ACP Type             |
|------------------|---------------------|----------------------|
| TextContent      | TextPart            | text content block   |
| ImageContent     | FilePart (inline)   | image content block  |
| EmbeddedResource | DataPart            | tool_results[].output|
| isError: true    | Task.status: failed | error content block  |
| ProgressToken    | Task.status: working| (stream signal)      |

---

## 3. Capability Propagation Across Protocols

### 3.1 Chain Integrity

When an A2A agent delegates to an MCP tool through ARC, the capability
chain remains intact. The bridge never manufactures authority.

```
  A2A Agent            ARC Kernel         MCP Tool Server
     |                    |                    |
     |-- SendMessage ---->|                    |
     |   (bridge cap ref) |                    |
     |                    |-- validate cap --->|
     |                    |-- tools/call ----->|
     |                    |<- result ----------|
     |                    |-- sign receipt     |
     |<- Task artifact ---|                    |
```

### 3.2 CapabilityBridge Trait

```rust
pub trait CapabilityBridge: Send + Sync {
    fn source_protocol(&self) -> &str;

    /// Extract capability reference from inbound protocol envelope.
    /// None triggers fallback to session-level ambient grants.
    fn extract_capability_ref(
        &self,
        request: &serde_json::Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError>;

    /// Inject ARC capability into outbound protocol envelope.
    fn inject_capability_ref(
        &self,
        envelope: &mut serde_json::Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolCapabilityRef {
    pub arc_capability_id: String,
    pub origin_protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_context: Option<serde_json::Value>,
    pub parent_capability_hash: String,
}
```

### 3.3 Capability Envelope

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolCapabilityEnvelope {
    pub schema: String,  // "arc.cross-protocol-cap.v1"
    pub capability: CapabilityToken,
    pub target_protocol: String,
    /// Must be a strict subset of capability.scope.
    pub attenuated_scope: ArcScope,
    pub bridged_at: u64,
    pub bridge_id: String,
}
```

### 3.4 Attenuation

Sub-capabilities crossing protocol boundaries are strictly narrower than
the parent. The bridge computes the intersection of the parent's `ArcScope`
with the target tool's requirements:

```rust
fn attenuate_for_bridge(
    parent_scope: &ArcScope,
    target_server: &str,
    target_tool: &str,
) -> Option<ArcScope> {
    let matching: Vec<ToolGrant> = parent_scope.grants.iter()
        .filter(|g| g.server_id == target_server && g.tool_name == target_tool)
        .cloned()
        .collect();
    if matching.is_empty() {
        return None; // Fail closed.
    }
    Some(ArcScope { grants: matching, resource_grants: vec![], prompt_grants: vec![] })
}
```

The kernel verifies `attenuated_scope.is_subset_of(&parent.scope)` before
admitting any cross-protocol request. Failure produces `Decision::Deny`.

---

## 4. Multi-Protocol Tool Discovery

### 4.1 Unified Registry

```rust
#[derive(Debug, Clone)]
pub struct DiscoveredTool {
    pub canonical_name: String,
    pub protocol: DiscoveryProtocol,
    pub origin: String,
    pub definition: ToolDefinition,
    pub adapter_metadata: AdapterMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DiscoveryProtocol { Native, Mcp, A2a, Acp }
```

```
  +------------------------------------------------+
  |           UnifiedToolRegistry                   |
  |  HashMap<canonical_name, Vec<DiscoveredTool>>   |
  |                                                 |
  |  "web-search" -> [MCP(srv-a), A2A(agent-b)]    |
  |  "code-exec"  -> [Native(sandbox-1)]            |
  |  "translate"   -> [A2A(agent-c), ACP(svc-d)]    |
  +------------------------------------------------+
```

### 4.2 Query API

```rust
pub trait ToolRegistry: Send + Sync {
    fn query_tools(&self, query: &ToolQuery) -> Vec<&DiscoveredTool>;
    fn register(&mut self, tool: DiscoveredTool);
    fn deregister_origin(&mut self, origin: &str);
}

#[derive(Debug, Clone)]
pub struct ToolQuery {
    pub name_pattern: Option<String>,
    pub protocols: Option<Vec<DiscoveryProtocol>>,
    pub scope_filter: Option<ArcScope>,
    pub limit: usize,
}
```

### 4.3 Automatic Multi-Protocol Registration

Registration through any adapter generates all three external
representations at registration time (not query time):

```
  Register "analyze-code" via ARC native API
     |
     +-> MCP: tools/list entry     (available to MCP clients)
     +-> A2A: AgentCard skill      (available to A2A agents)
     +-> ACP: capability entry     (available to ACP agents)
```

---

## 5. Receipt Correlation

### 5.1 Trace Context

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolTraceContext {
    pub trace_id: String,
    pub hops: Vec<ProtocolHop>,
    pub session_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolHop {
    pub protocol: String,
    pub receipt_id: String,
    pub bridge_id: String,
    pub timestamp: u64,
}
```

### 5.2 Receipt Tree

Receipts form a parent-child tree across protocol boundaries:

```
  ArcReceipt (root: A2A inbound)
    +-- ArcReceipt (bridge: A2A -> kernel)
    |     +-- ArcReceipt (kernel -> MCP tool)
    +-- ChildRequestReceipt (sampling callback)
```

The `CrossProtocolTraceContext` is embedded in each receipt's `metadata`
field. The receipt query API supports `trace_id` filters to reconstruct
the full cross-protocol call tree.

### 5.3 Session Fingerprint

```
SHA-256(session_id || initiating_protocol || initiating_agent_key || workflow_start_ts)
```

All components are UTF-8 encoded bytes. The `||` operator denotes byte
concatenation with no delimiter. Agent keys are hex-encoded before
concatenation. Timestamps are decimal Unix seconds (e.g., "1712973840").

Binds all receipts from a logical workflow together, even across kernel
instances in federated deployments.

---

## 6. Multi-Protocol Agent Orchestrator

### 6.1 Architecture

```rust
pub struct CrossProtocolOrchestrator {
    registry: Box<dyn ToolRegistry>,
    bridges: HashMap<DiscoveryProtocol, Box<dyn CapabilityBridge>>,
    kernel: Arc<ArcKernel>,
    active_traces: HashMap<String, CrossProtocolTraceContext>,
}
```

This orchestrator is part of the Tier 2 roadmap (Phase 6). Not yet implemented.

### 6.2 Flow: A2A -> MCP -> ACP

```
  A2A Agent         Orchestrator          MCP Server    ACP Agent
     |                  |                     |             |
     |-- SendMessage -->|                     |             |
     |                  |-- validate cap ---->|             |
     |                  |-- tools/call ------>|             |
     |                  |<- result -----------|             |
     |                  |-- receipt (hop 1)   |             |
     |                  |-- attenuate cap --->|             |
     |                  |-- tool_calls[] -----|------------>|
     |                  |<- tool_results[] ---|-------------|
     |                  |-- receipt (hop 2)   |             |
     |                  |-- unified receipt   |             |
     |<- Task artifact -|                     |             |
```

### 6.3 Unified Receipt

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolReceipt {
    pub root_receipt: ArcReceipt,
    pub hop_receipts: Vec<ArcReceipt>,
    pub trace: CrossProtocolTraceContext,
    /// Allow only if every hop allowed.
    pub aggregate_decision: Decision,
}
```

### 6.4 Error Handling

1. **Fail-closed propagation.** The orchestrator does not attempt the next
   hop after a failure. Partial results are discarded.
2. **Denial receipt.** `Decision::Deny` receipt emitted for the failing
   hop, citing bridge adapter and failure reason.
3. **Rollback receipts.** Best-effort cancellation receipts for completed
   hops if the tool supports idempotent undo.
4. **Caller notification.** Error in the originating protocol's native
   format (MCP error, A2A failed task, ACP error content block).

---

## 7. Latency-Aware Routing

### 7.1 Adapter Metadata

```rust
#[derive(Debug, Clone)]
pub struct AdapterMetadata {
    pub latency_p50_ms: Option<u64>,
    pub latency_p99_ms: Option<u64>,
    pub success_rate: Option<f64>,
    pub observation_count: u64,
    pub authoritative: bool,
    pub last_updated: u64,
}
```

### 7.2 Routing Policies

```rust
#[derive(Debug, Clone, Copy)]
pub enum RoutingPolicy {
    /// Lowest p50 latency. Ties broken by success rate.
    BestEffort,
    /// Highest success rate, ignoring latency.
    Critical,
    /// Prefer authoritative adapter. Fall back to BestEffort.
    Authoritative,
}

fn select_adapter<'a>(
    candidates: &'a [DiscoveredTool],
    policy: RoutingPolicy,
) -> Option<&'a DiscoveredTool> {
    match policy {
        RoutingPolicy::BestEffort => candidates.iter()
            .min_by_key(|c| c.adapter_metadata.latency_p50_ms.unwrap_or(u64::MAX)),
        RoutingPolicy::Critical => candidates.iter()
            .max_by(|a, b| {
                let ra = a.adapter_metadata.success_rate.unwrap_or(0.0);
                let rb = b.adapter_metadata.success_rate.unwrap_or(0.0);
                ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
            }),
        RoutingPolicy::Authoritative => candidates.iter()
            .find(|c| c.adapter_metadata.authoritative)
            .or_else(|| select_adapter(candidates, RoutingPolicy::BestEffort)),
    }
}
```

### 7.3 Metric Collection

Adapters update metadata after every invocation via exponential moving
average. Metrics are local to each kernel instance; federated aggregation
is a future extension through the evidence-sharing mechanism.

---

## 8. Implementation Roadmap

| Phase | Scope | Depends On |
|-------|-------|------------|
| 1 | Foundation: MCP + A2A adapters (shipped) | -- |
| 2 | `UnifiedToolRegistry`, `DiscoveredTool`, `ToolQuery` API | Phase 1 |
| 3 | `arc-acp-adapter` crate, ACP discovery + invocation | Phase 1 |
| 4 | `CapabilityBridge` trait, `CrossProtocolCapabilityEnvelope`, attenuation | Phase 2 |
| 5 | `CrossProtocolTraceContext`, receipt correlation, session fingerprint | Phase 4 |
| 6 | `CrossProtocolOrchestrator`, multi-hop chaining, unified receipts | Phase 4, 5 |
| 7 | `AdapterMetadata` collection, `RoutingPolicy`, latency-aware selection | Phase 2 |
| 8 | Conformance tests, fuzz testing, benchmarks, honest boundary docs | Phase 6, 7 |
