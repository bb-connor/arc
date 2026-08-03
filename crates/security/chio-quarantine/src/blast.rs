use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{
    response_affected_set_hash, BlastRadiusFenceAcquisition, BlastRadiusIncompleteReason,
    BlastRadiusPort, BlastRadiusQueryBounds, BlastRadiusRequest, BlastRadiusResult,
    BlastRadiusSnapshotMetadata, CausalLineageEdge, CausalLineageEdgeKind,
    CausalLineageFenceRequest, CausalLineageFenceStore, CausalLineageNode, CausalLineageNodeKind,
    CausalLineageSnapshot, CausalLineageSnapshotRequest, CausalLineageStore, Digest32,
    LineageFence, LineageFenceRelease, LineageFenceRenewal, LineageFenceRequest,
    LineageFenceTakeover, PortError, PortResult, RecordId, RecordIdSet, TenantScopedId,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

const GRAPH_SLICE_HASH_DOMAIN: &[u8] = b"chio.causal-blast-graph-slice.v1\0";
const MAX_QUERY_DEPTH: u32 = 64;
const MAX_QUERY_NODES: u32 = 4_096;
const MAX_QUERY_EDGES: u32 = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceValidationOutcome {
    ApprovalInvalidated,
    InvalidApprovedResult,
    PortFailure,
}

pub struct CausalBlastRadiusResolver<
    S: CausalLineageStore + ?Sized,
    F: CausalLineageFenceStore + ?Sized,
> {
    lineage: Arc<S>,
    fences: Arc<F>,
}

impl<S: CausalLineageStore + ?Sized, F: CausalLineageFenceStore + ?Sized>
    CausalBlastRadiusResolver<S, F>
{
    #[must_use]
    pub const fn new(lineage: Arc<S>, fences: Arc<F>) -> Self {
        Self { lineage, fences }
    }

    #[must_use]
    pub fn resolve(&self, request: &BlastRadiusRequest) -> BlastRadiusResult {
        self.resolve_with_fence(request, None)
    }

    pub fn acquire_validated_fence(
        &self,
        request: &BlastRadiusRequest,
        approved: &BlastRadiusResult,
        approved_expires_at_unix_ms: u64,
        expected: &LineageFenceRequest,
    ) -> Result<LineageFence, FenceValidationOutcome> {
        let (
            approved_metadata,
            approved_affected_set_hash,
            approved_graph_slice_hash,
            approved_sorted_affected_ids,
        ) = match approved {
            BlastRadiusResult::Exact {
                metadata,
                sorted_affected_ids,
                affected_set_hash,
                graph_slice_hash,
            } if metadata.query_bounds == request.query_bounds => (
                metadata,
                *affected_set_hash,
                *graph_slice_hash,
                sorted_affected_ids,
            ),
            _ => return Err(FenceValidationOutcome::InvalidApprovedResult),
        };
        let valid_approved_binding = approved_metadata.source_lineage_version > 0
            && approved_metadata.commit_index > 0
            && approved_metadata.commit_index == approved_metadata.authoritative_commit_index
            && approved_metadata
                .completeness_watermark
                .is_some_and(|watermark| watermark >= approved_metadata.commit_index)
            && expected.tenant_id == request.tenant_id
            && expected.action_id == request.action_id
            && expected.expected_commit_index == approved_metadata.commit_index
            && expected.expected_affected_set_hash == approved_affected_set_hash
            && expected.scheduler_fencing_token > 0
            && expected.expires_at_unix_ms == approved_expires_at_unix_ms
            && expected.expires_at_unix_ms > 0
            && !approved_sorted_affected_ids.as_slice().is_empty()
            && request.seed_ids.as_slice().iter().all(|seed| {
                approved_sorted_affected_ids
                    .as_slice()
                    .binary_search(seed)
                    .is_ok()
            })
            && response_affected_set_hash(&request.tenant_id, approved_sorted_affected_ids)
                .is_ok_and(|derived| derived == approved_affected_set_hash)
            && approved_graph_slice_hash != Digest32::new([0; 32]);
        if !valid_approved_binding {
            return Err(FenceValidationOutcome::InvalidApprovedResult);
        }
        let fence = self
            .fences
            .acquire_causal_fence(&CausalLineageFenceRequest {
                fence: expected.clone(),
                frozen_affected_ids: approved_sorted_affected_ids.clone(),
            })
            .map_err(|_| FenceValidationOutcome::PortFailure)?;
        let usable_fence_identity = fence.tenant_id == request.tenant_id
            && fence.action_id == request.action_id
            && fence.fencing_token > 0
            && fence.scheduler_lease_owner_id == expected.scheduler_lease_owner_id
            && fence.scheduler_fencing_token == expected.scheduler_fencing_token;
        let exact_fence = usable_fence_identity
            && fence.commit_index == approved_metadata.commit_index
            && fence.affected_set_hash == approved_affected_set_hash
            && fence.expires_at_unix_ms == expected.expires_at_unix_ms;
        if !exact_fence {
            if usable_fence_identity {
                let release = LineageFenceRelease {
                    tenant_id: fence.tenant_id.clone(),
                    action_id: fence.action_id.clone(),
                    fencing_token: fence.fencing_token,
                    scheduler_lease_owner_id: fence.scheduler_lease_owner_id.clone(),
                    scheduler_fencing_token: fence.scheduler_fencing_token,
                };
                self.fences
                    .release(&release)
                    .map_err(|_| FenceValidationOutcome::PortFailure)?;
            }
            return Err(FenceValidationOutcome::PortFailure);
        }
        let refreshed = self.resolve_with_fence(request, Some(request.action_id.clone()));
        let unchanged = matches!(
            &refreshed,
            BlastRadiusResult::Exact {
                metadata,
                sorted_affected_ids,
                affected_set_hash,
                graph_slice_hash,
            } if metadata.commit_index == approved_metadata.commit_index
                && metadata.authoritative_commit_index
                    == approved_metadata.authoritative_commit_index
                && metadata.source_lineage_version
                    == approved_metadata.source_lineage_version
                && metadata.completeness_watermark
                    == approved_metadata.completeness_watermark
                && affected_set_hash == &approved_affected_set_hash
                && graph_slice_hash == &approved_graph_slice_hash
                && sorted_affected_ids == approved_sorted_affected_ids
        );
        if unchanged {
            return Ok(fence);
        }
        let release = LineageFenceRelease {
            tenant_id: fence.tenant_id.clone(),
            action_id: fence.action_id.clone(),
            fencing_token: fence.fencing_token,
            scheduler_lease_owner_id: fence.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: fence.scheduler_fencing_token,
        };
        self.fences
            .release(&release)
            .map_err(|_| FenceValidationOutcome::PortFailure)?;
        Err(FenceValidationOutcome::ApprovalInvalidated)
    }

    pub fn query_validated_fence(
        &self,
        expected: &LineageFenceRequest,
    ) -> Result<Option<LineageFence>, FenceValidationOutcome> {
        let action = TenantScopedId {
            tenant_id: expected.tenant_id.clone(),
            id: RecordId::new(expected.action_id.as_str())
                .map_err(|_| FenceValidationOutcome::InvalidApprovedResult)?,
        };
        let Some(fence) = self
            .fences
            .query(&action)
            .map_err(|_| FenceValidationOutcome::PortFailure)?
        else {
            return Ok(None);
        };
        if fence.tenant_id != expected.tenant_id
            || fence.action_id != expected.action_id
            || fence.commit_index != expected.expected_commit_index
            || fence.affected_set_hash != expected.expected_affected_set_hash
            || fence.expires_at_unix_ms < expected.expires_at_unix_ms
            || fence.fencing_token == 0
            || fence.scheduler_lease_owner_id != expected.scheduler_lease_owner_id
            || fence.scheduler_fencing_token != expected.scheduler_fencing_token
        {
            return Err(FenceValidationOutcome::PortFailure);
        }
        Ok(Some(fence))
    }

    fn resolve_with_fence(
        &self,
        request: &BlastRadiusRequest,
        fence_action_id: Option<chio_security_types::ports::ActionId>,
    ) -> BlastRadiusResult {
        let fallback = fallback_metadata(&request.query_bounds);
        if !valid_bounds(&request.query_bounds) || request.seed_ids.is_empty() {
            return incomplete(fallback, BlastRadiusIncompleteReason::InvalidQueryBounds);
        }
        let snapshot = match self
            .lineage
            .load_causal_snapshot(&CausalLineageSnapshotRequest {
                tenant_id: request.tenant_id.clone(),
                seed_ids: request.seed_ids.clone(),
                query_bounds: request.query_bounds.clone(),
                fence_action_id,
            }) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return incomplete(fallback, BlastRadiusIncompleteReason::LineageStoreFailure);
            }
        };
        let metadata = snapshot_metadata(&request.query_bounds, &snapshot);
        match resolve_snapshot(request, snapshot) {
            Ok(exact) => BlastRadiusResult::Exact {
                metadata,
                sorted_affected_ids: exact.sorted_affected_ids,
                affected_set_hash: exact.affected_set_hash,
                graph_slice_hash: exact.graph_slice_hash,
            },
            Err(reason) => incomplete(metadata, reason),
        }
    }
}

impl<S: CausalLineageStore + ?Sized, F: CausalLineageFenceStore + ?Sized> BlastRadiusPort
    for CausalBlastRadiusResolver<S, F>
{
    fn ensure_blast_radius_ready(&self) -> PortResult<()> {
        self.lineage.ensure_causal_lineage_ready()?;
        self.fences.ensure_causal_lineage_fences_ready()
    }

    fn resolve(&self, request: &BlastRadiusRequest) -> PortResult<BlastRadiusResult> {
        Ok(CausalBlastRadiusResolver::resolve(self, request))
    }

    fn acquire_fence(
        &self,
        acquisition: &BlastRadiusFenceAcquisition,
        expected: &LineageFenceRequest,
    ) -> PortResult<LineageFence> {
        self.acquire_validated_fence(
            &acquisition.request,
            &acquisition.approved_result,
            acquisition.expires_at_unix_ms,
            expected,
        )
        .map_err(fence_validation_error_to_port)
    }

    fn query_fence(&self, expected: &LineageFenceRequest) -> PortResult<Option<LineageFence>> {
        self.query_validated_fence(expected)
            .map_err(fence_validation_error_to_port)
    }

    fn renew_fence(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        self.fences.renew(renewal)
    }

    fn takeover_fence(&self, takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        self.fences.takeover(takeover)
    }

    fn release_fence(&self, release: &LineageFenceRelease) -> PortResult<()> {
        self.fences.release(release)
    }
}

fn fence_validation_error_to_port(error: FenceValidationOutcome) -> PortError {
    match error {
        FenceValidationOutcome::ApprovalInvalidated => PortError::conflict(),
        FenceValidationOutcome::InvalidApprovedResult => PortError::invalid_data(),
        FenceValidationOutcome::PortFailure => PortError::unavailable(),
    }
}

struct ExactResolution {
    sorted_affected_ids: RecordIdSet,
    affected_set_hash: Digest32,
    graph_slice_hash: Digest32,
}

fn resolve_snapshot(
    request: &BlastRadiusRequest,
    snapshot: CausalLineageSnapshot,
) -> Result<ExactResolution, BlastRadiusIncompleteReason> {
    if snapshot.tenant_id != request.tenant_id {
        return Err(BlastRadiusIncompleteReason::CrossTenantSnapshot);
    }
    if snapshot.depth_truncated || snapshot.nodes_truncated || snapshot.edges_truncated {
        return Err(BlastRadiusIncompleteReason::TruncatedSnapshot);
    }
    if snapshot.metadata.source_lineage_version == 0 || snapshot.metadata.observed_commit_index == 0
    {
        return Err(BlastRadiusIncompleteReason::InvalidLineageMetadata);
    }
    if snapshot.metadata.observed_commit_index != snapshot.metadata.authoritative_commit_index {
        return Err(BlastRadiusIncompleteReason::ReplicaLag);
    }
    if snapshot
        .metadata
        .completeness_watermark
        .is_none_or(|watermark| watermark < snapshot.metadata.observed_commit_index)
    {
        return Err(BlastRadiusIncompleteReason::MissingCompletenessWatermark);
    }
    if snapshot.nodes.len() > request.query_bounds.max_nodes as usize
        || snapshot.edges.len() > request.query_bounds.max_edges as usize
    {
        return Err(BlastRadiusIncompleteReason::UnreportedTruncation);
    }

    let mut nodes = BTreeMap::<RecordId, CausalLineageNode>::new();
    for node in snapshot.nodes.into_vec() {
        if node.tenant_id != request.tenant_id {
            return Err(BlastRadiusIncompleteReason::CrossTenantNode);
        }
        if let Some(existing) = nodes.insert(node.node_id.clone(), node.clone()) {
            if existing != node {
                return Err(BlastRadiusIncompleteReason::ConflictingNode);
            }
        }
    }
    for seed in request.seed_ids.as_slice() {
        if nodes
            .get(seed)
            .is_none_or(|node| node.kind != CausalLineageNodeKind::Capability)
        {
            return Err(BlastRadiusIncompleteReason::MissingSeed);
        }
    }

    let mut edges = BTreeSet::<CausalLineageEdge>::new();
    for edge in snapshot.edges.into_vec() {
        if edge.tenant_id != request.tenant_id {
            return Err(BlastRadiusIncompleteReason::CrossTenantEdge);
        }
        let parent = nodes
            .get(&edge.parent_id)
            .ok_or(BlastRadiusIncompleteReason::CorruptEdge)?;
        let child = nodes
            .get(&edge.child_id)
            .ok_or(BlastRadiusIncompleteReason::CorruptEdge)?;
        if edge.parent_id == edge.child_id || !valid_edge_kind(parent, child, edge.kind) {
            return Err(BlastRadiusIncompleteReason::CorruptEdge);
        }
        edges.insert(edge);
    }

    let mut adjacency = BTreeMap::<RecordId, Vec<RecordId>>::new();
    for edge in &edges {
        adjacency
            .entry(edge.parent_id.clone())
            .or_default()
            .push(edge.child_id.clone());
    }
    for children in adjacency.values_mut() {
        children.sort();
        children.dedup();
    }
    let mut reachable = BTreeSet::<RecordId>::new();
    let mut queue = VecDeque::<(RecordId, u32)>::new();
    for seed in request.seed_ids.as_slice() {
        queue.push_back((seed.clone(), 0));
    }
    while let Some((node_id, depth)) = queue.pop_front() {
        if !reachable.insert(node_id.clone()) {
            continue;
        }
        if depth > request.query_bounds.max_depth {
            return Err(BlastRadiusIncompleteReason::DepthTruncated);
        }
        if let Some(children) = adjacency.get(&node_id) {
            let next_depth = depth
                .checked_add(1)
                .ok_or(BlastRadiusIncompleteReason::DepthTruncated)?;
            for child in children {
                queue.push_back((child.clone(), next_depth));
            }
        }
    }
    if reachable.len() != nodes.len() {
        return Err(BlastRadiusIncompleteReason::UnreachableNode);
    }
    if graph_has_cycle(&nodes, &edges) {
        return Err(BlastRadiusIncompleteReason::CycleCorruption);
    }

    let affected_ids = nodes
        .values()
        .filter(|node| node.kind == CausalLineageNodeKind::Capability)
        .map(|node| node.node_id.clone())
        .collect::<Vec<_>>();
    let sorted_affected_ids = RecordIdSet::new(affected_ids)
        .map_err(|_| BlastRadiusIncompleteReason::AffectedSetInvalid)?;
    let affected_set_hash = response_affected_set_hash(&request.tenant_id, &sorted_affected_ids)
        .map_err(|_| BlastRadiusIncompleteReason::HashFailure)?;
    let sorted_nodes = nodes.into_values().collect::<Vec<_>>();
    let sorted_edges = edges.into_iter().collect::<Vec<_>>();
    let graph_slice_hash = graph_slice_hash(
        &request.tenant_id,
        snapshot.metadata.source_lineage_version,
        snapshot.metadata.observed_commit_index,
        &sorted_nodes,
        &sorted_edges,
    )
    .map_err(|_| BlastRadiusIncompleteReason::HashFailure)?;
    Ok(ExactResolution {
        sorted_affected_ids,
        affected_set_hash,
        graph_slice_hash,
    })
}

fn valid_edge_kind(
    parent: &CausalLineageNode,
    child: &CausalLineageNode,
    kind: CausalLineageEdgeKind,
) -> bool {
    matches!(
        (parent.kind, child.kind, kind),
        (
            CausalLineageNodeKind::Capability,
            CausalLineageNodeKind::Capability,
            CausalLineageEdgeKind::CapabilityDelegation
        ) | (
            CausalLineageNodeKind::Capability,
            CausalLineageNodeKind::Receipt,
            CausalLineageEdgeKind::CapabilityReceipt
        ) | (
            CausalLineageNodeKind::Receipt,
            CausalLineageNodeKind::Receipt,
            CausalLineageEdgeKind::ReceiptLineage
        )
    )
}

fn graph_has_cycle(
    nodes: &BTreeMap<RecordId, CausalLineageNode>,
    edges: &BTreeSet<CausalLineageEdge>,
) -> bool {
    let mut indegree = nodes
        .keys()
        .cloned()
        .map(|node_id| (node_id, 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut adjacency = BTreeMap::<RecordId, Vec<RecordId>>::new();
    for edge in edges {
        let Some(value) = indegree.get_mut(&edge.child_id) else {
            return true;
        };
        *value = value.saturating_add(1);
        adjacency
            .entry(edge.parent_id.clone())
            .or_default()
            .push(edge.child_id.clone());
    }
    let mut queue = indegree
        .iter()
        .filter_map(|(node_id, degree)| (*degree == 0).then_some(node_id.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(node_id) = queue.pop_front() {
        visited = visited.saturating_add(1);
        if let Some(children) = adjacency.get(&node_id) {
            for child in children {
                let Some(degree) = indegree.get_mut(child) else {
                    return true;
                };
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    queue.push_back(child.clone());
                }
            }
        }
    }
    visited != nodes.len()
}

fn valid_bounds(bounds: &BlastRadiusQueryBounds) -> bool {
    bounds.max_depth > 0
        && bounds.max_depth <= MAX_QUERY_DEPTH
        && bounds.max_nodes > 0
        && bounds.max_nodes <= MAX_QUERY_NODES
        && bounds.max_edges > 0
        && bounds.max_edges <= MAX_QUERY_EDGES
}

fn fallback_metadata(bounds: &BlastRadiusQueryBounds) -> BlastRadiusSnapshotMetadata {
    BlastRadiusSnapshotMetadata {
        query_bounds: bounds.clone(),
        source_lineage_version: 0,
        commit_index: 0,
        authoritative_commit_index: 0,
        completeness_watermark: None,
    }
}

fn snapshot_metadata(
    bounds: &BlastRadiusQueryBounds,
    snapshot: &CausalLineageSnapshot,
) -> BlastRadiusSnapshotMetadata {
    BlastRadiusSnapshotMetadata {
        query_bounds: bounds.clone(),
        source_lineage_version: snapshot.metadata.source_lineage_version,
        commit_index: snapshot.metadata.observed_commit_index,
        authoritative_commit_index: snapshot.metadata.authoritative_commit_index,
        completeness_watermark: snapshot.metadata.completeness_watermark,
    }
}

fn incomplete(
    metadata: BlastRadiusSnapshotMetadata,
    reason: BlastRadiusIncompleteReason,
) -> BlastRadiusResult {
    BlastRadiusResult::Incomplete { metadata, reason }
}

fn graph_slice_hash(
    tenant_id: &chio_security_types::ports::TenantId,
    source_lineage_version: u64,
    commit_index: u64,
    nodes: &[CausalLineageNode],
    edges: &[CausalLineageEdge],
) -> Result<Digest32, ()> {
    #[derive(Serialize)]
    struct GraphSliceCommitment<'a> {
        tenant_id: &'a str,
        source_lineage_version: u64,
        commit_index: u64,
        nodes: &'a [CausalLineageNode],
        edges: &'a [CausalLineageEdge],
    }
    domain_hash(
        GRAPH_SLICE_HASH_DOMAIN,
        &GraphSliceCommitment {
            tenant_id: tenant_id.as_str(),
            source_lineage_version,
            commit_index,
            nodes,
            edges,
        },
    )
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32, ()> {
    let canonical = canonical_json_bytes(value).map_err(|_| ())?;
    let mut input = Vec::with_capacity(domain.len().saturating_add(canonical.len()));
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&input).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_security_types::ports::{
        ActionId, BlastRadiusQueryBounds, BlastRadiusRequest, BlastRadiusResult,
        CausalLineageCommitMetadata, CausalLineageEdge, CausalLineageEdgeKind, CausalLineageEdges,
        CausalLineageFenceRequest, CausalLineageFenceStore, CausalLineageNode,
        CausalLineageNodeKind, CausalLineageNodes, CausalLineageSnapshot,
        CausalLineageSnapshotRequest, CausalLineageStore, Digest32, LineageFence,
        LineageFenceRelease, LineageFenceRequest, LineageFenceStore, PortError, PortResult,
        RecordId, TenantId, TenantScopedId,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    enum SnapshotStep {
        Snapshot(CausalLineageSnapshot),
        Failure,
    }

    struct FakeLineage {
        steps: Mutex<VecDeque<SnapshotStep>>,
        requests: Mutex<Vec<CausalLineageSnapshotRequest>>,
    }

    impl FakeLineage {
        fn new(steps: Vec<SnapshotStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<CausalLineageSnapshotRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|_| panic!("lineage request mutex poisoned"))
                .clone()
        }
    }

    impl CausalLineageStore for FakeLineage {
        fn ensure_causal_lineage_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn load_causal_snapshot(
            &self,
            request: &CausalLineageSnapshotRequest,
        ) -> PortResult<CausalLineageSnapshot> {
            self.requests
                .lock()
                .map_err(|_| PortError::unavailable())?
                .push(request.clone());
            let mut steps = self.steps.lock().map_err(|_| PortError::unavailable())?;
            let step = if steps.len() > 1 {
                steps.pop_front()
            } else {
                steps.front().cloned()
            };
            match step {
                Some(SnapshotStep::Snapshot(snapshot)) => Ok(snapshot),
                Some(SnapshotStep::Failure) | None => Err(PortError::unavailable()),
            }
        }
    }

    #[derive(Default)]
    struct FakeFences {
        current: Mutex<Option<LineageFence>>,
        acquire_override: Mutex<Option<LineageFence>>,
        query_override: Mutex<Option<LineageFence>>,
        causal_acquisitions: Mutex<Vec<CausalLineageFenceRequest>>,
        acquisitions: Mutex<usize>,
        releases: Mutex<usize>,
    }

    impl FakeFences {
        fn acquisition_count(&self) -> usize {
            *self
                .acquisitions
                .lock()
                .unwrap_or_else(|_| panic!("fence acquisition mutex poisoned"))
        }

        fn release_count(&self) -> usize {
            *self
                .releases
                .lock()
                .unwrap_or_else(|_| panic!("fence release mutex poisoned"))
        }

        fn causal_acquisitions(&self) -> Vec<CausalLineageFenceRequest> {
            self.causal_acquisitions
                .lock()
                .unwrap_or_else(|_| panic!("causal fence acquisition mutex poisoned"))
                .clone()
        }

        fn override_acquire(&self, fence: LineageFence) {
            *self
                .acquire_override
                .lock()
                .unwrap_or_else(|_| panic!("fence acquire override mutex poisoned")) = Some(fence);
        }

        fn override_query(&self, fence: LineageFence) {
            *self
                .query_override
                .lock()
                .unwrap_or_else(|_| panic!("fence query override mutex poisoned")) = Some(fence);
        }
    }

    impl LineageFenceStore for FakeFences {
        fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence> {
            let mut acquisitions = self
                .acquisitions
                .lock()
                .map_err(|_| PortError::unavailable())?;
            *acquisitions = acquisitions.saturating_add(1);
            if let Some(overridden) = self
                .acquire_override
                .lock()
                .map_err(|_| PortError::unavailable())?
                .clone()
            {
                *self.current.lock().map_err(|_| PortError::unavailable())? =
                    Some(overridden.clone());
                return Ok(overridden);
            }
            let fence = LineageFence {
                tenant_id: request.tenant_id.clone(),
                action_id: request.action_id.clone(),
                commit_index: request.expected_commit_index,
                affected_set_hash: request.expected_affected_set_hash,
                fencing_token: 1,
                scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
                scheduler_fencing_token: request.scheduler_fencing_token,
                expires_at_unix_ms: request.expires_at_unix_ms,
            };
            *self.current.lock().map_err(|_| PortError::unavailable())? = Some(fence.clone());
            Ok(fence)
        }

        fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
            if let Some(overridden) = self
                .query_override
                .lock()
                .map_err(|_| PortError::unavailable())?
                .clone()
            {
                return Ok(Some(overridden));
            }
            Ok(self
                .current
                .lock()
                .map_err(|_| PortError::unavailable())?
                .clone()
                .filter(|fence| {
                    fence.tenant_id == action.tenant_id
                        && fence.action_id.as_str() == action.id.as_str()
                }))
        }

        fn renew(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
            let mut current = self.current.lock().map_err(|_| PortError::unavailable())?;
            let fence = current.as_mut().ok_or_else(PortError::conflict)?;
            if fence.tenant_id != renewal.tenant_id
                || fence.action_id != renewal.action_id
                || fence.fencing_token != renewal.fencing_token
                || fence.scheduler_lease_owner_id != renewal.scheduler_lease_owner_id
                || fence.scheduler_fencing_token != renewal.scheduler_fencing_token
                || fence.expires_at_unix_ms != renewal.expected_expires_at_unix_ms
                || renewal.renewed_expires_at_unix_ms <= renewal.expected_expires_at_unix_ms
            {
                return Err(PortError::conflict());
            }
            fence.expires_at_unix_ms = renewal.renewed_expires_at_unix_ms;
            Ok(fence.clone())
        }

        fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
            let mut current = self.current.lock().map_err(|_| PortError::unavailable())?;
            let Some(fence) = current.as_ref() else {
                return Err(PortError::conflict());
            };
            if fence.tenant_id != release.tenant_id
                || fence.action_id != release.action_id
                || fence.fencing_token != release.fencing_token
                || fence.scheduler_lease_owner_id != release.scheduler_lease_owner_id
                || fence.scheduler_fencing_token != release.scheduler_fencing_token
            {
                return Err(PortError::conflict());
            }
            *current = None;
            let mut releases = self.releases.lock().map_err(|_| PortError::unavailable())?;
            *releases = releases.saturating_add(1);
            Ok(())
        }
    }

    impl CausalLineageFenceStore for FakeFences {
        fn ensure_causal_lineage_fences_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn acquire_causal_fence(
            &self,
            request: &CausalLineageFenceRequest,
        ) -> PortResult<LineageFence> {
            self.causal_acquisitions
                .lock()
                .map_err(|_| PortError::unavailable())?
                .push(request.clone());
            self.acquire(&request.fence)
        }
    }

    fn tenant(value: &str) -> TenantId {
        TenantId::new(value).unwrap_or_else(|error| panic!("tenant id: {error}"))
    }

    fn action(value: &str) -> ActionId {
        ActionId::new(value).unwrap_or_else(|error| panic!("action id: {error}"))
    }

    fn record(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
    }

    fn node(tenant_id: &TenantId, id: &str, kind: CausalLineageNodeKind) -> CausalLineageNode {
        CausalLineageNode {
            tenant_id: tenant_id.clone(),
            node_id: record(id),
            kind,
        }
    }

    fn edge(
        tenant_id: &TenantId,
        parent: &str,
        child: &str,
        kind: CausalLineageEdgeKind,
    ) -> CausalLineageEdge {
        CausalLineageEdge {
            tenant_id: tenant_id.clone(),
            parent_id: record(parent),
            child_id: record(child),
            kind,
        }
    }

    fn snapshot() -> CausalLineageSnapshot {
        let tenant_id = tenant("tenant-a");
        CausalLineageSnapshot {
            tenant_id: tenant_id.clone(),
            metadata: CausalLineageCommitMetadata {
                source_lineage_version: 4,
                observed_commit_index: 11,
                authoritative_commit_index: 11,
                completeness_watermark: Some(11),
            },
            nodes: CausalLineageNodes::new(vec![
                node(&tenant_id, "cap-root", CausalLineageNodeKind::Capability),
                node(&tenant_id, "cap-child", CausalLineageNodeKind::Capability),
                node(&tenant_id, "receipt-a", CausalLineageNodeKind::Receipt),
                node(&tenant_id, "receipt-b", CausalLineageNodeKind::Receipt),
            ])
            .unwrap_or_else(|error| panic!("bounded nodes: {error}")),
            edges: CausalLineageEdges::new(vec![
                edge(
                    &tenant_id,
                    "cap-root",
                    "cap-child",
                    CausalLineageEdgeKind::CapabilityDelegation,
                ),
                edge(
                    &tenant_id,
                    "cap-child",
                    "receipt-a",
                    CausalLineageEdgeKind::CapabilityReceipt,
                ),
                edge(
                    &tenant_id,
                    "receipt-a",
                    "receipt-b",
                    CausalLineageEdgeKind::ReceiptLineage,
                ),
            ])
            .unwrap_or_else(|error| panic!("bounded edges: {error}")),
            depth_truncated: false,
            nodes_truncated: false,
            edges_truncated: false,
        }
    }

    fn request() -> BlastRadiusRequest {
        BlastRadiusRequest {
            tenant_id: tenant("tenant-a"),
            action_id: action("action-a"),
            seed_ids: chio_security_types::ports::BlastRadiusSeeds::new(vec![record("cap-root")])
                .unwrap_or_else(|error| panic!("bounded seeds: {error}")),
            query_bounds: BlastRadiusQueryBounds {
                max_depth: 8,
                max_nodes: 32,
                max_edges: 32,
            },
        }
    }

    fn expected_fence_request(
        request: &BlastRadiusRequest,
        approved: &BlastRadiusResult,
        expires_at_unix_ms: u64,
    ) -> LineageFenceRequest {
        let BlastRadiusResult::Exact {
            metadata,
            affected_set_hash,
            ..
        } = approved
        else {
            return LineageFenceRequest {
                tenant_id: request.tenant_id.clone(),
                action_id: request.action_id.clone(),
                expected_commit_index: 1,
                expected_affected_set_hash: Digest32::new([1; 32]),
                scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
                    "blast-test-worker",
                )
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
                scheduler_fencing_token: 19,
                expires_at_unix_ms,
            };
        };
        LineageFenceRequest {
            tenant_id: request.tenant_id.clone(),
            action_id: request.action_id.clone(),
            expected_commit_index: metadata.commit_index,
            expected_affected_set_hash: *affected_set_hash,
            scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
                "blast-test-worker",
            )
            .unwrap_or_else(|error| panic!("lease owner: {error}")),
            scheduler_fencing_token: 19,
            expires_at_unix_ms,
        }
    }

    fn resolver(
        steps: Vec<SnapshotStep>,
    ) -> (
        CausalBlastRadiusResolver<FakeLineage, FakeFences>,
        Arc<FakeLineage>,
        Arc<FakeFences>,
    ) {
        let lineage = Arc::new(FakeLineage::new(steps));
        let fences = Arc::new(FakeFences::default());
        (
            CausalBlastRadiusResolver::new(Arc::clone(&lineage), Arc::clone(&fences)),
            lineage,
            fences,
        )
    }

    #[test]
    fn exact_snapshot_returns_sorted_capability_targets_and_committed_graph_evidence() {
        let (resolver, lineage, fences) = resolver(vec![SnapshotStep::Snapshot(snapshot())]);
        let first = resolver.resolve(&request());
        let second = resolver.resolve(&request());

        let BlastRadiusResult::Exact {
            metadata,
            sorted_affected_ids,
            affected_set_hash,
            graph_slice_hash,
        } = first
        else {
            panic!("complete authoritative graph was not exact");
        };
        assert_eq!(metadata.query_bounds, request().query_bounds);
        assert_eq!(metadata.source_lineage_version, 4);
        assert_eq!(metadata.commit_index, 11);
        assert_eq!(metadata.completeness_watermark, Some(11));
        assert_eq!(
            sorted_affected_ids.as_slice(),
            &[record("cap-child"), record("cap-root")]
        );
        assert_ne!(affected_set_hash, Digest32::new([0; 32]));
        assert_ne!(graph_slice_hash, Digest32::new([0; 32]));
        assert!(matches!(
            second,
            BlastRadiusResult::Exact {
                affected_set_hash: second_affected,
                graph_slice_hash: second_graph,
                ..
            } if second_affected == affected_set_hash && second_graph == graph_slice_hash
        ));
        assert_eq!(lineage.requests().len(), 2);
        assert!(lineage
            .requests()
            .iter()
            .all(|query| query.fence_action_id.is_none()));
        assert_eq!(fences.acquisition_count(), 0);
    }

    #[test]
    fn exact_branch_deduplicates_shared_descendants_and_sorts_capability_targets() {
        let mut branched = snapshot();
        let mut nodes = branched.nodes.clone().into_vec();
        nodes.push(node(
            &branched.tenant_id,
            "cap-branch",
            CausalLineageNodeKind::Capability,
        ));
        branched.nodes =
            CausalLineageNodes::new(nodes).unwrap_or_else(|error| panic!("branch nodes: {error}"));
        let mut edges = branched.edges.clone().into_vec();
        edges.push(edge(
            &branched.tenant_id,
            "cap-root",
            "cap-branch",
            CausalLineageEdgeKind::CapabilityDelegation,
        ));
        edges.push(edge(
            &branched.tenant_id,
            "cap-branch",
            "receipt-a",
            CausalLineageEdgeKind::CapabilityReceipt,
        ));
        branched.edges =
            CausalLineageEdges::new(edges).unwrap_or_else(|error| panic!("branch edges: {error}"));
        let (resolver, _, _) = resolver(vec![SnapshotStep::Snapshot(branched)]);

        let BlastRadiusResult::Exact {
            sorted_affected_ids,
            ..
        } = resolver.resolve(&request())
        else {
            panic!("complete branch was not exact");
        };
        assert_eq!(
            sorted_affected_ids.as_slice(),
            &[
                record("cap-branch"),
                record("cap-child"),
                record("cap-root")
            ]
        );
    }

    #[test]
    fn corruption_truncation_lag_and_missing_completeness_are_never_exact() {
        let mut cases = Vec::new();

        let mut cycle = snapshot();
        let mut cycle_edges = cycle.edges.clone().into_vec();
        cycle_edges.push(edge(
            &cycle.tenant_id,
            "cap-child",
            "cap-root",
            CausalLineageEdgeKind::CapabilityDelegation,
        ));
        cycle.edges = CausalLineageEdges::new(cycle_edges)
            .unwrap_or_else(|error| panic!("cycle edges: {error}"));
        cases.push(cycle);

        let mut cross_tenant = snapshot();
        let mut cross_tenant_nodes = cross_tenant.nodes.clone().into_vec();
        cross_tenant_nodes[1].tenant_id = tenant("tenant-b");
        cross_tenant.nodes = CausalLineageNodes::new(cross_tenant_nodes)
            .unwrap_or_else(|error| panic!("cross-tenant nodes: {error}"));
        cases.push(cross_tenant);

        let mut cross_tenant_edge = snapshot();
        let mut cross_tenant_edges = cross_tenant_edge.edges.clone().into_vec();
        cross_tenant_edges[0].tenant_id = tenant("tenant-b");
        cross_tenant_edge.edges = CausalLineageEdges::new(cross_tenant_edges)
            .unwrap_or_else(|error| panic!("cross-tenant edges: {error}"));
        cases.push(cross_tenant_edge);

        let mut missing_seed = snapshot();
        let mut missing_seed_nodes = missing_seed.nodes.clone().into_vec();
        missing_seed_nodes[0].node_id = record("cap-other");
        missing_seed.nodes = CausalLineageNodes::new(missing_seed_nodes)
            .unwrap_or_else(|error| panic!("missing-seed nodes: {error}"));
        cases.push(missing_seed);

        let mut depth_truncated = snapshot();
        depth_truncated.depth_truncated = true;
        cases.push(depth_truncated);

        let mut node_truncated = snapshot();
        node_truncated.nodes_truncated = true;
        cases.push(node_truncated);

        let mut edge_truncated = snapshot();
        edge_truncated.edges_truncated = true;
        cases.push(edge_truncated);

        let mut lagged = snapshot();
        lagged.metadata.authoritative_commit_index = 12;
        cases.push(lagged);

        let mut no_watermark = snapshot();
        no_watermark.metadata.completeness_watermark = None;
        cases.push(no_watermark);

        let mut corrupt_edge = snapshot();
        let mut corrupt_edges = corrupt_edge.edges.clone().into_vec();
        corrupt_edges.push(edge(
            &corrupt_edge.tenant_id,
            "receipt-b",
            "missing-node",
            CausalLineageEdgeKind::ReceiptLineage,
        ));
        corrupt_edge.edges = CausalLineageEdges::new(corrupt_edges)
            .unwrap_or_else(|error| panic!("corrupt edges: {error}"));
        cases.push(corrupt_edge);

        for case in cases {
            let (resolver, _, _) = resolver(vec![SnapshotStep::Snapshot(case)]);
            assert!(matches!(
                resolver.resolve(&request()),
                BlastRadiusResult::Incomplete { .. }
            ));
        }

        let (resolver, _, _) = resolver(vec![SnapshotStep::Failure]);
        assert!(matches!(
            resolver.resolve(&request()),
            BlastRadiusResult::Incomplete { .. }
        ));
    }

    #[test]
    fn duplicate_edges_do_not_change_the_exact_graph_commitment() {
        let original = snapshot();
        let mut duplicate = original.clone();
        let mut duplicate_edges = duplicate.edges.clone().into_vec();
        duplicate_edges.push(original.edges.as_slice()[0].clone());
        duplicate.edges = CausalLineageEdges::new(duplicate_edges)
            .unwrap_or_else(|error| panic!("duplicate edges: {error}"));
        let (baseline, _, _) = resolver(vec![SnapshotStep::Snapshot(original)]);
        let (deduplicated, _, _) = resolver(vec![SnapshotStep::Snapshot(duplicate)]);

        assert_eq!(
            baseline.resolve(&request()),
            deduplicated.resolve(&request())
        );
    }

    #[test]
    fn changed_descendant_under_fence_releases_and_invalidates_approval() {
        let approved_snapshot = snapshot();
        let mut changed = approved_snapshot.clone();
        changed.metadata.observed_commit_index = 12;
        changed.metadata.authoritative_commit_index = 12;
        changed.metadata.completeness_watermark = Some(12);
        let mut changed_nodes = changed.nodes.clone().into_vec();
        changed_nodes.push(node(
            &changed.tenant_id,
            "cap-new-child",
            CausalLineageNodeKind::Capability,
        ));
        changed.nodes = CausalLineageNodes::new(changed_nodes)
            .unwrap_or_else(|error| panic!("new descendant nodes: {error}"));
        let mut changed_edges = changed.edges.clone().into_vec();
        changed_edges.push(edge(
            &changed.tenant_id,
            "cap-root",
            "cap-new-child",
            CausalLineageEdgeKind::CapabilityDelegation,
        ));
        changed.edges = CausalLineageEdges::new(changed_edges)
            .unwrap_or_else(|error| panic!("new descendant edges: {error}"));
        let (resolver, lineage, fences) = resolver(vec![
            SnapshotStep::Snapshot(approved_snapshot),
            SnapshotStep::Snapshot(changed),
        ]);
        let blast_request = request();
        let approved = resolver.resolve(&blast_request);
        let expected = expected_fence_request(&blast_request, &approved, 50_000);

        let error =
            match resolver.acquire_validated_fence(&blast_request, &approved, 50_000, &expected) {
                Ok(_) => panic!("changed descendant must invalidate approval"),
                Err(error) => error,
            };
        assert_eq!(error, FenceValidationOutcome::ApprovalInvalidated);
        assert_eq!(fences.acquisition_count(), 1);
        assert_eq!(fences.release_count(), 1);
        assert_eq!(lineage.requests().len(), 2);
        assert!(lineage.requests()[0].fence_action_id.is_none());
        assert_eq!(
            lineage.requests()[1].fence_action_id.as_ref(),
            Some(&request().action_id)
        );
    }

    #[test]
    fn exact_fence_is_requeried_and_can_be_recovered_by_exact_action_binding() {
        let stable = snapshot();
        let (resolver, lineage, fences) = resolver(vec![
            SnapshotStep::Snapshot(stable.clone()),
            SnapshotStep::Snapshot(stable),
        ]);
        let blast_request = request();
        let approved = resolver.resolve(&blast_request);
        let expected = expected_fence_request(&blast_request, &approved, 50_000);
        let fence = resolver
            .acquire_validated_fence(&blast_request, &approved, 50_000, &expected)
            .unwrap_or_else(|error| panic!("exact fence acquisition failed: {error:?}"));
        assert_eq!(fence.commit_index, 11);
        assert_eq!(fence.expires_at_unix_ms, 50_000);
        assert_eq!(fences.acquisition_count(), 1);
        assert_eq!(fences.release_count(), 0);
        assert_eq!(lineage.requests().len(), 2);
        assert_eq!(
            lineage.requests()[1].fence_action_id.as_ref(),
            Some(&blast_request.action_id)
        );

        let recovered = resolver
            .query_validated_fence(&LineageFenceRequest {
                tenant_id: blast_request.tenant_id,
                action_id: blast_request.action_id,
                expected_commit_index: 11,
                expected_affected_set_hash: fence.affected_set_hash,
                scheduler_lease_owner_id: fence.scheduler_lease_owner_id.clone(),
                scheduler_fencing_token: fence.scheduler_fencing_token,
                expires_at_unix_ms: 50_000,
            })
            .unwrap_or_else(|error| panic!("exact fence query failed: {error:?}"));
        assert_eq!(recovered, Some(fence));
    }

    #[test]
    fn dynamic_blast_radius_port_cannot_bypass_frozen_set_and_requery() {
        let stable = snapshot();
        let (resolver, lineage, fences) = resolver(vec![
            SnapshotStep::Snapshot(stable.clone()),
            SnapshotStep::Snapshot(stable),
        ]);
        let port: &dyn BlastRadiusPort = &resolver;
        let blast_request = request();
        let approved = port
            .resolve(&blast_request)
            .unwrap_or_else(|error| panic!("blast resolution failed: {error}"));
        let expected = expected_fence_request(&blast_request, &approved, 50_000);
        let fence = port
            .acquire_fence(
                &BlastRadiusFenceAcquisition {
                    request: blast_request.clone(),
                    approved_result: approved,
                    expires_at_unix_ms: 50_000,
                },
                &expected,
            )
            .unwrap_or_else(|error| panic!("validated trait acquisition failed: {error}"));

        assert_eq!(fence.commit_index, 11);
        assert_eq!(lineage.requests().len(), 2);
        assert_eq!(
            lineage.requests()[1].fence_action_id.as_ref(),
            Some(&blast_request.action_id)
        );
        let causal_acquisitions = fences.causal_acquisitions();
        assert_eq!(causal_acquisitions.len(), 1);
        assert_eq!(
            causal_acquisitions[0].frozen_affected_ids.as_slice(),
            &[record("cap-child"), record("cap-root")]
        );
    }

    #[test]
    fn invalid_or_incomplete_approval_never_acquires_a_fence() {
        let stable = snapshot();
        let (resolver, _, fences) = resolver(vec![SnapshotStep::Snapshot(stable)]);
        let blast_request = request();
        let incomplete = BlastRadiusResult::Incomplete {
            metadata: fallback_metadata(&blast_request.query_bounds),
            reason: BlastRadiusIncompleteReason::ReplicaLag,
        };
        let incomplete_expected = expected_fence_request(&blast_request, &incomplete, 50_000);
        assert_eq!(
            resolver.acquire_validated_fence(
                &blast_request,
                &incomplete,
                50_000,
                &incomplete_expected,
            ),
            Err(FenceValidationOutcome::InvalidApprovedResult)
        );

        let mut forged = resolver.resolve(&blast_request);
        if let BlastRadiusResult::Exact {
            affected_set_hash, ..
        } = &mut forged
        {
            *affected_set_hash = Digest32::new([9; 32]);
        } else {
            panic!("stable snapshot was not exact");
        }
        let forged_expected = expected_fence_request(&blast_request, &forged, 50_000);
        assert_eq!(
            resolver.acquire_validated_fence(&blast_request, &forged, 50_000, &forged_expected,),
            Err(FenceValidationOutcome::InvalidApprovedResult)
        );
        assert_eq!(fences.acquisition_count(), 0);
        assert_eq!(fences.release_count(), 0);
    }

    #[test]
    fn corrupt_acquire_or_query_fence_binding_fails_closed() {
        let stable = snapshot();
        let (acquire_resolver, _, fences) = resolver(vec![
            SnapshotStep::Snapshot(stable.clone()),
            SnapshotStep::Snapshot(stable),
        ]);
        let blast_request = request();
        let approved = acquire_resolver.resolve(&blast_request);
        let expected = expected_fence_request(&blast_request, &approved, 50_000);
        fences.override_acquire(LineageFence {
            tenant_id: tenant("tenant-b"),
            action_id: blast_request.action_id.clone(),
            commit_index: 11,
            affected_set_hash: Digest32::new([8; 32]),
            fencing_token: 0,
            scheduler_lease_owner_id: expected.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: expected.scheduler_fencing_token,
            expires_at_unix_ms: 50_000,
        });
        assert_eq!(
            acquire_resolver.acquire_validated_fence(&blast_request, &approved, 50_000, &expected,),
            Err(FenceValidationOutcome::PortFailure)
        );
        assert_eq!(fences.release_count(), 0);

        let stable = snapshot();
        let (usable_resolver, _, usable_fences) = resolver(vec![
            SnapshotStep::Snapshot(stable.clone()),
            SnapshotStep::Snapshot(stable),
        ]);
        let usable_approved = usable_resolver.resolve(&blast_request);
        let usable_expected = expected_fence_request(&blast_request, &usable_approved, 50_000);
        usable_fences.override_acquire(LineageFence {
            tenant_id: blast_request.tenant_id.clone(),
            action_id: blast_request.action_id.clone(),
            commit_index: 12,
            affected_set_hash: Digest32::new([7; 32]),
            fencing_token: 7,
            scheduler_lease_owner_id: usable_expected.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: usable_expected.scheduler_fencing_token,
            expires_at_unix_ms: 50_000,
        });
        assert_eq!(
            usable_resolver.acquire_validated_fence(
                &blast_request,
                &usable_approved,
                50_000,
                &usable_expected,
            ),
            Err(FenceValidationOutcome::PortFailure)
        );
        assert_eq!(usable_fences.release_count(), 1);

        let (_, _, query_fences) = resolver(vec![SnapshotStep::Snapshot(snapshot())]);
        query_fences.override_query(LineageFence {
            tenant_id: blast_request.tenant_id.clone(),
            action_id: blast_request.action_id.clone(),
            commit_index: 12,
            affected_set_hash: Digest32::new([9; 32]),
            fencing_token: 2,
            scheduler_lease_owner_id: usable_expected.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: usable_expected.scheduler_fencing_token,
            expires_at_unix_ms: 50_000,
        });
        let query_resolver = CausalBlastRadiusResolver::new(
            Arc::new(FakeLineage::new(vec![SnapshotStep::Snapshot(snapshot())])),
            Arc::clone(&query_fences),
        );
        assert_eq!(
            query_resolver.query_validated_fence(&LineageFenceRequest {
                tenant_id: blast_request.tenant_id,
                action_id: blast_request.action_id,
                expected_commit_index: 11,
                expected_affected_set_hash: Digest32::new([8; 32]),
                scheduler_lease_owner_id: usable_expected.scheduler_lease_owner_id,
                scheduler_fencing_token: usable_expected.scheduler_fencing_token,
                expires_at_unix_ms: 50_000,
            }),
            Err(FenceValidationOutcome::PortFailure)
        );
    }
}
