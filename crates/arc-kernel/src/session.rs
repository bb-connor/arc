use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_core::crypto::{canonical_json_bytes, sha256_hex};
use arc_core::session::{
    CompletionResult, CreateElicitationOperation, NormalizedRoot, OperationContext, OperationKind,
    OperationTerminalState, ProgressToken, PromptDefinition, PromptResult, RequestId,
    RequestOwnershipSnapshot, ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
    RootDefinition, SessionAnchorReference, SessionAuthContext, SessionId,
};
use arc_core::{AgentId, CapabilityToken};

use crate::{ToolCallResponse, ToolServerEvent};
use arc_core::receipt::ArcReceipt;

/// Lifecycle state of a logical kernel session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Initializing,
    Ready,
    Draining,
    Closed,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }
}

/// Feature flags negotiated with the peer at session establishment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCapabilities {
    pub supports_progress: bool,
    pub supports_cancellation: bool,
    pub supports_subscriptions: bool,
    pub supports_arc_tool_streaming: bool,
    pub supports_roots: bool,
    pub roots_list_changed: bool,
    pub supports_sampling: bool,
    pub sampling_context: bool,
    pub sampling_tools: bool,
    pub supports_elicitation: bool,
    pub elicitation_form: bool,
    pub elicitation_url: bool,
}

/// Bookkeeping record for an in-flight request.
#[derive(Debug, Clone)]
pub struct InflightRequest {
    pub request_id: RequestId,
    pub parent_request_id: Option<RequestId>,
    pub operation_kind: OperationKind,
    pub session_anchor_id: String,
    pub started_at: Instant,
    pub progress_token: Option<ProgressToken>,
    pub cancellation_requested: bool,
    pub cancellable: bool,
}

impl InflightRequest {
    pub fn ownership(&self) -> RequestOwnershipSnapshot {
        RequestOwnershipSnapshot::request_owned()
    }
}

/// Registry of requests that are currently active within a session.
#[derive(Debug, Clone, Default)]
pub struct InflightRegistry {
    requests: HashMap<RequestId, InflightRequest>,
}

impl InflightRegistry {
    pub fn track(
        &mut self,
        context: &OperationContext,
        operation_kind: OperationKind,
        session_anchor_id: &str,
        cancellable: bool,
    ) -> Result<(), SessionError> {
        if self.requests.contains_key(&context.request_id) {
            return Err(SessionError::DuplicateInflightRequest {
                request_id: context.request_id.clone(),
            });
        }

        self.requests.insert(
            context.request_id.clone(),
            InflightRequest {
                request_id: context.request_id.clone(),
                parent_request_id: context.parent_request_id.clone(),
                operation_kind,
                session_anchor_id: session_anchor_id.to_string(),
                started_at: Instant::now(),
                progress_token: context.progress_token.clone(),
                cancellation_requested: false,
                cancellable,
            },
        );
        Ok(())
    }

    pub fn complete(&mut self, request_id: &RequestId) -> Result<InflightRequest, SessionError> {
        self.requests
            .remove(request_id)
            .ok_or_else(|| SessionError::RequestNotInflight {
                request_id: request_id.clone(),
            })
    }

    pub fn mark_cancellation_requested(
        &mut self,
        request_id: &RequestId,
    ) -> Result<(), SessionError> {
        let request =
            self.requests
                .get_mut(request_id)
                .ok_or_else(|| SessionError::RequestNotInflight {
                    request_id: request_id.clone(),
                })?;

        if !request.cancellable {
            return Err(SessionError::RequestNotCancellable {
                request_id: request_id.clone(),
            });
        }

        request.cancellation_requested = true;
        Ok(())
    }

    pub fn get(&self, request_id: &RequestId) -> Option<&InflightRequest> {
        self.requests.get(request_id)
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    pub fn clear(&mut self) {
        self.requests.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SubscriptionSubject {
    Resource(String),
}

/// Registry for session-scoped subscriptions.
#[derive(Debug, Clone, Default)]
pub struct SubscriptionRegistry {
    subscriptions: HashSet<SubscriptionSubject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LateSessionEvent {
    ElicitationCompleted {
        elicitation_id: String,
        related_task_id: Option<String>,
    },
    ResourceUpdated {
        uri: String,
    },
    ResourcesListChanged,
    ToolsListChanged,
    PromptsListChanged,
}

#[derive(Debug, Clone)]
struct PendingUrlElicitation {
    related_task_id: Option<String>,
}

impl SubscriptionRegistry {
    pub fn subscribe_resource(&mut self, uri: impl Into<String>) {
        self.subscriptions
            .insert(SubscriptionSubject::Resource(uri.into()));
    }

    pub fn unsubscribe_resource(&mut self, uri: &str) {
        self.subscriptions
            .remove(&SubscriptionSubject::Resource(uri.to_string()));
    }

    pub fn contains_resource(&self, uri: &str) -> bool {
        self.subscriptions
            .contains(&SubscriptionSubject::Resource(uri.to_string()))
    }

    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }

    pub fn clear(&mut self) {
        self.subscriptions.clear();
    }
}

const TERMINAL_HISTORY_LIMIT: usize = 256;

/// Bounded history of terminal request outcomes for a session.
#[derive(Debug, Clone)]
pub struct TerminalRegistry {
    states: HashMap<RequestId, OperationTerminalState>,
    order: VecDeque<RequestId>,
    limit: usize,
}

impl Default for TerminalRegistry {
    fn default() -> Self {
        Self {
            states: HashMap::new(),
            order: VecDeque::new(),
            limit: TERMINAL_HISTORY_LIMIT,
        }
    }
}

impl TerminalRegistry {
    pub fn record(&mut self, request_id: RequestId, state: OperationTerminalState) {
        if !self.states.contains_key(&request_id) {
            self.order.push_back(request_id.clone());
        }
        self.states.insert(request_id, state);

        while self.order.len() > self.limit {
            if let Some(oldest) = self.order.pop_front() {
                self.states.remove(&oldest);
            }
        }
    }

    pub fn get(&self, request_id: &RequestId) -> Option<&OperationTerminalState> {
        self.states.get(request_id)
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

/// Errors for session lifecycle and in-flight management.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("invalid session transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },

    #[error("session {session_id} cannot handle {operation} while {state}")]
    OperationNotAllowed {
        session_id: SessionId,
        operation: &'static str,
        state: &'static str,
    },

    #[error("operation context session {actual} does not match runtime session {expected}")]
    ContextSessionMismatch {
        expected: SessionId,
        actual: SessionId,
    },

    #[error("operation context agent {actual} does not match session agent {expected}")]
    ContextAgentMismatch { expected: AgentId, actual: AgentId },

    #[error("request {request_id} is already in flight")]
    DuplicateInflightRequest { request_id: RequestId },

    #[error("request {request_id} already has authoritative lineage in this session")]
    DuplicateRequestLineage { request_id: RequestId },

    #[error("request {request_id} is not in flight")]
    RequestNotInflight { request_id: RequestId },

    #[error("request {request_id} is not cancellable")]
    RequestNotCancellable { request_id: RequestId },

    #[error("parent request {parent_request_id} is not in flight for child request {request_id}")]
    ParentRequestNotInflight {
        request_id: RequestId,
        parent_request_id: RequestId,
    },

    #[error(
        "parent request {parent_request_id} for child request {request_id} belongs to stale session anchor {parent_session_anchor_id}, current anchor is {current_session_anchor_id}"
    )]
    ParentRequestAnchorMismatch {
        request_id: RequestId,
        parent_request_id: RequestId,
        parent_session_anchor_id: String,
        current_session_anchor_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAnchorState {
    id: String,
    auth_epoch: u64,
    auth_context_hash: String,
    issued_at: u64,
}

impl SessionAnchorState {
    fn new(session_id: &SessionId, auth_context: &SessionAuthContext, auth_epoch: u64) -> Self {
        let auth_context_hash = auth_context_hash(auth_context);
        let hash_prefix = &auth_context_hash[..12.min(auth_context_hash.len())];
        Self {
            id: format!("{session_id}:anchor:{auth_epoch}:{hash_prefix}"),
            auth_epoch,
            auth_context_hash,
            issued_at: current_unix_timestamp(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn auth_epoch(&self) -> u64 {
        self.auth_epoch
    }

    pub fn auth_context_hash(&self) -> &str {
        &self.auth_context_hash
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn reference(&self) -> SessionAnchorReference {
        SessionAnchorReference::new(self.id.clone(), self.auth_context_hash.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLineageRecord {
    pub request_id: RequestId,
    pub session_anchor_id: String,
    pub auth_epoch: u64,
    pub parent_request_id: Option<RequestId>,
    pub operation_kind: OperationKind,
    pub started_at: u64,
    pub terminal_state: Option<OperationTerminalState>,
}

/// Session host object owned by the kernel.
#[derive(Debug, Clone)]
pub struct Session {
    id: SessionId,
    agent_id: AgentId,
    state: SessionState,
    session_anchor: SessionAnchorState,
    auth_context: SessionAuthContext,
    peer_capabilities: PeerCapabilities,
    roots: Vec<RootDefinition>,
    normalized_roots: Vec<NormalizedRoot>,
    issued_capabilities: Vec<CapabilityToken>,
    inflight: InflightRegistry,
    subscriptions: SubscriptionRegistry,
    terminal: TerminalRegistry,
    request_lineage: HashMap<RequestId, RequestLineageRecord>,
    pending_url_elicitations: HashMap<String, PendingUrlElicitation>,
    late_events: VecDeque<LateSessionEvent>,
}

impl Session {
    pub fn new(
        id: SessionId,
        agent_id: AgentId,
        issued_capabilities: Vec<CapabilityToken>,
    ) -> Self {
        let auth_context = SessionAuthContext::in_process_anonymous();
        let session_anchor = SessionAnchorState::new(&id, &auth_context, 0);
        Self {
            id,
            agent_id,
            state: SessionState::Initializing,
            session_anchor,
            auth_context,
            peer_capabilities: PeerCapabilities::default(),
            roots: Vec::new(),
            normalized_roots: Vec::new(),
            issued_capabilities,
            inflight: InflightRegistry::default(),
            subscriptions: SubscriptionRegistry::default(),
            terminal: TerminalRegistry::default(),
            request_lineage: HashMap::new(),
            pending_url_elicitations: HashMap::new(),
            late_events: VecDeque::new(),
        }
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn auth_context(&self) -> &SessionAuthContext {
        &self.auth_context
    }

    pub fn session_anchor(&self) -> &SessionAnchorState {
        &self.session_anchor
    }

    pub fn request_lineage(&self, request_id: &RequestId) -> Option<&RequestLineageRecord> {
        self.request_lineage.get(request_id)
    }

    pub fn peer_capabilities(&self) -> &PeerCapabilities {
        &self.peer_capabilities
    }

    pub fn capabilities(&self) -> &[CapabilityToken] {
        &self.issued_capabilities
    }

    pub fn roots(&self) -> &[RootDefinition] {
        &self.roots
    }

    pub fn normalized_roots(&self) -> &[NormalizedRoot] {
        &self.normalized_roots
    }

    pub fn enforceable_filesystem_roots(&self) -> impl Iterator<Item = &NormalizedRoot> {
        self.normalized_roots
            .iter()
            .filter(|root| root.is_enforceable_filesystem())
    }

    pub fn inflight(&self) -> &InflightRegistry {
        &self.inflight
    }

    pub fn subscriptions(&self) -> &SubscriptionRegistry {
        &self.subscriptions
    }

    pub fn terminal(&self) -> &TerminalRegistry {
        &self.terminal
    }

    pub fn register_pending_url_elicitation(
        &mut self,
        elicitation_id: impl Into<String>,
        related_task_id: Option<String>,
    ) {
        self.pending_url_elicitations.insert(
            elicitation_id.into(),
            PendingUrlElicitation { related_task_id },
        );
    }

    pub fn register_required_url_elicitations(
        &mut self,
        elicitations: &[CreateElicitationOperation],
        related_task_id: Option<&str>,
    ) {
        for elicitation in elicitations {
            let CreateElicitationOperation::Url { elicitation_id, .. } = elicitation else {
                continue;
            };
            self.register_pending_url_elicitation(
                elicitation_id.clone(),
                related_task_id.map(ToString::to_string),
            );
        }
    }

    pub fn queue_late_event(&mut self, event: LateSessionEvent) {
        self.late_events.push_back(event);
    }

    pub fn take_late_events(&mut self) -> Vec<LateSessionEvent> {
        self.late_events.drain(..).collect()
    }

    pub fn queue_tool_server_event(&mut self, event: ToolServerEvent) {
        match event {
            ToolServerEvent::ElicitationCompleted { elicitation_id } => {
                let Some(pending) = self.pending_url_elicitations.remove(&elicitation_id) else {
                    return;
                };
                self.queue_late_event(LateSessionEvent::ElicitationCompleted {
                    elicitation_id,
                    related_task_id: pending.related_task_id,
                });
            }
            ToolServerEvent::ResourceUpdated { uri } => {
                if self.is_resource_subscribed(&uri) {
                    self.queue_late_event(LateSessionEvent::ResourceUpdated { uri });
                }
            }
            ToolServerEvent::ResourcesListChanged => {
                self.queue_late_event(LateSessionEvent::ResourcesListChanged);
            }
            ToolServerEvent::ToolsListChanged => {
                self.queue_late_event(LateSessionEvent::ToolsListChanged);
            }
            ToolServerEvent::PromptsListChanged => {
                self.queue_late_event(LateSessionEvent::PromptsListChanged);
            }
        }
    }

    pub fn queue_elicitation_completion(&mut self, elicitation_id: &str) {
        let Some(pending) = self.pending_url_elicitations.remove(elicitation_id) else {
            return;
        };
        self.queue_late_event(LateSessionEvent::ElicitationCompleted {
            elicitation_id: elicitation_id.to_string(),
            related_task_id: pending.related_task_id,
        });
    }

    pub fn subscribe_resource(&mut self, uri: impl Into<String>) {
        self.subscriptions.subscribe_resource(uri);
    }

    pub fn unsubscribe_resource(&mut self, uri: &str) {
        self.subscriptions.unsubscribe_resource(uri);
    }

    pub fn is_resource_subscribed(&self, uri: &str) -> bool {
        self.subscriptions.contains_resource(uri)
    }

    pub fn set_auth_context(&mut self, auth_context: SessionAuthContext) -> bool {
        let rotated = self.auth_context != auth_context;
        if rotated {
            let next_epoch = self.session_anchor.auth_epoch.saturating_add(1);
            self.session_anchor = SessionAnchorState::new(&self.id, &auth_context, next_epoch);
        }
        self.auth_context = auth_context;
        rotated
    }

    pub fn set_peer_capabilities(&mut self, peer_capabilities: PeerCapabilities) {
        self.peer_capabilities = peer_capabilities;
    }

    pub fn replace_roots(&mut self, roots: Vec<RootDefinition>) {
        self.normalized_roots = roots
            .iter()
            .map(RootDefinition::normalize_for_runtime)
            .collect();
        self.roots = roots;
    }

    pub fn activate(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::Ready)
    }

    pub fn begin_draining(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::Draining)
    }

    pub fn close(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::Closed)?;
        self.inflight.clear();
        self.subscriptions.clear();
        self.roots.clear();
        self.normalized_roots.clear();
        self.pending_url_elicitations.clear();
        self.late_events.clear();
        Ok(())
    }

    pub fn ensure_operation_allowed(&self, operation: OperationKind) -> Result<(), SessionError> {
        let allowed = match self.state {
            SessionState::Initializing => matches!(
                operation,
                OperationKind::ListCapabilities | OperationKind::Heartbeat
            ),
            SessionState::Ready => true,
            SessionState::Draining => matches!(
                operation,
                OperationKind::ListCapabilities | OperationKind::Heartbeat
            ),
            SessionState::Closed => false,
        };

        if allowed {
            Ok(())
        } else {
            Err(SessionError::OperationNotAllowed {
                session_id: self.id.clone(),
                operation: operation.as_str(),
                state: self.state.as_str(),
            })
        }
    }

    pub fn track_request(
        &mut self,
        context: &OperationContext,
        operation_kind: OperationKind,
        cancellable: bool,
    ) -> Result<(), SessionError> {
        self.validate_context(context)?;
        if let Some(parent_request_id) = &context.parent_request_id {
            self.validate_parent_request_lineage(&context.request_id, parent_request_id)?;
        }
        if self.request_lineage.contains_key(&context.request_id) {
            return Err(SessionError::DuplicateRequestLineage {
                request_id: context.request_id.clone(),
            });
        }
        self.inflight.track(
            context,
            operation_kind,
            self.session_anchor.id(),
            cancellable,
        )?;
        self.request_lineage.insert(
            context.request_id.clone(),
            RequestLineageRecord {
                request_id: context.request_id.clone(),
                session_anchor_id: self.session_anchor.id().to_string(),
                auth_epoch: self.session_anchor.auth_epoch(),
                parent_request_id: context.parent_request_id.clone(),
                operation_kind,
                started_at: current_unix_timestamp(),
                terminal_state: None,
            },
        );
        Ok(())
    }

    pub fn complete_request(
        &mut self,
        request_id: &RequestId,
    ) -> Result<InflightRequest, SessionError> {
        self.complete_request_with_terminal_state(request_id, OperationTerminalState::Completed)
    }

    pub fn complete_request_with_terminal_state(
        &mut self,
        request_id: &RequestId,
        terminal_state: OperationTerminalState,
    ) -> Result<InflightRequest, SessionError> {
        let inflight = self.inflight.complete(request_id)?;
        self.terminal
            .record(request_id.clone(), terminal_state.clone());
        if let Some(lineage) = self.request_lineage.get_mut(request_id) {
            lineage.terminal_state = Some(terminal_state);
        }
        Ok(inflight)
    }

    pub fn request_cancellation(&mut self, request_id: &RequestId) -> Result<(), SessionError> {
        self.inflight.mark_cancellation_requested(request_id)
    }

    pub fn validate_parent_request_lineage(
        &self,
        request_id: &RequestId,
        parent_request_id: &RequestId,
    ) -> Result<&RequestLineageRecord, SessionError> {
        let Some(parent_inflight) = self.inflight.get(parent_request_id) else {
            return Err(SessionError::ParentRequestNotInflight {
                request_id: request_id.clone(),
                parent_request_id: parent_request_id.clone(),
            });
        };
        let Some(parent_lineage) = self.request_lineage.get(parent_request_id) else {
            return Err(SessionError::ParentRequestNotInflight {
                request_id: request_id.clone(),
                parent_request_id: parent_request_id.clone(),
            });
        };
        if parent_lineage.session_anchor_id != self.session_anchor.id() {
            return Err(SessionError::ParentRequestAnchorMismatch {
                request_id: request_id.clone(),
                parent_request_id: parent_request_id.clone(),
                parent_session_anchor_id: parent_inflight.session_anchor_id.clone(),
                current_session_anchor_id: self.session_anchor.id().to_string(),
            });
        }
        Ok(parent_lineage)
    }

    fn transition(&mut self, next: SessionState) -> Result<(), SessionError> {
        let valid = match (self.state, next) {
            (SessionState::Initializing, SessionState::Ready)
            | (SessionState::Initializing, SessionState::Closed)
            | (SessionState::Ready, SessionState::Draining)
            | (SessionState::Ready, SessionState::Closed)
            | (SessionState::Draining, SessionState::Closed) => true,
            _ if self.state == next => true,
            _ => false,
        };

        if !valid {
            return Err(SessionError::InvalidTransition {
                from: self.state.as_str(),
                to: next.as_str(),
            });
        }

        self.state = next;
        Ok(())
    }

    pub fn validate_context(&self, context: &OperationContext) -> Result<(), SessionError> {
        if context.session_id != self.id {
            return Err(SessionError::ContextSessionMismatch {
                expected: self.id.clone(),
                actual: context.session_id.clone(),
            });
        }

        if context.agent_id != self.agent_id {
            return Err(SessionError::ContextAgentMismatch {
                expected: self.agent_id.clone(),
                actual: context.agent_id.clone(),
            });
        }

        Ok(())
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn auth_context_hash(auth_context: &SessionAuthContext) -> String {
    canonical_json_bytes(auth_context)
        .map(|bytes| sha256_hex(&bytes))
        .unwrap_or_else(|_| "session-auth-context-hash-unavailable".to_string())
}

/// Session-aware kernel response, decoupled from the current wire protocol.
#[derive(Debug)]
pub enum SessionOperationResponse {
    ToolCall(ToolCallResponse),
    RootList {
        roots: Vec<RootDefinition>,
    },
    ResourceList {
        resources: Vec<ResourceDefinition>,
    },
    ResourceRead {
        contents: Vec<ResourceContent>,
    },
    ResourceReadDenied {
        receipt: ArcReceipt,
    },
    ResourceTemplateList {
        templates: Vec<ResourceTemplateDefinition>,
    },
    PromptList {
        prompts: Vec<PromptDefinition>,
    },
    PromptGet {
        prompt: PromptResult,
    },
    Completion {
        completion: CompletionResult,
    },
    CapabilityList {
        capabilities: Vec<CapabilityToken>,
    },
    Heartbeat,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_context(request_id: &str) -> OperationContext {
        OperationContext {
            session_id: SessionId::new("sess-1"),
            request_id: RequestId::new(request_id),
            agent_id: "agent-1".to_string(),
            parent_request_id: None,
            progress_token: Some(ProgressToken::String("progress-1".to_string())),
        }
    }

    #[test]
    fn lifecycle_transitions_cover_ready_draining_closed() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

        assert_eq!(session.state(), SessionState::Initializing);
        session.activate().unwrap();
        assert_eq!(session.state(), SessionState::Ready);
        session.begin_draining().unwrap();
        assert_eq!(session.state(), SessionState::Draining);
        session.close().unwrap();
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn tool_calls_not_allowed_during_initializing_or_draining() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

        let err = session
            .ensure_operation_allowed(OperationKind::ToolCall)
            .unwrap_err();
        assert!(matches!(err, SessionError::OperationNotAllowed { .. }));

        session.activate().unwrap();
        session.begin_draining().unwrap();

        let err = session
            .ensure_operation_allowed(OperationKind::ToolCall)
            .unwrap_err();
        assert!(matches!(err, SessionError::OperationNotAllowed { .. }));
    }

    #[test]
    fn peer_capabilities_and_roots_are_session_scoped() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

        session.set_peer_capabilities(PeerCapabilities {
            supports_progress: false,
            supports_cancellation: false,
            supports_subscriptions: false,
            supports_arc_tool_streaming: false,
            supports_roots: true,
            roots_list_changed: true,
            supports_sampling: true,
            sampling_context: true,
            sampling_tools: false,
            supports_elicitation: false,
            elicitation_form: false,
            elicitation_url: false,
        });
        session.replace_roots(vec![RootDefinition {
            uri: "file:///workspace/project".to_string(),
            name: Some("Project".to_string()),
        }]);

        assert!(session.peer_capabilities().supports_roots);
        assert!(session.peer_capabilities().roots_list_changed);
        assert_eq!(session.roots().len(), 1);
        assert_eq!(session.roots()[0].uri, "file:///workspace/project");
        assert_eq!(session.normalized_roots().len(), 1);
        assert!(matches!(
            session.normalized_roots()[0],
            NormalizedRoot::EnforceableFileSystem {
                ref normalized_path,
                ..
            } if normalized_path == "/workspace/project"
        ));
        assert_eq!(session.enforceable_filesystem_roots().count(), 1);

        session.close().unwrap();
        assert!(session.roots().is_empty());
        assert!(session.normalized_roots().is_empty());
    }

    #[test]
    fn mixed_roots_preserve_metadata_without_widening_enforceable_set() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        session.replace_roots(vec![
            RootDefinition {
                uri: "file:///workspace/project/src".to_string(),
                name: Some("Code".to_string()),
            },
            RootDefinition {
                uri: "repo://docs/roadmap".to_string(),
                name: Some("Roadmap".to_string()),
            },
            RootDefinition {
                uri: "file://remote-host/workspace/project".to_string(),
                name: Some("Remote".to_string()),
            },
        ]);

        assert_eq!(session.normalized_roots().len(), 3);
        assert!(matches!(
            session.normalized_roots()[0],
            NormalizedRoot::EnforceableFileSystem {
                ref normalized_path,
                ..
            } if normalized_path == "/workspace/project/src"
        ));
        assert!(matches!(
            session.normalized_roots()[1],
            NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
        ));
        assert!(matches!(
            session.normalized_roots()[2],
            NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
                if reason == "non_local_file_authority"
        ));
        assert_eq!(session.enforceable_filesystem_roots().count(), 1);
    }

    #[test]
    fn inflight_registry_tracks_and_completes_requests() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let context = make_context("req-1");

        session.activate().unwrap();
        session
            .track_request(&context, OperationKind::ToolCall, true)
            .unwrap();
        assert_eq!(session.inflight().len(), 1);

        let completed = session.complete_request(&context.request_id).unwrap();
        assert_eq!(completed.request_id, RequestId::new("req-1"));
        assert_eq!(completed.parent_request_id, None);
        assert!(completed.cancellable);
        assert!(session.inflight().is_empty());
        assert_eq!(
            session.terminal().get(&context.request_id),
            Some(&OperationTerminalState::Completed)
        );
    }

    #[test]
    fn child_request_requires_parent_inflight() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let mut child_context = make_context("req-child");
        child_context.parent_request_id = Some(RequestId::new("req-parent"));

        session.activate().unwrap();
        let err = session
            .track_request(&child_context, OperationKind::CreateMessage, true)
            .unwrap_err();
        assert!(matches!(err, SessionError::ParentRequestNotInflight { .. }));
    }

    #[test]
    fn duplicate_inflight_request_is_rejected() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let context = make_context("req-1");

        session.activate().unwrap();
        session
            .track_request(&context, OperationKind::ToolCall, true)
            .unwrap();

        let err = session
            .track_request(&context, OperationKind::ToolCall, true)
            .unwrap_err();
        assert!(matches!(err, SessionError::DuplicateInflightRequest { .. }));
    }

    #[test]
    fn cancellation_marks_cancellable_request() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let context = make_context("req-1");

        session.activate().unwrap();
        session
            .track_request(&context, OperationKind::ToolCall, true)
            .unwrap();
        session.request_cancellation(&context.request_id).unwrap();

        let inflight = session.inflight().get(&context.request_id).unwrap();
        assert!(inflight.cancellation_requested);
    }

    #[test]
    fn inflight_request_reports_request_owned_semantics() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let context = make_context("req-1");

        session.activate().unwrap();
        session
            .track_request(&context, OperationKind::ToolCall, true)
            .unwrap();

        let inflight = session.inflight().get(&context.request_id).unwrap();
        let ownership = inflight.ownership();
        assert_eq!(ownership.work_owner, arc_core::session::WorkOwner::Request);
        assert_eq!(
            ownership.result_stream_owner,
            arc_core::session::StreamOwner::RequestStream
        );
        assert_eq!(
            ownership.terminal_state_owner,
            arc_core::session::WorkOwner::Request
        );
    }

    #[test]
    fn complete_request_can_record_cancelled_terminal_state() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let context = make_context("req-1");

        session.activate().unwrap();
        session
            .track_request(&context, OperationKind::ToolCall, true)
            .unwrap();
        session.request_cancellation(&context.request_id).unwrap();
        session
            .complete_request_with_terminal_state(
                &context.request_id,
                OperationTerminalState::Cancelled {
                    reason: "cancelled by client".to_string(),
                },
            )
            .unwrap();

        assert!(session.inflight().is_empty());
        assert_eq!(
            session.terminal().get(&context.request_id),
            Some(&OperationTerminalState::Cancelled {
                reason: "cancelled by client".to_string(),
            })
        );
    }

    #[test]
    fn resource_subscriptions_are_cleared_on_close() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

        session.activate().unwrap();
        session.subscribe_resource("repo://docs/roadmap");

        assert!(session.is_resource_subscribed("repo://docs/roadmap"));
        assert_eq!(session.subscriptions().len(), 1);

        session.close().unwrap();

        assert!(!session.is_resource_subscribed("repo://docs/roadmap"));
        assert_eq!(session.subscriptions().len(), 0);
    }

    #[test]
    fn session_anchor_rotates_on_auth_context_change() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let initial_anchor = session.session_anchor().clone();
        assert_eq!(
            session.auth_context(),
            &SessionAuthContext::in_process_anonymous()
        );

        let rotated = session.set_auth_context(SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:abcd1234",
            "cafebabe",
            Some("http://localhost:3000".to_string()),
        ));

        assert!(rotated);
        assert!(session.auth_context().is_authenticated());
        assert_eq!(
            session.auth_context().principal(),
            Some("static-bearer:abcd1234")
        );
        assert_ne!(session.session_anchor().id(), initial_anchor.id());
        assert_eq!(session.session_anchor().auth_epoch(), 1);
        assert_ne!(
            session.session_anchor().auth_context_hash(),
            initial_anchor.auth_context_hash()
        );
    }

    #[test]
    fn session_anchor_does_not_rotate_when_auth_context_is_unchanged() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let auth_context = SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:abcd1234",
            "cafebabe",
            Some("http://localhost:3000".to_string()),
        );

        assert!(session.set_auth_context(auth_context.clone()));
        let rotated_anchor = session.session_anchor().clone();
        assert!(!session.set_auth_context(auth_context));

        assert_eq!(session.session_anchor(), &rotated_anchor);
    }

    #[test]
    fn child_request_is_rejected_after_parent_anchor_rotation() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        let parent_context = make_context("req-parent");
        let mut child_context = make_context("req-child");
        child_context.parent_request_id = Some(parent_context.request_id.clone());

        session.activate().unwrap();
        session
            .track_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();
        assert!(
            session.set_auth_context(SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:abcd1234",
                "cafebabe",
                Some("http://localhost:3000".to_string()),
            ))
        );

        let err = session
            .track_request(&child_context, OperationKind::CreateMessage, true)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionError::ParentRequestAnchorMismatch { .. }
        ));
    }

    #[test]
    fn url_elicitation_completions_become_session_late_events() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        session.register_pending_url_elicitation("elicit-1", Some("task-7".to_string()));

        session.queue_elicitation_completion("elicit-1");
        session.queue_elicitation_completion("unknown");

        assert_eq!(
            session.take_late_events(),
            vec![LateSessionEvent::ElicitationCompleted {
                elicitation_id: "elicit-1".to_string(),
                related_task_id: Some("task-7".to_string()),
            }]
        );
        assert!(session.take_late_events().is_empty());
    }

    #[test]
    fn tool_server_events_are_filtered_and_stored_per_session() {
        let mut session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
        session.activate().unwrap();
        session.subscribe_resource("repo://docs/roadmap");
        session.register_pending_url_elicitation("elicit-2", None);

        session.queue_tool_server_event(ToolServerEvent::ResourceUpdated {
            uri: "repo://secret/ops".to_string(),
        });
        session.queue_tool_server_event(ToolServerEvent::ResourceUpdated {
            uri: "repo://docs/roadmap".to_string(),
        });
        session.queue_tool_server_event(ToolServerEvent::ResourcesListChanged);
        session.queue_tool_server_event(ToolServerEvent::ElicitationCompleted {
            elicitation_id: "elicit-2".to_string(),
        });

        assert_eq!(
            session.take_late_events(),
            vec![
                LateSessionEvent::ResourceUpdated {
                    uri: "repo://docs/roadmap".to_string(),
                },
                LateSessionEvent::ResourcesListChanged,
                LateSessionEvent::ElicitationCompleted {
                    elicitation_id: "elicit-2".to_string(),
                    related_task_id: None,
                },
            ]
        );
    }
}
