"""ARC LangGraph integration.

Wraps LangGraph (:mod:`langgraph`) so every node transition in a state
graph flows through the ARC sidecar for capability-scoped authorization,
and so HITL approval nodes map LangGraph's :func:`langgraph.types.interrupt`
pause/resume cycle to ARC's ``Verdict::PendingApproval`` path.

Public surface
--------------

* :func:`arc_node` -- wrap a LangGraph node callable so each dispatch
  evaluates through the ARC sidecar before the wrapped body runs. A
  deny verdict raises :class:`ArcLangGraphError`.
* :func:`arc_approval_node` -- wrap a node that must await human
  approval. Posts an approval request, pauses the graph via
  :func:`langgraph.types.interrupt`, and resumes when a decision is
  supplied via ``langgraph.types.Command(resume=...)``.
* :class:`ArcGraphConfig` -- graph-level capability wiring, including
  per-node scopes and the subgraph scope ceiling.
* :class:`ApprovalRequestPayload` / :class:`ApprovalResolution` -- wire
  shapes for the HITL approval flow.
* :class:`ArcLangGraphError` / :class:`ArcLangGraphConfigError` --
  error types.
"""

from arc_langgraph.approval import (
    ApprovalDispatcher,
    ApprovalPolicy,
    ApprovalPolicyDecision,
    ApprovalRequestPayload,
    ApprovalResolution,
    arc_approval_node,
)
from arc_langgraph.errors import ArcLangGraphConfigError, ArcLangGraphError
from arc_langgraph.nodes import arc_node
from arc_langgraph.scoping import ArcGraphConfig, enforce_subgraph_ceiling

__all__ = [
    "ApprovalDispatcher",
    "ApprovalPolicy",
    "ApprovalPolicyDecision",
    "ApprovalRequestPayload",
    "ApprovalResolution",
    "ArcGraphConfig",
    "ArcLangGraphConfigError",
    "ArcLangGraphError",
    "arc_approval_node",
    "arc_node",
    "enforce_subgraph_ceiling",
]
