"""Chio LangGraph integration.

Wraps LangGraph (:mod:`langgraph`) so every node transition in a state
graph flows through the Chio sidecar for capability-scoped authorization,
and so HITL approval nodes map LangGraph's :func:`langgraph.types.interrupt`
pause/resume cycle to Chio's ``Verdict::PendingApproval`` path.

Public surface
--------------

* :func:`chio_node` -- wrap a LangGraph node callable so each dispatch
  evaluates through the Chio sidecar before the wrapped body runs. A
  deny verdict raises :class:`ChioLangGraphError`.
* :func:`chio_approval_node` -- wrap a node that must await human
  approval. Posts an approval request, pauses the graph via
  :func:`langgraph.types.interrupt`, and resumes when a decision is
  supplied via ``langgraph.types.Command(resume=...)``.
* :class:`ChioGraphConfig` -- graph-level capability wiring, including
  per-node scopes and the subgraph scope ceiling.
* :class:`ApprovalRequestPayload` / :class:`ApprovalResolution` -- wire
  shapes for the HITL approval flow.
* :class:`ChioLangGraphError` / :class:`ChioLangGraphConfigError` --
  error types.
"""

from chio_langgraph.approval import (
    ApprovalDispatcher,
    ApprovalPolicy,
    ApprovalPolicyDecision,
    ApprovalRequestPayload,
    ApprovalResolution,
    chio_approval_node,
)
from chio_langgraph.errors import ChioLangGraphConfigError, ChioLangGraphError
from chio_langgraph.nodes import chio_node
from chio_langgraph.scoping import ChioGraphConfig, enforce_subgraph_ceiling

__all__ = [
    "ApprovalDispatcher",
    "ApprovalPolicy",
    "ApprovalPolicyDecision",
    "ApprovalRequestPayload",
    "ApprovalResolution",
    "ChioGraphConfig",
    "ChioLangGraphConfigError",
    "ChioLangGraphError",
    "chio_approval_node",
    "chio_node",
    "enforce_subgraph_ceiling",
]
