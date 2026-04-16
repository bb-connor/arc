"""ARC LlamaIndex integration.

Wraps LlamaIndex's :class:`llama_index.core.tools.FunctionTool` and
:class:`llama_index.core.tools.QueryEngineTool` so every tool dispatch
flows through the ARC sidecar kernel for capability-scoped
authorization, guard enforcement, and signed receipts.

Public surface:

* :class:`ArcFunctionTool` -- :class:`FunctionTool` subclass that gates
  ``call`` / ``acall`` on an ARC allow verdict.
* :class:`ArcQueryEngineTool` -- :class:`QueryEngineTool` subclass that
  additionally scopes which vector collection may be queried.
* :class:`ArcAgentRunner` -- helper that binds a per-agent capability
  token to every ARC-governed tool on an :class:`AgentRunner`.
* :class:`ArcToolError` / :class:`ArcLlamaIndexConfigError` -- error
  types.
"""

from arc_llamaindex.agent_runner import ArcAgentRunner
from arc_llamaindex.errors import ArcLlamaIndexConfigError, ArcToolError
from arc_llamaindex.function_tool import ArcFunctionTool
from arc_llamaindex.query_engine_tool import ArcQueryEngineTool

__all__ = [
    "ArcAgentRunner",
    "ArcFunctionTool",
    "ArcLlamaIndexConfigError",
    "ArcQueryEngineTool",
    "ArcToolError",
]
