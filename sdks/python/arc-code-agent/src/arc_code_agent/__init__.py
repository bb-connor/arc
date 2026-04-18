"""ARC-governed tool wrappers for coding agents.

This package ships a zero-config default policy plus three tool
wrappers -- :class:`FileTool`, :class:`ShellTool`, :class:`GitTool` --
that route every operation through the ARC sidecar. It is designed so
an MCP-style coding agent (Claude Code, Cursor, custom CLI) can get
ARC protection with a single line of setup.

Public surface:

* :class:`CodeAgent` -- facade bundling all three tools.
* :data:`DEFAULT_POLICY` -- the bundled, fail-closed default policy.
* :data:`DEFAULT_POLICY_YAML` -- the raw YAML, byte-identical to the
  copy embedded by the Rust ``arc mcp serve --preset code-agent``
  flag.
* :class:`FileTool`, :class:`ShellTool`, :class:`GitTool` -- per-tool
  wrappers for direct use.
* :class:`ArcCodeAgentError`, :class:`ArcCodeAgentDeniedError`,
  :class:`ArcCodeAgentPolicyError` -- error types.
"""

from arc_code_agent.agent import CodeAgent
from arc_code_agent.errors import (
    ArcCodeAgentDeniedError,
    ArcCodeAgentError,
    ArcCodeAgentPolicyError,
)
from arc_code_agent.policy import (
    DEFAULT_POLICY,
    DEFAULT_POLICY_YAML,
    AllowedTool,
    CodeAgentPolicy,
    compile_policy,
)
from arc_code_agent.tools import (
    FileTool,
    GitTool,
    ShellResult,
    ShellTool,
    ToolInvocation,
)

__all__ = [
    "AllowedTool",
    "ArcCodeAgentDeniedError",
    "ArcCodeAgentError",
    "ArcCodeAgentPolicyError",
    "CodeAgent",
    "CodeAgentPolicy",
    "DEFAULT_POLICY",
    "DEFAULT_POLICY_YAML",
    "FileTool",
    "GitTool",
    "ShellResult",
    "ShellTool",
    "ToolInvocation",
    "compile_policy",
]

__version__ = "0.1.0"
