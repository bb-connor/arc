"""Chio-governed tool wrappers for coding agents.

This package ships a zero-config default policy plus three tool
wrappers -- :class:`FileTool`, :class:`ShellTool`, :class:`GitTool` --
that route every operation through the Chio sidecar. It is designed so
an MCP-style coding agent (Claude Code, Cursor, custom CLI) can get
Chio protection with a single line of setup.

Public surface:

* :class:`CodeAgent` -- facade bundling all three tools.
* :data:`DEFAULT_POLICY` -- the bundled, fail-closed default policy.
* :data:`DEFAULT_POLICY_YAML` -- the raw YAML, byte-identical to the
  copy embedded by the Rust ``chio mcp serve --preset code-agent``
  flag.
* :class:`FileTool`, :class:`ShellTool`, :class:`GitTool` -- per-tool
  wrappers for direct use.
* :class:`ChioCodeAgentError`, :class:`ChioCodeAgentDeniedError`,
  :class:`ChioCodeAgentPolicyError` -- error types.
"""

from chio_code_agent.agent import CodeAgent
from chio_code_agent.errors import (
    ChioCodeAgentDeniedError,
    ChioCodeAgentError,
    ChioCodeAgentPolicyError,
)
from chio_code_agent.policy import (
    DEFAULT_POLICY,
    DEFAULT_POLICY_YAML,
    AllowedTool,
    CodeAgentPolicy,
    compile_policy,
)
from chio_code_agent.tools import (
    FileTool,
    GitTool,
    ShellResult,
    ShellTool,
    ToolInvocation,
)

__all__ = [
    "AllowedTool",
    "ChioCodeAgentDeniedError",
    "ChioCodeAgentError",
    "ChioCodeAgentPolicyError",
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
