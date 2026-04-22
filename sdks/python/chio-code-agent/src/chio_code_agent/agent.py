"""High-level :class:`CodeAgent` facade.

:class:`CodeAgent` ties together :class:`FileTool`, :class:`ShellTool`,
and :class:`GitTool` so an MCP-style coding agent can get Chio
protection with a single line of setup::

    agent = CodeAgent(chio_client=client, capability_id="cap-123")
    result = await agent.files.read_file("README.md")

The agent does not perform I/O by itself -- its tool methods expect
the caller to supply an ``executor`` (or rely on the default
filesystem executor for ``FileTool.read_file`` / ``write_file``). That
way the class works unchanged in unit tests with ``MockChioClient`` and
in production with the real HTTP client.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from chio_code_agent.policy import CodeAgentPolicy, DEFAULT_POLICY
from chio_code_agent.tools import (
    FileTool,
    GitTool,
    ShellTool,
    ToolInvocation,
    _ChioClientLike,
)


class CodeAgent:
    """Facade bundling file, shell, and git tool wrappers.

    Parameters
    ----------
    chio_client:
        :class:`chio_sdk.ChioClient` (or ``MockChioClient``) used to
        evaluate each call.
    capability_id:
        Capability token id to reference on every call.
    policy:
        Policy to enforce before the sidecar round-trip. Defaults to
        the bundled :data:`DEFAULT_POLICY`.
    cwd:
        Working directory to use as the root for path checks.
        Defaults to :func:`pathlib.Path.cwd`.

    Attributes
    ----------
    files:
        Bound :class:`FileTool`.
    shell:
        Bound :class:`ShellTool`.
    git:
        Bound :class:`GitTool`.
    """

    def __init__(
        self,
        *,
        chio_client: _ChioClientLike,
        capability_id: str,
        policy: CodeAgentPolicy | None = None,
        cwd: Path | None = None,
    ) -> None:
        self._chio_client = chio_client
        self._capability_id = capability_id
        self._policy = policy or DEFAULT_POLICY
        self._cwd = (cwd or Path.cwd()).resolve()

        self.files = FileTool(
            chio_client=chio_client,
            capability_id=capability_id,
            policy=self._policy,
            cwd=self._cwd,
        )
        self.shell = ShellTool(
            chio_client=chio_client,
            capability_id=capability_id,
            policy=self._policy,
            cwd=self._cwd,
        )
        self.git = GitTool(
            chio_client=chio_client,
            capability_id=capability_id,
            policy=self._policy,
            cwd=self._cwd,
        )

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def policy(self) -> CodeAgentPolicy:
        return self._policy

    @property
    def cwd(self) -> Path:
        return self._cwd

    @property
    def capability_id(self) -> str:
        return self._capability_id

    # ------------------------------------------------------------------
    # MCP-style dispatch helper
    # ------------------------------------------------------------------

    async def dispatch(
        self,
        tool: str,
        **kwargs: Any,
    ) -> ToolInvocation:
        """Route a ``server/tool`` string to the matching wrapper.

        Intended for MCP hosts that dispatch tool calls by a single
        string name (e.g. ``"fs/read_file"``). Unknown tools raise
        :class:`ValueError`.
        """
        try:
            server, tool_name = tool.split("/", 1)
        except ValueError as exc:
            raise ValueError(
                f"dispatch name {tool!r} must be of the form 'server/tool'"
            ) from exc

        if server == "fs":
            method = getattr(self.files, tool_name, None)
        elif server == "shell":
            method = getattr(self.shell, tool_name, None)
        elif server == "git":
            method = getattr(self.git, tool_name, None)
        else:
            method = None

        if method is None or not callable(method):
            raise ValueError(f"unknown tool {tool!r}")

        return await method(**kwargs)


__all__ = ["CodeAgent"]
