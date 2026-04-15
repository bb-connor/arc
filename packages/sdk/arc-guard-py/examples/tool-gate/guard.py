"""Example guard: tool-name-based allow/deny.

Mirrors the Rust tool-gate example (examples/guards/tool-gate/src/lib.rs)
and the TypeScript SDK equivalent. Allows all tools except those on a
deny list.

This file is the componentize-py entry point for the ``arc:guard/guard``
world. Import paths come from the generated bindings produced by
``componentize-py bindings``.
"""

from guard import Evaluate as BaseEvaluate
from guard.types import GuardRequest, Verdict_Allow, Verdict_Deny


BLOCKED_TOOLS: frozenset[str] = frozenset({
    "dangerous_tool",
    "rm_rf",
    "drop_database",
})


class Evaluate(BaseEvaluate):
    """Evaluate a tool-call request and return a verdict."""

    def evaluate(self, request: GuardRequest) -> Verdict_Allow | Verdict_Deny:
        if request.tool_name in BLOCKED_TOOLS:
            return Verdict_Deny("tool is blocked by policy")
        return Verdict_Allow()
