"""ARC CrewAI integration.

Wraps CrewAI's :class:`crewai.tools.BaseTool` and :class:`crewai.Crew`
so every tool invocation flows through the ARC sidecar for
capability-scoped authorization and signed receipts.

Public surface:

* :class:`ArcBaseTool` -- :class:`crewai.tools.BaseTool` subclass that
  gates ``_run`` on an ARC allow verdict.
* :class:`ArcCrew` -- :class:`crewai.Crew` subclass that accepts a
  per-role ``capability_scope`` mapping and mints scoped tokens.
* :class:`ArcToolError` / :class:`ArcCrewConfigError` -- error types.
"""

from arc_crewai.crew import ArcCrew
from arc_crewai.errors import ArcCrewConfigError, ArcToolError
from arc_crewai.tool import ArcBaseTool

__all__ = [
    "ArcBaseTool",
    "ArcCrew",
    "ArcCrewConfigError",
    "ArcToolError",
]
