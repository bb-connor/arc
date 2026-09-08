"""The same workload instructions and tool definitions for each framework."""

from server import TOOLS

NAMESPACE = "shared-resource-v1"
ROLES = {"compatibility": ["api", "worker"], "performance": ["search"]}
INSTRUCTION = (
    "Use only the supplied task evidence and tools. First read the task. "
    "The shared document ID is release-board; service names are not document IDs. "
    "Read its current snapshot before replacing it. Its value has exactly this shape: "
    '{"assessments": {"service-name": {"decision": "ready or blocked", '
    '"evidence_ids": ["evidence-id"], "reason": "short explanation"}}}. '
    "Each service has one assessment object, never an array. "
    "Assess only your assigned services. Merge your assessments into the current "
    "assessments object and preserve every other service's assessment unchanged. "
    "On a known version conflict, read a new snapshot and merge your assessments "
    "into that snapshot before planning a new replacement. "
    "Do not claim completion before a committed replacement."
)
DEFINITIONS = [
    dict(
        name="board__" + t["name"],
        server_id="board",
        tool_name=t["name"],
        description=t["description"],
        input_schema=t["inputSchema"],
    )
    for t in TOOLS
    if t["name"] != "outcome"
]
SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["input_schema"],
        },
    }
    for t in DEFINITIONS
]
