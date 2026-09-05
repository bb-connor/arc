"""An ordinary MCP server with operator-supplied environment configuration."""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Journal")
journal = Path(os.environ["JOURNAL_PATH"])
operator_label = os.environ["OPERATOR_LABEL"]


@mcp.tool()
def append_note(note: str) -> dict:
    """Append a note to the operator's journal."""
    with journal.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"note": note}) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"saved": note, "operator_label": operator_label}


if __name__ == "__main__":
    mcp.run(transport="stdio")
