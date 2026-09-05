"""Small real MCP tool server used by the kernel adoption example.

The server owns a journal path chosen by the operator. Agent arguments cannot
select a destination. Chio owns the invocation allowance outside this process.
"""

import json
import os
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Journal")
journal = Path(sys.argv[1])


@mcp.tool()
def append_note(note: str) -> dict:
    """Append a note to the operator's journal."""
    with journal.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"note": note}, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"saved": note}


if __name__ == "__main__":
    mcp.run(transport="stdio")
