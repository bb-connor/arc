"""Start a live Chio Workbench repair using an authenticated Claude Code client."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


TASK = "Fix the addition bug in calc.py and have the reviewer verify the result."
CHECK = "import runpy; f = runpy.run_path('calc.py')['add']; assert all(f(a,b) == a+b for a,b in [(2,3),(-2,3),(0,1),(-3,-4)])"


def prepare(output: Path) -> tuple[Path, Path]:
    output.mkdir(mode=0o700)
    output = output.resolve()
    workspace = output / "workspace"
    workspace.mkdir()
    (workspace / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    return workspace, output / "state"


def command(binary: Path, workspace: Path, state: Path, model: str, client: str) -> list[str]:
    return [str(binary), "--provider", "claude-code", "--model", model,
            "--claude-command", client, "--workspace", str(workspace),
            "--state-dir", str(state), "--port", "0", "--", sys.executable, "-I", "-c", CHECK]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new private directory for the repair")
    parser.add_argument("--model", required=True)
    parser.add_argument("--claude-command", default="claude")
    args = parser.parse_args()
    binary = args.workbench.resolve(strict=True)
    workspace, state = prepare(args.output)
    print(f"Open the URL below and enter this task:\n{TASK}\n", flush=True)
    os.execv(binary, command(binary, workspace, state, args.model, args.claude_command))


if __name__ == "__main__":
    main()
