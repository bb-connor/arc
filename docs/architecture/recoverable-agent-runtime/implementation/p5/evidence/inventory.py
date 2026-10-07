"""Shared deterministic source binding for the P5 evidence package."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[6]
PHASE = Path(__file__).resolve().parent.parent
PREFIX = "docs/architecture/recoverable-agent-runtime/implementation/"

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def sources() -> list[dict]:
    baseline = json.loads((PHASE / "source-baseline.json").read_text())
    paths = {row["path"] for row in baseline["sources"]}
    for command in [["git", "diff", "--name-only", "HEAD"],
                    ["git", "ls-files", "--others", "--exclude-standard"]]:
        paths.update(subprocess.check_output(command, cwd=ROOT, text=True).splitlines())
    paths.update(str(p.relative_to(ROOT)) for p in (PHASE / "evidence").glob("*.py"))
    paths.update(str(p.relative_to(ROOT)) for p in (ROOT / "crates/security/chio-cage").rglob("*") if p.is_file())
    result = []
    for path in sorted(paths):
        file = ROOT / path
        if "node_modules" in file.parts or path.startswith(PREFIX) and not path.startswith(str((PHASE / "evidence").relative_to(ROOT)) + "/"):
            continue
        if file.is_symlink():
            raise ValueError("symbolic source path: " + path)
        if file.is_file() and (not path.startswith(PREFIX) or file.suffix == ".py"):
            result.append({"path": path, "sha256": sha(file)})
    return result

def source_binding() -> str:
    return hashlib.sha256(json.dumps(sources(), separators=(",", ":"), sort_keys=True).encode()).hexdigest()
