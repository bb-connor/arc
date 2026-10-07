"""Exact P6 runtime and qualification-source bindings, kept separate."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[6]
PHASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fixtures/recovery-product"))
from manifest_builder import source_inventory


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def binding(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def runtime_sources():
    return source_inventory(ROOT)


def qualification_sources():
    rows = runtime_sources()
    rows += [{"path":str(path.relative_to(ROOT)), "sha256":sha(path)}
             for path in sorted((PHASE / "evidence").glob("*.py"))]
    rows += [{"path":str(path.relative_to(ROOT)), "sha256":sha(path)}
             for path in [PHASE / name for name in ["OPERATIONS.md", "REPRODUCE.md",
                         "supported-matrix.json", "adoption-metrics.json", "requirements-coverage.json"]]]
    return sorted(rows, key=lambda row:row["path"])


def phase_delta():
    baseline = json.loads((PHASE / "source-baseline.json").read_bytes())
    old = {row["path"]:row["sha256"] for row in baseline["sources"]}
    return [row for row in qualification_sources() if old.get(row["path"]) != row["sha256"]]
