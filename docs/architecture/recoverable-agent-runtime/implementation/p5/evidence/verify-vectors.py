#!/usr/bin/env python3
"""Recompute the shared P5 corpus from the authored Rust fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[6]
with tempfile.TemporaryDirectory(prefix="chio-p5-vectors-") as directory:
    output = Path(directory) / "p5-contracts.json"
    command = ["cargo", "test", "--offline", "--locked", "-p", "chio-core-types", "--test",
               "recovery_p5_contracts", "p5_write_shared_vectors", "--", "--exact"]
    subprocess.run(command, cwd=ROOT, env={**os.environ, "CHIO_P5_VECTOR_OUT": str(output),
        "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
        "TMPDIR": str(Path(os.environ.get("TMPDIR", "/tmp")).resolve())}, check=True)
    expected = ROOT / "spec/vectors/recovery/v1/p5-contracts.json"
    if output.read_bytes() != expected.read_bytes():
        raise SystemExit("P5 corpus differs from Rust recomputation")
    cases = json.loads(output.read_text())["cases"]
    if len(cases) != 26:
        raise SystemExit("P5 vector inventory differs")
    print(f"PASS: {len(cases)} shared P5 vectors exactly recomputed")
