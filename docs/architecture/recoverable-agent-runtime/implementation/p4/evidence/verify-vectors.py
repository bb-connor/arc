#!/usr/bin/env python3
"""Recompute the shared P4 corpus using the actual Rust contracts and signer."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[6]
with tempfile.TemporaryDirectory(prefix="recovery-p4-vectors-") as directory:
    output = Path(directory) / "p4-contracts.json"
    command = ["cargo", "test", "--offline", "--locked", "-p", "chio-core-types", "--test", "recovery_p4_contracts", "p4_write_shared_vectors", "--", "--exact"]
    subprocess.run(command, cwd=ROOT, env={**os.environ,"CHIO_P4_VECTOR_OUT":str(output),"CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"2"},check=True)
    original = ROOT / "spec/vectors/recovery/v1/p4-contracts.json"
    if output.read_bytes() != original.read_bytes():
        raise SystemExit("P4 corpus drift")
    corpus = json.loads(output.read_bytes())
    assert corpus["schema"] == "chio.recovery-p4-contract-vectors.v1"
    print(f'Recomputed {len(corpus["cases"])} P4 vectors, including closed ingress and tampered signatures')
