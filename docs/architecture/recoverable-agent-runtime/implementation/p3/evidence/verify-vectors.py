#!/usr/bin/env python3
"""Recompute the deterministic P3 corpus without replacing its retained bytes."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[6]
result = subprocess.run(
    ["cargo", "run", "--offline", "--locked", "-p", "chio-semantic-contracts",
     "--example", "p3_vectors"],
    cwd=root, check=True, stdout=subprocess.PIPE,
)
expected = (root / "spec/vectors/recovery/v1/p3-contracts.json").read_bytes()
if result.stdout != expected:
    raise ValueError("P3 vector corpus differs from independent recomputation")
print("PASS: all 50 P3 vector bytes independently recomputed")
