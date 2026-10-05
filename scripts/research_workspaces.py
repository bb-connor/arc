"""Standalone Rust workspaces that supply manuscript evidence."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACES = (
    'examples/federated-work',
    'examples/composed-baseline',
    'examples/outcome-ledger-comparison',
    'labs/kernel-work-composition',
    'labs/kernel-work-families',
)
