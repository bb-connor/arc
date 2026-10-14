"""Standalone Rust workspaces that supply manuscript evidence."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACES = (
    'examples/composed-baseline',
    'labs/kernel-work-composition',
    'labs/kernel-work-families',
)
