"""Pytest configuration for chio-adapter-base.

No shared fixtures yet; the smoke test (``test_imports.py``) only
asserts that the public API surface imports cleanly. Shared fixtures
(workspace tmpdir, sample receipt records, mock subprocess) will be
added here as the per-primitive test files come online.
"""

from __future__ import annotations
