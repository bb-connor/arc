"""Normalize comparison ownership ancestors without following the final entry."""

from pathlib import Path


def ownership_path(path):
    path = Path(path).absolute()
    return path.parent.resolve(strict=True) / path.name
