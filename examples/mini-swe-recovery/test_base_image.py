"""The worker base image is one digest-pinned reference shared by every consumer."""

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINNED = re.compile(r"^[a-z0-9./_-]+:[\w.-]+@sha256:[0-9a-f]{64}$")


def test_base_image_is_digest_pinned():
    reference = (HERE / "base-image.txt").read_text().strip()
    assert PINNED.fullmatch(reference)


def test_repository_dockerfile_default_matches_base_image():
    reference = (HERE / "base-image.txt").read_text().strip()
    first = (HERE / "Repository.Dockerfile").read_text().splitlines()[0]
    assert first == "ARG BASE=" + reference
