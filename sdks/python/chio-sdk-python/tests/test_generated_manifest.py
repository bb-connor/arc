"""Current manifest runtime validation, distinct from signature verification."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chio_sdk._generated.security.signed_tool_manifest_v1_schema import (
    ChioSignedToolManifestV1,
)


_CORPUS = json.loads(
    (Path(__file__).resolve().parents[4] / "tests/bindings/fixtures/manifest-consumers.json")
    .read_text(encoding="utf-8")
)["cases"]


@pytest.mark.parametrize("case", _CORPUS, ids=lambda case: case["name"])
def test_manifest_runtime_corpus(case):
    if not case["valid"]:
        with pytest.raises(ValidationError):
            ChioSignedToolManifestV1.model_validate(case["instance"])
        return
    model = ChioSignedToolManifestV1.model_validate(case["instance"])
    decoded = model.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert decoded == case["instance"]
    # This existing canonical vector contains only ASCII strings and small
    # integers, for which compact sorted JSON is exactly the RFC 8785 encoding.
    encoded = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == (
        "b3387974261d22131bee3b2d2113e761db60bf610921e96955a76b349ac60bc2"
    )
