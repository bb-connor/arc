"""Current manifest runtime validation, distinct from signature verification."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chio_sdk._generated.security.signed_tool_manifest_v2_schema import (
    ChioSignedToolManifestV2,
)


_CORPUS = json.loads(
    (Path(__file__).resolve().parents[4] / "tests/bindings/fixtures/manifest-v2-consumers.json")
    .read_text(encoding="utf-8")
)["cases"]


@pytest.mark.parametrize("case", _CORPUS, ids=lambda case: case["name"])
def test_manifest_v2_runtime_corpus(case):
    if not case["valid"]:
        with pytest.raises(ValidationError):
            ChioSignedToolManifestV2.model_validate(case["instance"])
        return
    model = ChioSignedToolManifestV2.model_validate(case["instance"])
    decoded = model.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert decoded == case["instance"]
    # This existing canonical vector contains only ASCII strings and small
    # integers, for which compact sorted JSON is exactly the RFC 8785 encoding.
    encoded = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == (
        "4f9a91d6859c909e118bc89d1645d20da15fc3ac90aae26c4d796e3c56e8d603"
    )
