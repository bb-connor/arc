"""Capture installed image identities for a coding session; never pull or build."""

import json
import re
from pathlib import Path

from chio_mini_swe import operator
from chio_mini_swe.repository_container import qualify_image
from chio_mini_swe.repository_transport import docker

SCHEMA = "chio.mini-swe.runtime-profile.v1"


def create(worker, execution, helper, output):
    images = {}
    for key, selected in [("worker_image", worker), ("execution_image", execution), ("helper_image", helper)]:
        if not selected or selected.startswith("-") or len(selected) > 1024:
            raise ValueError("Select an installed Docker image name or ID")
        image = json.loads(docker("image", "inspect", "--format", "{{json .}}", selected))
        identifier = image.get("Id")
        if not isinstance(identifier, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", identifier) is None:
            raise ValueError("Docker did not return an immutable image ID")
        qualify_image(identifier)
        images[key] = identifier
    output = Path(output)
    value = {"schema": SCHEMA, **images}
    operator.write(output, value)
    return {"profile": str(output), **value}


def add_parser(commands):
    command = commands.add_parser("runtime-profile", help="Record installed image IDs for a coding session")
    command.add_argument("--worker-image", required=True)
    command.add_argument("--execution-image", required=True)
    command.add_argument("--helper-image", required=True)
    command.add_argument("--out", required=True)
