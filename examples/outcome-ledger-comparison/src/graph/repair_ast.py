"""Trusted syntax fingerprinting. Parse supplied source as data; never import it."""

import ast
import hashlib
import json
import pathlib

artifact = json.loads(pathlib.Path("/artifact.json").read_text())
trees = {
    name: ast.dump(ast.parse(source), include_attributes=False)
    for name, source in artifact["files"].items()
}
encoded = json.dumps(trees, sort_keys=True, separators=(",", ":")).encode()
print(json.dumps({"astSha256": hashlib.sha256(encoded).hexdigest()}))
