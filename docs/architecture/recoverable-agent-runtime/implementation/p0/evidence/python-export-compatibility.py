"""Compare generated Python export names and import identities with the P0 base."""

import ast
import subprocess
from pathlib import Path

BASE = "de84fc306efbb4c8dd6de748d0ad2a8d695fd30e"
MODULE = "sdks/python/chio-sdk-python/src/chio_sdk/_generated/__init__.py"


def inventory(source):
    exports = None
    imports = {}
    aliases = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.ImportFrom):
            for name in node.names:
                imports[name.asname or name.name] = (node.level, node.module, name.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id == "__all__":
                    exports = set(ast.literal_eval(node.value))
                elif isinstance(node.value, ast.Name):
                    aliases[target.id] = node.value.id
    assert exports is not None, "Generated module has no explicit export inventory"
    return exports, imports, aliases


previous = inventory(subprocess.check_output(["git", "show", f"{BASE}:{MODULE}"], text=True))
current = inventory(Path(MODULE).read_text())
missing = previous[0] - current[0]
assert not missing, f"Missing previous exports: {sorted(missing)}"
for name in sorted(previous[0]):
    if name in previous[1]:
        assert previous[1][name] == current[1].get(name), f"Changed import identity: {name}"
    if name in previous[2]:
        assert previous[2][name] == current[2].get(name), f"Changed alias identity: {name}"
print(f"PASS all existing generated Python exports: {len(previous[0])} retained; import and alias identities unchanged")
