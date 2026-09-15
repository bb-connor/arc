#!/usr/bin/env python3
"""Hostile self-test for the chio-cage Linux all-target inventory."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-cage-all-target-inventory.py"
SPEC = importlib.util.spec_from_file_location("cage_inventory", CHECKER)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load cage inventory checker")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


HEADERS = {
    "lib": "Running unittests src/lib.rs (/tmp/chio_cage-lib)",
    "bin_chio_cage_init": (
        "Running unittests src/bin/chio-cage-init.rs (/tmp/chio_cage_init-bin)"
    ),
    "enforcement_evidence": (
        "Running tests/enforcement_evidence.rs (/tmp/enforcement_evidence)"
    ),
    "linux_compile": "Running tests/linux_compile.rs (/tmp/linux_compile)",
    "linux_enforcement": (
        "Running tests/linux_enforcement.rs (/tmp/linux_enforcement)"
    ),
}


def render(inventory: dict[str, list[str]]) -> str:
    lines = []
    for target in MODULE.EXPECTED_COUNTS:
        names = inventory[target]
        lines.extend([HEADERS[target], f"running {len(names)} tests"])
        lines.extend(f"test {name} ... ok" for name in names)
        lines.append(
            f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 0.01s"
        )
    return "\n".join(lines) + "\n"


def invoke(root: Path, output: str | None) -> int:
    command = ["python3", str(CHECKER), "--root", str(root)]
    if output is None:
        command.append("--source-only")
    else:
        output_path = root / "all-targets.out"
        output_path.write_text(output, encoding="utf-8")
        command.extend(["--run-output", str(output_path)])
    return subprocess.run(command, check=False, capture_output=True).returncode


def require_rejected(root: Path, output: str, label: str) -> None:
    if invoke(root, output) == 0:
        raise SystemExit(f"cage inventory checker accepted {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="chio-cage-inventory-") as directory:
        root = Path(directory)
        crate = root / "crates/security/chio-cage"
        shutil.copytree(ROOT / "crates/security/chio-cage/src", crate / "src")
        shutil.copytree(ROOT / "crates/security/chio-cage/tests", crate / "tests")
        shutil.copy2(
            ROOT / "crates/security/chio-cage/Cargo.toml", crate / "Cargo.toml"
        )

        inventory = MODULE.source_inventory(root)
        valid = render(inventory)
        if invoke(root, None) != 0 or invoke(root, valid) != 0:
            raise SystemExit("cage inventory checker rejected the exact fixture")

        missing = {target: list(names) for target, names in inventory.items()}
        missing["linux_compile"] = missing["linux_compile"][:-1]
        require_rejected(root, render(missing), "a missing executed test")

        extra = {target: list(names) for target, names in inventory.items()}
        extra["enforcement_evidence"].append("uncommitted_inventory_case")
        require_rejected(root, render(extra), "an extra executed test")

        renamed = {target: list(names) for target, names in inventory.items()}
        renamed["lib"][-1] = "renamed_inventory_case"
        require_rejected(root, render(renamed), "a renamed executed test")

        zero = {target: [] for target in inventory}
        require_rejected(root, render(zero), "a zero all-target execution")

        ignored = valid.replace(" ... ok", " ... ignored", 1).replace(
            "0 ignored", "1 ignored", 1
        )
        require_rejected(root, ignored, "an ignored executed test")

        first_block_end = valid.index(HEADERS["bin_chio_cage_init"])
        require_rejected(root, valid[first_block_end:], "a missing target")
        require_rejected(
            root,
            valid
            + "Running unittests examples/unratcheted.rs (/tmp/unratcheted)\n"
            + "running 0 tests\n"
            + "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
            + "0 filtered out; finished in 0.01s\n",
            "an extra all-target harness",
        )

        evidence = crate / "tests/enforcement_evidence.rs"
        original = evidence.read_text(encoding="utf-8")
        evidence.write_text(
            original.replace(
                "fn fully_enforced_requires_prepared_exec_identity_and_status_eof()",
                "fn renamed_inventory_case()",
                1,
            ),
            encoding="utf-8",
        )
        if invoke(root, None) == 0:
            raise SystemExit("cage inventory checker accepted a renamed source test")

        evidence.write_text(
            original + "\n#[test]\nfn uncommitted_inventory_case() {}\n",
            encoding="utf-8",
        )
        if invoke(root, None) == 0:
            raise SystemExit("cage inventory checker accepted an extra source test")

        evidence.write_text(
            original.replace("#[test]", "#[cfg(any())]", 1), encoding="utf-8"
        )
        if invoke(root, None) == 0:
            raise SystemExit("cage inventory checker accepted a missing source test")

        evidence.write_text(original, encoding="utf-8")
        extra_target = crate / "tests/unratcheted.rs"
        extra_target.write_text(
            "#[test]\nfn uncommitted_target_case() {}\n", encoding="utf-8"
        )
        if invoke(root, None) == 0:
            raise SystemExit("cage inventory checker accepted an extra source target")
        extra_target.unlink()

        for path in crate.rglob("*.rs"):
            path.write_text("", encoding="utf-8")
        if invoke(root, None) == 0:
            raise SystemExit("cage inventory checker accepted a zero source inventory")

    print("chio-cage Linux all-target inventory self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
