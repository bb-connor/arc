#!/usr/bin/env python3
"""Behavior tests for scripts/select-fuzz-targets.py."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = Path(os.environ.get("FUZZ_SELECTOR", ROOT / "scripts/select-fuzz-targets.py"))
INVENTORY = sorted(tomllib.loads((ROOT / "fuzz/target-map.toml").read_text())["targets"])
GRAPH = {
    package["name"]
    for package in tomllib.loads((ROOT / "fuzz/Cargo.lock").read_text())["package"]
    if "source" not in package
}


def select(
    changed: list[str], root: Path = ROOT, base: str | None = None
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        listing = Path(temporary) / "changed.txt"
        listing.write_text("".join(path + "\n" for path in changed))
        classification = Path(temporary) / "classification.txt"
        command = [
            sys.executable,
            str(SELECTOR),
            "--changed",
            str(listing),
            "--root",
            str(root),
            "--classification",
            str(classification),
        ]
        if base is not None:
            command += ["--base", base]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        result.classification = (  # type: ignore[attr-defined]
            classification.read_text() if classification.exists() else None
        )
        return result


def classified(changed: list[str], **kwargs: object) -> str:
    result = select(changed, **kwargs)  # type: ignore[arg-type]
    assert result.returncode == 0, (changed, result.stderr)
    return result.classification  # type: ignore[attr-defined]


def selected(changed: list[str], **kwargs: object) -> list[str]:
    result = select(changed, **kwargs)  # type: ignore[arg-type]
    assert result.returncode == 0, (changed, result.stderr)
    return result.stdout.splitlines()


def manifests() -> list[tuple[str, str | None]]:
    paths = subprocess.check_output(
        ["git", "ls-files", "--", "*Cargo.toml"], cwd=ROOT, text=True
    ).splitlines()
    assert len(paths) > 100, "manifest discovery unexpectedly omitted workspace members"
    found = []
    for path in paths:
        package = tomllib.loads((ROOT / path).read_text()).get("package", {})
        found.append((path, package.get("name")))
    return found


def fuzz_graph_manifests_select_full_inventory() -> None:
    in_graph = [path for path, name in manifests() if name in GRAPH]
    assert len(in_graph) > 50, in_graph
    for path in in_graph:
        assert selected([path]) == INVENTORY, path


def build_inputs_select_full_inventory() -> None:
    for path in [
        "Cargo.toml",
        "fuzz/Cargo.toml",
        "fuzz/Cargo.lock",
        "fuzz/target-map.toml",
        ".clusterfuzzlite/build.sh",
        ".cargo/config.toml",
        ".github/workflows/cflite_pr.yml",
        "scripts/select-fuzz-targets.py",
        "Makefile",
        "crates/future/new-member/Cargo.toml",
        "deploy/docker/chio-workspace/Cargo.toml",
    ]:
        assert selected([path]) == INVENTORY, path


def manifests_outside_fuzz_graph_select_nothing() -> None:
    outside = [path for path, name in manifests() if name is not None and name not in GRAPH]
    assert "crates/core/chio-adversarial-suite/Cargo.toml" in outside, outside
    for path in outside:
        assert selected([path]) != INVENTORY, path
    assert selected(["crates/core/chio-adversarial-suite/Cargo.toml"]) == []


def root_lockfile_selects_nothing() -> None:
    assert selected(["Cargo.lock"]) == []


def triggers_select_mapped_targets() -> None:
    fired = selected(["crates/core/chio-core-types/src/canonical.rs", "docs/Cargo.toml.example"])
    assert "canonical_json" in fired and fired != INVENTORY, fired
    assert selected(["src/Cargo.toml.rs", "docs/README.md"]) == []


def single_star_does_not_cross_directories() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fake_repo(root, triggers=["src/*.rs"], graph=["alpha"])
        assert selected(["src/lib.rs"], root=root) == ["only"]
        assert selected(["src/deep/lib.rs"], root=root) == []
        assert selected(["src/lib.rs.bak"], root=root) == []


def renamed_member_uses_base_name() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fake_repo(root, triggers=["src/**"], graph=["alpha"])
        manifest = root / "crates/alpha/Cargo.toml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text('[package]\nname = "alpha"\n')
        git(root, "add", "-A")
        git(root, "commit", "-qm", "base")
        base = git(root, "rev-parse", "HEAD").strip()
        manifest.write_text('[package]\nname = "renamed"\n')
        assert selected(["crates/alpha/Cargo.toml"], root=root) == []
        assert selected(["crates/alpha/Cargo.toml"], root=root, base=base) == ["only"]
        manifest.unlink()
        assert selected(["crates/alpha/Cargo.toml"], root=root, base=base) == ["only"]
        assert selected(["crates/alpha/Cargo.toml"], root=root) == ["only"]


def invalid_inputs_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fake_repo(root, triggers=[], graph=["alpha"])
        result = select(["src/lib.rs"], root=root)
        assert result.returncode == 2 and "has no triggers" in result.stderr, result
        fake_repo(root, triggers=["src/**"], graph=[])
        result = select(["src/lib.rs"], root=root)
        assert result.returncode == 2 and "records no path packages" in result.stderr, result


def selections_are_classified() -> None:
    assert classified(["crates/core/chio-core-types/src/canonical.rs"]) == "targets-selected\n"
    assert classified(["Cargo.toml"]) == "targets-selected\n"


def irrelevant_diffs_are_classified() -> None:
    for changed in [
        ["docs/README.md"],
        ["Cargo.lock"],
        ["crates/core/chio-adversarial-suite/Cargo.toml"],
        ["crates/core/chio-adversarial-suite/src/lib.rs"],
        ["crates/core/chio-core-types/tests/canonical_roundtrip.rs"],
        ["crates/kernel/chio-kernel-core/benches/eval.rs"],
        ["crates/core/chio-bounded/src/bounds_tests.rs"],
        ["tests/bindings/vectors/unmapped/v1.json"],
    ]:
        assert selected(changed) == [], changed
        assert classified(changed) == "no-fuzz-relevant-change\n", changed


def unmapped_fuzz_graph_changes_stay_unclassified() -> None:
    graph_crate = "crates/core/chio-bounded/src/unmapped_module.rs"
    for changed in [
        [graph_crate],
        ["docs/README.md", graph_crate],
        ["crates/core/chio-bounded/src/data/table.json"],
        ["fuzz/src/unmapped.rs"],
        ["spec/schemas/unmapped/v1.json"],
        ['"crates/core/chio-core/src/\\303\\251.rs"'],
        ["crates/future/unowned/src/lib.rs"],
    ]:
        result = select(changed)
        assert result.returncode == 0, (changed, result.stderr)
        assert result.stdout == "", (changed, result.stdout)
        assert result.classification == "unclassified\n", (changed, result.classification)  # type: ignore[attr-defined]
        assert "fuzz-relevant change without a mapped target" in result.stderr, result.stderr


def deleted_crate_files_use_base_manifest() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fake_repo(root, triggers=["mapped/**"], graph=["alpha"])
        for name in ["alpha", "beta"]:
            manifest = root / f"crates/{name}/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(f'[package]\nname = "{name}"\n')
            (root / f"crates/{name}/src").mkdir()
            (root / f"crates/{name}/src/lib.rs").write_text("")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "base")
        base = git(root, "rev-parse", "HEAD").strip()
        for name in ["alpha", "beta"]:
            for path in (root / f"crates/{name}").rglob("*"):
                if path.is_file():
                    path.unlink()
        assert classified(["crates/beta/src/lib.rs"], root=root, base=base) == (
            "no-fuzz-relevant-change\n"
        )
        assert classified(["crates/alpha/src/lib.rs"], root=root, base=base) == "unclassified\n"
        assert classified(["crates/beta/src/lib.rs"], root=root) == "unclassified\n"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        cwd=root,
        text=True,
    )


def fake_repo(root: Path, triggers: list[str], graph: list[str]) -> None:
    (root / "fuzz").mkdir(exist_ok=True)
    quoted = ", ".join(f'"{trigger}"' for trigger in triggers)
    (root / "fuzz/target-map.toml").write_text(f"[targets.only]\ntriggers = [{quoted}]\n")
    packages = "".join(f'[[package]]\nname = "{name}"\nversion = "0.1.0"\n\n' for name in graph)
    packages += '[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+x"\n'
    (root / "fuzz/Cargo.lock").write_text("version = 4\n\n" + packages)
    if not (root / ".git").exists():
        git(root, "init", "-q")


CASES = [
    fuzz_graph_manifests_select_full_inventory,
    build_inputs_select_full_inventory,
    manifests_outside_fuzz_graph_select_nothing,
    root_lockfile_selects_nothing,
    triggers_select_mapped_targets,
    single_star_does_not_cross_directories,
    renamed_member_uses_base_name,
    invalid_inputs_fail_closed,
    selections_are_classified,
    irrelevant_diffs_are_classified,
    unmapped_fuzz_graph_changes_stay_unclassified,
    deleted_crate_files_use_base_manifest,
]


def main() -> int:
    failures = 0
    for case in CASES:
        try:
            case()
        except AssertionError as error:
            failures += 1
            print(f"FAIL {case.__name__}: {error}")
        else:
            print(f"PASS {case.__name__}")
    print(f"{len(CASES) - failures}/{len(CASES)} fuzz selection cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
