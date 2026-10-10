"""Starter validation must finish before installing or executing artifacts."""

import importlib.util
import json
import platform
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("starter", Path(__file__).with_name("run.py"))
starter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(starter)


@pytest.fixture
def kit(tmp_path, monkeypatch):
    root = tmp_path / "kit"
    root.mkdir()
    (root / "packages").mkdir()
    names = [
        "packages/chio_process-0.1.0-py3-none-any.whl",
        "packages/chio-protocol-process-0.1.0.tgz",
    ]
    for name in names:
        (root / name).write_bytes(b"pinned package")
    manifest = {
        "system": platform.system(),
        "machine": platform.machine(),
        "files": {name: starter.digest(root / name) for name in names},
    }
    monkeypatch.setattr(starter, "HERE", root)
    state = tmp_path / "state"
    monkeypatch.setattr(starter.sys, "argv", ["run.py", "--state", str(state)])

    def no_install(*args):
        pytest.fail("artifact validation permitted installation")

    monkeypatch.setattr(starter, "prepare", no_install)
    return root, state, manifest


@pytest.mark.parametrize("extra", ["evil.whl", "evil.tgz"])
def test_unlisted_package_refused_before_install(kit, extra):
    root, state, manifest = kit
    (root / "packages" / extra).write_bytes(b"malicious extra package")
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match="unlisted package artifact"):
        starter.main()
    assert not state.exists()


@pytest.mark.parametrize("field,value", [("system", "Darwin"), ("machine", "unsupported-cpu")])
def test_platform_mismatch_refused_before_install(kit, field, value):
    root, state, manifest = kit
    manifest[field] = value
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match="another operating system or architecture"):
        starter.main()
    assert not state.exists()


def test_listed_ambiguous_wheel_refused_before_install(kit):
    root, state, manifest = kit
    name = "packages/chio_process-0.2.0-py3-none-any.whl"
    (root / name).write_bytes(b"second listed package")
    manifest["files"][name] = starter.digest(root / name)
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match="exactly one expected"):
        starter.main()
    assert not state.exists()


def test_manifest_selects_exact_expected_packages_and_normalized_architectures(kit):
    root, _, manifest = kit
    assert starter.packages(manifest["files"]) == [
        root / "packages/chio_process-0.1.0-py3-none-any.whl",
        root / "packages/chio-protocol-process-0.1.0.tgz",
    ]
    assert starter.normalized_platform("Linux", "ARM64") == ("linux", "aarch64")
    assert starter.normalized_platform("LINUX", "AMD64") == ("linux", "x86_64")


def test_hash_listed_uv_metadata_is_not_an_installable_package(kit):
    root, _, manifest = kit
    metadata = root / "packages/.gitignore"
    metadata.write_text("*")
    manifest["files"]["packages/.gitignore"] = starter.digest(metadata)
    assert [path.suffix for path in starter.packages(manifest["files"])] == [".whl", ".tgz"]
