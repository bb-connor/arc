"""Reject provenance that does not describe the actual optimized installed build."""

import json
import types
import zipfile

import capture_optimized_build as helper
import pytest


@pytest.fixture(autouse=True)
def no_external_commands(monkeypatch):
    def unexpected(*arguments, **keywords):
        raise AssertionError("Unit tests must not run build tools or Docker")

    monkeypatch.setattr(helper.subprocess, "run", unexpected)


@pytest.fixture
def artifact_case(tmp_path):
    binary = tmp_path / "chio"
    binary.write_bytes(b"optimized-cli")
    built = tmp_path / "built-chio"
    built.write_bytes(binary.read_bytes())
    message = {
        "reason": "compiler-artifact",
        "package_id": "path+file:///fixture#chio-cli@0.1.0",
        "manifest_path": str(tmp_path / "crates/products/chio-cli/Cargo.toml"),
        "target": {"name": "chio", "kind": ["bin"]},
        "profile": {
            "opt_level": "3",
            "debug_assertions": False,
            "overflow_checks": False,
            "test": False,
            "debuginfo": 0,
        },
        "executable": str(built),
        "features": [],
        "fresh": False,
    }
    return tmp_path, binary, built, message


def messages(root, *entries):
    path = root / "cargo.jsonl"
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
    return path


def test_actual_cargo_executable_matches_protected_copy(artifact_case):
    root, binary, _, artifact = artifact_case
    path = messages(
        root,
        {"reason": "build-script-executed"},
        artifact,
        {"reason": "build-finished", "success": True},
    )
    report = helper.cargo_artifact(path, root, binary)
    assert report["profile"]["opt_level"] == "3"
    assert report["cargo_messages_sha256"] == helper.digest(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("opt_level", "0"),
        ("debug_assertions", True),
        ("overflow_checks", True),
        ("test", True),
        ("debuginfo", 2),
    ],
)
def test_rejects_development_or_modified_profile(artifact_case, field, value):
    root, binary, _, artifact = artifact_case
    artifact["profile"][field] = value
    path = messages(root, artifact, {"reason": "build-finished", "success": True})
    with pytest.raises(ValueError, match="expected release"):
        helper.cargo_artifact(path, root, binary)


@pytest.mark.parametrize(
    "failure", ["failed", "unfinished", "duplicate", "wrong-package", "wrong-bytes"]
)
def test_rejects_failed_ambiguous_or_unrelated_build(artifact_case, failure):
    root, binary, built, artifact = artifact_case
    entries = [artifact, {"reason": "build-finished", "success": True}]
    if failure == "failed":
        entries[-1]["success"] = False
    elif failure == "unfinished":
        entries.pop()
    elif failure == "duplicate":
        entries.insert(0, artifact)
    elif failure == "wrong-package":
        artifact["manifest_path"] = str(root / "foreign/Cargo.toml")
    else:
        built.write_bytes(b"other-cli")
    with pytest.raises(ValueError):
        helper.cargo_artifact(messages(root, *entries), root, binary)


def test_records_only_allowed_build_environment():
    environment = {**helper.BUILD_ENVIRONMENT, "PROVIDER_API_KEY": "must-not-appear"}
    report = helper.build_environment(environment)
    assert "must-not-appear" not in json.dumps(report)
    assert report["CARGO_PROFILE_RELEASE_OPT_LEVEL"] == "3"


@pytest.mark.parametrize(
    "name,value",
    [
        ("CARGO_PROFILE_RELEASE_LTO", "thin"),
        ("CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL", "0"),
        ("CARGO_BUILD_RUSTFLAGS", "-C opt-level=0"),
        ("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "-C opt-level=0"),
        ("RUSTFLAGS", "-C opt-level=0"),
        ("CARGO_ENCODED_RUSTFLAGS", "-C\x1fopt-level=0"),
        ("RUSTC_WRAPPER", "/foreign/wrapper"),
        ("PYTHONDONTWRITEBYTECODE", "0"),
    ],
)
def test_rejects_unexpected_compiler_or_environment_overrides(name, value):
    with pytest.raises(ValueError):
        helper.build_environment({**helper.BUILD_ENVIRONMENT, name: value})


@pytest.mark.parametrize("failure", ["dirty", "missing", "sparse", "sha"])
def test_rejects_checkout_drift(tmp_path, monkeypatch, failure):
    responses = {
        ("rev-parse", "--show-toplevel"): str(tmp_path),
        ("status", "--porcelain=v1", "--untracked-files=all"): "",
        ("ls-files", "--deleted"): "",
        ("ls-files", "-t"): "H Cargo.toml",
        ("rev-parse", "HEAD"): "a" * 40,
        ("rev-parse", "HEAD^{tree}"): "b" * 40,
    }
    if failure == "dirty":
        responses[("status", "--porcelain=v1", "--untracked-files=all")] = " M Cargo.toml"
    elif failure == "missing":
        responses[("ls-files", "--deleted")] = "fixtures/proof-room/example.json"
    elif failure == "sparse":
        responses[("ls-files", "-t")] = "S spec/schemas/example.json"
    monkeypatch.setattr(helper, "run", lambda program, *args: responses[args])
    with pytest.raises(ValueError):
        helper.checkout_identity(tmp_path, {"GITHUB_SHA": ("c" if failure == "sha" else "a") * 40})


@pytest.fixture
def package_case(tmp_path, monkeypatch):
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    prefix = tmp_path / "installed"
    prefix.mkdir()
    installed = {}
    for module, distribution in helper.PACKAGES.items():
        package = tmp_path / "sdks/python" / distribution
        source = package / "src" / module
        source.mkdir(parents=True)
        (source / "__init__.py").write_text("def loaded():\n    return 'source'\n")
        (package / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
        target = prefix / module
        target.mkdir()
        (target / "__init__.py").write_bytes((source / "__init__.py").read_bytes())
        installed[module] = target
        with zipfile.ZipFile(wheels / f"{module}-0.1.0-py3-none-any.whl", "w") as archive:
            archive.writestr(module + "/__init__.py", (source / "__init__.py").read_bytes())
    monkeypatch.setattr(helper.sys, "prefix", str(prefix))
    monkeypatch.setattr(helper, "environment_identity", lambda: {"sources": "verified-fixture"})
    monkeypatch.setattr(
        helper.importlib.util,
        "find_spec",
        lambda module: types.SimpleNamespace(origin=str(installed[module] / "__init__.py")),
    )
    monkeypatch.setattr(
        helper.importlib.metadata,
        "version",
        lambda name: "2.4.6" if name == "mini-swe-agent" else "0.1.0",
    )
    monkeypatch.setattr(helper.importlib.metadata, "distributions", lambda: [])
    return tmp_path, wheels, installed


def test_installed_sources_wheels_and_checkout_agree(package_case):
    root, wheels, _ = package_case
    report = helper.installed_sources(root, wheels)
    assert set(report["packages"]) == set(helper.PACKAGES)
    for package in report["packages"].values():
        assert package["wheel_sha256"] == helper.digest(wheels / package["wheel"])


@pytest.mark.parametrize("change", ["installed", "wheel", "extra-source", "extra-wheel"])
def test_rejects_installed_or_wheel_source_drift(package_case, change):
    root, wheels, installed = package_case
    if change == "installed":
        (installed["chio_process"] / "__init__.py").write_text("changed")
    elif change == "extra-source":
        (installed["chio_process"] / "extra.py").write_text("extra")
    elif change == "extra-wheel":
        (wheels / "unrelated.whl").write_bytes(b"extra")
    else:
        with zipfile.ZipFile(wheels / "chio_process-0.1.0-py3-none-any.whl", "w") as archive:
            archive.writestr("chio_process/__init__.py", "changed")
    with pytest.raises(ValueError):
        helper.installed_sources(root, wheels)


def test_workflow_identity_excludes_secrets_and_requires_exact_run():
    environment = {
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/comparison.yml@refs/heads/topic",
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_SHA": "a" * 40,
        "GITHUB_REF": "refs/heads/topic",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_TOKEN": "must-not-appear",
    }
    assert "must-not-appear" not in json.dumps(helper.workflow_identity(environment))
    with pytest.raises(ValueError, match="workflow run"):
        helper.workflow_identity({**environment, "GITHUB_RUN_ATTEMPT": ""})
