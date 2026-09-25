"""Installed executable and image selection does not invent or replace identity."""

import json

import pytest
from chio_mini_swe import operator, runtime_profile
from chio_mini_swe import session_security


def test_package_manager_records_do_not_relax_executable_permissions(tmp_path):
    metadata = tmp_path / "lib/python3.12/site-packages/example.dist-info/RECORD"
    metadata.parent.mkdir(parents=True)
    metadata.write_text("inventory only")
    metadata.chmod(0o664)
    assert session_security._package_record(tmp_path, metadata)
    session_security._protected(metadata, package_record=True)
    source = metadata.with_name("__init__.py")
    source.write_text("print('code')")
    source.chmod(0o664)
    assert not session_security._package_record(tmp_path, source)
    with pytest.raises(ValueError, match="writable"):
        session_security._protected(source)
    lock = tmp_path / ".lock"
    lock.symlink_to(metadata)
    with pytest.raises(ValueError, match="package-manager record"):
        session_security._protected(lock, package_record=True)
    metadata.chmod(0o775)
    with pytest.raises(ValueError, match="package-manager record"):
        session_security._protected(metadata, package_record=True)


def test_executable_path_lookup_and_explicit_override(tmp_path, monkeypatch):
    executable = tmp_path / "chio"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert operator.resolve_executable(tmp_path / "elsewhere", "chio") == executable
    assert operator.resolve_executable(tmp_path, "./chio") == executable
    assert operator.resolve_executable(tmp_path, str(executable)) == executable
    with pytest.raises(ValueError, match="not found on PATH"):
        operator.resolve_executable(tmp_path, "missing-chio")


def test_profile_records_qualified_ids_and_refuses_overwrite(tmp_path, monkeypatch):
    identities = {name: "sha256:" + digit * 64 for name, digit in
                  [("worker", "1"), ("execution", "2"), ("helper", "3")]}
    commands, qualified = [], []

    def inspect(*arguments):
        commands.append(arguments)
        return json.dumps({"Id": identities[arguments[-1]]}).encode()

    monkeypatch.setattr(runtime_profile, "docker", inspect)
    monkeypatch.setattr(runtime_profile, "qualify_image", qualified.append)
    output = tmp_path / "runtime.json"
    runtime_profile.create("worker", "execution", "helper", output)
    original = output.read_bytes()
    assert qualified == list(identities.values())
    assert all(arguments[:2] == ("image", "inspect") for arguments in commands)
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(original)["worker_image"] == identities["worker"]
    with pytest.raises(FileExistsError):
        runtime_profile.create("worker", "execution", "helper", output)
    assert output.read_bytes() == original


def test_invalid_image_never_writes_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_profile, "docker", lambda *_: b'{"Id":"mutable-tag"}')
    with pytest.raises(ValueError, match="immutable"):
        runtime_profile.create("worker", "execution", "helper", tmp_path / "runtime.json")
    assert not (tmp_path / "runtime.json").exists()
