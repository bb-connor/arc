"""Permission preparation cannot follow swapped paths into external files."""

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import prepare_session_environment as helper
import pytest


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def installation(tmp_path, monkeypatch):
    prefix = tmp_path / "venv"
    prefix.mkdir()
    prefix.chmod(0o775)
    package = prefix / "package"
    package.mkdir()
    package.chmod(0o775)
    ordinary = package / "ordinary.py"
    ordinary.write_text("installed code\n")
    ordinary.chmod(0o664)
    interpreter = tmp_path / "python"
    interpreter.write_text("#!/bin/sh\nexit 0\n")
    interpreter.chmod(0o755)
    monkeypatch.setattr(
        helper,
        "sys",
        SimpleNamespace(prefix=str(prefix), base_prefix="/unused", executable=str(interpreter)),
    )
    monkeypatch.setattr(helper, "environment_identity", lambda: {"interpreter": str(interpreter)})
    secret = tmp_path / "secret"
    secret.write_text("private operator secret\n")
    secret.chmod(0o600)
    return prefix, ordinary, secret


def after_inventory(monkeypatch, attack):
    original = helper._inventory

    def inventory(descriptor):
        value = original(descriptor)
        attack()
        return value

    monkeypatch.setattr(helper, "_inventory", inventory)


def test_file_swapped_to_secret_symlink_is_refused_without_external_mutation(
    installation, monkeypatch
):
    prefix, ordinary, secret = installation

    def attack():
        ordinary.unlink()
        ordinary.symlink_to(secret)

    after_inventory(monkeypatch, attack)
    with pytest.raises(ValueError, match="changed"):
        helper.protect()
    assert mode(secret) == 0o600 and secret.read_text() == "private operator secret\n"
    assert mode(prefix) == 0o775 and mode(ordinary.parent) == 0o775


def test_parent_replaced_with_external_directory_symlink_cannot_redirect_chmod(
    installation, monkeypatch
):
    prefix, ordinary, secret = installation
    external = prefix.parent / "external"
    external.mkdir()
    target = external / ordinary.name
    target.write_text("external code\n")
    target.chmod(0o600)
    displaced = prefix.parent / "displaced"

    def attack():
        ordinary.parent.rename(displaced)
        ordinary.parent.symlink_to(external, target_is_directory=True)

    after_inventory(monkeypatch, attack)
    with pytest.raises(ValueError, match="changed"):
        helper.protect()
    assert mode(target) == 0o600 and target.read_text() == "external code\n"
    assert mode(secret) == 0o600 and mode(displaced) == 0o775
    assert mode(displaced / ordinary.name) == 0o664 and mode(prefix) == 0o775


@pytest.mark.parametrize("introduced_after_inventory", [False, True])
def test_shared_file_is_refused_before_permission_changes(
    installation, monkeypatch, introduced_after_inventory
):
    prefix, ordinary, secret = installation
    alias = prefix.parent / "shared-cache-entry"

    def share():
        os.link(ordinary, alias)

    if introduced_after_inventory:
        after_inventory(monkeypatch, share)
    else:
        share()
    with pytest.raises(ValueError, match="link-mode copy"):
        helper.protect()
    assert mode(prefix) == 0o775 and mode(ordinary.parent) == 0o775
    assert mode(ordinary) == mode(alias) == 0o664 and mode(secret) == 0o600


def test_current_restrictive_file_mode_is_preserved_after_inventory(installation, monkeypatch):
    prefix, ordinary, secret = installation
    after_inventory(monkeypatch, lambda: ordinary.chmod(0o600))
    result = helper.protect()
    assert result["protected_entries"] == 2
    assert mode(prefix) == mode(ordinary.parent) == 0o755
    assert mode(ordinary) == mode(secret) == 0o600


def test_existing_external_symlink_target_is_never_chmodded(installation):
    prefix, ordinary, secret = installation
    link = prefix / "external-link"
    link.symlink_to(secret)
    result = helper.protect()
    assert result["protected_entries"] == 3 and link.is_symlink()
    assert mode(prefix) == mode(ordinary.parent) == 0o755
    assert mode(ordinary) == 0o644 and mode(secret) == 0o600


def test_special_file_anywhere_in_initial_inventory_refuses_without_mutation(installation):
    prefix, ordinary, secret = installation
    os.mkfifo(prefix / "unsupported-fifo")
    with pytest.raises(ValueError, match="link-mode copy"):
        helper.protect()
    assert mode(prefix) == mode(ordinary.parent) == 0o775
    assert mode(ordinary) == 0o664 and mode(secret) == 0o600


def test_hardlink_created_after_directory_protection_is_rechecked(installation, monkeypatch):
    prefix, ordinary, secret = installation
    alias = prefix.parent / "new-cache-alias"
    original = helper._remove_write

    def protect_entry(descriptor, expected):
        if expected[2] == stat.S_IFREG:
            os.link(ordinary, alias)
        return original(descriptor, expected)

    monkeypatch.setattr(helper, "_remove_write", protect_entry)
    with pytest.raises(ValueError, match="link-mode copy"):
        helper.protect()
    # Safe partial progress can narrow installation directories. The shared
    # regular file and every external file remain untouched.
    assert mode(prefix) == mode(ordinary.parent) == 0o755
    assert mode(ordinary) == mode(alias) == 0o664 and mode(secret) == 0o600


def test_symlink_swap_after_open_does_not_redirect_descriptor_chmod(installation, monkeypatch):
    _, ordinary, secret = installation
    original = helper._remove_write
    retained = ordinary.parent / "retained.py"

    def protect_entry(descriptor, expected):
        if expected[2] == stat.S_IFREG:
            ordinary.rename(retained)
            ordinary.symlink_to(secret)
        return original(descriptor, expected)

    monkeypatch.setattr(helper, "_remove_write", protect_entry)
    with pytest.raises(ValueError, match="changed"):
        helper.protect()
    assert mode(secret) == 0o600 and mode(retained) == 0o644
    assert ordinary.is_symlink() and Path(os.readlink(ordinary)) == secret
