"""Adversarial source boundaries and report identity, without a model account."""

import json
import subprocess

import pytest
from snapshot import capture, digest, load
from tools import call


def commit(repo, message):
    subprocess.run(
        ["git", "-C", str(repo), "add", "."], check=True, capture_output=True
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Review Test",
            "-c",
            "user.email=review@example.invalid",
            "commit",
            "--no-verify",
            "-qm",
            message,
        ],
        check=True,
        capture_output=True,
    )
    return (
        subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"])
        .decode()
        .strip()
    )


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "app.py").write_text("value = 1\n")
    base = commit(repo, "base")
    (repo / "app.py").write_text("value = 2\n")
    (repo / "test_app.py").write_text("assert value == 2\n")
    (repo / "secret-link").symlink_to("/etc/passwd")
    (repo / "binary").write_bytes(b"\x00data")
    (repo / "large.txt").write_bytes(b"x" * 65537)
    (repo / "line\nbreak.md").write_text("A path containing a newline.\n")
    head = commit(repo, "head")
    return repo, base, head


def test_snapshot_uses_git_objects_and_explicit_omissions(repository, tmp_path):
    repo, base, head = repository
    (repo / "app.py").write_text("uncommitted = 'must never enter the snapshot'\n")
    snapshot = capture(repo, base, head)
    files = {item["path"]: item for item in snapshot["files"]}
    assert files["app.py"]["head"]["content"] == "value = 2\n"
    assert files["secret-link"]["head"]["reason"] == "not a regular file"
    assert files["binary"]["head"]["reason"] == "binary or non-UTF-8"
    assert files["large.txt"]["head"]["reason"] == "exceeds 64 KiB"
    assert "line\nbreak.md" in files
    key = digest(snapshot)
    for path in ("../secret", "/etc/passwd", "missing"):
        with pytest.raises(ValueError, match="outside"):
            call(
                snapshot,
                key,
                tmp_path / "reports.db",
                "read_file",
                {"path": path, "revision": "head"},
            )
    data = call(
        snapshot, key, None, "read_file", {"path": "app.py", "revision": "base"}
    )
    assert data["content"] == "1: value = 1"
    inventory = call(snapshot, key, None, "test_inventory", {})
    assert [item["path"] for item in inventory["files"]] == ["test_app.py"]
    assert "app.py" in inventory["other_changed_paths"]


def test_snapshot_and_publication_reject_changed_identity(repository, tmp_path):
    snapshot = capture(*repository)
    path = tmp_path / "snapshot.json"
    key = digest(snapshot)
    path.write_text(json.dumps(snapshot))
    assert load(path, key) == snapshot
    snapshot["head"] = "changed"
    path.write_text(json.dumps(snapshot))
    with pytest.raises(ValueError, match="snapshot changed"):
        load(path, key)
    with pytest.raises(ValueError, match="another snapshot"):
        call(
            snapshot,
            key,
            tmp_path / "reports.db",
            "publish_report",
            {"report": "review", "snapshot_hash": "another"},
        )
    assert not (tmp_path / "reports.db").exists()


def test_snapshot_rejects_empty_and_oversized_change_sets(repository):
    repo, base, head = repository
    with pytest.raises(ValueError, match="between 1 and 128"):
        capture(repo, head, head)
    for number in range(129):
        (repo / f"extra-{number}").write_text("extra")
    latest = commit(repo, "too large")
    with pytest.raises(ValueError, match="between 1 and 128"):
        capture(repo, base, latest)


def test_snapshot_ignores_git_replace_and_ambient_repository_override(
    repository, tmp_path, monkeypatch
):
    repo, base, head = repository
    oid = (
        subprocess.check_output(["git", "-C", str(repo), "rev-parse", head + ":app.py"])
        .decode()
        .strip()
    )
    replacement = (
        subprocess.check_output(
            ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
            input=b"substituted source\n",
        )
        .decode()
        .strip()
    )
    subprocess.run(["git", "-C", str(repo), "replace", oid, replacement], check=True)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "not-the-repository"))
    snapshot = capture(repo, base, head)
    file = next(item for item in snapshot["files"] if item["path"] == "app.py")
    assert file["head"]["oid"] == oid
    assert file["head"]["content"] == "value = 2\n"
