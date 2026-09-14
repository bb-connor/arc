"""Snapshot storage must retain exact history through sharing and failed writes."""

import hashlib
import json
import os
import random

import pytest
from chio_mini_swe import repository_snapshots as snapshots
from chio_mini_swe.repository_archive import encode_entries
from chio_mini_swe.repository_store import atomic_bytes


@pytest.fixture
def storage(tmp_path):
    tmp_path.chmod(0o700)
    return snapshots.SnapshotStore.create(tmp_path / "snapshots", atomic_bytes)


def sample():
    return encode_entries(
        {
            "binary": ("file", 0o644, bytes(range(256)) * 8),
            "empty": ("file", 0o644, b""),
            "executable": ("file", 0o755, b"#!/bin/sh\nexit 0\n"),
            "link": ("symlink", 0o777, b"binary"),
            "nested": ("directory", 0o755, b""),
            "nested/" + "long" * 50: ("file", 0o644, b"long path\n"),
            ".git/config": ("file", 0o644, b"opaque Git configuration"),
        }
    )


@pytest.mark.parametrize("data", [encode_entries({}), sample()])
def test_reopened_store_recovers_original_archive_bytes(storage, data):
    key = storage.put(data)
    assert key == hashlib.sha256(data).hexdigest()
    reopened = snapshots.SnapshotStore(storage.root, atomic_bytes)
    assert reopened.load(key) == data
    files_before = {p.name: p.stat().st_mtime_ns for p in storage.objects.iterdir()}
    assert reopened.put(data) == key
    assert files_before == {p.name: p.stat().st_mtime_ns for p in storage.objects.iterdir()}


def test_tiny_edits_and_inserted_paths_share_unchanged_bodies_and_keep_history(storage):
    payload = random.Random(0).randbytes(4 * 1024 * 1024)
    history = []
    for sequence in range(32):
        data = encode_entries(
            {
                "a" * (sequence + 1): ("file", 0o644, b"shifts archive offsets"),
                "payload": ("file", 0o644, payload),
                "marker": ("file", 0o644, b"x" * sequence),
            }
        )
        key = storage.put(data)
        history.append((key, data))
    assert storage.usage() < 6 * 1024 * 1024
    payload_file = storage.objects / hashlib.sha256(payload).hexdigest()
    assert payload_file.read_bytes() == payload
    reopened = snapshots.SnapshotStore(storage.root, atomic_bytes)
    for key, data in history:
        assert reopened.load(key) == data


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "unknown",
        "digest",
        "boolean_bytes",
        "negative_bytes",
        "too_large",
        "no_chunks",
        "too_many_chunks",
        "chunk_type",
        "chunk_shape",
        "boolean_length",
        "negative_length",
        "path",
        "uppercase",
        "total",
        "sum_overflow",
        "reordered",
    ],
)
def test_invalid_indexes_fail_before_returning_any_archive(storage, mutation):
    key = storage.put(sample())
    path = storage.root / key
    index = json.loads(path.read_bytes())
    if mutation == "schema":
        index["schema"] = "future"
    elif mutation == "unknown":
        index["extra"] = 1
    elif mutation == "digest":
        index["sha256"] = "0" * 64
    elif mutation == "boolean_bytes":
        index["bytes"] = True
    elif mutation == "negative_bytes":
        index["bytes"] = -1
    elif mutation == "too_large":
        index["bytes"] = snapshots.MAX_ARCHIVE + 1
    elif mutation == "no_chunks":
        index["chunks"] = []
    elif mutation == "too_many_chunks":
        index["chunks"] = [["0" * 64, 1]] * (snapshots.MAX_CHUNKS + 1)
    elif mutation == "chunk_type":
        index["chunks"][0] = "invalid"
    elif mutation == "chunk_shape":
        index["chunks"][0].append(1)
    elif mutation == "boolean_length":
        index["chunks"][0][1] = True
    elif mutation == "negative_length":
        index["chunks"][0][1] = -1
    elif mutation == "path":
        index["chunks"][0][0] = "../outside"
    elif mutation == "uppercase":
        index["chunks"][0][0] = "A" * 64
    elif mutation == "total":
        index["bytes"] += 1
    elif mutation == "sum_overflow":
        index["chunks"] = [["0" * 64, snapshots.MAX_ARCHIVE]] * 2
    else:
        index["chunks"].reverse()
    atomic_bytes(path, json.dumps(index).encode())
    with pytest.raises(ValueError):
        storage.load(key)


@pytest.mark.parametrize("value", [b'{"schema":1,"schema":2}', b'{"bytes":NaN}', b"[]"])
def test_duplicate_nonfinite_and_nonobject_indexes_fail(storage, value):
    key = storage.put(sample())
    atomic_bytes(storage.root / key, value)
    with pytest.raises(ValueError):
        storage.load(key)


@pytest.mark.parametrize("location", ["index", "object"])
@pytest.mark.parametrize(
    "mutation", ["missing", "tampered", "symlink", "hardlink", "fifo", "public"]
)
def test_unsafe_or_corrupt_storage_never_loads(storage, tmp_path, location, mutation):
    key = storage.put(sample())
    index = json.loads((storage.root / key).read_bytes())
    path = storage.root / key if location == "index" else storage.objects / index["chunks"][0][0]
    original = path.read_bytes()
    path.unlink()
    outside = tmp_path / "outside"
    atomic_bytes(outside, original)
    if mutation == "tampered":
        atomic_bytes(path, b"x" * len(original))
    elif mutation == "symlink":
        path.symlink_to(outside)
    elif mutation == "hardlink":
        os.link(outside, path)
    elif mutation == "fifo":
        os.mkfifo(path, 0o600)
    elif mutation == "public":
        atomic_bytes(path, original)
        path.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        storage.load(key)
    assert outside.read_bytes() == original


def test_budget_refusal_writes_nothing_and_counts_orphan_objects(storage):
    data = sample()
    key = storage.put(data)
    charged = storage.usage()
    before = sorted(p.name for p in storage.objects.iterdir())
    with pytest.raises(ValueError, match="budget"):
        storage.put(encode_entries({"new": ("file", 0o644, b"new")}), charged)
    assert sorted(p.name for p in storage.objects.iterdir()) == before
    assert storage.load(key) == data
    orphan = b"not referenced by any snapshot"
    atomic_bytes(storage.objects / hashlib.sha256(orphan).hexdigest(), orphan)
    assert storage.usage() == charged + snapshots.MIN_FILE_CHARGE
    with pytest.raises(ValueError, match="budget"):
        storage.put(data, charged)


@pytest.mark.parametrize("stop_after", [1, 3, 6])
def test_interrupted_object_writes_preserve_old_snapshot_and_retry(storage, stop_after):
    original = encode_entries({"before": ("file", 0o644, b"original")})
    original_key = storage.put(original)
    before = storage.usage()
    calls = 0

    def interrupted(path, data):
        nonlocal calls
        calls += 1
        if calls == stop_after:
            raise OSError("disk write interrupted")
        atomic_bytes(path, data)

    data = sample()
    key = hashlib.sha256(data).hexdigest()
    storage.writer = interrupted
    with pytest.raises(OSError, match="interrupted"):
        storage.put(data)
    assert not (storage.root / key).exists()
    assert storage.load(original_key) == original
    assert storage.usage() >= before
    reopened = snapshots.SnapshotStore(storage.root, atomic_bytes)
    assert reopened.put(data) == key
    assert reopened.load(key) == data
    assert reopened.load(original_key) == original


def test_index_is_published_only_after_every_referenced_object(storage):
    def publish(path, data):
        if path.parent == storage.root:
            index = json.loads(data)
            for key, length in index["chunks"]:
                content = (storage.objects / key).read_bytes()
                assert len(content) == length
                assert hashlib.sha256(content).hexdigest() == key
        atomic_bytes(path, data)

    storage.writer = publish
    assert storage.load(storage.put(sample())) == sample()
