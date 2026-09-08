"""A recipient authenticates the patch without the producer's private workspace."""

import copy
import json
import os

import pytest
from chio_mini_swe import repository_review as review
from chio_mini_swe import repository_store as store
from chio_mini_swe.repository import export
from chio_mini_swe.repository_archive import digest, encode_entries, entries, git
from chio_mini_swe.repository_proof import bindings, output_digest
from test_repository import commit, legacy_snapshots


@pytest.fixture(params=["v1", "v2"])
def bundle(tmp_path, monkeypatch, request):
    source = tmp_path / "source"
    source.mkdir()
    git("init", "--quiet", cwd=source)
    (source / "file").write_bytes(b"original\n")
    commit(source)
    monkeypatch.setattr(store, "engine", lambda: "fixture-engine")
    monkeypatch.setattr(store, "qualify_image", lambda _: None)
    state = tmp_path / "private-state"
    initialized = store.initialize(
        source, "HEAD", "sha256:" + "1" * 64, "sha256:" + "2" * 64, state, 1
    )
    if request.param == "v1":
        legacy_snapshots(state)

    class Completed:
        def execute(self, snapshot, command):
            files = entries(snapshot, allow_git=True)
            files["file"] = ("file", 0o644, command.encode())
            files["binary"] = ("file", 0o644, b"\0\xffbinary")
            files["link"] = ("symlink", 0o777, b"file")
            return encode_entries(files), {"output": "done", "returncode": 0, "exception_info": ""}

        def cleanup(self):
            pass

    monkeypatch.setattr(store.Workspace, "containers", lambda *_: Completed())
    output = tmp_path / "bundle"
    key = tmp_path / "trusted-key"
    key.write_bytes(b"fixture-key")
    receipts = []
    with store.Workspace(state) as workspace:
        for command in ("first change", "second change"):
            result = workspace.execute(command)
            receipts.append(
                {
                    "id": str(len(receipts)),
                    "tool_server": "sandbox",
                    "tool_name": "execute",
                    "content_hash": output_digest(result),
                    "action": {"parameters": {"command": command}},
                    "decision": {"verdict": "allow"},
                    "metadata": {"admission_operation": {"projected_state": "completed"}},
                }
            )
        export(workspace, output)
        raw = b"\n".join(json.dumps(r).encode() for r in receipts) + b"\n"
        verification = {"receipts_verified": len(receipts), "trusted_kernel_key": "fixture-key"}
        proof = {
            "schema": "chio.repository.receipt-binding.v1",
            "server_id": "sandbox",
            "verification": verification,
            "transitions": bindings(workspace, receipts, "sandbox"),
            "receipts_sha256": digest(raw),
            "kernel_key_sha256": digest(key.read_bytes()),
        }
    (output / "receipts.ndjson").write_bytes(raw)
    (output / "kernel.pub").write_bytes(key.read_bytes())
    (output / "receipt-binding.json").write_text(json.dumps(proof))

    def authenticate(_binary, actual, trusted):
        # Unit tests isolate bundle validation. Installed qualification exercises
        # the native signature verifier with original signed receipts separately.
        if actual != raw or trusted != key.read_bytes():
            raise ValueError("Receipt authentication failed")
        return copy.deepcopy(receipts), verification

    monkeypatch.setattr(review, "verified_receipts", authenticate)

    def forbidden(*_, **__):
        pytest.fail("Review tried to initialize private state or a Docker tool")

    monkeypatch.setattr(store, "Workspace", forbidden)
    monkeypatch.setattr(store, "engine", forbidden)
    (source / "file").write_bytes(b"unrelated reviewer changes\n")
    arguments = {
        "binary": "/unused/chio",
        "repository": source,
        "revision": initialized["source_commit"],
        "key_path": key,
        "server_id": "sandbox",
    }
    return output, arguments


def test_recipient_verifies_patch_from_own_commit_without_private_state(bundle):
    output, arguments = bundle
    value = review.verify_export(output, **arguments)
    assert value["verified_transitions"] == 2
    assert value["patch_sha256"] == digest((output / "changes.patch").read_bytes())
    assert (arguments["repository"] / "file").read_bytes() == b"unrelated reviewer changes\n"


@pytest.mark.parametrize(
    "mutation",
    [
        "baseline",
        "workspace",
        "patch",
        "config",
        "image",
        "command",
        "output",
        "sequence",
        "boolean_sequence",
        "interrupted",
        "chain",
        "proof_order",
        "proof_duplicate",
        "cached_success",
        "manifest",
        "key",
        "receipt",
        "server",
        "revision",
        "revision_ref",
    ],
)
def test_modified_evidence_is_refused(bundle, mutation):
    output, arguments = bundle
    if mutation in {"baseline", "workspace"}:
        target = output / (mutation + ".tar")
        files = entries(target.read_bytes())
        files["file"] = ("file", 0o644, b"forged contents")
        target.write_bytes(encode_entries(files))
    elif mutation == "patch":
        (output / "changes.patch").write_bytes(b"forged patch")
    elif mutation == "key":
        (output / "kernel.pub").write_bytes(b"attacker-key")
    elif mutation == "receipt":
        (output / "receipts.ndjson").write_bytes(b"{}\n")
    elif mutation in {"server", "revision", "revision_ref"}:
        arguments["server_id" if mutation == "server" else "revision"] = {
            "server": "other",
            "revision": "0" * 40,
            "revision_ref": "HEAD",
        }[mutation]
    else:
        name = (
            "configuration.json"
            if mutation in {"config", "image"}
            else "receipt-binding.json"
            if mutation in {"proof_order", "proof_duplicate", "cached_success"}
            else "manifest.json"
            if mutation == "manifest"
            else "commands.json"
        )
        target = output / name
        value = json.loads(target.read_text())
        if mutation == "config":
            value["timeout_seconds"] = 2
        elif mutation == "image":
            value["image"] = "sha256:" + "3" * 64
        elif mutation == "proof_order":
            value["transitions"].reverse()
        elif mutation == "proof_duplicate":
            value["transitions"][1] = value["transitions"][0]
        elif mutation == "cached_success":
            value["verification"]["receipts_verified"] = 999
        elif mutation == "manifest":
            value["interrupted"] = True
        elif mutation == "command":
            value[0]["command"] = "a different action"
        elif mutation == "output":
            value[0]["result"]["output"] = "tampered"
        elif mutation in {"sequence", "boolean_sequence"}:
            value[0]["sequence"] = True if mutation == "boolean_sequence" else 2
        elif mutation == "interrupted":
            value[0]["status"] = "interrupted"
        elif mutation == "chain":
            value[1]["before_sha256"] = "0" * 64
        target.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        review.verify_export(output, **arguments)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "large", "duplicate_json", "truncated"])
def test_unsafe_or_malformed_bundle_input_fails_before_native_verification(
    bundle, monkeypatch, kind
):
    output, arguments = bundle
    path = output / "manifest.json"
    if kind in {"symlink", "fifo"}:
        path.unlink()
        if kind == "symlink":
            path.symlink_to(arguments["key_path"])
        else:
            os.mkfifo(path)
    elif kind == "large":
        with path.open("wb") as stream:
            stream.truncate(65537)
    else:
        path.write_text('{"schema":1,"schema":2}' if kind == "duplicate_json" else "{")
    if kind in {"symlink", "fifo", "large"}:
        monkeypatch.setattr(review, "verified_receipts", lambda *_: pytest.fail("unsafe file read"))
    with pytest.raises((OSError, ValueError)):
        review.verify_export(output, **arguments)


def test_directory_replacement_cannot_mix_received_files(bundle, monkeypatch):
    output, _ = bundle
    real_read = review.read_file

    def replacing(path, maximum, *, directory=None):
        value = real_read(path, maximum, directory=directory)
        if path == "manifest.json":
            output.rename(output.with_name("captured"))
            output.mkdir()
        return value

    monkeypatch.setattr(review, "read_file", replacing)
    captured = review.capture(output)
    assert captured["changes.patch"] and not list(output.iterdir())
