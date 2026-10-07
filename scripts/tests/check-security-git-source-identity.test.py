#!/usr/bin/env python3
"""Exercise security source projection against real Git object substitutions."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "security_source_identity_boundary",
    ROOT / "scripts/run-security-execution-container.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load security source boundary")
BOUNDARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BOUNDARY
SPEC.loader.exec_module(BOUNDARY)

AGGREGATE_SPEC = importlib.util.spec_from_file_location(
    "security_source_identity_aggregate",
    ROOT / "scripts/aggregate-security-evidence-shards.py",
)
if AGGREGATE_SPEC is None or AGGREGATE_SPEC.loader is None:
    raise SystemExit("unable to load security evidence aggregator")
AGGREGATE = importlib.util.module_from_spec(AGGREGATE_SPEC)
sys.modules[AGGREGATE_SPEC.name] = AGGREGATE
AGGREGATE_SPEC.loader.exec_module(AGGREGATE)

REVIEWED = b"reviewed source\n"
SUBSTITUTED = b"unreviewed source\n"


def git(root: Path, *arguments: str, payload: str | None = None) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(root), *arguments],
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
        check=True,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


class GitSourceIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="chio-source-identity-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "candidate"
        self.root.mkdir()
        git(self.root, "init", "--quiet")
        git(self.root, "config", "user.name", "Source identity test")
        git(self.root, "config", "user.email", "source-identity@invalid")
        (self.root / "source.rs").write_bytes(REVIEWED)
        git(self.root, "add", "source.rs")
        git(self.root, "commit", "--quiet", "-m", "reviewed source")
        self.approved = git(self.root, "rev-parse", "HEAD")
        self.approved_tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.approved_blob = git(self.root, "rev-parse", "HEAD:source.rs")
        (self.root / "source.rs").write_bytes(SUBSTITUTED)
        git(self.root, "add", "source.rs")
        git(self.root, "commit", "--quiet", "-m", "unreviewed source")
        self.substituted = git(self.root, "rev-parse", "HEAD")
        self.substituted_tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.substituted_blob = git(self.root, "rev-parse", "HEAD:source.rs")

    def test_normal_projection_copies_the_approved_commit(self) -> None:
        git(self.root, "checkout", "--quiet", "--detach", self.approved)
        identity = BOUNDARY.repository_identity(self.root, self.approved, None)
        destination = self.directory / "projected"
        BOUNDARY.materialize_private_copy(identity, destination)
        self.assertEqual((destination / "source.rs").read_bytes(), REVIEWED)
        self.assertEqual(identity.tree, self.approved_tree)

    def configure_transport_callback(self) -> Path:
        marker = self.directory / "untrusted-transport-executed"
        callback = self.directory / "transport-program"
        callback.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
            "raise SystemExit(1)\n"
        )
        callback.chmod(0o700)
        git(self.root, "config", "core.sshCommand", str(callback))
        git(self.root, "config", "protocol.ssh.allow", "always")
        return marker

    def configure_promisor_source(self) -> Path:
        git(self.root, "checkout", "--quiet", "--detach", self.approved)
        marker = self.configure_transport_callback()
        for name, value in (
            ("extensions.partialClone", "fixture"),
            ("remote.fixture.promisor", "true"),
            ("remote.fixture.partialCloneFilter", "blob:none"),
            ("remote.fixture.url", "ssh://example.invalid/approved-source"),
        ):
            git(self.root, "config", name, value)
        return marker

    def remove_promised_blob(self) -> Path:
        marker = self.configure_promisor_source()
        (self.root / ".git/objects" / self.approved_blob[:2] / self.approved_blob[2:]).unlink()
        return marker

    def test_fully_present_promisor_source_copies_local_approved_bytes(self) -> None:
        marker = self.configure_promisor_source()
        identity = BOUNDARY.repository_identity(self.root, self.approved, None)
        destination = self.directory / "projected"
        BOUNDARY.materialize_private_copy(identity, destination)
        self.assertEqual((destination / "source.rs").read_bytes(), REVIEWED)
        self.assertEqual(identity.tree, self.approved_tree)
        self.assertFalse(marker.exists())

    def test_missing_source_blob_cannot_execute_a_promisor_transport(self) -> None:
        marker = self.remove_promised_blob()
        with self.assertRaises(BOUNDARY.BoundaryError):
            identity = BOUNDARY.repository_identity(self.root, self.approved, None)
            BOUNDARY.materialize_private_copy(identity, self.directory / "projected")
        self.assertFalse(marker.exists(), "source projection executed a host transport")

    def test_batch_reader_cannot_fetch_a_missing_blob_after_preflight(self) -> None:
        git(self.root, "checkout", "--quiet", "--detach", self.approved)
        identity = BOUNDARY.repository_identity(self.root, self.approved, None)
        entries = BOUNDARY.parse_tree(identity.root, identity.head)
        marker = self.remove_promised_blob()
        with self.assertRaises(BOUNDARY.BoundaryError):
            BOUNDARY.read_git_blobs(identity.root, entries)
        self.assertFalse(marker.exists(), "batch source reader executed a host transport")

    def test_aggregate_reader_cannot_fetch_a_missing_promised_blob(self) -> None:
        marker = self.remove_promised_blob()
        with self.assertRaises(AGGREGATE.AggregationError):
            AGGREGATE.git(self.root, "cat-file", "blob", self.approved_blob)
        self.assertFalse(marker.exists(), "aggregate source reader executed a host transport")

    def test_repository_transport_permission_cannot_override_host_boundary(self) -> None:
        marker = self.configure_transport_callback()
        for label, read, error in (
            ("private source", lambda: BOUNDARY.git_command(
                self.root, ["ls-remote", "ssh://example.invalid/approved-source"]
            ), BOUNDARY.BoundaryError),
            ("aggregate", lambda: AGGREGATE.git(
                self.root, "ls-remote", "ssh://example.invalid/approved-source"
            ), AGGREGATE.AggregationError),
        ):
            with self.subTest(reader=label):
                with self.assertRaises(error):
                    read()
                self.assertFalse(marker.exists(), "repository transport permission executed a host program")
            marker.unlink(missing_ok=True)

    def test_source_configuration_cannot_execute_a_clean_filter(self) -> None:
        callback = self.directory / "clean-filter"
        marker = self.directory / "untrusted-filter-executed"
        callback.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\nimport sys\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n"
        )
        callback.chmod(0o700)
        (self.root / ".git/info/attributes").write_text("source.rs filter=fixture\n")
        git(self.root, "config", "filter.fixture.clean", str(callback))
        (self.root / "source.rs").write_bytes(SUBSTITUTED)
        try:
            BOUNDARY.repository_identity(self.root, self.substituted, None)
        except BOUNDARY.BoundaryError as error:
            self.assertIn("executable or redirected local Git configuration", str(error))
            self.assertNotIn(str(callback), str(error))
        else:
            self.assertFalse(marker.exists(), "source identity ran a host-side clean filter")
            self.fail("source identity accepted executable local Git configuration")
        self.assertFalse(marker.exists())

    def test_commit_replacement_cannot_copy_unreviewed_bytes(self) -> None:
        git(self.root, "replace", self.approved, self.substituted)
        git(self.root, "update-ref", "HEAD", self.approved)
        destination = self.directory / "projected"
        try:
            identity = BOUNDARY.repository_identity(self.root, self.approved, None)
        except BOUNDARY.BoundaryError as error:
            # A checkout of the replacement tree is dirty against the actual
            # approved object and must fail before any source is materialized.
            self.assertIn("must be clean before isolation", str(error))
            self.assertFalse(destination.exists())
            return
        BOUNDARY.materialize_private_copy(identity, destination)
        self.assertEqual((destination / "source.rs").read_bytes(), REVIEWED)
        self.assertEqual(identity.head, self.approved)
        self.assertEqual(identity.tree, self.approved_tree)

    def test_tree_replacement_cannot_change_projected_entries(self) -> None:
        git(self.root, "replace", self.approved_tree, self.substituted_tree)
        entries = BOUNDARY.parse_tree(self.root, self.approved)
        self.assertEqual(entries, [(0o100644, self.approved_blob, "source.rs")])
        self.assertEqual(
            BOUNDARY.read_git_blobs(self.root, entries),
            [(0o100644, "source.rs", REVIEWED)],
        )

    def test_blob_replacement_cannot_change_batch_reader_bytes(self) -> None:
        git(self.root, "replace", self.approved_blob, self.substituted_blob)
        entries = BOUNDARY.parse_tree(self.root, self.approved)
        self.assertEqual(entries, [(0o100644, self.approved_blob, "source.rs")])
        self.assertEqual(
            BOUNDARY.read_git_blobs(self.root, entries),
            [(0o100644, "source.rs", REVIEWED)],
        )

    def test_aggregate_commit_reader_uses_the_actual_approved_object(self) -> None:
        git(self.root, "replace", self.approved, self.substituted)
        self.assertEqual(
            AGGREGATE.git(self.root, "show", f"{self.approved}:source.rs"),
            REVIEWED,
        )

    def test_aggregate_blob_reader_uses_the_actual_approved_object(self) -> None:
        git(self.root, "replace", self.approved_blob, self.substituted_blob)
        self.assertEqual(
            AGGREGATE.git(self.root, "cat-file", "blob", self.approved_blob),
            REVIEWED,
        )

    def test_object_reads_never_invoke_a_configured_signature_program(self) -> None:
        callback = self.directory / "signature-program"
        marker = self.directory / "untrusted-signature-program-executed"
        callback.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
        )
        callback.chmod(0o700)
        # This deliberately invalid signature is object-reader test data. It
        # must not trigger a host-side verifier, and conveys no authenticity.
        commit = git(self.root, "cat-file", "commit", self.approved)
        signed = commit.replace(
            "\n\n",
            "\ngpgsig -----BEGIN PGP SIGNATURE-----\n fixture\n"
            " -----END PGP SIGNATURE-----\n\n",
            1,
        ) + "\n"
        object_id = git(self.root, "hash-object", "-t", "commit", "-w", "--stdin", payload=signed)
        git(self.root, "config", "log.showSignature", "true")
        git(self.root, "config", "gpg.program", str(callback))
        for label, read in (
            ("private source", lambda: BOUNDARY.git_command(self.root, ["show", "--no-patch", "--format=%T", object_id])),
            ("aggregate", lambda: AGGREGATE.git(self.root, "show", "--no-patch", "--format=%T", object_id)),
        ):
            with self.subTest(reader=label):
                self.assertEqual(read().decode().strip(), self.approved_tree)
                self.assertFalse(marker.exists(), "Git object inspection executed a signature program")
            marker.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
