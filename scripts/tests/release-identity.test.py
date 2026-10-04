#!/usr/bin/env python3
"""Execute the documented verifier with real local-CA signatures and real cosign.

The test adapter substitutes only the CA and disables public log checks for these
local fixtures. It does not establish GitHub OIDC, Fulcio or Rekor acceptance.
"""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-release-identity.py"
REPO = "bb-connor/arc"
ISSUER = "https://token.actions.githubusercontent.com"
CHANNELS = {"binaries": "release-binaries.yml", "pypi": "release-pypi.yml", "npm": "release-npm.yml"}
TAGS = {"binaries": "v0.1.1-rc.1", "pypi": "py/chio-crewai-v0.2.0", "npm": "ts/express-v0.2.0"}


class ReleaseIdentityControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="chio-release-identity-")
        cls.directory = Path(cls.temp.name)
        cls.evidence = Path(os.environ.get("RL1_TEST_EVIDENCE_DIR", cls.directory / "evidence"))
        cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.cosign = shutil.which(os.environ.get("RL1_COSIGN", "cosign"))
        if not cls.cosign:
            raise RuntimeError("real cosign v2.4.1 is required; this test cannot use a mock")
        cls.tool_env = os.environ.copy()
        cls.tool_env["PATH"] = str(cls.directory / "bin") + os.pathsep + cls.tool_env["PATH"]
        (cls.directory / "bin").mkdir()
        adapter = cls.directory / "bin/cosign"
        adapter.write_text(
            "#!/usr/bin/env python3\nimport os, sys\n"
            f"tool = {cls.cosign!r}\n"
            "args = sys.argv[1:]\n"
            "if args and args[0] == 'verify-blob':\n"
            "    allowed = {'--signature', '--certificate', '--certificate-identity', '--certificate-oidc-issuer'}\n"
            "    if len(args) != 10 or set(args[1:-1:2]) != allowed:\n"
            "        sys.exit('production verifier changed its strict public verification flags')\n"
            f"    args[1:1] = ['--certificate-chain', {str(cls.directory / 'ca.pem')!r}, "
            "'--insecure-ignore-sct', '--insecure-ignore-tlog']\n"
            "os.execv(tool, [tool, *args])\n"
        )
        adapter.chmod(0o755)
        result = cls.run_command(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                         "-nodes", "-keyout", str(cls.directory / "ca.key"), "-out", str(cls.directory / "ca.pem"),
                         "-days", "1", "-subj", "/CN=RL1 local test CA", "-addext", "basicConstraints=critical,CA:TRUE",
                         "-addext", "keyUsage=critical,keyCertSign,cRLSign"], "fixture-ca")
        if result.returncode:
            raise RuntimeError(result.stderr)
        shutil.copyfile(cls.directory / "ca.pem", cls.evidence / "local-test-ca.pem")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def run_command(cls, command, label, env=None):
        result = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True, timeout=60)
        (cls.evidence / (label + ".json")).write_text(json.dumps({
            "command": command, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
            "qualification": "local CA command behavior only; no hosted keyless acceptance",
        }, indent=2) + "\n")
        return result

    def fixture(self, label, channel, identity=None, issuer=ISSUER):
        path = self.directory / label
        path.mkdir()
        artifact = path / "artifact.bin"
        artifact.write_bytes(b"RL1 signed release verification fixture\n")
        identity = identity or f"https://github.com/{REPO}/.github/workflows/{CHANNELS[channel]}@refs/tags/{TAGS[channel]}"
        extensions = path / "extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                              "extendedKeyUsage=codeSigning\nsubjectAltName=URI:" + identity + "\n"
                              "1.3.6.1.4.1.57264.1.1=DER:" + ":".join(f"{b:02x}" for b in issuer.encode()) + "\n")
        commands = [
            ["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", str(path / "leaf.key"), "-out", str(path / "leaf.csr"), "-subj", "/CN=RL1 local fixture"],
            ["openssl", "x509", "-req", "-in", str(path / "leaf.csr"), "-CA", str(self.directory / "ca.pem"),
             "-CAkey", str(self.directory / "ca.key"), "-set_serial", "123", "-out", str(artifact) + ".pem",
             "-days", "1", "-extfile", str(extensions)],
            ["openssl", "dgst", "-sha256", "-sign", str(path / "leaf.key"), "-out", str(path / "signature.raw"), str(artifact)],
        ]
        for index, command in enumerate(commands):
            result = self.run_command(command, label + f"-create-{index}")
            self.assertEqual(result.returncode, 0, result.stderr)
        Path(str(artifact) + ".sig").write_bytes(base64.b64encode((path / "signature.raw").read_bytes()))
        for suffix in ("", ".sig", ".pem"):
            shutil.copyfile(str(artifact) + suffix, self.evidence / (label + ".bin" + suffix))
        return artifact

    def verify_documented(self, label, channel, artifact, tag=None):
        # Retain the actual verification inputs, including mutations and absence.
        for suffix in ("", ".sig", ".pem"):
            source = Path(str(artifact) + suffix)
            retained = self.evidence / (label + ".bin" + suffix)
            if source.is_file():
                shutil.copyfile(source, retained)
            elif retained.exists():
                retained.unlink()
        document = (ROOT / "docs/install/VERIFY.md").read_text()
        match = re.search(r"<!-- release-verification-command -->\s*```bash\n(.*?)\n```", document, re.S)
        self.assertIsNotNone(match, "the documented release verification command path is missing")
        env = self.tool_env | {"CHIO_CHECKOUT": str(ROOT), "CHANNEL": channel, "TAG": tag or TAGS[channel],
                               "ARTIFACT": str(artifact)}
        return self.run_command(["bash", "-euo", "pipefail", "-c", match.group(1)], label, env)

    def test_documentation_uses_one_explicit_repository_and_exact_identity(self):
        for name in ("VERIFY", "PUBLISHING"):
            document = (ROOT / f"docs/install/{name}.md").read_text()
            self.assertNotRegex(document, r"backbay-industries|backbay-labs/chio|<owner>|certificate-identity-regexp")
            self.assertIn(REPO, document)

    def test_active_install_examples_use_canonical_repository_and_verify_before_extraction(self):
        for path in (ROOT / "docs/install").glob("*.md"):
            for example in re.findall(r"```[^\n]*\n(.*?)\n```", path.read_text(), re.S):
                self.assertNotRegex(example, r"backbay-labs/chio|backbay-industries|<owner>/chio", str(path))
        distribution = (ROOT / "docs/install/BINARY_DISTRIBUTION.md").read_text()
        example = next(block for block in re.findall(r"```bash\n(.*?)\n```", distribution, re.S) if "tar xf" in block)
        self.assertIn("verify-release-identity.py verify", example)
        self.assertLess(example.index("verify-release-identity.py verify"), example.index("tar xf"))

    def test_producers_check_the_same_repository_workflow_and_tag_policy(self):
        for channel, workflow in CHANNELS.items():
            document = (ROOT / ".github/workflows" / workflow).read_text()
            self.assertIn(f"verify-release-identity.py check-context --channel {channel}", document)
        self.assertTrue((ROOT / ".github/workflows/release-identity-check.yml").is_file(), "CI must execute the documented fixture checks")

    def test_correct_signed_fixture_for_each_artifact_family(self):
        for channel in CHANNELS:
            with self.subTest(channel=channel):
                label = "correct-" + channel
                result = self.verify_documented(label, channel, self.fixture(label, channel))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Verified OK", result.stderr)

    def test_valid_signatures_from_wrong_owner_repository_workflow_tag_or_issuer_fail(self):
        for channel, workflow in CHANNELS.items():
            identity = f"https://github.com/{REPO}/.github/workflows/{workflow}@refs/tags/{TAGS[channel]}"
            substitutions = {"wrong-owner": identity.replace("bb-connor", "attacker"),
                             "wrong-repository": identity.replace("/arc/", "/chio/"),
                             "wrong-workflow": identity.replace(workflow, "attacker.yml"),
                             "wrong-tag": identity.replace(TAGS[channel], TAGS[channel] + ".other"),
                             "branch-identity": identity.replace("refs/tags/" + TAGS[channel], "refs/heads/main")}
            for mutation, san in substitutions.items():
                label = channel + "-" + mutation
                with self.subTest(label=label):
                    result = self.verify_documented(label, channel, self.fixture(label, channel, san))
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIn("none of the expected identities", result.stderr)
            label = channel + "-wrong-oidc-issuer"
            with self.subTest(label=label):
                result = self.verify_documented(label, channel, self.fixture(label, channel, issuer="https://attacker.example"))
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn("none of the expected identities", result.stderr)

    def test_missing_empty_or_corrupt_signature_and_certificate_and_changed_bytes_fail(self):
        for suffix in (".sig", ".pem"):
            for mutation in ("missing", "empty", "corrupt"):
                label = mutation + suffix
                artifact = self.fixture(label, "binaries")
                sidecar = Path(str(artifact) + suffix)
                if mutation == "missing":
                    sidecar.unlink()
                else:
                    sidecar.write_bytes(b"invalid" if mutation == "corrupt" else b"")
                result = self.verify_documented(label, "binaries", artifact)
                self.assertNotEqual(result.returncode, 0, result.stderr)
        artifact = self.fixture("altered-bytes", "binaries")
        artifact.write_bytes(b"tampered bytes\n")
        result = self.verify_documented("altered-bytes", "binaries", artifact)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("signature", result.stderr.lower())

    def test_matching_identity_on_an_untrusted_certificate_fails(self):
        artifact = self.fixture("untrusted-certificate", "binaries")
        path = artifact.parent
        result = self.run_command([
            "openssl", "req", "-x509", "-key", str(path / "leaf.key"),
            "-out", str(artifact) + ".pem", "-days", "1",
            "-subj", "/CN=RL1 untrusted fixture", "-extensions", "default",
            "-config", str(path / "extensions.cnf"),
        ], "create-untrusted-certificate")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.verify_documented("untrusted-certificate", "binaries", artifact)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("certificate signed by unknown authority", result.stderr)

    def test_invalid_tag_inputs_and_channel_tag_confusion_are_rejected(self):
        self.assertTrue(SCRIPT.is_file(), "exact identity verifier is missing")
        tags = ("v.*", "v1.2.3$", "v1.2.3\n", "v1.2.3/other", "v01.2.3", "v1.2.3-01", "py/v1.2.3", "v1.2.3;echo injected")
        for index, tag in enumerate(tags):
            result = self.run_command(["python3", str(SCRIPT), "identity", "--channel", "binaries", "--tag", tag],
                                      "invalid-tag-" + str(index))
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_workflow_context_rejects_repository_workflow_ref_and_branch_substitution(self):
        self.assertTrue(SCRIPT.is_file(), "exact identity verifier is missing")
        env = self.tool_env | {"GITHUB_REPOSITORY": REPO, "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": TAGS["binaries"],
                               "GITHUB_REF": "refs/tags/" + TAGS["binaries"],
                               "GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/release-binaries.yml@refs/tags/" + TAGS["binaries"]}
        command = ["python3", str(SCRIPT), "check-context", "--channel", "binaries"]
        result = self.run_command(command, "correct-workflow-context", env)
        self.assertEqual(result.returncode, 0, result.stderr)
        for key in ("GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_REF", "GITHUB_REF_TYPE", "GITHUB_REF_NAME"):
            for value in ("foreign", ""):
                result = self.run_command(command, "context-reject-" + key + ("-missing" if not value else ""), env | {key: value})
                self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
