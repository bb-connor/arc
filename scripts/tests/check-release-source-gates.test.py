#!/usr/bin/env python3
"""Publication must reject stale, foreign, incomplete or failing source checks."""

import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "check-release-source-gates.py"
SPEC = importlib.util.spec_from_file_location("release_gate", PATH)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
REPOSITORY = "test/owned"
HEAD = "a" * 40
ROOT = PATH.parents[1]


def require_signing_source_boundary(text, job_name, sdk=None):
    """Check the ordered Actions prerequisites that protect canonical signing."""
    match = re.search(
        rf"^  {re.escape(job_name)}:\n(.*?)(?=^  [\w-]+:|\Z)",
        text.split("\njobs:\n", 1)[1],
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing signing job: {job_name}")
    job = match.group(1)
    header, step_text = job.split("    steps:\n", 1)
    if not re.search(r"^      actions: read$", header, re.MULTILINE):
        raise AssertionError("source qualification requires actions: read")
    steps = re.split(r"(?=^      - )", step_text, flags=re.MULTILINE)[1:]
    command = "python3 scripts/check-release-source-gates.py"
    if sdk:
        command += f' --sdk {sdk} --package "$PACKAGE_DIR"'
    gates = [i for i, step in enumerate(steps) if f"        run: {command}\n" in step]
    if len(gates) != 1:
        raise AssertionError("canonical signing job needs one exact-source gate")
    gate_index = gates[0]
    gate = steps[gate_index]
    if "GH_TOKEN: ${{ github.token }}" not in gate:
        raise AssertionError("source gate must use the job's GitHub token")
    if sdk and "PACKAGE_DIR: ${{ matrix.package }}" not in gate:
        raise AssertionError("SDK source gate must qualify the selected package")
    condition = re.search(r"^        if: (.*)$", gate, re.MULTILINE)
    if condition and (not sdk or condition.group(1) != "github.event_name == 'push'"):
        raise AssertionError("source gate must protect every canonical signing event")
    if re.search(r"^        continue-on-error:", gate, re.MULTILINE):
        raise AssertionError("source qualification failure must stop the job")
    checkouts = [
        i
        for i, step in enumerate(steps[:gate_index])
        if "uses: actions/checkout@" in step
    ]
    if not checkouts:
        raise AssertionError("source qualification requires a checkout")
    checkout = steps[checkouts[-1]]
    if "ref: ${{ github.sha }}" not in checkout or "fetch-depth: 0" not in checkout:
        raise AssertionError(
            "source gate must inspect the immutable event commit and tag"
        )
    signing = [
        i
        for i, step in enumerate(steps)
        if re.search(r"^\s+cosign sign-blob --yes", step, re.MULTILINE)
    ]
    if not signing or any(index <= gate_index for index in signing):
        raise AssertionError(
            "source qualification must succeed before all canonical signing"
        )
    first_setup = {"npm": "uses: actions/setup-node@", "pypi": "name: Install uv"}.get(
        sdk
    )
    if not sdk:
        first_setup = (
            "name: Checkout main"
            if job_name == "checksum-index"
            else "name: Install Rust toolchain"
        )
    if not any(first_setup in step for step in steps[gate_index + 1 :]):
        raise AssertionError(
            "source qualification must precede generated or modified build inputs"
        )


class SigningSourceWorkflow(unittest.TestCase):
    def test_all_canonical_signers_qualify_source_before_build_or_render(self):
        for filename, job_name, sdk in (
            ("release-binaries.yml", "build", None),
            ("release-binaries.yml", "checksum-index", None),
            ("release-npm.yml", "build", "npm"),
            ("release-pypi.yml", "build", "pypi"),
        ):
            with self.subTest(workflow=filename, job=job_name):
                require_signing_source_boundary(
                    (ROOT / ".github/workflows" / filename).read_text(), job_name, sdk
                )

    def test_checksum_signing_keeps_tagged_helpers_and_copies_exact_bytes_to_main(self):
        """Run the workflow checkout and shell boundaries with newer main code.

        GitHub qualification results are supplied and hosted cosign uses a file
        recorder. Git checkouts, the tagged identity helper, rendering and
        copying are real.
        """
        workflow = (ROOT / ".github/workflows/release-binaries.yml").read_text()
        job = re.search(
            r"^  checksum-index:\n(.*?)(?=^  [\w-]+:|\Z)",
            workflow.split("\njobs:\n", 1)[1],
            re.MULTILINE | re.DOTALL,
        ).group(1)
        steps = re.split(
            r"(?=^      - )", job.split("    steps:\n", 1)[1], flags=re.MULTILINE
        )[1:]

        def field(step, name, default=None):
            match = re.search(
                rf"^          {re.escape(name)}: (.*)$", step, re.MULTILINE
            )
            return match.group(1) if match else default

        def command(step):
            script = step.split("        run: ", 1)[1].rstrip()
            return textwrap.dedent(script[2:]) if script.startswith("|\n") else script

        with tempfile.TemporaryDirectory(prefix="chio-checksum-checkout-") as directory:
            root = Path(directory)
            origin = root / "origin"
            origin.mkdir()

            def git(cwd, *args):
                return subprocess.check_output(
                    ["git", *args], cwd=cwd, text=True, stderr=subprocess.PIPE
                ).strip()

            git(origin, "init", "--quiet", "--initial-branch=main")
            (origin / "scripts").mkdir()
            for name in ("verify-release-identity.py", "check-release-source-gates.py"):
                shutil.copyfile(ROOT / "scripts" / name, origin / "scripts" / name)
            manifest = origin / "crates/products/chio-cli/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text('[package]\nversion = "1.2.3"\n')

            def commit(message):
                git(origin, "add", ".")
                git(
                    origin,
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "--quiet",
                    "-m",
                    message,
                )
                return git(origin, "rev-parse", "HEAD")

            source = commit("qualified release source")
            git(origin, "tag", "v1.2.3")
            (origin / "scripts/verify-release-identity.py").write_text(
                "from pathlib import Path\n"
                'Path("supply-chain/checksums/v1.2.3.txt").write_text("new unqualified main changed signing bytes\\n")\n'
            )
            newer_main = commit("new main changes signing helper")
            tools = root / "tools"
            tools.mkdir()
            recorder = tools / "cosign"
            recorder.write_text(
                "#!/usr/bin/env python3\nimport hashlib, sys\nfrom pathlib import Path\n"
                "args = sys.argv[1:]\n"
                "blob = Path(args[-1]).read_bytes()\n"
                "Path(args[args.index('--output-signature') + 1]).write_text(hashlib.sha256(blob).hexdigest())\n"
                "Path(args[args.index('--output-certificate') + 1]).write_text('checkout fixture certificate\\n')\n"
            )
            recorder.chmod(0o755)
            workspace = root / "workspace"
            env = os.environ | {
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_REPOSITORY": "bb-connor/arc",
                "GITHUB_SHA": source,
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF_NAME": "v1.2.3",
                "GITHUB_REF": "refs/tags/v1.2.3",
                "GITHUB_WORKFLOW_REF": "bb-connor/arc/.github/workflows/release-binaries.yml@refs/tags/v1.2.3",
                "CHIO_VERSION": "1.2.3",
                "CHIO_RELEASE_TAG": "v1.2.3",
                "CHIO_SOURCE_REF": "refs/tags/v1.2.3",
                "CHIO_SOURCE_SHA": source,
            }

            def run(step):
                subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", command(step)],
                    cwd=workspace,
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                )

            index = workspace / "supply-chain/checksums/v1.2.3.txt"
            rendered = None
            signed_materials = {}
            reviewed = False
            for step in steps:
                name = step.split("\n", 1)[0].removeprefix("      - name: ")
                if "uses: actions/checkout@" in step:
                    target = workspace / field(step, "path", "")
                    if not target.exists():
                        git(
                            root,
                            "clone",
                            "--quiet",
                            "--no-local",
                            str(origin),
                            str(target),
                        )
                    ref = field(step, "ref")
                    git(
                        target,
                        "checkout",
                        "--quiet",
                        source if ref == "${{ github.sha }}" else ref,
                    )
                elif (
                    name
                    == "Require exact-source qualification before rendering or signing"
                ):
                    with (
                        patch.object(
                            GATE,
                            "__file__",
                            str(workspace / "scripts/check-release-source-gates.py"),
                        ),
                        patch.dict(os.environ, env, clear=True),
                        patch.object(GATE, "require_gates", return_value=[]),
                        contextlib.redirect_stdout(io.StringIO()),
                    ):
                        GATE.main()
                elif name == "Download release build artifacts":
                    artifacts = workspace / "artifacts"
                    artifacts.mkdir()
                    (artifacts / "release.sha256").write_text(
                        "a" * 64 + "  fixture.tar.gz\n"
                    )
                elif name == "Render checksum index":
                    run(step)
                    rendered = index.read_bytes()
                elif name == "Require canonical release signing identity":
                    run(step)
                elif name == "Cosign sign-blob checksum index":
                    run(step)
                    self.assertEqual(
                        index.read_bytes(),
                        rendered,
                        "new main helper changed canonical signing bytes",
                    )
                    self.assertEqual(git(workspace, "rev-parse", "HEAD"), source)
                    for suffix in (".txt", ".txt.sig", ".txt.pem"):
                        relative = Path("supply-chain/checksums/v1.2.3" + suffix)
                        signed_materials[relative] = (workspace / relative).read_bytes()
                elif name == "Copy signed checksum materials into review checkout":
                    run(step)
                elif name == "Open checksum index PR":
                    review = workspace / field(step, "path", "")
                    self.assertEqual(field(step, "base"), "main")
                    self.assertEqual(git(review, "rev-parse", "HEAD"), newer_main)
                    self.assertEqual(len(signed_materials), 3)
                    for relative, signed_bytes in signed_materials.items():
                        self.assertEqual((review / relative).read_bytes(), signed_bytes)
                        self.assertEqual(
                            (workspace / relative).read_bytes(), signed_bytes
                        )
                    reviewed = True
            self.assertTrue(
                reviewed, "the signed checksum review PR boundary did not run"
            )


class SourceGate(unittest.TestCase):
    def setUp(self):
        self.responses = {}
        self.run_paths = []
        self.job_paths = []
        self.requests = []
        for i, (name, (event, required)) in enumerate(GATE.REQUIRED.items(), 1):
            prefix = f"repos/{REPOSITORY}/actions"
            workflow = {"id": i, "path": f".github/workflows/{name}"}
            run = {
                "id": i * 10,
                "run_number": 1,
                "run_attempt": 2,
                "head_sha": HEAD,
                "head_branch": "main",
                "head_repository": {"full_name": REPOSITORY},
                "workflow_id": i,
                "path": workflow["path"],
                "event": event or "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
            }
            jobs = [
                {
                    "name": n,
                    "run_id": run["id"],
                    "head_sha": HEAD,
                    "run_attempt": 2,
                    "status": "completed",
                    "conclusion": "success",
                }
                for n in sorted(required)
            ]
            self.responses[f"{prefix}/workflows/{name}"] = workflow
            run_path = (
                f"{prefix}/workflows/{i}/runs?head_sha={HEAD}&branch=main&per_page=100"
            )
            job_path = f"{prefix}/runs/{run['id']}/attempts/2/jobs?per_page=100"
            self.responses[run_path] = {"total_count": 1, "workflow_runs": [run]}
            self.responses[job_path] = {"total_count": len(jobs), "jobs": jobs}
            self.run_paths.append(run_path)
            self.job_paths.append(job_path)

    def read(self, path):
        self.requests.append(path)
        return copy.deepcopy(self.responses[path])

    def require(self):
        return GATE.require_gates(REPOSITORY, HEAD, self.read)

    def test_exact_source_latest_attempt_succeeds(self):
        self.assertEqual(len(self.require()), len(GATE.REQUIRED))
        self.assertTrue(all(path in self.requests for path in self.job_paths))

    def test_foreign_or_unreviewed_run_never_substitutes(self):
        for key, value in [
            ("head_sha", "b" * 40),
            ("head_branch", "topic"),
            ("head_repository", {"full_name": "foreign/fork"}),
            ("workflow_id", 999),
            ("path", ".github/workflows/other.yml"),
            ("event", "pull_request"),
        ]:
            with self.subTest(field=key):
                self.setUp()
                self.responses[self.run_paths[0]]["workflow_runs"][0][key] = value
                with self.assertRaises(ValueError):
                    self.require()

    def test_incomplete_failed_or_cancelled_run_refuses(self):
        for status, conclusion in [
            ("in_progress", None),
            ("queued", None),
            ("completed", "failure"),
            ("completed", "cancelled"),
            ("completed", "skipped"),
            ("completed", "neutral"),
        ]:
            with self.subTest(status=status, conclusion=conclusion):
                self.setUp()
                self.responses[self.run_paths[1]]["workflow_runs"][0].update(
                    status=status, conclusion=conclusion
                )
                with self.assertRaises(ValueError):
                    self.require()

    def test_older_success_does_not_hide_latest_failure(self):
        data = self.responses[self.run_paths[0]]
        newer = copy.deepcopy(data["workflow_runs"][0])
        newer.update(id=999, run_number=2, conclusion="failure")
        data["workflow_runs"].append(newer)
        data["total_count"] += 1
        with self.assertRaises(ValueError):
            self.require()

    def test_required_job_binding_and_success(self):
        for key, value in [
            ("head_sha", "b" * 40),
            ("run_id", 999),
            ("run_attempt", 1),
            ("name", "unrelated"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("conclusion", "skipped"),
        ]:
            with self.subTest(field=key, value=value):
                self.setUp()
                self.responses[self.job_paths[0]]["jobs"][0][key] = value
                with self.assertRaises(ValueError):
                    self.require()

    def test_missing_or_duplicate_required_job_refuses(self):
        for duplicate in [False, True]:
            with self.subTest(duplicate=duplicate):
                self.setUp()
                data = self.responses[self.job_paths[0]]
                if duplicate:
                    data["jobs"].append(copy.deepcopy(data["jobs"][0]))
                else:
                    data["jobs"].pop()
                data["total_count"] = len(data["jobs"])
                with self.assertRaises(ValueError):
                    self.require()

    def test_truncated_api_results_refuse(self):
        for kind in ["run", "job"]:
            self.setUp()
            path = (self.run_paths if kind == "run" else self.job_paths)[0]
            self.responses[path]["total_count"] += 1
            with self.assertRaises(ValueError):
                self.require()

    def test_missing_or_malformed_api_response_refuses(self):
        for value in [{}, {"total_count": 0, "workflow_runs": []}]:
            self.setUp()
            self.responses[self.run_paths[0]] = value
            with self.assertRaises((KeyError, ValueError)):
                self.require()

    def test_api_failure_is_not_success(self):
        def fail(_):
            raise OSError("unavailable")

        with self.assertRaises(OSError):
            GATE.require_gates(REPOSITORY, HEAD, fail)


class ReleaseCheckout(unittest.TestCase):
    """Exercise real Git state and manifest reads; only the network is replaced."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="chio-release-gate-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "scripts").mkdir()
        (self.root / "crates/products/chio-cli").mkdir(parents=True)
        self.manifest = self.root / "crates/products/chio-cli/Cargo.toml"
        self.manifest.write_text('[package]\nversion = "0.1.1-rc.1"\n')
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )
        self.head = self.git("rev-parse", "HEAD").strip()
        self.git("tag", "v0.1.1-rc.1")
        self.env = {
            "GITHUB_SHA": self.head,
            "GITHUB_REF_NAME": "v0.1.1-rc.1",
            "GITHUB_REF_TYPE": "tag",
            "GITHUB_REPOSITORY": REPOSITORY,
        }

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def run_main(self, sdk=None, package=None):
        output = io.StringIO()
        with (
            patch.object(GATE, "__file__", str(self.root / "scripts/gate.py")),
            patch.dict(os.environ, self.env, clear=True),
            patch.object(
                GATE, "require_gates", return_value=[{"fixture": True}]
            ) as remote,
            contextlib.redirect_stdout(output),
        ):
            try:
                GATE.main(sdk, package)
            except (ValueError, subprocess.CalledProcessError):
                remote.assert_not_called()
                raise
            remote.assert_called_once_with(REPOSITORY, self.head)
        return json.loads(output.getvalue())

    def test_matching_tag_and_clean_exact_checkout_succeeds(self):
        self.assertEqual(self.run_main()["version"], "0.1.1-rc.1")

    def test_sdk_tags_require_the_selected_package_and_same_source_gates(self):
        for sdk, prefix, package, manifest, contents in [
            (
                "npm",
                "ts",
                "sdks/typescript/packages/process",
                "package.json",
                '{"version":"0.1.1-rc.1"}',
            ),
            (
                "pypi",
                "py",
                "sdks/python/chio-process",
                "pyproject.toml",
                '[project]\nversion = "0.1.1-rc.1"\n',
            ),
        ]:
            with self.subTest(sdk=sdk):
                path = self.root / package
                path.mkdir(parents=True)
                (path / manifest).write_text(contents)
                self.git("add", ".")
                self.git(
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "--quiet",
                    "-m",
                    "SDK package",
                )
                self.head = self.git("rev-parse", "HEAD").strip()
                self.env["GITHUB_SHA"] = self.head
                for tag in [
                    f"{prefix}/v0.1.1-rc.1",
                    f"{prefix}/{path.name}-v0.1.1-rc.1",
                ]:
                    self.git("tag", tag)
                    self.env["GITHUB_REF_NAME"] = tag
                    self.assertEqual(self.run_main(sdk, package)["source"], self.head)
                self.env["GITHUB_REF_NAME"] = f"{prefix}/other-v0.1.1-rc.1"
                with self.assertRaises(ValueError):
                    self.run_main(sdk, package)
                with self.assertRaises(ValueError):
                    self.run_main(sdk, "crates/products/chio-cli")

    def test_wrong_tag_ref_or_source_refuses_before_network(self):
        for key, value in [
            ("GITHUB_REF_NAME", "v0.1.0"),
            ("GITHUB_REF_TYPE", "branch"),
            ("GITHUB_SHA", "b" * 40),
        ]:
            with (
                self.subTest(field=key),
                patch.dict(self.env, {key: value}),
                self.assertRaises(ValueError),
            ):
                self.run_main()

    def test_dirty_tracked_checkout_refuses(self):
        self.manifest.write_text(self.manifest.read_text() + "# modified\n")
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_main()

    def test_missing_or_moved_release_tag_refuses_before_network(self):
        self.git("tag", "-d", "v0.1.1-rc.1")
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.run_main()
        self.git("tag", "v0.1.1-rc.1")
        self.manifest.write_text(self.manifest.read_text() + "# next source\n")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "next source",
        )
        self.head = self.git("rev-parse", "HEAD").strip()
        self.env["GITHUB_SHA"] = self.head
        with self.assertRaises(ValueError):
            self.run_main()

    def test_workspace_inherited_version_is_resolved(self):
        self.manifest.write_text("[package]\nversion.workspace = true\n")
        (self.root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "0.1.1-rc.1"\n'
        )
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "inherited version",
        )
        self.head = self.git("rev-parse", "HEAD").strip()
        self.env["GITHUB_SHA"] = self.head
        self.git("tag", "-f", "v0.1.1-rc.1")
        self.assertEqual(self.run_main()["version"], "0.1.1-rc.1")


if __name__ == "__main__":
    unittest.main()
