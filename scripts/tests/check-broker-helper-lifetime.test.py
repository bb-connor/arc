#!/usr/bin/env python3
"""Exercise the release script across disposable candidate-command targets."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/check-secret-broker-boundary.sh"


class BrokerHelperLifetimeTests(unittest.TestCase):
    def test_release_helpers_survive_intervening_candidate_commands(self) -> None:
        source = GATE.read_text()
        start = source.rindex('if [[ "${mode}" == "--release" ]]; then')
        end = source.index('\necho "Secret broker boundary gate passed"', start)
        release = source[start:end]
        with tempfile.TemporaryDirectory(prefix="chio-broker-helper-lifetime-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            cargo = bin_dir / "cargo"
            cargo.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import os, shutil, sys\n"
                "transient = Path(os.environ['FIXTURE_TRANSIENT_TARGET'])\n"
                "shutil.rmtree(transient, ignore_errors=True)\n"
                "transient.mkdir()\n"
                "args = sys.argv[1:]\n"
                "if args[0] == 'build':\n"
                "    target = Path(os.environ['CARGO_TARGET_DIR'])\n"
                "    if '--target' in args:\n"
                "        target /= args[args.index('--target') + 1]\n"
                "    target /= 'debug'\n"
                "    target.mkdir(parents=True, exist_ok=True)\n"
                "    names = (['chio-keylog-witness', 'chio-keylog-audit']\n"
                "             if '--bins' in args else [args[args.index('--bin') + 1]])\n"
                "    for name in names:\n"
                "        path = target / name\n"
                "        path.write_text('#!/bin/sh\\nexit 0\\n')\n"
                "        path.chmod(0o755)\n"
                "elif args[0] == 'test':\n"
                "    helpers = [Path(os.environ[name]) for name in\n"
                "               ['CHIO_CAGE_TEST_HELPER', 'CHIO_BROKER_MCP_TOOL',\n"
                "                'CHIO_KEYLOG_WITNESS', 'CHIO_KEYLOG_AUDIT']]\n"
                "    helpers.append(helpers[2].with_name('chio'))\n"
                "    for helper in helpers:\n"
                "        if not helper.is_file() or not os.access(helper, os.X_OK):\n"
                "            sys.exit('built release helper disappeared: ' + str(helper))\n"
                "    with open(os.environ['FIXTURE_OBSERVATIONS'], 'a') as output:\n"
                "        output.write('all five helpers available\\n')\n"
                "else:\n"
                "    sys.exit('unexpected fixture cargo command')\n"
            )
            cargo.chmod(0o755)
            observations = root / "observations"
            environment = {
                **os.environ,
                "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                "CARGO_TARGET_DIR": str(root / "transient"),
                "FIXTURE_TRANSIENT_TARGET": str(root / "transient"),
                "FIXTURE_OBSERVATIONS": str(observations),
                "CHIO_ENTERPRISE_SECURITY_RUNNER": "1",
                "candidate_artifacts": str(root / "artifacts"),
                "workspace": str(ROOT),
            }
            script = (
                "set -euo pipefail\nmode=--release\n"
                "run_tests() { shift 3; \"$@\" -- --list; \"$@\"; }\n"
                + release
            )
            result = subprocess.run(
                ["bash", "-c", script], env=environment,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                observations.read_text().splitlines(),
                ["all five helpers available"] * 4,
            )
            self.assertFalse(any((root / "transient").iterdir()))


if __name__ == "__main__":
    unittest.main()
