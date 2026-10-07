#!/usr/bin/env python3
"""Run pinned upstream and comparison bytecode tests without editing contract code."""
import argparse
import pathlib
import shutil
import subprocess
import sys

PIN = "142e669c1fd318486a4628395b629f033654dd06"
URL = "https://github.com/erc-8183/base-contracts.git"
ROOT = pathlib.Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument("--upstream", type=pathlib.Path, default=ROOT.parent / "chio-paper-erc8183")
p.add_argument("--forge", default=shutil.which("forge") or str(ROOT / "tools/forge"))
p.add_argument("--label", default="reproduction")
a = p.parse_args()
upstream = a.upstream.resolve()
(ROOT / "empty-src").mkdir(exist_ok=True)
if not upstream.exists():
    subprocess.run(["git", "clone", "--no-checkout", URL, str(upstream)], check=True)
    subprocess.run(["git", "checkout", "--detach", PIN], cwd=upstream, check=True)
actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=upstream, text=True).strip()
if actual != PIN:
    sys.exit(f"Refusing different upstream commit: {actual}; expected {PIN}")
subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=upstream, check=True)
subprocess.run(["git", "submodule", "update", "--init", "--recursive"], cwd=upstream, check=True)
config = ROOT / "foundry.toml"
config.write_text(f'''[profile.default]
src = "empty-src"
test = "test"
out = "out"
cache_path = "cache"
libs = ["{upstream}/lib"]
allow_paths = ["{upstream}"]
solc_version = "0.8.28"
evm_version = "cancun"
optimizer = true
optimizer_runs = 200
remappings = [
  "upstream/={upstream}/",
  "@openzeppelin/contracts/={upstream}/lib/openzeppelin-contracts/contracts/",
  "@openzeppelin/contracts-upgradeable/={upstream}/lib/openzeppelin-contracts-upgradeable/contracts/",
  "forge-std/={upstream}/lib/forge-std/src/",
]
''')


def run(label, cwd, command):
    subprocess.run([
        sys.executable, str(ROOT / "record.py"), "--cwd", str(cwd),
        a.label + "-" + label, "--", *command,
    ], check=True)


run("forge-version", upstream, [a.forge, "--version"])
run("upstream", upstream, [a.forge, "test", "-vv"])
run("comparison-traces", ROOT, [a.forge, "test", "--config-path", str(config), "-vvvv"])
run("comparison-json", ROOT, [a.forge, "test", "--config-path", str(config), "--json"])
