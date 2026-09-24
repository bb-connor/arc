"""Run the public Rust worker API regression against the dedicated fixture."""

import argparse
import json
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-state", type=Path, required=True)
    args = parser.parse_args()
    state = json.loads(args.database_state.read_text())
    environment = {
        **os.environ,
        "CHIO_JOB_DATABASE_CA": state["ca"],
        "CHIO_JOB_TEST_RUNTIME_URL": state["urls"]["runtime"],
        "CHIO_JOB_TEST_WORKER_URL": state["urls"]["worker"],
    }
    result = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "chio-finding-market-store-postgres",
            "--test",
            "worker_lease_api",
            "--",
            "--ignored",
            "--nocapture",
        ],
        env=environment,
        timeout=600,
    )
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
