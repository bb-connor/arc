#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

bash -n scripts/check-chio-drogon.sh scripts/setup-drogon-test-deps.sh
grep -Fq -- '-DCHIO_DROGON_REQUIRE_DEPS=ON' scripts/check-chio-drogon.sh
grep -Fq 'CHIO_DROGON_REQUIRE_DEPS=1 ./examples/hello-drogon/smoke.sh' scripts/check-chio-drogon.sh
grep -Fq 'cargo build --locked -p chio-cli --bin chio' scripts/check-chio-drogon.sh
grep -Fq 'CARGO_TARGET_DIR' scripts/check-chio-drogon.sh
grep -Fq -- '--no-tests=error' examples/hello-drogon/smoke.sh
test "$(grep -c -- '--no-tests=error' scripts/check-chio-drogon.sh)" -eq 2
if grep -Eq -- 'target help|package build skipped' scripts/check-chio-drogon.sh; then
  echo 'Drogon acceptance must not skip its configured package' >&2
  exit 1
fi
grep -Fq 'self.requires("drogon/1.9.12"' sdks/cpp/chio-drogon/conanfile.py
grep -Fq '89aca8c7993c8194f2c109c1d06a3b45bf363d5d' scripts/setup-drogon-test-deps.sh
grep -Fq 'test "$(git -C "${destination}" rev-parse HEAD)" = "${revision}"' scripts/setup-drogon-test-deps.sh
for gate in scripts/check-chio-cpp.sh sdks/cpp/chio-cpp-kernel/scripts/check-with-ffi.sh; do
  grep -Fq -- '--no-tests=error' "${gate}"
  grep -Fq 'CARGO_TARGET_DIR' "${gate}"
done
for workflow in .github/workflows/chio-cpp.yml .github/workflows/release-cpp.yml .github/workflows/sdk-parity.yml; do
  grep -Fq 'CMAKE_PREFIX_PATH="$(./scripts/setup-drogon-test-deps.sh)"' "${workflow}"
  # Each pinned-bootstrap job needs the Linux UUID development dependency.
  bootstrap_count="$(grep -Fc 'CMAKE_PREFIX_PATH="$(./scripts/setup-drogon-test-deps.sh)"' "${workflow}")"
  uuid_install_count="$(grep -Ec '^[[:space:]]*(packages:|sudo apt-get install).* uuid-dev( |$)' "${workflow}")"
  test "${uuid_install_count}" -eq "${bootstrap_count}"
done
python3 - <<'PY'
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import textwrap

source = Path("examples/hello-drogon/smoke.sh").read_text()
start = source.index("cleanup() {\n")
end = source.index("trap cleanup EXIT\n", start) + len("trap cleanup EXIT\n")
cleanup = source[start:end]
receipt = '{"id":"receipt-before-failure","signature":"fixture"}'
writer = textwrap.dedent('''
    import os, signal, sqlite3, time
    from pathlib import Path
    connection = sqlite3.connect(os.environ["RECEIPT_STORE"])
    assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE http_receipts (receipt_json TEXT NOT NULL)")
    connection.execute("INSERT INTO http_receipts VALUES (?)", (os.environ["DROGON_TEST_RECEIPT"],))
    connection.commit()
    def stop(signum, frame):
        connection.execute("INSERT INTO http_receipts VALUES (?)", ('{"id":"receipt-during-stop"}',))
        connection.commit()
        os._exit(0)  # Leave committed WAL bytes for cleanup to retain.
    signal.signal(signal.SIGTERM, stop)
    Path(os.environ["STATE_DIR"], "ready").touch()
    time.sleep(30)
''')
harness = "set -euo pipefail\n" + cleanup + '''
"$DROGON_TEST_PYTHON" -c "$DROGON_TEST_WRITER" &
SIDECAR_PID=$!
for ((attempt = 0; attempt < 500; attempt++)); do
  if [[ -f "$STATE_DIR/ready" ]]; then
    exit "$DROGON_TEST_EXIT"
  fi
  sleep 0.01
done
echo 'SQLite receipt fixture did not become ready' >&2
exit 99
'''

for retention_error in (False, True):
    with tempfile.TemporaryDirectory(prefix="drogon receipt retention ") as temporary:
        root = Path(temporary)
        state = root / "private state"
        state.mkdir(mode=0o700)
        (state / "authority.seed").write_text("private signing fixture\n")
        artifacts = root / "public artifacts"
        artifacts.mkdir()
        (artifacts / "receipts.ndjson").write_text("existing receipt export\n")
        database = artifacts / "sidecar-receipts.sqlite3"
        if retention_error:
            database.mkdir()  # A directory cannot receive the database copy.
        result = subprocess.run(
            ["bash", "-c", harness], capture_output=True, text=True, timeout=10,
            env={
                **os.environ,
                "STATE_DIR": str(state),
                "RECEIPT_STORE": str(state / "sidecar-receipts.sqlite3"),
                "ARTIFACT_ROOT": str(artifacts),
                "DROGON_TEST_PYTHON": sys.executable,
                "DROGON_TEST_WRITER": writer,
                "DROGON_TEST_RECEIPT": receipt,
                "DROGON_TEST_EXIT": "0" if retention_error else "23",
            },
        )
        if retention_error:
            assert result.returncode == 1, (result.returncode, result.stderr)
            assert (state / "sidecar-receipts.sqlite3").is_file()
        else:
            assert result.returncode == 23, (result.returncode, result.stderr)
            assert not state.exists(), "private signing state survived cleanup"
            for suffix in ("", "-wal", "-shm"):
                assert Path(str(database) + suffix).is_file(), f"lost receipt file {suffix!r}"
            assert {path.name for path in artifacts.iterdir()} == {
                "receipts.ndjson", "sidecar-receipts.sqlite3",
                "sidecar-receipts.sqlite3-wal", "sidecar-receipts.sqlite3-shm",
            }, "cleanup retained files beyond the receipt evidence"
            with sqlite3.connect(database) as connection:
                assert connection.execute("SELECT receipt_json FROM http_receipts ORDER BY rowid").fetchall() == [
                    (receipt,), ('{"id":"receipt-during-stop"}',),
                ]
            assert not (artifacts / "authority.seed").exists()
        assert (artifacts / "receipts.ndjson").read_text() == "existing receipt export\n"
print("Drogon cleanup retains failed-run receipts and rejects retention failures")
PY
echo 'C++ consumer gates require real dependency and nonempty test execution'
