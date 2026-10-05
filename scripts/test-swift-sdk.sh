#!/usr/bin/env bash
set -euo pipefail

SDK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../sdks/swift" && pwd)"
TEST_OUTPUT="${CHIO_SWIFT_TEST_OUTPUT:-$(mktemp -d -t chio-swift-tests)}"
mkdir -p "${TEST_OUTPUT}"
cd "${SDK_ROOT}"
xcodebuild -version
swift --version
xcodebuild -list -json > "${TEST_OUTPUT}/schemes.json"
SCHEME=$(python3 - "${TEST_OUTPUT}/schemes.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as source:
    data = json.load(source)
schemes = data.get('workspace', data.get('project', {})).get('schemes', [])
for candidate in ('Chio-Package', 'Chio'):
    if candidate in schemes:
        print(candidate)
        break
else:
    raise SystemExit('No recognized Swift package test scheme')
PY
)
xcrun simctl list runtimes --json > "${TEST_OUTPUT}/runtimes.json"
xcrun simctl list devices --json > "${TEST_OUTPUT}/devices.json"
SIMULATOR=$(python3 - "${TEST_OUTPUT}" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
runtimes = json.loads((root / 'runtimes.json').read_text())['runtimes']
devices = json.loads((root / 'devices.json').read_text())['devices']
ios = [r for r in runtimes if r['isAvailable'] and 'iOS' in r['name']]
for runtime in sorted(ios, key=lambda r: tuple(map(int, r['version'].split('.'))), reverse=True):
    for device in devices.get(runtime['identifier'], []):
        if device.get('isAvailable') and device['name'].startswith('iPhone'):
            print(device['udid'])
            raise SystemExit(0)
raise SystemExit('No available iPhone simulator')
PY
)
xcodebuild test \
  -scheme "${SCHEME}" \
  -destination "platform=iOS Simulator,id=${SIMULATOR}" \
  -resultBundlePath "${TEST_OUTPUT}/ChioTests.xcresult" \
  | tee "${TEST_OUTPUT}/xcodebuild.log"
xcrun xcresulttool get test-results summary \
  --path "${TEST_OUTPUT}/ChioTests.xcresult" --format json > "${TEST_OUTPUT}/summary.json"
python3 - "${TEST_OUTPUT}/summary.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as source:
    result = json.load(source)
passed = result.get('passedTests', 0)
failed = result.get('failedTests', 0)
print(f'Swift SDK: {passed} passed, {failed} failed')
if passed < 5 or failed != 0:
    raise SystemExit('Swift SDK requires all five native consumer and App Attest tests')
PY
