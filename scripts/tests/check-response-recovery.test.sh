#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-response-recovery.sh"
test -x "${runner}"
bash -n "${runner}"

for required in \
  '--test state_machine' \
  '--test response_executor executor_crash_' \
  '--test response_executor receipt_truth_' \
  '--test response_scheduler scheduler_fencing_' \
  '--test response_scheduler scheduler_ttl_' \
  '--test security_state overlapping_overlay_' \
  'matched zero tests'
do
  grep -Fq -- "${required}" "${runner}"
done

echo "Response recovery gate contract passed"
