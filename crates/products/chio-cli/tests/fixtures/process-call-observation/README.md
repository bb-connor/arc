# Retained call-observation fixture

`issued-denial.json` is a public signed call observation from a confined budget
run. Its retained operation was compensated before dispatch, and its signed
response is a kernel denial. The observation is verified with the kernel key
pinned in `call_evidence/tests.rs`. No private key or private retained admission
request is included. The fixture supports offline signature and semantic
regressions; it does not certify all M5 requirements.
