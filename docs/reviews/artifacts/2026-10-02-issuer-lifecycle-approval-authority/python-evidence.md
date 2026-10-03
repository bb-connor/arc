# AP2/AP3 Python contract evidence

Checkout: /tmp/arc-security-launch, packet/3-retention-accounting. Cargo commands are serialized by parent; this owner ran no Cargo.

## Retained executions

- sdk-red.log: real SDK missing signed capability and unsigned decision controls failed before repair.
- sdk-control-red.log: workflow bearer propagation failed before repair.
- mock-approval-red.log: 2 failures, MockChioClient accepted ID-only submission and unsigned resolution before repair.
- hermes-approval-red.log: 1 failure, ID-only Hermes falsely returned requires_approval before repair.
- hermes-route-red.log: 1 failure, pending approval named UI chio_shell_run instead of kernel run_command before repair.
- sdk-mock-green-attempt.log: full SDK suite 216 passed, exit 0.
- hermes-final-tests-2.log: full Hermes suite 271 passed, 4 skipped, exit 0. The four test_against_real_sidecar cases require CHIO_INTEGRATION=1 and remain unavailable live operational evidence.
- hermes-ruff-final.log: affected Hermes sources/tests pass Ruff, exit 0.
- python-changed-surface-ruff.log: affected Hermes plus new SDK approval contract/model/tests pass Ruff, exit 0.
- python-ruff-attempt.log: initially 11 lint findings: one new Hermes import order repaired; 10 existing SDK client/testing findings. sdk-client-ruff-base.log and sdk-testing-ruff-base.log reproduce 9+1 at a617c0b02f182afac6acab2df89a2cd9270e4923. No suppression or baseline edits.

## Commands

```sh
PYTHONPATH=sdks/python/chio-sdk-python/src uv run --isolated --with httpx --with 'pydantic>=2.5,<3' --with pytest --with pytest-asyncio --with respx python -m pytest -q sdks/python/chio-sdk-python/tests
PYTHONPATH=sdks/python/chio-hermes:sdks/python/chio-hermes/src:sdks/python/chio-sdk-python/src:sdks/python/chio-code-agent/src:sdks/python/chio-adapter-base/src uv run --isolated --with httpx --with 'pydantic>=2.5,<3' --with pyyaml --with certifi --with pytest --with pytest-asyncio --with respx python -m pytest -q -rs sdks/python/chio-hermes/tests
```

The first SDK command with tests/test_approvals.py -k mock_rejects produced mock RED. The Hermes command with tests/test_hitl_approval.py -k requires_retained_full produced ID-only RED; -k records_submit_call produced exact kernel-route RED.

## Boundaries

Mock tokens are explicitly noncryptographic wire-shape fixtures. The mock validates supplied capability and decision identity/intent shapes and never manufactures an unsigned decision. Rust production tests own signature, admission, dispatch and restart authority evidence.

Hermes persists the full minted capability in its private cache, restores active matching tokens, requires the capability subject at submission, and submits actual kernel route/arguments. Operator CLI reads externally signed token files; slash commands accept explicitly supplied signed JSON. Duplicate fields and noninteger decision numbers fail parsing. CLI workflow clients may receive CHIO_SIDECAR_CONTROL_TOKEN; agent runtime never automatically adopts that token. No approver signer is provisioned.

Hermes native execution resume remains unavailable. Retrying a command is a different request; the CLI no longer promises that a plain retry will execute an approved call.
