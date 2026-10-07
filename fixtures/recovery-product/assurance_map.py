"""Source crosswalk for finite abstractions, explicitly not a SQL/system proof."""
import hashlib
import json
from pathlib import Path
import re

STORE = "crates/platform/chio-store-sqlite/src/admission_operation_store/recovery/"
TEST = "crates/platform/chio-control-plane/src/recovery/tests.rs"
MODEL = "docs/architecture/recoverable-agent-runtime/model/"
# Each group covers the named transitions, not every instruction in its owner.
ROWS = [
    ("ownership.select/approve", "state.rs", STORE+"commands.rs", "apply", TEST, "recovery_two_coordinators_select_once_and_review_exact_payload"),
    ("ownership.close/cancel", "state.rs", STORE+"native.rs", "begin_tx", TEST, "recovery_cancel_negative_lookup_fences_late_original_admission"),
    ("ownership.acquire/capture/stale-epoch", "state.rs", STORE+"native.rs", "verify_capture_tx", TEST, "recovery_two_coordinators_select_once_and_review_exact_payload"),
    ("ownership.effect/crash/observe/terminal-close", "state.rs", STORE+"native.rs", "settle", TEST, "recovery_fresh_process_cutpoints_preserve_original_ownership"),
    ("admission.intent/submit/native-project", "review_states.rs", STORE+"native.rs", "begin_tx", TEST, "recovery_fresh_process_cutpoints_preserve_original_ownership"),
    ("admission.cancel/late-admission/capture", "review_states.rs", STORE+"native.rs", "verify_capture_tx", TEST, "recovery_cancel_negative_lookup_fences_late_original_admission"),
    ("knowledge.prepare/observation/release/delivery/fence", "review_states.rs", "crates/platform/chio-control-plane/src/knowledge.rs", "release_into", "crates/platform/chio-control-plane/src/recovery/tests/knowledge.rs", "artifacts_native_publication_and_taint_commit_before_first_byte"),
    ("replay.original-revision/fresh-authorization/cached-refusal", "review_states.rs", STORE+"commands.rs", "apply", TEST, "recovery_command_replay_conflict_rotation_and_revocation"),
    ("partial-effect.observation/consumption/no-new-effect", "review_states.rs", STORE+"native.rs", "attach_provider_finality", TEST, "recovery_partial_finality_is_positive_scoped_and_spends_the_original"),
    ("nonce.reserve/frozen-envelope/custody/finalize", "third_nonce.rs", "crates/kernel/chio-process/src/recovery.rs", "finalize_recovery_call", TEST, "recovery_fresh_process_cutpoints_preserve_original_ownership"),
    ("nonce.intent/preflight/exact-native-attachment", "third_nonce.rs", STORE+"issuance.rs", "attach", TEST, "recovery_fresh_process_cutpoints_preserve_original_ownership"),
    ("nonce.original-capture/death/missing-ack/restart", "third_nonce.rs", STORE+"native.rs", "settle", TEST, "recovery_fresh_process_cutpoints_preserve_original_ownership"),
    ("nonce.expired-initiator/historical-settlement", "third_nonce.rs", STORE+"native.rs", "historical_release", TEST, "recovery_expired_initiating_authority_cannot_renew_pending_work"),
    ("coverage.four-obligations/four-context-bindings/principal-alias", "third_contracts.rs", "crates/security/chio-flow/src/recovery_authority.rs", "verify_recovery_coverage", "crates/core/chio-core-types/tests/recovery_authority_contracts.rs", "recovery_shared_closed_wire_and_signature_corpus"),
    ("parser.closed-versioned-wire/duplicates/allocation-bounds", None, "crates/core/chio-core-types/src/recovery/decode.rs", "decode_contract", "crates/core/chio-core-types/tests/recovery_contracts.rs", "malformed_tokens_and_nested_duplicates_have_no_permissive_fallback"),
    ("concurrency.native-two-coordinator-interleaving", None, STORE+"commands.rs", "apply", TEST, "recovery_two_coordinators_select_once_and_review_exact_payload"),
    ("concurrency.session/revocation/receipt-lock", None, "crates/kernel/chio-kernel/tests/loom_concurrency.rs", "loom_revocation_race_eval", "crates/kernel/chio-kernel/tests/loom_concurrency.rs", "loom_real_session_admission_never_outlives_terminal"),
]


def build_map(root):
    entries = [{"transitions":name, "model":MODEL+model if model else None,
                "owner":owner,"function":function,"cutpoint_file":test,"cutpoint":cutpoint}
               for name,model,owner,function,test,cutpoint in ROWS]
    paths = {p for entry in entries for p in [entry["owner"],entry["cutpoint_file"],entry["model"]] if p}
    paths.update(str(path.relative_to(root)) for path in (root/MODEL).glob("*.rs"))
    return {"schema":"chio.recovery-assurance-map.v1", "full_system_proof":False,
            "sources":[{"path":path,"sha256":hashlib.sha256((root/path).read_bytes()).hexdigest()} for path in sorted(paths)],
            "transitions":entries,
            "assumptions":["Finite bounds only", "Atomic authoritative model transitions", "Authentic scoped approvals and provider evidence",
                           "Correct storage bytes and provider idempotency", "Abstract cryptography, clocks and scheduling fairness"],
            "uncovered":["Complete production SQL transaction proof", "Complete two-store reservation bridge",
                         "General prerequisite DAG model", "Full artifact publication/custody/retention model",
                         "Provider correctness theorem", "Covert channels", "End-to-end liveness/fairness"],
            "interpretation":"The models verify their finite abstractions. Function/cutpoint hashes map those abstractions to tested owners; that crosswalk does not prove implementation refinement or complete-system correctness."}


def verify_map(root, mapping):
    if mapping.get("full_system_proof") is not False:
        raise ValueError("assurance.claim_expansion")
    expected = build_map(root)
    if mapping != expected:
        raise ValueError("assurance.stale_or_incomplete_source_map")
    for entry in mapping["transitions"]:
        for file, function in [(entry["owner"],entry["function"]), (entry["cutpoint_file"],entry["cutpoint"])]:
            if not re.search(r"\bfn\s+"+re.escape(function)+r"\b", (root/file).read_text()):
                raise ValueError("assurance.missing_owner_or_cutpoint")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    mapping = build_map(root)
    verify_map(root, mapping)
    print(json.dumps(mapping, indent=2))
