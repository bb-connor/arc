"""Shared native recovery structural vectors. Rust owns signature and context verification."""
import importlib
import json
from pathlib import Path
import pytest
from .recovery_schema_validation import RecoverySchemaRegistry, RecoverySchemaValidator as Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[4]
FILE_MODELS = {
    "action": ("action-intent", "RecoveryExactActionIntentV1"),
    "requirements": ("authorization-requirements", "RecoveryAuthorizationRequirementsV1"),
    "grant_binding": ("grant-binding", "RecoveryMandatoryGrantBindingV1"),
    "approval_intent": ("approval-intent", "RecoveryApprovalIntentV1"),
    "grant": ("signed-grant-v2", "SignedRecoveryDeclassificationGrantV2"),
    "coverage": ("signed-authority-coverage", "SignedRecoveryAuthorityCoverageV1"),
    "provider_finality": ("signed-provider-finality", "SignedRecoveryProviderFinalityV1"),
    "provider_body": ("provider-finality", "RecoveryProviderPositiveFinalityV1"),
    "command": ("command", "RecoveryCommandV1"),
    "support_issue_effect": ("support-issue-effect", "RecoverySupportIssueEffectContractV1"),
    "support_issue_input": ("support-issue-input", "RecoverySupportIssueInputV1"),
    "command_response": ("command-response", "RecoveryCommandResponseV1"),
    "command_result": ("command-result", "RecoveryCommandResultV1"),
    "review_document": ("review-document", "RecoveryReviewDocumentV1"),
}
SCHEMA_ROOT = ROOT / "spec/schemas/chio-wire/v1"
RESOURCES = []
for path in SCHEMA_ROOT.rglob("*.schema.json"):
    schema = json.loads(path.read_text())
    if "$id" in schema:
        resource = Resource.from_contents(schema)
        RESOURCES.append((schema["$id"], resource))
        # The established receipt ID uses a different namespace. File-relative
        # references still resolve through the authoritative local schema tree.
        for domain in ["chio.computer", "chio.world"]:
            alias = "https://" + domain + "/schemas/chio-wire/v1/" + path.relative_to(SCHEMA_ROOT).as_posix()
            if alias != schema["$id"]:
                RESOURCES.append((alias, resource))
REGISTRY = RecoverySchemaRegistry(Registry().with_resources(RESOURCES))
VECTORS = json.loads((ROOT / "spec/vectors/recovery/v1/authority-contracts.json").read_text())["vectors"]

@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_shared_closed_wire_shape(vector):
    name, _ = FILE_MODELS[vector["contract"]]
    schema = json.loads((ROOT / "spec/schemas/chio-wire/v1/recovery" / f"{name}.schema.json").read_text())
    assert Draft202012Validator(schema, registry=REGISTRY).is_valid(json.loads(vector["wire"])) == vector["schema_valid"]

@pytest.mark.parametrize("vector", [v for v in VECTORS if v["valid"]], ids=lambda vector: vector["name"])
def test_generated_types_preserve_native_positive_bytes(vector):
    name, cls = FILE_MODELS[vector["contract"]]
    module = importlib.import_module("chio_sdk._generated.recovery." + name.replace("-", "_") + "_schema")
    model = getattr(module, cls).model_validate_json(vector["wire"], strict=True)
    # Optional absent fields are omitted, matching the Rust wire projection.
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(vector["wire"])


def test_current_native_review_preserves_original_operation_claim():
    positive = json.loads((ROOT / "spec/vectors/recovery/v1/authority-positive.json").read_text())
    action = positive["action"]
    origin = action.get("origin")
    assert origin is not None, "current native actions must identify the original denial"
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    model = module.RecoveryExactActionIntentV1.model_validate_json(json.dumps(action), strict=True)
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True)["origin"] == origin
    preview = json.loads(positive["review_document"]["canonical_preview"])
    assert preview[0]["origin"] == origin
    schema = json.loads((SCHEMA_ROOT / "recovery/action-intent.schema.json").read_text())
    assert Draft202012Validator(schema, registry=REGISTRY).is_valid(action)


def test_generated_action_preserves_absent_legacy_origin_and_refuses_explicit_null():
    legacy = (ROOT / "spec/vectors/recovery/v1/legacy-action-intent.json").read_bytes()
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    model = module.RecoveryExactActionIntentV1.model_validate_json(legacy, strict=True)
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(legacy)
    assert model.model_dump(mode="json", by_alias=True) == json.loads(legacy)
    assert json.loads(model.model_dump_json(by_alias=True)) == json.loads(legacy)
    action = json.loads(legacy)
    action["origin"] = None
    with pytest.raises(ValueError):
        module.RecoveryExactActionIntentV1.model_validate_json(json.dumps(action), strict=True)


@pytest.mark.parametrize("member", ["request_id", "closure"])
def test_original_claim_identifiers_refuse_final_newline_in_every_schema_engine(member):
    action = json.loads((ROOT / "spec/vectors/recovery/v1/authority-positive.json").read_bytes())["action"]
    action["origin"][member] += "\n"
    schema = json.loads((SCHEMA_ROOT / "recovery/action-intent.schema.json").read_bytes())
    assert not Draft202012Validator(schema, registry=REGISTRY).is_valid(action)


@pytest.mark.parametrize("member,limit", [("title", 256), ("body", 16384)])
def test_generated_support_text_uses_decoded_utf8_byte_bounds(member, limit):
    module = importlib.import_module("chio_sdk._generated.recovery.support_issue_input_schema")
    payload = {"title": "title", "body": "body"}
    payload[member] = "é" * (limit // 2 + 1)
    with pytest.raises(ValueError):
        module.RecoverySupportIssueInputV1.model_validate(payload, strict=True)
    payload[member] = "é" * (limit // 2)
    assert getattr(module.RecoverySupportIssueInputV1.model_validate(payload, strict=True), member) == payload[member]


def test_signed_grant_binding_requires_a_positive_native_epoch():
    positive = json.loads((ROOT / "spec/vectors/recovery/v1/authority-positive.json").read_bytes())
    binding = positive["grant"]["body"]["recovery"]
    binding["isolation_epoch"] = 0
    schema = json.loads((SCHEMA_ROOT / "recovery/grant-binding.schema.json").read_bytes())
    assert not Draft202012Validator(schema, registry=REGISTRY).is_valid(binding)


def test_fresh_approval_schema_ceiling_is_sixteen_authority_attestations():
    positive = json.loads((ROOT / "spec/vectors/recovery/v1/authority-positive.json").read_bytes())
    submission = {"intent": positive["approval_intent"], "coverage": [positive["coverage"][0]] * 17}
    schema = json.loads((SCHEMA_ROOT / "recovery/approval-submission.schema.json").read_bytes())
    validator = Draft202012Validator(schema, registry=REGISTRY)
    assert not validator.is_valid(submission)
    submission["coverage"].pop()
    assert validator.is_valid(submission)


@pytest.mark.parametrize("vector_name", ["current-origin/duplicate-origin", "current-origin/duplicate-origin-closure"])
@pytest.mark.parametrize("wire_type", [str, bytes, bytearray], ids=["text", "bytes", "bytearray"])
def test_generated_action_json_refuses_duplicate_original_claims(vector_name, wire_type):
    vector = next(value for value in VECTORS if value["name"] == vector_name)
    wire = vector["wire"] if wire_type is str else wire_type(vector["wire"].encode("utf-8"))
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    with pytest.raises(ValueError, match="foundation profile"):
        module.RecoveryExactActionIntentV1.model_validate_json(wire, strict=True)


@pytest.mark.parametrize("wire_type", [str, bytes, bytearray], ids=["text", "bytes", "bytearray"])
def test_generated_action_json_preflight_preserves_current_and_legacy_data(wire_type):
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    current = next(value["wire"] for value in VECTORS if value["name"] == "current-origin/action-positive")
    legacy = (ROOT / "spec/vectors/recovery/v1/legacy-action-intent.json").read_text()
    for source in [current, legacy]:
        wire = source if wire_type is str else wire_type(source.encode("utf-8"))
        before = wire if wire_type is str else bytes(wire)
        model = module.RecoveryExactActionIntentV1.model_validate_json(wire, strict=True)
        assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(source)
        assert (wire if wire_type is str else bytes(wire)) == before
        assert ("origin" in model.model_dump(mode="json", by_alias=True)) == ("origin" in json.loads(source))


def test_generated_action_json_preserves_public_validation_overrides_and_context():
    from pydantic import field_validator
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    observed = []

    class ContextAction(module.RecoveryExactActionIntentV1):
        @field_validator("version", mode="after")
        @classmethod
        def capture_context(cls, value, information):
            observed.append(information.context)
            return value

    source = next(value["wire"] for value in VECTORS if value["name"] == "current-origin/action-positive")
    expected = json.loads(source)
    payload = json.loads(source)
    payload["schema_"] = payload.pop("schema")
    requirements = payload["authorization_requirements"]
    requirements["schema_"] = requirements.pop("schema")
    payload["consumer_extra"] = True
    context = {"consumer": "preserved"}
    model = ContextAction.model_validate_json(json.dumps(payload), strict=True, extra="ignore", context=context,
                                             by_alias=False, by_name=True)
    assert observed == [context]
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == expected
    with pytest.raises(ValueError):
        ContextAction.model_validate_json(json.dumps(payload), strict=True, extra="forbid", by_alias=False, by_name=True)


def test_generated_action_json_signature_preserves_supported_pydantic_parameters():
    import inspect
    from pydantic import BaseModel
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    current = inspect.signature(module.RecoveryExactActionIntentV1.model_validate_json)
    upstream = inspect.signature(BaseModel.model_validate_json)
    assert [(name, value.kind, value.default) for name, value in current.parameters.items()] == [
        (name, value.kind, value.default) for name, value in upstream.parameters.items()
    ]


def test_generated_action_json_preflight_applies_before_ignored_extra_allocation():
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    from chio_sdk.recovery_wire import MAX_WIRE_BYTES
    source = next(value["wire"] for value in VECTORS if value["name"] == "current-origin/action-positive")
    payload = json.loads(source)
    payload["consumer_extra"] = "x" * MAX_WIRE_BYTES
    with pytest.raises(ValueError, match="foundation profile"):
        module.RecoveryExactActionIntentV1.model_validate_json(json.dumps(payload), extra="ignore")


def test_generated_action_json_keeps_the_preflight_bytearray_snapshot(monkeypatch):
    from chio_sdk import recovery_wire
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    source = next(value["wire"] for value in VECTORS if value["name"] == "current-origin/action-positive")
    duplicate = next(value["wire"] for value in VECTORS if value["name"] == "current-origin/duplicate-origin")
    wire = bytearray(source.encode("utf-8"))
    preflight = recovery_wire.assert_foundation_wire

    def mutate_after_preflight(value):
        preflight(value)
        wire[:] = duplicate.encode("utf-8")

    monkeypatch.setattr(recovery_wire, "assert_foundation_wire", mutate_after_preflight)
    model = module.RecoveryExactActionIntentV1.model_validate_json(wire, strict=True)
    assert bytes(wire) == duplicate.encode("utf-8")
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(source)


@pytest.mark.parametrize("wire", ["{", b"\xff", bytearray(b"\xff")], ids=["syntax", "bytes-utf8", "bytearray-utf8"])
def test_generated_action_json_preserves_validation_error_family(wire):
    from pydantic import ValidationError
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    with pytest.raises(ValidationError) as error:
        module.RecoveryExactActionIntentV1.model_validate_json(wire, strict=True)
    assert error.value.error_count() == 1
    assert error.value.errors()[0]["type"] == "json_invalid"
    assert error.value.errors()[0]["input"] is None
    assert error.value.__context__ is None


@pytest.mark.parametrize("kind", [str, bytes, bytearray], ids=["text", "bytes", "bytearray"])
def test_generated_action_json_normalizes_subclasses_without_callbacks(kind):
    module = importlib.import_module("chio_sdk._generated.recovery.action_intent_schema")
    source = next(value["wire"] for value in VECTORS if value["name"] == "current-origin/action-positive")
    duplicate = next(value["wire"] for value in VECTORS if value["name"] == "current-origin/duplicate-origin")

    class CallbackWire(kind):
        def __len__(self):
            raise AssertionError("input length callback")

        def __str__(self):
            raise AssertionError("input string callback")

        def __bytes__(self):
            raise AssertionError("input bytes callback")

        def __getitem__(self, key):
            raise AssertionError("input indexing callback")

        def encode(self, *args, **kwargs):
            raise AssertionError("input encoding callback")

        def decode(self, *args, **kwargs):
            raise AssertionError("input decoding callback")

    positive_wire = CallbackWire(source if kind is str else source.encode("utf-8"))
    model = module.RecoveryExactActionIntentV1.model_validate_json(positive_wire, strict=True)
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(source)
    negative_wire = CallbackWire(duplicate if kind is str else duplicate.encode("utf-8"))
    with pytest.raises(ValueError, match="foundation profile"):
        module.RecoveryExactActionIntentV1.model_validate_json(negative_wire, strict=True)
