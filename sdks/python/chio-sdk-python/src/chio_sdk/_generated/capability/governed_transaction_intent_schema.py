# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class OrderedEffect(Enum):
    throttle_session = "throttle_session"
    restrict_egress = "restrict_egress"
    suspend_session = "suspend_session"
    suspend_capability_set = "suspend_capability_set"
    freeze_issuance = "freeze_issuance"


class Tier(Enum):
    direct = "direct"
    delegated = "delegated"
    autonomous = "autonomous"


class Commerce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    seller: Annotated[str, Field(min_length=1)]
    shared_payment_token_id: Annotated[str, Field(min_length=1)]


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class GovernanceIdentifier(RootModel[str]):
    root: Annotated[str, Field(max_length=256, min_length=1)]


class SettlementMode(Enum):
    must_prepay = "must_prepay"
    hold_capture = "hold_capture"
    allow_then_settle = "allow_then_settle"


class MonetaryAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: Annotated[str, Field(min_length=1)]
    units: Annotated[int, Field(ge=0)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class ActiveResponsePlanBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    canonicalPlanBody: dict[str, Any]
    executorSubject: PublicKey
    expiresAt: Annotated[int, Field(ge=1)]
    operatorCapabilityExpiresAt: Annotated[int, Field(ge=1)]
    operatorCapabilityHash: Digest
    operatorCapabilityId: GovernanceIdentifier
    orderedEffects: Annotated[list[OrderedEffect], Field(max_length=5, min_length=1)]
    planBodyHash: Digest
    planId: GovernanceIdentifier
    planSchema: Literal["chio.response-plan.v1"]
    rollbackBinding: dict[str, Any]
    targetBinding: dict[str, Any]


class Autonomy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    delegationBondId: GovernanceIdentifier | None = None
    tier: Tier


class CallChain(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: GovernanceIdentifier
    delegatorSubject: Annotated[str, Field(min_length=1)]
    originSubject: Annotated[str, Field(min_length=1)]
    parentReceiptId: GovernanceIdentifier | None = None
    parentRequestId: GovernanceIdentifier


class Quote(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    billingUnit: Annotated[str, Field(min_length=1)]
    expiresAt: Annotated[int | None, Field(ge=1)] = None
    issuedAt: Annotated[int, Field(ge=0)]
    provider: Annotated[str, Field(min_length=1)]
    quoteId: GovernanceIdentifier
    quotedCost: MonetaryAmount
    quotedUnits: Annotated[int, Field(ge=0)]


class MeteredBilling(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    maxBilledUnits: Annotated[int | None, Field(ge=0)] = None
    quote: Quote
    settlementMode: SettlementMode


class ToolInvocationBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    autonomy: Autonomy | None = None
    call_chain: CallChain | None = None
    commerce: Commerce | None = None
    context: Any | None = None
    id: GovernanceIdentifier
    max_amount: MonetaryAmount | None = None
    metered_billing: MeteredBilling | None = None
    purpose: Annotated[str, Field(min_length=1)]
    runtime_attestation: dict[str, Any] | None = None
    server_id: Annotated[str, Field(min_length=1)]
    tool_name: Annotated[str, Field(min_length=1)]


class ChioGovernedTransactionIntent1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: ToolInvocationBody
    kind: Literal["tool_invocation"]
    schema_: Annotated[
        Literal["chio.governed-transaction-intent.v2"], Field(alias="schema")
    ]


class ChioGovernedTransactionIntent2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: ActiveResponsePlanBody
    kind: Literal["active_response_plan"]
    schema_: Annotated[
        Literal["chio.governed-transaction-intent.v2"], Field(alias="schema")
    ]


class ChioGovernedTransactionIntent(
    RootModel[ChioGovernedTransactionIntent1 | ChioGovernedTransactionIntent2]
):
    root: Annotated[
        ChioGovernedTransactionIntent1 | ChioGovernedTransactionIntent2,
        Field(title="Chio governed transaction intent"),
    ]
