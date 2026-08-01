# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import tool_flow_declaration_schema


class ServerTool(Enum):
    computer_use = "computer_use"
    bash = "bash"
    text_editor = "text_editor"


class MonetaryAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: Annotated[str, Field(pattern="^[A-Z]{3}$")]
    units: Annotated[int, Field(ge=0, le=18446744073709551615)]


class NetworkDestination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    host: Annotated[str, Field(max_length=253, min_length=1, pattern="^[^A-Z*\\s/]+$")]
    port: Annotated[int, Field(ge=1, le=65535)]


class EnvironmentVariable(RootModel[str]):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?!(?:[lL][dD]_|[dD][yY][lL][dD]_|[bB][aA][sS][hH]_[fF][uU][nN][cC]_|[mM][aA][lL][lL][oO][cC]_))(?!(?:[bB][aA][sS][hH]_[eE][nN][vV]|[dD][oO][cC][kK][eE][rR]_[cC][oO][nN][fF][iI][gG]|[eE][nN][vV]|[gG][cC][oO][nN][vV]_[pP][aA][tT][hH]|[gG][eE][mM]_[hH][oO][mM][eE]|[gG][eE][mM]_[pP][aA][tT][hH]|[gG][iI][tT]_[aA][sS][kK][pP][aA][sS][sS]|[gG][lL][iI][bB][cC]_[tT][uU][nN][aA][bB][lL][eE][sS]|[gG][pP][gG]_[aA][gG][eE][nN][tT]_[iI][nN][fF][oO]|[iI][fF][sS]|[jJ][aA][vV][aA]_[tT][oO][oO][lL]_[oO][pP][tT][iI][oO][nN][sS]|[jJ][dD][kK]_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS]|[kK][rR][bB]5[cC][cC][nN][aA][mM][eE]|[lL][oO][cC][pP][aA][tT][hH]|[nN][eE][tT][rR][cC]|[nN][lL][sS][pP][aA][tT][hH]|[nN][oO][dD][eE]_[oO][pP][tT][iI][oO][nN][sS]|[nN][oO][dD][eE]_[pP][aA][tT][hH]|[nN][pP][mM]_[cC][oO][nN][fF][iI][gG]_[uU][sS][eE][rR][cC][oO][nN][fF][iI][gG]|[pP][eE][rR][lL]5[oO][pP][tT]|[pP][eE][rR][lL]5[lL][iI][bB]|[pP][yY][tT][hH][oO][nN][hH][oO][mM][eE]|[pP][yY][tT][hH][oO][nN][iI][nN][sS][pP][eE][cC][tT]|[pP][yY][tT][hH][oO][nN][pP][aA][tT][hH]|[pP][yY][tT][hH][oO][nN][sS][tT][aA][rR][tT][uU][pP]|[rR][uU][bB][yY][lL][iI][bB]|[rR][uU][bB][yY][oO][pP][tT]|[rR][uU][sS][tT][cC]_[wW][rR][aA][pP][pP][eE][rR]|[sS][sS][lL][kK][eE][yY][lL][oO][gG][fF][iI][lL][eE]|[sS][sS][lL]_[cC][eE][rR][tT]_[dD][iI][rR]|[sS][sS][lL]_[cC][eE][rR][tT]_[fF][iI][lL][eE]|[sS][sS][hH]_[aA][uU][tT][hH]_[sS][oO][cC][kK]|[sS][uU][dD][oO]_[aA][sS][kK][pP][aA][sS][sS]|[zZ][dD][oO][tT][dD][iI][rR]|_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS])$)(?!.*(?:[tT][oO][kK][eE][nN]|[sS][eE][cC][rR][eE][tT]|[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][dD]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[aA][pP][iI]_[kK][eE][yY]|[pP][rR][iI][vV][aA][tT][eE]_[kK][eE][yY]|[aA][cC][cC][eE][sS][sS]_[kK][eE][yY]|[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]))[A-Za-z_][A-Za-z0-9_]*$"
        ),
    ]


class NativeSyscallProfile(Enum):
    native_minimal_v1 = "native_minimal_v1"
    native_standard_v1 = "native_standard_v1"
    brokered_native_v1 = "brokered_native_v1"


class ReadPath(RootModel[str]):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: Annotated[
        str, Field(pattern="^/(?!$)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*\\/$).+$")
    ]


class WritePath(RootModel[str]):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: Annotated[
        str, Field(pattern="^/(?!$)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*\\/$).+$")
    ]


class RequiredPermissions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    environment_variables: Annotated[
        list[EnvironmentVariable] | None, Field(min_length=1)
    ] = None
    native_syscall_profile: NativeSyscallProfile
    network_destinations: Annotated[
        list[NetworkDestination] | None, Field(min_length=1)
    ] = None
    read_paths: Annotated[list[ReadPath] | None, Field(min_length=1)] = None
    write_paths: Annotated[list[WritePath] | None, Field(min_length=1)] = None


class ToolAnnotations(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destructive: bool
    idempotent: bool
    read_only: bool
    requires_approval: bool


class LatencyHint(Enum):
    instant = "instant"
    fast = "fast"
    moderate = "moderate"
    slow = "slow"


class PricingModel(Enum):
    flat = "flat"
    per_invocation = "per_invocation"
    per_unit = "per_unit"
    hybrid = "hybrid"


class ToolPricing(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    base_price: MonetaryAmount | None = None
    billing_unit: Annotated[str | None, Field(min_length=1)] = None
    pricing_model: PricingModel
    unit_price: MonetaryAmount | None = None


class ToolDefinition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    annotations: ToolAnnotations
    description: str
    flow: tool_flow_declaration_schema.ToolFlowDeclaration | None = None
    input_schema: dict[str, Any]
    latency_hint: LatencyHint | None = None
    name: Annotated[str, Field(min_length=1)]
    output_schema: dict[str, Any] | None = None
    pricing: ToolPricing | None = None


class ChioToolManifestV2(BaseModel):
    """
    Strict signed platform manifest body combining normative tool flow metadata and typed native cage permissions.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    description: str | None = None
    name: Annotated[str, Field(min_length=1)]
    public_key: Annotated[str, Field(min_length=1)]
    required_permissions: RequiredPermissions | None = None
    schema_: Annotated[Literal["chio.manifest.v2"], Field(alias="schema")]
    server_id: Annotated[str, Field(min_length=1)]
    server_tools: Annotated[list[ServerTool] | None, Field(min_length=1)] = None
    tools: Annotated[list[ToolDefinition], Field(min_length=1)]
    version: Annotated[str, Field(min_length=1)]
