# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9695e2b405d3cd46de929a925e1a3b9b33ec4a67a0a5e93f625c433f820e1920
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import tool_flow_declaration_schema


class ServerTool(Enum):
    computer_use = "computer_use"
    bash = "bash"
    text_editor = "text_editor"


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


class MonetaryAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0, le=18446744073709551615)
    currency: constr(pattern=r"^[A-Z]{3}$")


class ToolAnnotations(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    read_only: bool
    destructive: bool
    idempotent: bool
    requires_approval: bool


class ReadPath(RootModel):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: constr(pattern=r"^/(?!$)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*\/$).+$")


class WritePath(RootModel):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: constr(pattern=r"^/(?!$)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*\/$).+$")


class EnvironmentVariable(RootModel):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: constr(
        pattern=r"^(?!(?:[lL][dD]_|[dD][yY][lL][dD]_|[bB][aA][sS][hH]_[fF][uU][nN][cC]_|[mM][aA][lL][lL][oO][cC]_))(?!(?:[bB][aA][sS][hH]_[eE][nN][vV]|[dD][oO][cC][kK][eE][rR]_[cC][oO][nN][fF][iI][gG]|[eE][nN][vV]|[gG][cC][oO][nN][vV]_[pP][aA][tT][hH]|[gG][eE][mM]_[hH][oO][mM][eE]|[gG][eE][mM]_[pP][aA][tT][hH]|[gG][iI][tT]_[aA][sS][kK][pP][aA][sS][sS]|[gG][lL][iI][bB][cC]_[tT][uU][nN][aA][bB][lL][eE][sS]|[gG][pP][gG]_[aA][gG][eE][nN][tT]_[iI][nN][fF][oO]|[iI][fF][sS]|[jJ][aA][vV][aA]_[tT][oO][oO][lL]_[oO][pP][tT][iI][oO][nN][sS]|[jJ][dD][kK]_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS]|[kK][rR][bB]5[cC][cC][nN][aA][mM][eE]|[lL][oO][cC][pP][aA][tT][hH]|[nN][eE][tT][rR][cC]|[nN][lL][sS][pP][aA][tT][hH]|[nN][oO][dD][eE]_[oO][pP][tT][iI][oO][nN][sS]|[nN][oO][dD][eE]_[pP][aA][tT][hH]|[nN][pP][mM]_[cC][oO][nN][fF][iI][gG]_[uU][sS][eE][rR][cC][oO][nN][fF][iI][gG]|[pP][eE][rR][lL]5[oO][pP][tT]|[pP][eE][rR][lL]5[lL][iI][bB]|[pP][yY][tT][hH][oO][nN][hH][oO][mM][eE]|[pP][yY][tT][hH][oO][nN][iI][nN][sS][pP][eE][cC][tT]|[pP][yY][tT][hH][oO][nN][pP][aA][tT][hH]|[pP][yY][tT][hH][oO][nN][sS][tT][aA][rR][tT][uU][pP]|[rR][uU][bB][yY][lL][iI][bB]|[rR][uU][bB][yY][oO][pP][tT]|[rR][uU][sS][tT][cC]_[wW][rR][aA][pP][pP][eE][rR]|[sS][sS][lL][kK][eE][yY][lL][oO][gG][fF][iI][lL][eE]|[sS][sS][lL]_[cC][eE][rR][tT]_[dD][iI][rR]|[sS][sS][lL]_[cC][eE][rR][tT]_[fF][iI][lL][eE]|[sS][sS][hH]_[aA][uU][tT][hH]_[sS][oO][cC][kK]|[sS][uU][dD][oO]_[aA][sS][kK][pP][aA][sS][sS]|[zZ][dD][oO][tT][dD][iI][rR]|_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS])$)(?!.*(?:[tT][oO][kK][eE][nN]|[sS][eE][cC][rR][eE][tT]|[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][dD]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[aA][pP][iI]_[kK][eE][yY]|[pP][rR][iI][vV][aA][tT][eE]_[kK][eE][yY]|[aA][cC][cC][eE][sS][sS]_[kK][eE][yY]|[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]))[A-Za-z_][A-Za-z0-9_]*$"
    )


class NativeSyscallProfile(Enum):
    native_minimal_v1 = "native_minimal_v1"
    native_standard_v1 = "native_standard_v1"
    brokered_native_v1 = "brokered_native_v1"


class NetworkDestination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    host: constr(pattern=r"^[^A-Z*\s/]+$", min_length=1, max_length=253)
    port: conint(ge=1, le=65535)


class ToolPricing(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    pricing_model: PricingModel
    base_price: MonetaryAmount | None = None
    unit_price: MonetaryAmount | None = None
    billing_unit: constr(min_length=1) | None = None


class RequiredPermissions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    read_paths: list[ReadPath] | None = Field(None, min_length=1)
    write_paths: list[WritePath] | None = Field(None, min_length=1)
    network_destinations: list[NetworkDestination] | None = Field(None, min_length=1)
    environment_variables: list[EnvironmentVariable] | None = Field(None, min_length=1)
    native_syscall_profile: NativeSyscallProfile


class ToolDefinition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: constr(min_length=1)
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    pricing: ToolPricing | None = None
    annotations: ToolAnnotations
    latency_hint: LatencyHint | None = None
    flow: tool_flow_declaration_schema.ToolFlowDeclaration | None = None


class ChioToolManifestV2(BaseModel):
    """
    Strict signed platform manifest body combining normative tool flow metadata and typed native cage permissions.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.manifest.v2"] = Field(..., alias="schema")
    server_id: constr(min_length=1)
    name: constr(min_length=1)
    description: str | None = None
    version: constr(min_length=1)
    tools: list[ToolDefinition] = Field(..., min_length=1)
    server_tools: list[ServerTool] | None = Field(None, min_length=1)
    required_permissions: RequiredPermissions | None = None
    public_key: constr(min_length=1)
