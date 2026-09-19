"""Shared validation for generated, non-nullable security object properties.

Manifest optional properties are omitted, never encoded as null. This base is
installed by xtask generation so ordinary public model parsing cannot silently
discard a present security property during exclude_none serialization. It does
not verify a publisher signature or authorize the declared permissions.
"""

from typing import Any

from pydantic import BaseModel, model_validator


class SecurityWireModel(BaseModel):
    @model_validator(mode="before")
    @classmethod
    def _reject_null_properties(cls, value: Any) -> Any:
        if isinstance(value, dict) and any(item is None for item in value.values()):
            raise ValueError("security properties must be omitted instead of null")
        return value
