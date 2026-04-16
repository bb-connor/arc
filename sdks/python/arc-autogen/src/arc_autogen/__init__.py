"""ARC AutoGen integration.

Wraps AutoGen's ``register_function`` / ``function_map`` and
``GroupChat`` / ``GroupChatManager`` so every registered function call
flows through the ARC sidecar for capability-scoped authorization and
signed receipts.

Public surface:

* :class:`ArcFunctionRegistry` -- per-agent registry that wraps each
  registered function with an ARC allow gate.
* :class:`ArcGroupChat` / :class:`ArcGroupChatManager` -- subclasses
  of :class:`autogen.GroupChat` / :class:`autogen.GroupChatManager`
  that accept a per-role ``capability_scope`` mapping.
* :func:`register_nested_chats_with_attenuation` -- mints attenuated
  child capabilities for nested conversations.
* :class:`ArcToolError` / :class:`ArcAutogenConfigError` -- error
  types.
"""

from arc_autogen.errors import ArcAutogenConfigError, ArcToolError
from arc_autogen.functions import (
    ArcFunctionRegistry,
    attach_registry,
    registry_for,
)
from arc_autogen.group_chat import ArcGroupChat, ArcGroupChatManager
from arc_autogen.nested import (
    attenuate_for_initiate_chats,
    rebind_registries,
    register_nested_chats_with_attenuation,
)

__all__ = [
    "ArcAutogenConfigError",
    "ArcFunctionRegistry",
    "ArcGroupChat",
    "ArcGroupChatManager",
    "ArcToolError",
    "attach_registry",
    "attenuate_for_initiate_chats",
    "rebind_registries",
    "register_nested_chats_with_attenuation",
    "registry_for",
]
