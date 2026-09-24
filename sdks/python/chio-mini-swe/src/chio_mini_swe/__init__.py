"""Experimental integration with mini-SWE-agent 2.4.6."""

__all__ = ["ChioAgent", "ChioEnvironment", "ChioExecutionError", "ChioModel", "ChioModelError"]


def __getattr__(name):
    # Operator configuration and tool discovery must not load upstream dotenv
    # files, initialize a provider, or print startup text onto an MCP stream.
    from importlib import import_module

    modules = {
        "ChioAgent": "agent",
        "ChioEnvironment": "environment",
        "ChioExecutionError": "environment",
        "ChioModel": "model",
        "ChioModelError": "model",
    }
    if name not in modules:
        raise AttributeError(name)
    value = getattr(import_module(f"chio_mini_swe.{modules[name]}"), name)
    globals()[name] = value
    return value
