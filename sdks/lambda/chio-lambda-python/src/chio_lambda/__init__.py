"""Python client for the Chio Lambda Extension.

The extension ships in the same Lambda execution environment as the handler
and listens on ``http://127.0.0.1:9090``. This package provides a thin
synchronous HTTP client and a ``@chio_tool`` decorator for wrapping handler
functions with capability evaluation.

Typical usage:

.. code-block:: python

    from chio_lambda import ChioLambdaClient, ChioLambdaError, chio_tool

    client = ChioLambdaClient()  # defaults to http://127.0.0.1:9090
    verdict = client.evaluate(
        capability_id="cap-...",
        tool_server="tools.example",
        tool_name="query",
    )
    if verdict.denied:
        raise RuntimeError(verdict.reason)

    @chio_tool(scope="db:read", tool_server="tools.example", tool_name="query")
    def handler(event, context, capability_id):
        return run_query(event["body"])
"""

from chio_lambda.client import (
    ChioLambdaClient,
    ChioLambdaError,
    EvaluateVerdict,
)
from chio_lambda.decorators import chio_tool

__all__ = [
    "ChioLambdaClient",
    "ChioLambdaError",
    "EvaluateVerdict",
    "chio_tool",
]
