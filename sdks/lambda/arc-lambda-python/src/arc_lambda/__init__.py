"""Python client for the ARC Lambda Extension.

The extension ships in the same Lambda execution environment as the handler
and listens on ``http://127.0.0.1:9090``. This package provides a thin
synchronous HTTP client and a ``@arc_tool`` decorator for wrapping handler
functions with capability evaluation.

Typical usage:

.. code-block:: python

    from arc_lambda import ArcLambdaClient, ArcLambdaError, arc_tool

    client = ArcLambdaClient()  # defaults to http://127.0.0.1:9090
    verdict = client.evaluate(
        capability_id="cap-...",
        tool_server="tools.example",
        tool_name="query",
    )
    if verdict.denied:
        raise RuntimeError(verdict.reason)

    @arc_tool(scope="db:read", tool_server="tools.example", tool_name="query")
    def handler(event, context, capability_id):
        return run_query(event["body"])
"""

from arc_lambda.client import (
    ArcLambdaClient,
    ArcLambdaError,
    EvaluateVerdict,
)
from arc_lambda.decorators import arc_tool

__all__ = [
    "ArcLambdaClient",
    "ArcLambdaError",
    "EvaluateVerdict",
    "arc_tool",
]
