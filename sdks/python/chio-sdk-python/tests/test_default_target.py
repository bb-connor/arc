import inspect

from chio_sdk import client as chio_client


def test_default_tool_call_target_is_advisory_id_based():
    """The id-only SDK default must reach the advisory id-based path.

    The wrappers hold a capability id, not a signed capability token, so
    ``evaluate_tool_call`` must take ``capability_id`` and delegate to the
    advisory route. It must never post an id-only stub to the token-requiring
    kernel-mediated ``/v1/evaluate`` route.
    """
    signature = inspect.signature(chio_client.ChioClient.evaluate_tool_call)
    assert "capability_id" in signature.parameters
    assert "capability" not in signature.parameters

    eval_src = inspect.getsource(chio_client.ChioClient.evaluate_tool_call)
    assert "evaluate_tool_call_advisory" in eval_src
    assert '"/v1/evaluate"' not in eval_src

    # The mediated route stays available as an explicit full-token helper.
    mediated_src = inspect.getsource(
        chio_client.ChioClient.evaluate_tool_call_mediated
    )
    assert '"/v1/evaluate"' in mediated_src
