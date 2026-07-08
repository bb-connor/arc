import inspect

from chio_sdk import client as chio_client


def test_default_tool_call_target_is_mediated():
    source = inspect.getsource(chio_client)
    # The mediated evaluate method must target /v1/evaluate, not the advisory route.
    assert '"/v1/evaluate"' in source or "'/v1/evaluate'" in source
    eval_src = inspect.getsource(chio_client.ChioClient.evaluate_tool_call)
    assert "/v1/evaluate/advisory" not in eval_src
    assert "/v1/evaluate" in eval_src
