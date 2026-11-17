from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
import yaml

from gnetclisdk.client import Gnetcli, HostParams
from gnetclisdk.config import Config, config_to_yaml
from gnetclisdk.proto import server_pb2


@pytest.mark.asyncio
@pytest.mark.parametrize("host_params", [None, HostParams(device="huawei")])
async def test_collect_model_request_and_integer_precision(monkeypatch, host_params):
    call = AsyncMock(return_value=server_pb2.CollectModelResult(json='{"up-time":1770000000123456789}'))
    monkeypatch.setattr("gnetclisdk.client.server_pb2_grpc.GnetcliStub", lambda channel: SimpleNamespace(CollectModel=call))
    client = Gnetcli(insecure_grpc=True)
    client._grpc_channel_fn = Mock(return_value=object())
    result = await client.collect_model("lab.example.net", "uptime", host_params)
    assert result == {"up-time": 1770000000123456789}
    assert isinstance(result["up-time"], int)
    request = call.call_args.kwargs["request"]
    assert request.host == "lab.example.net"
    assert request.model == "uptime"
    assert request.HasField("host_params") == (host_params is not None)
    if host_params:
        assert request.host_params.device == "huawei"
    await client.collect_model("lab.example.net", "uptime", host_params)
    client._grpc_channel_fn.assert_called_once()


@pytest.mark.asyncio
async def test_collect_model_propagates_errors(monkeypatch):
    call = AsyncMock(side_effect=RuntimeError("model failed"))
    monkeypatch.setattr("gnetclisdk.client.server_pb2_grpc.GnetcliStub", lambda channel: SimpleNamespace(CollectModel=call))
    client = Gnetcli(insecure_grpc=True)
    client._grpc_channel_fn = Mock(return_value=object())
    with pytest.raises(RuntimeError, match="model failed"):
        await client.collect_model("lab.example.net", "uptime")


def test_models_directory_config():
    assert yaml.safe_load(config_to_yaml(Config(models_dir="/etc/gnetcli/models")))["models_dir"] == "/etc/gnetcli/models"
    assert "models_dir" not in yaml.safe_load(config_to_yaml(Config()))
