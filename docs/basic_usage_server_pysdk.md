## gnetclisdk

Gnetclisdk is a python client for [Gnetcli GRPC-server](https://annetutil.github.io/gnetcli/basic_usage_server/).

Install:

```shell
pip install gnetclisdk
```

Start a local server on `127.0.0.1:50051` with explicit Basic auth first.
Set `GNETCLI_AUTH` to `Basic <base64(server-login:server-password)>`.
`LOGIN` and `PASSWORD` below are device credentials, not server credentials.
Plaintext gRPC is for local testing only.

Example:

```python
from gnetclisdk.client import Credentials, Gnetcli, HostParams
import os, asyncio

async def example():
    api = Gnetcli(
        server="localhost:50051",
        auth_token=os.environ["GNETCLI_AUTH"],
        insecure_grpc=True,
    )
    dev_creds = Credentials(os.environ.get("LOGIN"), os.environ.get("PASSWORD"))
    await api.set_host_params(hostname="myhost", params=HostParams(device="huawei", credentials=dev_creds))
    res = await api.cmd(hostname="myhost", cmd="dis clock")
    print("err=%s status=%s out=%s" % (res.error, res.status, res.out))

asyncio.run(example())
```

Output:

```
err=b'' status=0 out=b'2023-11-10 09:31:58\nFriday\nTime Zone(UTC) : UTC'
```
