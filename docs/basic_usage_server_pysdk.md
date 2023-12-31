## gnetclisdk

Gnetclisdk is a python client for [Gnetcli GRPC-server](https://annetutil.github.io/gnetcli/basic_usage_server/).

Install:

```shell
pip install gnetclisdk
```

Example:

```python
from gnetclisdk.client import Credentials, Gnetcli
import os, asyncio

async def example():
    api = Gnetcli(insecure_grpc=True)
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
