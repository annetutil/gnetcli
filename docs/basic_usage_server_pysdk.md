## gnetclisdk

Gnetclisdk is a python GRPC-client. 

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
    res = await api.cmd(hostname="myhost", device="huawei", cmd="dis clock", credentials=dev_creds)
    print("err=%s status=%s out=%s" % (res.error, res.status, res.out))

asyncio.run(example())
```

Output:

```
err=b'' status=0 out=b'2023-11-10 09:31:58\nFriday\nTime Zone(UTC) : UTC'
```
