## python client for Gnetcli server

Install Gnetcli GRPC-server.
- Download latest release from https://github.com/annetutil/gnetcli/releases/
- `tar -xzvf gnetcli_server-v1.0.0-darwin-amd64.tar.gz` (If see 'cannot be opened because the developer cannot be verified', then call `sudo xattr -d com.apple.quarantine gnetcli_server`)
- `./gnetcli_server -debug`

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

```
err=b'' status=0 out=b'2023-11-10 09:31:58\nFriday\nTime Zone(UTC) : UTC'
```
