## Python client for Gnetcli GRPC server

Gnetcli provides a universal way to execute arbitrary commands using a CLI,
eliminating the need for screen scraping with expect.

See documentation on [gnetcli server](https://annetutil.github.io/gnetcli/).

Start the server on `127.0.0.1:50051` with explicit authentication.
Set `GNETCLI_AUTH` to `Basic <base64(server-login:server-password)>`;
`LOGIN`/`PASSWORD` below are the device credentials. Plaintext gRPC is for
local testing only. See the server guide for TLS.

Example:

```python
from gnetclisdk.client import Credentials, Gnetcli, HostParams
import os, asyncio

async def example():
    api = Gnetcli(server="localhost:50051", insecure_grpc=True, auth_token=os.environ["GNETCLI_AUTH"])
    dev_creds = Credentials(os.environ.get("LOGIN"), os.environ.get("PASSWORD"))
    res = await api.cmd(hostname="myhost", cmd="dis clock", host_params=HostParams(device="huawei", credentials=dev_creds))
    print("err=%s status=%s out=%s" % (res.error, res.status, res.out))

asyncio.run(example())
```

Output:
```
err=b'' status=0 out=b'2023-11-10 09:31:58\nFriday\nTime Zone(UTC) : UTC'
```

### Tests

From this directory, with Go on `PATH` (to build `gnetcli_server` and `gswitch`):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-test.txt -e .
pytest tests/
```

Optional: `GNETCLI_TEST_PREBUILT_DIR` — directory that already contains `gnetcli_server` and `gswitch` binaries (skip `go build` in tests).
