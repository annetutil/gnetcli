### GRPC

GRPC-server provides API to exec, upload and download. 
Example:
```python
async def amain(
        host: str,
        cmd: str,
        device: str,
        token: Optional[str] = None,
        insecure: bool = False,
        device_login: Optional[str] = "",
        device_password: Optional[str] = "",
):
    api = Gnetcli(auth_token=token, insecure_grpc=insecure)
    dev_creds = None
    if device_login and device_password:
        dev_creds = Credentials(device_login, device_password)
    # set connection parameters for host
    await api.set_host_params(hostname=host, params=HostParams(device=device, credentials=dev_creds))
    # exec cmd
    res = await api.cmd(hostname=host, cmd=cmd)
    print("err=%s status=%s out=%s" % (res.error, res.status, res.out))
    # download some file
    res = await api.download(hostname=host, paths=["/tmp/test"])
    print(res)
```
See full [example](https://github.com/annetutil/gnetcli/blob/main/grpc_sdk/python/example.py).

Before do anything with a host, `SetupHostParams` must be called with parameters for the host. 
See all possible options in `message HostParams`.

### SetupHostParams

Set credentials, device type and other parameters for the host.

### AddDevice

See [docs](new_device.md) about adding new device type.

### ExecChat/Exec

RPCs for command execution. ExecChat executing command in the same session.

### Download/Upload
RPCs for Download/Upload.
