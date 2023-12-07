import argparse
import asyncio
import logging
from base64 import b64encode
from typing import Optional

from gnetclisdk.client import Credentials, Gnetcli, HostParams


async def amain(
    host: str,
    cmd: str,
    device: str,
    token: Optional[str] = None,
    insecure: bool = False,
    device_login: Optional[str] = "",
    device_password: Optional[str] = "",
    device_port: Optional[int] = None,
):
    api = Gnetcli(auth_token=token, insecure_grpc=insecure)
    dev_creds = None
    if device_login and device_password:
        dev_creds = Credentials(device_login, device_password)
    await api.set_host_params(hostname=host, params=HostParams(device=device, credentials=dev_creds, port=device_port))
    res = await api.cmd(hostname=host, cmd=cmd)
    print("err=%s status=%s out=%s" % (res.error, res.status, res.out))
    res = await api.download(hostname=host, paths=["/tmp/test"])
    print(res)


def basic_auth(username: str, password: str) -> str:
    token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return token


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exec arbitrary command")
    parser.add_argument("--user", "-u", help="Specify the user name and password to use for basic auth")
    parser.add_argument("--cmd", help="Command", required=True, default="dis ver")
    parser.add_argument("--device-login", help="Device login")
    parser.add_argument("--device-password", help="Device password")
    parser.add_argument("--device", help="Device type", default="device", required=True)
    parser.add_argument("--insecure", help="Use insecure connection", action="store_true")
    parser.add_argument("--debug", help="Set debug log level", action="store_true")
    parser.add_argument("--host", help="Host", required=True)
    parser.add_argument("--port", help="Port", type=int, default=22, required=False)
    args = parser.parse_args()
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    token = None
    if args.user:
        btoken = basic_auth(*args.user.split(":"))
        token = "Basic %s" % btoken
    asyncio.run(
        amain(
            token=token,
            host=args.host,
            cmd=args.cmd,
            device=args.device,
            insecure=args.insecure,
            device_login=args.device_login,
            device_password=args.device_password,
            device_port=args.port,
        )
    )
