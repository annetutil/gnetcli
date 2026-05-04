"""
Integration tests: dev_auth vs HostParams.credentials for SSH to gswitch.

Requires Go to build gnetcli_server and gswitch (or set GNETCLI_TEST_PREBUILT_DIR).
"""
from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Optional, Tuple

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gnetclisdk.client import Credentials, Gnetcli, HostParams
from gnetclisdk.config import AuthAppConfig, Config, LogConfig
from gnetclisdk.exceptions import GnetcliException
from gnetclisdk.starter import GnetcliStarter


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def wait_tcp(host: str, port: int, timeout: float = 20.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            _r, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"timeout waiting for {host}:{port}")

# Emulated switch accepts only this pair; server default dev_auth is wrong on purpose.
EMU_USER = "emuuser"
EMU_PASS = "emupass"


def _wrong_default_server_config() -> Config:
    return Config(
        logging=LogConfig(level="info", json=True),
        port="127.0.0.1:0",
        dev_auth=AuthAppConfig(
            login="wrong-default-user",
            password="wrong-default-pass",
            use_agent=False,
            ssh_config=False,
        ),
    )


def _dev_auth_private_key_only_config(private_key_path: str) -> Config:
    """Server uses SSH key from config; no useful password (gRPC must not send credentials)."""
    return Config(
        logging=LogConfig(level="info", json=True),
        port="127.0.0.1:0",
        dev_auth=AuthAppConfig(
            login=EMU_USER,
            password="",
            private_key=private_key_path,
            use_agent=False,
            ssh_config=False,
        ),
    )


def _write_ed25519_keypair(dir_path: str) -> Tuple[str, str]:
    """Return (path_to_openssh_private_pem, path_to_authorized_keys)."""
    d = Path(dir_path)
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_line = priv.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    pk_path = d / "id_ed25519"
    auth_path = d / "authorized_keys"
    pk_path.write_bytes(priv_pem)
    auth_path.write_bytes(pub_line + b"\n")
    return str(pk_path), str(auth_path)


async def _terminate_gswitch(proc: asyncio.subprocess.Process) -> None:
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=10)
    except asyncio.TimeoutError:
        proc.kill()


@asynccontextmanager
async def _gswitch_emu_listen(
    gswitch_bin: str,
    *,
    authorized_keys_path: Optional[str] = None,
) -> AsyncIterator[int]:
    """Start gswitch (Cisco emu) on 127.0.0.1:random port; yield port; then stop the process."""
    port = pick_free_port()
    args = [
        gswitch_bin,
        "-host",
        "127.0.0.1",
        "-port",
        str(port),
        "-username",
        EMU_USER,
        "-password",
        EMU_PASS,
        "-enable-telnet=false",
    ]
    if authorized_keys_path:
        args.extend(["-authorized-keys", authorized_keys_path])
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await wait_tcp("127.0.0.1", port)
        yield port
    finally:
        await _terminate_gswitch(proc)


@pytest.mark.asyncio
async def test_api_login_password_used_for_device(go_binaries: Tuple[str, str]) -> None:
    """Per-request credentials must override broken default dev_auth."""
    gnetcli_server_bin, gswitch_bin = go_binaries
    async with _gswitch_emu_listen(gswitch_bin) as port:
        starter = GnetcliStarter(
            gnetcli_server_bin,
            server_conf=_wrong_default_server_config(),
            start_timeout=30,
        )
        async with starter as url:
            client = Gnetcli(server=url, insecure_grpc=True)
            res = await client.cmd(
                hostname="pytest-host",
                cmd="show version",
                host_params=HostParams(
                    device="cisco",
                    ip="127.0.0.1",
                    port=port,
                    credentials=Credentials(login=EMU_USER, password=EMU_PASS),
                ),
            )
            out = bytes(res.out)
            assert b"Cisco IOS Software" in out


@pytest.mark.asyncio
async def test_default_dev_auth_used_when_no_api_credentials(go_binaries: Tuple[str, str]) -> None:
    """Without HostParams.credentials the server falls back to dev_auth (wrong) → SSH fails."""
    gnetcli_server_bin, gswitch_bin = go_binaries
    async with _gswitch_emu_listen(gswitch_bin) as port:
        starter = GnetcliStarter(
            gnetcli_server_bin,
            server_conf=_wrong_default_server_config(),
            start_timeout=30,
        )
        async with starter as url:
            client = Gnetcli(server=url, insecure_grpc=True)
            with pytest.raises(GnetcliException) as exc:
                await client.cmd(
                    hostname="pytest-host",
                    cmd="show version",
                    host_params=HostParams(
                        device="cisco",
                        ip="127.0.0.1",
                        port=port,
                        credentials=None,
                    ),
                )
            msg = str(exc.value).lower()
            assert "authenticate" in msg or "failed to connect" in msg


@pytest.mark.asyncio
async def test_dev_auth_private_key_used_no_grpc_credentials(
    go_binaries: Tuple[str, str], tmp_path: Path
) -> None:
    """private_key only in server dev_auth; HostParams without login/password — SSH uses the key."""
    gnetcli_server_bin, gswitch_bin = go_binaries
    key_dir = tmp_path / "ssh_keys"
    key_dir.mkdir()
    priv_path, auth_path = _write_ed25519_keypair(str(key_dir))

    async with _gswitch_emu_listen(gswitch_bin, authorized_keys_path=auth_path) as port:
        starter = GnetcliStarter(
            gnetcli_server_bin,
            server_conf=_dev_auth_private_key_only_config(priv_path),
            start_timeout=30,
        )
        async with starter as url:
            client = Gnetcli(server=url, insecure_grpc=True)
            res = await client.cmd(
                hostname="pytest-host",
                cmd="show version",
                host_params=HostParams(
                    device="cisco",
                    ip="127.0.0.1",
                    port=port,
                    credentials=None,
                ),
            )
            assert b"Cisco IOS Software" in bytes(res.out)
