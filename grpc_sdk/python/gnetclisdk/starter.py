import asyncio
import json
import logging
from asyncio.subprocess import Process
from json import JSONDecodeError
from subprocess import DEVNULL, PIPE, TimeoutExpired


logger = logging.getLogger(__name__)

DEFAULT_GNETCLI_SERVER_CONF = """
logging:
  level: debug
  json: true
port: 0
dev_auth:
  use_agent: true
  ssh_config: true
"""


class GnetcliStarter:
    def __init__(
        self,
        server_path: str,
        server_conf: str = DEFAULT_GNETCLI_SERVER_CONF,
        start_timeout: int = 5,
        stop_timeout: int = 10,
    ):
        self._server_path = server_path
        self._server_conf = server_conf
        self._running = False
        self._proc: Process | None = None
        self._start_timeout = start_timeout
        self._stop_timeout = stop_timeout

    async def _start(self) -> Process:
        logger.debug("Starting Gnetcli server: %s", self._server_path)
        proc = await asyncio.create_subprocess_exec(
            self._server_path,
            "--conf-file",
            "-",
            stdout=DEVNULL,  # we do not read stdout
            stderr=PIPE,
            stdin=PIPE,
        )
        self._running = True
        proc.stdin.write(self._server_conf.encode())
        await proc.stdin.drain()
        proc.stdin.close()
        return proc

    async def _wait_url(self) -> str:
        while proc := self._proc:
            output = await proc.stderr.readline()
            if output == "" and proc.returncode is not None:
                break
            if not output:
                continue
            logger.debug("gnetcli output: %s", output.strip())
            try:
                data = json.loads(output)
            except JSONDecodeError:
                logger.error("cannot decode data")
                continue
            if data.get("msg") == "init tcp socket":
                logger.debug("Tcp socket found")
                return data.get("address")
            if data.get("msg") == "init unix socket":
                logger.debug("Unix socket found")
                return "unix:" + data.get("path")
            if data.get("level") == "panic":
                logger.error("gnetcli error %s", data)
        return ""  # stopped

    async def __aenter__(self) -> str:
        self._proc = await self._start()
        try:
            return await asyncio.wait_for(
                self._wait_url(), timeout=self._start_timeout
            )
        except asyncio.TimeoutError:
            logger.error("gnetcli _wait_url timeout, terminating")
            await self._terminate()
            raise RuntimeError("gnetcli start failed")

    async def _terminate(self) -> None:
        if (proc := self._proc) is None:
            return
        if proc.returncode is not None:
            logger.error(
                "gnetcli already terminated with code: %s", proc.returncode
            )
            return
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=self._stop_timeout)
        except TimeoutExpired:
            logger.debug("gnetcli terminate failed, killing")
            self._proc.kill()
        self._proc = None

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        await self._terminate()
