import asyncio
import logging
import os.path
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from typing import Any, AsyncIterator, List, Optional, Tuple

import grpc
from google.protobuf.message import Message

from .proto import server_pb2, server_pb2_grpc
from .auth import BasicClientAuthentication, ClientAuthentication, OAuthClientAuthentication
from .exceptions import parse_grpc_error
from .interceptors import get_auth_client_interceptors

_logger = logging.getLogger(__name__)
HEADER_REQUEST_ID = "x-request-id"
HEADER_USER_AGENT = "user-agent"
DEFAULT_USER_AGENT = "Gnetcli SDK"
DEFAULT_SERVER = "localhost:50051"
SERVER_ENV = "GNETCLI_SERVER"
GRPC_MAX_MESSAGE_LENGTH = 130 * 1024**2

default_grpc_options: List[Tuple[str, Any]] = [
    ("grpc.max_concurrent_streams", 900),
    ("grpc.max_send_message_length", GRPC_MAX_MESSAGE_LENGTH),
    ("grpc.max_receive_message_length", GRPC_MAX_MESSAGE_LENGTH),
]


@dataclass
class QA:
    question: str
    answer: str


@dataclass
class Credentials:
    login: str
    password: str

    def make_pb(self) -> Message:
        pb = server_pb2.Credentials()
        pb.login = self.login
        pb.password = self.password
        return pb


def make_auth(auth_token: str) -> ClientAuthentication:
    if auth_token.lower().startswith("oauth"):
        authentication = OAuthClientAuthentication(auth_token.split(" ")[1])
    elif auth_token.lower().startswith("basic"):
        authentication = BasicClientAuthentication(auth_token.split(" ")[1])
    else:
        raise Exception("unknown token type")
    return authentication


class Gnetcli:
    def __init__(
        self,
        auth_token: Optional[str] = None,  # like 'Basic ...'
        server: Optional[str] = None,
        target_name_override: Optional[str] = None,
        cert_file: Optional[str] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        insecure_grpc: bool = False,
    ):
        if server is None:
            self._server = os.getenv(SERVER_ENV, DEFAULT_SERVER)
        else:
            self._server = server
        self._user_agent = user_agent

        options: List[Tuple[str, Any]] = [
            *default_grpc_options,
            ("grpc.primary_user_agent", user_agent),
        ]
        if target_name_override:
            _logger.warning("set target_name_override %s", target_name_override)
            options.append(("grpc.ssl_target_name_override", target_name_override))
        self._target_name_override = target_name_override
        cert = get_cert(cert_file=cert_file)
        channel_credentials = grpc.ssl_channel_credentials(root_certificates=cert)
        interceptors = []
        if auth_token:
            authentication: ClientAuthentication
            authentication = make_auth(auth_token)
            interceptors = get_auth_client_interceptors(authentication)
        grpc_channel_fn = partial(grpc.aio.secure_channel, credentials=channel_credentials, interceptors=interceptors)
        if insecure_grpc:
            grpc_channel_fn = partial(grpc.aio.insecure_channel, interceptors=interceptors)
        self._grpc_channel_fn = grpc_channel_fn
        self._options = options
        self._channel: Optional[grpc.aio.Channel] = None
        self._insecure_grpc: bool = insecure_grpc

    async def cmd(
        self,
        hostname: str,
        cmd: str,
        device: str,
        trace: bool = False,
        qa: Optional[List[QA]] = None,
        read_timeout: float = 0.0,
        cmd_timeout: float = 0.0,
        credentials: Optional[Credentials] = None,
    ) -> Message:
        pbcmd = make_cmd(
            hostname=hostname,
            device=device,
            cmd=cmd,
            trace=trace,
            qa=qa,
            read_timeout=read_timeout,
            cmd_timeout=cmd_timeout,
            credentials=credentials,
        )
        if self._channel is None:
            _logger.debug("connect to %s", self._server)
            self._channel = self._grpc_channel_fn(self._server, options=self._options)
        stub = server_pb2_grpc.GnetcliStub(self._channel)
        response = await grpc_call_wrapper(stub.Exec, pbcmd)
        return response

    async def add_device(
        self,
        name: str,
        prompt_expression: str,
        error_expression: Optional[str] = None,
        pager_expression: Optional[str] = None,
    ) -> Message:
        pbdev = server_pb2.Device
        pbdev.name = name
        pbdev.prompt_expression = prompt_expression
        if error_expression:
            pbdev.error_expression = error_expression
        if pager_expression:
            pbdev.pager_expression = pager_expression
        if self._channel is None:
            _logger.debug("connect to %s", self._server)
            self._channel = self._grpc_channel_fn(self._server, options=self._options)
        stub = server_pb2_grpc.GnetcliStub(self._channel)
        response = await grpc_call_wrapper(stub.AddDevice, pbdev)
        return response

    def connect(self) -> None:
        # make connection here will pass it to session
        if not self._channel:
            _logger.debug("real connect to %s", self._server)
            self._channel = self._grpc_channel_fn(self._server, options=self._options)

    async def cmd_netconf(self, hostname: str, cmd: str, json: bool = False, trace: bool = False) -> Message:
        pbcmd = server_pb2.CMDNetconf(host=hostname, cmd=cmd, json=json, trace=trace)
        _logger.debug("connect to %s", self._server)
        async with self._grpc_channel_fn(self._server, options=self._options) as channel:
            stub = server_pb2_grpc.GnetcliStub(channel)
            _logger.debug("executing netconf cmd: %r", pbcmd)
            try:
                response = await grpc_call_wrapper(stub.ExecNetconf, pbcmd)
            except Exception as e:
                _logger.error("error hostname=%s cmd=%r error=%s", hostname, repr(pbcmd), e)
                raise
            return response

    @asynccontextmanager
    async def cmd_session(self, hostname: str) -> AsyncIterator["GnetcliSessionCmd"]:
        sess = GnetcliSessionCmd(
            hostname,
            server=self._server,
            channel=self._channel,
            target_name_override=self._target_name_override,
            user_agent=self._user_agent,
            insecure_grpc=self._insecure_grpc,
        )
        await sess.connect()
        try:
            yield sess
        finally:
            await sess.close()

    @asynccontextmanager
    async def netconf_session(self, hostname: str) -> AsyncIterator["GnetcliSessionNetconf"]:
        sess = GnetcliSessionNetconf(
            hostname,
            # self._token,
            server=self._server,
            target_name_override=self._target_name_override,
            user_agent=self._user_agent,
            insecure_grpc=self._insecure_grpc,
        )
        await sess.connect()
        try:
            yield sess
        finally:
            await sess.close()

    async def upload(self, hostname: str, file_path: str, data: bytes) -> Message:
        pbcmd = server_pb2.FileUploadRequest(host=hostname, path=file_path, data=data)
        _logger.debug("connect to %s", self._server)
        async with self._grpc_channel_fn(self._server, options=self._options) as channel:
            _logger.debug("upload %s to %s", file_path, hostname)
            stub = server_pb2_grpc.GnetcliStub(channel)
            response: Message = await grpc_call_wrapper(stub.Upload, pbcmd)
            return response

    async def download(self, hostname: str, file_path: str) -> Message:
        pbcmd = server_pb2.FileDownloadRequest(host=hostname, path=file_path)
        _logger.debug("connect to %s", self._server)
        async with self._grpc_channel_fn(self._server, options=self._options) as channel:
            _logger.debug("download %s for %s", file_path, hostname)
            stub = server_pb2_grpc.GnetcliStub(channel)
            response: Message = await grpc_call_wrapper(stub.Download, pbcmd)
            return response

    async def downloads(self, hostname: str, file_path: str) -> Message:
        pbcmd = server_pb2.FileDownloadRequest(host=hostname, path=file_path)
        _logger.debug("connect to %s", self._server)
        async with self._grpc_channel_fn(self._server, options=self._options) as channel:
            _logger.debug("downloads %s for %s", file_path, hostname)
            stub = server_pb2_grpc.GnetcliStub(channel)
            response: Message = await grpc_call_wrapper(stub.Downloads, pbcmd)
            return response


class GnetcliSession(ABC):
    def __init__(
        self,
        hostname: str,
        token: str,
        server: str = DEFAULT_SERVER,
        target_name_override: Optional[str] = None,
        cert_file: Optional[str] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        insecure_grpc: bool = False,
        channel: Optional[grpc.aio.Channel] = None,
        credentials: Optional[Credentials] = None,
    ):
        self._hostname = hostname
        self._credentials = credentials
        self._server = server
        self._channel: Optional[grpc.aio.Channel] = channel
        self._stub: Optional[server_pb2_grpc.GnetcliStub] = None
        self._stream: Optional[grpc.aio.StreamStreamCall] = None
        self._user_agent = user_agent

        options: List[Tuple[str, Any]] = [
            ("grpc.max_concurrent_streams", 900),
            ("grpc.max_send_message_length", GRPC_MAX_MESSAGE_LENGTH),
            ("grpc.max_receive_message_length", GRPC_MAX_MESSAGE_LENGTH),
        ]
        if target_name_override:
            options.append(("grpc.ssl_target_name_override", target_name_override))
        cert = get_cert(cert_file=cert_file)
        channel_credentials = grpc.ssl_channel_credentials(root_certificates=cert)
        authentication: ClientAuthentication
        if token.startswith("OAuth"):
            authentication = OAuthClientAuthentication(token.split(" ")[1])
        elif token.startswith("Basic"):
            authentication = BasicClientAuthentication(token.split(" ")[1])
        else:
            raise Exception("unknown token type")
        interceptors = get_auth_client_interceptors(authentication)
        grpc_channel_fn = partial(grpc.aio.secure_channel, credentials=channel_credentials, interceptors=interceptors)
        if insecure_grpc:
            grpc_channel_fn = partial(grpc.aio.insecure_channel, interceptors=interceptors)
        self._grpc_channel_fn = grpc_channel_fn
        self._options = options
        self._req_id: Optional[Any] = None

    def _get_metadata(self) -> List[Tuple[str, str]]:
        req_id = make_req_id()
        metadata = [
            (HEADER_REQUEST_ID, req_id),
            (HEADER_USER_AGENT, self._user_agent),
        ]
        return metadata

    @abstractmethod
    async def connect(self) -> None:
        if self._channel is None:
            _logger.debug("connect to %s self._channel=%s", self._server, self._channel)
            self._channel = self._grpc_channel_fn(self._server, options=self._options)
        self._stub = server_pb2_grpc.GnetcliStub(self._channel)
        if self._stub is None:
            raise Exception("empty stub")

    async def _cmd(self, cmdpb: Any) -> Message:
        # TODO: add connect retry on first cmd
        if not self._stream:
            raise Exception("empty self._stream")
        try:
            _logger.debug("cmd %r on %r", str(cmdpb).replace("\n", ""), self._stream)
            await self._stream.write(cmdpb)
            response: Message = await self._stream.read()
        except grpc.aio.AioRpcError as e:
            _logger.debug("caught exception %s %s", e, parse_grpc_error(e))
            gn_exc, verbose = parse_grpc_error(e)
            last_exc = gn_exc(
                message=f"{e.__class__.__name__} {e.details()}",
                imetadata=e.initial_metadata(),  # type: ignore
                verbose=verbose,
            )
            last_exc.__cause__ = e
            raise last_exc from None
        _logger.debug("response %s", format_long_msg(str(response), 100))
        return response

    async def close(self) -> None:
        _logger.debug("close stream %s", self._stream)
        if self._stream:
            await self._stream.done_writing()
            self._stream.done()
            self._stream = None


class GnetcliSessionCmd(GnetcliSession):
    async def cmd(
        self,
        cmd: str,
        device: str,
        trace: bool = False,
        qa: Optional[List[QA]] = None,
        cmd_timeout: float = 0.0,
        read_timeout: float = 0.0,
        credentials: Optional[Credentials] = None,
    ) -> Message:
        _logger.debug("session cmd %r", cmd)
        pbcmd = make_cmd(
            hostname=self._hostname,
            device=device,
            cmd=cmd,
            trace=trace,
            qa=qa,
            read_timeout=read_timeout,
            cmd_timeout=cmd_timeout,
            credentials=credentials,
        )
        return await self._cmd(pbcmd)

    async def connect(self) -> None:
        await super(GnetcliSessionCmd, self).connect()
        if self._stub:
            self._stream = self._stub.ExecChat(metadata=self._get_metadata())
        else:
            raise Exception()


class GnetcliSessionNetconf(GnetcliSession):
    async def cmd(self, cmd: str, trace: bool = False, json: bool = False) -> Message:
        _logger.debug("netconf session cmd %r", cmd)
        cmdpb = server_pb2.CMDNetconf(host=self._hostname, credentials=self._credentials, cmd=cmd, json=json)
        return await self._cmd(cmdpb)

    async def connect(self) -> None:
        await super(GnetcliSessionNetconf, self).connect()
        if self._stub:
            self._stream = self._stub.ExecNetconfChat(metadata=self._get_metadata())
        else:
            raise Exception()


async def grpc_call_wrapper(stub: grpc.UnaryUnaryMultiCallable, request: Any) -> Message:
    last_exc: Optional[Exception] = None
    response: Optional[Message] = None
    for i in range(5):
        req_id = make_req_id()
        metadata = [
            (HEADER_REQUEST_ID, req_id),
        ]
        _logger.debug("executing %s: %r, req_id=%s", type(request), repr(request), req_id)
        await asyncio.sleep(i * 2)
        try:
            response = await stub(request=request, metadata=metadata)
        except grpc.aio.AioRpcError as e:
            _logger.debug("caught exception %s req_id=%s %s", e, req_id, parse_grpc_error(e))
            gn_exc, verbose = parse_grpc_error(e)
            last_exc = gn_exc(
                message=f"{e.__class__.__name__} {e.details()}",
                imetadata=e.initial_metadata(),  # type: ignore
                request_id=req_id,
                verbose=verbose,
            )
            last_exc.__cause__ = e
            raise last_exc from None
        else:
            last_exc = None
            break

    if last_exc is not None:
        raise last_exc
    if response is None:
        raise Exception()
    else:
        return response


def make_req_id() -> str:
    return str(uuid.uuid4())


def get_cert(cert_file: Optional[str]) -> Optional[bytes]:
    cert: Optional[bytes] = None
    if cert_file:
        _logger.debug("open cert_file %s", cert_file)
        with open(cert_file, "rb") as f:
            cert = f.read()
    return cert


def format_long_msg(msg: str, max_len: int) -> str:
    if len(msg) <= max_len:
        return msg
    return "%s... and %s more" % (msg[:max_len], len(msg) - max_len)


def make_cmd(
    hostname: str,
    cmd: str,
    device: str,
    trace: bool = False,
    qa: Optional[List[QA]] = None,
    read_timeout: float = 0.0,
    cmd_timeout: float = 0.0,
    credentials: Optional[Credentials] = None,
) -> Message:
    qa_cmd: List[Message] = []
    if qa:
        for item in qa:
            qaitem = server_pb2.QA()
            qaitem.question = item.question
            qaitem.answer = item.answer
            qa_cmd.append(qaitem)
    credentialspb = None
    if credentials:
        credentialspb = credentials.make_pb()
    res = server_pb2.CMD(
        host=hostname,
        cmd=cmd,
        trace=trace,
        qa=qa_cmd,
        read_timeout=read_timeout,
        cmd_timeout=cmd_timeout,
        device=device,
        credentials=credentialspb,
    )
    return res  # type: ignore
