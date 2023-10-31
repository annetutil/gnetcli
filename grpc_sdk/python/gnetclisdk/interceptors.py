#  type: ignore
import uuid
from typing import Callable, Iterable, List, Optional, Tuple, Union

import grpc
from grpc.aio._call import StreamStreamCall
from grpc.aio._interceptor import ClientCallDetails
from grpc.aio._typing import RequestIterableType, RequestType, ResponseType

from .auth import ClientAuthentication

_RequestMetadata = Optional[Iterable[Tuple[str, str]]]
ResponseIterableType = grpc.aio._typing.ResponseIterableType


def get_auth_client_interceptors(
    authentication: ClientAuthentication,
) -> List[grpc.aio.ClientInterceptor]:
    return [
        _AuthInterceptorUnaryUnary(authentication),
        _AuthInterceptorUnaryStream(authentication),
        _AuthInterceptorStreamUnary(authentication),
        _AuthInterceptorStreamStream(authentication),
    ]


def get_request_id_interceptors(
    request_id: uuid.UUID,
) -> List[grpc.aio.ClientInterceptor]:
    return [
        _RequestIdInterceptorUnaryUnary(request_id),
        _RequestIdInterceptorUnaryStream(request_id),
        _RequestIdInterceptorStreamUnary(request_id),
        _RequestIdInterceptorStreamStream(request_id),
    ]


class _AuthInterceptorAgent:
    def __init__(self, authentication: ClientAuthentication):
        self.__authentication = authentication

    def _add_auth(self, details: grpc.aio.ClientCallDetails) -> grpc.aio.ClientCallDetails:
        return grpc.aio.ClientCallDetails(
            method=details.method,
            timeout=details.timeout,
            metadata=self.__add_auth_meta(details.metadata),
            credentials=details.credentials,
            wait_for_ready=None,
        )

    def __add_auth_meta(self, metadata: _RequestMetadata = None) -> _RequestMetadata:
        result: Tuple[Tuple[str, str]] = []
        if metadata is not None:
            for m in metadata:
                result.append(m)
        result.append(
            (
                self.__authentication.get_authentication_header_key(),
                self.__authentication.create_authentication_header_value(),
            )
        )
        return tuple(result)


class _AuthInterceptorUnaryUnary(_AuthInterceptorAgent, grpc.aio.UnaryUnaryClientInterceptor):
    async def intercept_unary_unary(
        self,
        continuation: Callable[[grpc.aio.ClientCallDetails, RequestType], grpc.aio.UnaryUnaryCall],
        client_call_details: grpc.aio.ClientCallDetails,
        request: RequestType,
    ) -> Union[grpc.aio._call.UnaryUnaryCall, ResponseType]:
        res = await continuation(self._add_auth(client_call_details), request)
        return res


class _AuthInterceptorUnaryStream(_AuthInterceptorAgent, grpc.aio.UnaryStreamClientInterceptor):
    async def intercept_unary_stream(
        self,
        continuation: Callable[[grpc.aio.ClientCallDetails, RequestType], grpc.aio.UnaryStreamCall],
        details: grpc.aio.ClientCallDetails,
        request: RequestType,
    ) -> Union[ResponseIterableType, grpc.aio.UnaryStreamCall]:
        return await continuation(self._add_auth(details), request)


class _AuthInterceptorStreamUnary(
    _AuthInterceptorAgent,
    grpc.aio.StreamUnaryClientInterceptor,
):
    async def intercept_stream_unary(
        self,
        continuation: Callable[[grpc.aio.ClientCallDetails, RequestType], grpc.aio.StreamUnaryCall],
        client_call_details: grpc.aio.ClientCallDetails,
        request_iterator: RequestIterableType,
    ) -> grpc.aio.StreamUnaryCall:
        return await continuation(self._add_auth(client_call_details), request_iterator)


class _AuthInterceptorStreamStream(
    _AuthInterceptorAgent,
    grpc.aio.StreamStreamClientInterceptor,
):
    async def intercept_stream_stream(
        self,
        continuation: Callable[[ClientCallDetails, RequestType], StreamStreamCall],
        client_call_details: ClientCallDetails,
        request_iterator: RequestIterableType,
    ) -> Union[ResponseIterableType, StreamStreamCall]:
        return await continuation(self._add_auth(client_call_details), request_iterator)


class _RequestIdInterceptorAgent:
    _interceptor_type: str

    def __init__(self, request_id: uuid.UUID):
        self.__request_id = request_id
        self.__counter = 0

    def _add_request_id(self, details: ClientCallDetails) -> ClientCallDetails:
        self.__counter += 1

        metadata = ()
        if details.metadata is not None:
            metadata = tuple(details.metadata)
        metadata += (
            (
                "x-request-id",
                f"{self.__request_id}/{self._interceptor_type}_{self.__counter}",
            ),
        )

        res = grpc.aio.ClientCallDetails(
            method=details.method,
            timeout=details.timeout,
            metadata=metadata,
            credentials=details.credentials,
            wait_for_ready=None,
        )
        return res


class _RequestIdInterceptorUnaryUnary(
    _RequestIdInterceptorAgent,
    grpc.aio.UnaryUnaryClientInterceptor,
):
    _interceptor_type = "unary_unary"

    async def intercept_unary_unary(
        self,
        continuation: Callable[[grpc.aio.ClientCallDetails, RequestType], grpc.aio.UnaryUnaryCall],
        client_call_details: grpc.aio.ClientCallDetails,
        request: RequestType,
    ) -> Union[grpc.aio.UnaryUnaryCall, ResponseType]:
        return await continuation(self._add_request_id(client_call_details), request)


class _RequestIdInterceptorUnaryStream(
    _RequestIdInterceptorAgent,
    grpc.aio.UnaryStreamClientInterceptor,
):
    _interceptor_type = "unary_stream"

    async def intercept_unary_stream(
        self,
        continuation: Callable[[grpc.aio.ClientCallDetails, RequestType], grpc.aio.UnaryStreamCall],
        client_call_details: grpc.aio.ClientCallDetails,
        request: RequestType,
    ) -> Union[ResponseIterableType, grpc.aio.UnaryStreamCall]:
        return await continuation(self._add_request_id(client_call_details), request)


class _RequestIdInterceptorStreamUnary(
    _RequestIdInterceptorAgent,
    grpc.aio.StreamUnaryClientInterceptor,
):
    _interceptor_type = "stream_unary"

    async def intercept_stream_unary(
        self,
        continuation: Callable[[grpc.aio.ClientCallDetails, RequestType], grpc.aio.StreamUnaryCall],
        client_call_details: grpc.aio.ClientCallDetails,
        request_iterator: RequestIterableType,
    ) -> grpc.aio.StreamUnaryCall:
        return await continuation(self._add_request_id(client_call_details), request_iterator)


class _RequestIdInterceptorStreamStream(_RequestIdInterceptorAgent, grpc.aio.StreamStreamClientInterceptor):
    _interceptor_type = "stream_stream"

    async def intercept_stream_stream(
        self,
        continuation: Callable[[ClientCallDetails, RequestType], StreamStreamCall],
        client_call_details: ClientCallDetails,
        request_iterator: RequestIterableType,
    ) -> Union[ResponseIterableType, StreamStreamCall]:
        return await continuation(self._add_request_id(client_call_details), request_iterator)
