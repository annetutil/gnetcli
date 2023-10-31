from typing import Optional, Sequence, Tuple, Type, Union

import grpc.aio

MetadataType = Sequence[Tuple[str, Union[str, bytes]]]


def extract_metadata(m: MetadataType) -> dict:
    # calling get from metadataType throws KeyError
    metadata = {}
    for k, v in m:
        metadata[k] = v
    return metadata


class GnetcliException(Exception):
    def __init__(
        self,
        message: str = "",
        imetadata: Optional[MetadataType] = None,
        request_id: Optional[str] = None,
        verbose: Optional[str] = "",
    ):
        self.message = message
        if imetadata:
            rs = extract_metadata(imetadata).get("real-server")
            if rs:
                self.message = f"{self.message} RS:{rs}"
        if request_id:
            self.message = f"{self.message} req_id:{request_id}"
        if verbose:
            self.message = f"{self.message} verbose:{verbose}"
        super().__init__(self.message)


class DeviceConnectError(GnetcliException):
    """
    Problem with connection to a device.
    """

    pass


class UnknownDevice(GnetcliException):
    """
    Host is not found in inventory
    """

    pass


class DeviceAuthError(DeviceConnectError):
    """
    Unable to authenticate on a device.
    """

    pass


class ExecError(GnetcliException):
    """
    Error happened during execution.
    """

    pass


class NotReady(GnetcliException):
    """
    Server is not ready.
    """

    pass


class Unauthenticated(GnetcliException):
    """
    Unable to authenticate on Gnetcli server.
    """

    pass


class PermissionDenied(GnetcliException):
    """
    Permission denied.
    """

    pass


def parse_grpc_error(grpc_error: grpc.aio.AioRpcError) -> Tuple[Type[GnetcliException], str]:
    code = grpc_error.code()
    detail = ""
    if grpc_error.details():
        detail = grpc_error.details()  # type: ignore
    if code == grpc.StatusCode.UNAVAILABLE and detail == "not ready":
        return NotReady, ""
    if code == grpc.StatusCode.UNAUTHENTICATED:
        return Unauthenticated, detail
    if code == grpc.StatusCode.PERMISSION_DENIED:
        return PermissionDenied, detail
    if code == grpc.StatusCode.OUT_OF_RANGE:
        return UnknownDevice, detail
    if code == grpc.StatusCode.INTERNAL:
        if detail == "auth_device_error":
            verbose = ""
            return DeviceAuthError, verbose
        if detail in {"connection_error", "busy_error"}:
            verbose = ""
            return DeviceConnectError, verbose
        elif detail in {"exec_error", "generic_error"}:
            verbose = ""
            return ExecError, verbose

    return GnetcliException, ""
