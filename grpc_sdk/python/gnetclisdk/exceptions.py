from typing import Optional, Sequence, Tuple, Type, Union
from google.rpc import error_details_pb2, status_pb2
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


class EOFError(GnetcliException):
    """
    EOF error.
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
    rich_statuses = []
    for key, value in grpc_error.trailing_metadata():
        if key == "grpc-status-details-bin":
            rich_status = status_pb2.Status.FromString(value)
            for rdetail in rich_status.details:
                if rdetail.Is(error_details_pb2.ErrorInfo.DESCRIPTOR):
                    error_info = error_details_pb2.ErrorInfo()
                    rdetail.Unpack(error_info)
                    rich_statuses.append(error_info)
            break
    error_info = None
    if len(rich_statuses) > 1:
        raise Exception("unexpected rich_statuses len %s", len(rich_statuses))
    elif len(rich_statuses) == 1:
        error_info = rich_statuses[0]

    code = grpc_error.code()
    detail = ""
    if grpc_error.details():
        detail = grpc_error.details()  # type: ignore
    reason = ""
    metadata = None
    if error_info:
        reason = error_info.reason
        metadata = dict(error_info.metadata)
    if code == grpc.StatusCode.UNAVAILABLE and detail == "not ready":
        return NotReady, ""
    if code == grpc.StatusCode.UNAUTHENTICATED:
        return Unauthenticated, detail
    if code == grpc.StatusCode.PERMISSION_DENIED:
        return PermissionDenied, detail
    if code == grpc.StatusCode.OUT_OF_RANGE:
        return UnknownDevice, detail
    if code == grpc.StatusCode.INTERNAL:
        if reason == "error_eof":  # new way: pass errors using error_details
            verbose = str(metadata)
            return EOFError, verbose
        elif detail == "auth_device_error":
            verbose = ""
            return DeviceAuthError, verbose
        elif detail in {"connection_error", "busy_error"}:
            verbose = ""
            return DeviceConnectError, verbose
        elif detail in {"exec_error", "generic_error"}:
            verbose = ""
            return ExecError, verbose

    return GnetcliException, ""
