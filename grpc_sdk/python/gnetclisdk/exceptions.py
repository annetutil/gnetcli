from typing import Dict, Optional, Sequence, Tuple, Type, Union
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


class DeviceConnectionError(GnetcliException):
    """
    Problem with connection to a device.
    """

    pass


class DeviceConnectError(GnetcliException):
    """
    Problem with connecting to a device.
    """

    pass


class UnknownDevice(GnetcliException):
    """
    Host is not found in inventory
    """

    pass


class DeviceAuthError(DeviceConnectionError):
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


# Maps the server's ErrorInfo.reason (set by gnetcli for execution- and
# connect-phase failures) to an SDK exception type. This is the preferred,
# type-stable classification; parse_grpc_error falls back to matching the
# status detail string only when no reason is present.
REASON_TO_EXCEPTION: Dict[str, Type[GnetcliException]] = {
    # execution phase (a session was established, the command failed)
    "error_eof": EOFError,
    "error_question": ExecError,
    "error_echo": ExecError,
    "error_exec_timeout": ExecError,
    "error_exec": ExecError,
    "error_unknown": ExecError,
    # connect phase (the session could not be established)
    "error_auth": DeviceAuthError,
    "error_handshake": DeviceConnectError,
    "error_refused": DeviceConnectError,
    "error_connect_timeout": DeviceConnectError,
    "error_unreachable": DeviceConnectError,
    "error_connect": DeviceConnectError,
}


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
        # Preferred: classify by ErrorInfo.reason (new way: pass errors using
        # error_details). Covers error_eof plus the finer exec/connect reasons.
        if reason:
            exc = REASON_TO_EXCEPTION.get(reason)
            if exc is not None:
                return exc, str(metadata)
        # Backwards-compatible fallback: classify by the status detail string.
        if detail == "auth_device_error":
            verbose = ""
            return DeviceAuthError, verbose
        elif detail in {"connection_error", "busy_error"}:
            verbose = ""
            return DeviceConnectionError, verbose
        elif detail in {"exec_error", "generic_error"}:
            verbose = ""
            return ExecError, verbose
        elif detail == "connect_error":
            verbose = str(error_info)
            return DeviceConnectError, verbose

    return GnetcliException, ""
