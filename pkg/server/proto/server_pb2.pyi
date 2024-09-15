from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TraceOperation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    Operation_notset: _ClassVar[TraceOperation]
    Operation_unknown: _ClassVar[TraceOperation]
    Operation_write: _ClassVar[TraceOperation]
    Operation_read: _ClassVar[TraceOperation]

class DeviceResultStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    Device_notset: _ClassVar[DeviceResultStatus]
    Device_ok: _ClassVar[DeviceResultStatus]
    Device_error: _ClassVar[DeviceResultStatus]

class FileStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FileStatus_notset: _ClassVar[FileStatus]
    FileStatus_ok: _ClassVar[FileStatus]
    FileStatus_error: _ClassVar[FileStatus]
    FileStatus_not_found: _ClassVar[FileStatus]
    FileStatus_is_dir: _ClassVar[FileStatus]
Operation_notset: TraceOperation
Operation_unknown: TraceOperation
Operation_write: TraceOperation
Operation_read: TraceOperation
Device_notset: DeviceResultStatus
Device_ok: DeviceResultStatus
Device_error: DeviceResultStatus
FileStatus_notset: FileStatus
FileStatus_ok: FileStatus
FileStatus_error: FileStatus
FileStatus_not_found: FileStatus
FileStatus_is_dir: FileStatus

class QA(_message.Message):
    __slots__ = ("question", "answer")
    QUESTION_FIELD_NUMBER: _ClassVar[int]
    ANSWER_FIELD_NUMBER: _ClassVar[int]
    question: str
    answer: str
    def __init__(self, question: _Optional[str] = ..., answer: _Optional[str] = ...) -> None: ...

class Credentials(_message.Message):
    __slots__ = ("login", "password")
    LOGIN_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    login: str
    password: str
    def __init__(self, login: _Optional[str] = ..., password: _Optional[str] = ...) -> None: ...

class CMD(_message.Message):
    __slots__ = ("host", "cmd", "trace", "qa", "read_timeout", "cmd_timeout", "string_result", "host_params")
    HOST_FIELD_NUMBER: _ClassVar[int]
    CMD_FIELD_NUMBER: _ClassVar[int]
    TRACE_FIELD_NUMBER: _ClassVar[int]
    QA_FIELD_NUMBER: _ClassVar[int]
    READ_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    CMD_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    STRING_RESULT_FIELD_NUMBER: _ClassVar[int]
    HOST_PARAMS_FIELD_NUMBER: _ClassVar[int]
    host: str
    cmd: str
    trace: bool
    qa: _containers.RepeatedCompositeFieldContainer[QA]
    read_timeout: float
    cmd_timeout: float
    string_result: bool
    host_params: HostParams
    def __init__(self, host: _Optional[str] = ..., cmd: _Optional[str] = ..., trace: bool = ..., qa: _Optional[_Iterable[_Union[QA, _Mapping]]] = ..., read_timeout: _Optional[float] = ..., cmd_timeout: _Optional[float] = ..., string_result: bool = ..., host_params: _Optional[_Union[HostParams, _Mapping]] = ...) -> None: ...

class Device(_message.Message):
    __slots__ = ("name", "prompt_expression", "error_expression", "pager_expression")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROMPT_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    ERROR_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    PAGER_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    name: str
    prompt_expression: str
    error_expression: str
    pager_expression: str
    def __init__(self, name: _Optional[str] = ..., prompt_expression: _Optional[str] = ..., error_expression: _Optional[str] = ..., pager_expression: _Optional[str] = ...) -> None: ...

class CMDNetconf(_message.Message):
    __slots__ = ("host", "cmd", "json", "read_timeout", "cmd_timeout")
    HOST_FIELD_NUMBER: _ClassVar[int]
    CMD_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    READ_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    CMD_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    host: str
    cmd: str
    json: bool
    read_timeout: float
    cmd_timeout: float
    def __init__(self, host: _Optional[str] = ..., cmd: _Optional[str] = ..., json: bool = ..., read_timeout: _Optional[float] = ..., cmd_timeout: _Optional[float] = ...) -> None: ...

class CMDTraceItem(_message.Message):
    __slots__ = ("operation", "data")
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    operation: TraceOperation
    data: bytes
    def __init__(self, operation: _Optional[_Union[TraceOperation, str]] = ..., data: _Optional[bytes] = ...) -> None: ...

class HostParams(_message.Message):
    __slots__ = ("host", "credentials", "port", "device", "ip")
    HOST_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    IP_FIELD_NUMBER: _ClassVar[int]
    host: str
    credentials: Credentials
    port: int
    device: str
    ip: str
    def __init__(self, host: _Optional[str] = ..., credentials: _Optional[_Union[Credentials, _Mapping]] = ..., port: _Optional[int] = ..., device: _Optional[str] = ..., ip: _Optional[str] = ...) -> None: ...

class CMDResult(_message.Message):
    __slots__ = ("out", "out_str", "error", "error_str", "trace", "status")
    OUT_FIELD_NUMBER: _ClassVar[int]
    OUT_STR_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    ERROR_STR_FIELD_NUMBER: _ClassVar[int]
    TRACE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    out: bytes
    out_str: str
    error: bytes
    error_str: str
    trace: _containers.RepeatedCompositeFieldContainer[CMDTraceItem]
    status: int
    def __init__(self, out: _Optional[bytes] = ..., out_str: _Optional[str] = ..., error: _Optional[bytes] = ..., error_str: _Optional[str] = ..., trace: _Optional[_Iterable[_Union[CMDTraceItem, _Mapping]]] = ..., status: _Optional[int] = ...) -> None: ...

class DeviceResult(_message.Message):
    __slots__ = ("res", "error")
    RES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    res: DeviceResultStatus
    error: str
    def __init__(self, res: _Optional[_Union[DeviceResultStatus, str]] = ..., error: _Optional[str] = ...) -> None: ...

class FileDownloadRequest(_message.Message):
    __slots__ = ("host", "paths", "device", "host_params")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PATHS_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    HOST_PARAMS_FIELD_NUMBER: _ClassVar[int]
    host: str
    paths: _containers.RepeatedScalarFieldContainer[str]
    device: str
    host_params: HostParams
    def __init__(self, host: _Optional[str] = ..., paths: _Optional[_Iterable[str]] = ..., device: _Optional[str] = ..., host_params: _Optional[_Union[HostParams, _Mapping]] = ...) -> None: ...

class FileData(_message.Message):
    __slots__ = ("path", "data", "status")
    PATH_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    path: str
    data: bytes
    status: FileStatus
    def __init__(self, path: _Optional[str] = ..., data: _Optional[bytes] = ..., status: _Optional[_Union[FileStatus, str]] = ...) -> None: ...

class FileUploadRequest(_message.Message):
    __slots__ = ("host", "device", "files", "host_params")
    HOST_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    FILES_FIELD_NUMBER: _ClassVar[int]
    HOST_PARAMS_FIELD_NUMBER: _ClassVar[int]
    host: str
    device: str
    files: _containers.RepeatedCompositeFieldContainer[FileData]
    host_params: HostParams
    def __init__(self, host: _Optional[str] = ..., device: _Optional[str] = ..., files: _Optional[_Iterable[_Union[FileData, _Mapping]]] = ..., host_params: _Optional[_Union[HostParams, _Mapping]] = ...) -> None: ...

class FilesResult(_message.Message):
    __slots__ = ("files",)
    FILES_FIELD_NUMBER: _ClassVar[int]
    files: _containers.RepeatedCompositeFieldContainer[FileData]
    def __init__(self, files: _Optional[_Iterable[_Union[FileData, _Mapping]]] = ...) -> None: ...
