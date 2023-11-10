from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TraceOperation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    Operation_notset: _ClassVar[TraceOperation]
    Operation_unknown: _ClassVar[TraceOperation]
    Operation_write: _ClassVar[TraceOperation]
    Operation_read: _ClassVar[TraceOperation]

class DeviceResultStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    Device_notset: _ClassVar[DeviceResultStatus]
    Device_ok: _ClassVar[DeviceResultStatus]
    Device_error: _ClassVar[DeviceResultStatus]
Operation_notset: TraceOperation
Operation_unknown: TraceOperation
Operation_write: TraceOperation
Operation_read: TraceOperation
Device_notset: DeviceResultStatus
Device_ok: DeviceResultStatus
Device_error: DeviceResultStatus

class QA(_message.Message):
    __slots__ = ["question", "answer"]
    QUESTION_FIELD_NUMBER: _ClassVar[int]
    ANSWER_FIELD_NUMBER: _ClassVar[int]
    question: str
    answer: str
    def __init__(self, question: _Optional[str] = ..., answer: _Optional[str] = ...) -> None: ...

class Credentials(_message.Message):
    __slots__ = ["login", "password"]
    LOGIN_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    login: str
    password: str
    def __init__(self, login: _Optional[str] = ..., password: _Optional[str] = ...) -> None: ...

class CMD(_message.Message):
    __slots__ = ["host", "cmd", "trace", "qa", "read_timeout", "cmd_timeout", "device", "string_result", "credentials"]
    HOST_FIELD_NUMBER: _ClassVar[int]
    CMD_FIELD_NUMBER: _ClassVar[int]
    TRACE_FIELD_NUMBER: _ClassVar[int]
    QA_FIELD_NUMBER: _ClassVar[int]
    READ_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    CMD_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    STRING_RESULT_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    host: str
    cmd: str
    trace: bool
    qa: _containers.RepeatedCompositeFieldContainer[QA]
    read_timeout: float
    cmd_timeout: float
    device: str
    string_result: bool
    credentials: Credentials
    def __init__(self, host: _Optional[str] = ..., cmd: _Optional[str] = ..., trace: bool = ..., qa: _Optional[_Iterable[_Union[QA, _Mapping]]] = ..., read_timeout: _Optional[float] = ..., cmd_timeout: _Optional[float] = ..., device: _Optional[str] = ..., string_result: bool = ..., credentials: _Optional[_Union[Credentials, _Mapping]] = ...) -> None: ...

class Device(_message.Message):
    __slots__ = ["name", "prompt_expression", "error_expression", "pager_expression"]
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
    __slots__ = ["host", "cmd", "json", "read_timeout", "cmd_timeout", "Credentials"]
    HOST_FIELD_NUMBER: _ClassVar[int]
    CMD_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    READ_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    CMD_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    host: str
    cmd: str
    json: bool
    read_timeout: float
    cmd_timeout: float
    Credentials: Credentials
    def __init__(self, host: _Optional[str] = ..., cmd: _Optional[str] = ..., json: bool = ..., read_timeout: _Optional[float] = ..., cmd_timeout: _Optional[float] = ..., Credentials: _Optional[_Union[Credentials, _Mapping]] = ...) -> None: ...

class CMDTraceItem(_message.Message):
    __slots__ = ["operation", "data"]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    operation: TraceOperation
    data: bytes
    def __init__(self, operation: _Optional[_Union[TraceOperation, str]] = ..., data: _Optional[bytes] = ...) -> None: ...

class CMDResult(_message.Message):
    __slots__ = ["out", "out_str", "error", "error_str", "trace", "status"]
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
    __slots__ = ["res", "error"]
    RES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    res: DeviceResultStatus
    error: str
    def __init__(self, res: _Optional[_Union[DeviceResultStatus, str]] = ..., error: _Optional[str] = ...) -> None: ...

class FileDownloadRequest(_message.Message):
    __slots__ = ["host", "path", "device", "credentials"]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    host: str
    path: str
    device: str
    credentials: Credentials
    def __init__(self, host: _Optional[str] = ..., path: _Optional[str] = ..., device: _Optional[str] = ..., credentials: _Optional[_Union[Credentials, _Mapping]] = ...) -> None: ...

class FileUploadRequest(_message.Message):
    __slots__ = ["host", "path", "data", "device", "credentials"]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    host: str
    path: str
    data: bytes
    device: str
    credentials: Credentials
    def __init__(self, host: _Optional[str] = ..., path: _Optional[str] = ..., data: _Optional[bytes] = ..., device: _Optional[str] = ..., credentials: _Optional[_Union[Credentials, _Mapping]] = ...) -> None: ...

class FileResult(_message.Message):
    __slots__ = ["path", "data"]
    PATH_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    path: str
    data: bytes
    def __init__(self, path: _Optional[str] = ..., data: _Optional[bytes] = ...) -> None: ...

class FilesResult(_message.Message):
    __slots__ = ["files"]
    FILES_FIELD_NUMBER: _ClassVar[int]
    files: _containers.RepeatedCompositeFieldContainer[FileResult]
    def __init__(self, files: _Optional[_Iterable[_Union[FileResult, _Mapping]]] = ...) -> None: ...
