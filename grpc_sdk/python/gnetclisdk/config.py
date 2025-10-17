from dataclasses import dataclass, asdict, field
from datetime import timedelta

import yaml


@dataclass
class LogConfig:
    level: str = "info"
    json: bool = False


@dataclass
class AuthAppConfig:
    login: str = ""
    password: str = ""
    private_key: str = ""  # path to private key file
    proxy_jump: str = ""
    use_agent: bool = False
    ssh_config: bool = False


@dataclass
class Config:
    logging: LogConfig = field(default_factory=LogConfig)
    port: str = ""  # Listen address
    http_port: str = ""  # Http listen address
    dev_auth: AuthAppConfig = field(default_factory=AuthAppConfig)
    dev_conf: str = ""  # Path to yaml with device types
    tls: bool = False
    cert_file: str = ""
    key_file: str = ""
    basic_auth: str = ""
    disable_tcp: bool = False
    unix_socket: str = ""  # Unix socket pat
    default_read_timeout: timedelta = timedelta(seconds=0)
    default_cmd_timeout: timedelta = timedelta(seconds=0)


def dict_factory(data):
    return {
        key: (
            f"{value.total_seconds()}s"
            if isinstance(value, timedelta)
            else value
        )
        for key, value in data
        if value != ""  # skip empty strings
    }


def config_to_yaml(cfg: Config) -> str:
    cfg_dict = asdict(cfg, dict_factory=dict_factory)
    return yaml.safe_dump(cfg_dict, sort_keys=False)
