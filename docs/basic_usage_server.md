Gnetcli 'server' is a GRPC-server for interacting with non-Go projects and other automations.
The server supports basic auth for clients, executing commands in stream mode, upload and downloading.
Authentication on a device can be specified as a part of `Exec()` RPC or using `-dev*` arguments.
See GRPC-server calls description in [server.proto](https://github.com/annetutil/gnetcli/blob/main/pkg/server/proto/server.proto).

Installation:
```shell
go install github.com/annetutil/gnetcli/cmd/gnetcli_server@latest
```
Or download latest release from [Github release](https://github.com/annetutil/gnetcli/releases/).

Starting:
```shell
# ~/go/bin/gnetcli_server
gnetcli_server -debug -basic-auth mylogin:mysecret
```

Exec a command on a device using `grpcurl`:
```shell
TOKEN=$(echo -n "$LOGIN:$PASSWORD" | base64)
grpcurl -H "Authorization: Basic $TOKEN" -plaintext -d '{"host": "hostname", "cmd": "dis clock", "host_params": {"device": "juniper", "credentials": {"login": "test", "password": "test"}}, "string_result": true}' localhost:50051 gnetcli.Gnetcli.Exec
```


### Help

```
Usage of server:
  -basic-auth string
    	Authenticate client using Basic auth
  -cert-file string
    	The TLS cert file
  -conf-file string
    	Path to config file. '-' for stdin
  -d	Set debug log level (short)
  -debug
    	Set debug log level
  -dev-login string
    	Default device login
  -dev-pass string
    	Default device password
  -dev-use-agent

  -disable_tcp
    	Disable TCP listener
  -key-file string
    	The TLS key file
  -port string
    	Listen address (default "127.0.0.1:50051")
  -tls
    	Connection uses TLS if true
  -unix-socket string
    	Unix socket path
```

### Configuration file

Using `-conf-file conf.yaml` it's possible to set more parameters, like enabling ssh config or jump host.

```yaml
logging:
  level: debug
  json: true
dev_auth:
  login: login
  password: pass
  ssh_config: true # read config from ~/.ssh/config
  proxy_jump: my_jump_host
  use_agent: true
port: 0  # 0 random
```
