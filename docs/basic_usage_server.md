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
LOGIN=mylogin
PASSWORD=mysecret
gnetcli_server -debug -basic-auth "$LOGIN:$PASSWORD"
```

Exec a command on a device using `grpcurl`:
```shell
# In another terminal, use the same server credentials as above.
# These are not the network device credentials in host_params.
LOGIN=mylogin
PASSWORD=mysecret
TOKEN=$(printf '%s' "$LOGIN:$PASSWORD" | base64 | tr -d '\n')
grpcurl -H "Authorization: Basic $TOKEN" -plaintext -d '{"host": "hostname", "cmd": "dis clock", "host_params": {"device": "juniper", "credentials": {"login": "test", "password": "test"}}, "string_result": true}' localhost:50051 gnetcli.Gnetcli.Exec
```

### HTTP gateway on the gRPC port

Restart the server with the **same address** for `-port` and `-http_port`:

```shell
LOGIN=mylogin
PASSWORD=mysecret
gnetcli_server -port 127.0.0.1:50051 -http_port 127.0.0.1:50051 -basic-auth "$LOGIN:$PASSWORD"
```

In another terminal, send HTTP/1 requests to that same port. The gateway
forwards authentication to the native gRPC server; it does not bypass its
interceptors. These are demonstration credentials for local testing only.

```shell
LOGIN=mylogin
PASSWORD=mysecret
TOKEN=$(printf '%s' "$LOGIN:$PASSWORD" | base64 | tr -d '\n')
curl --http1.1 -H "Authorization: Basic $TOKEN" -H 'Content-Type: application/json' \
  'http://127.0.0.1:50051/api/v1/exec' \
  -d '{"host": "hostname", "cmd": "dis clock", "host_params": {"device": "huawei", "credentials": {"login": "test", "password": "test"}}, "string_result": true}'
```

The previous `grpcurl` invocation still works on port 50051. For separate ports,
set `-http_port 127.0.0.1:50052` instead. Omitting `http_port` keeps gRPC-only
mode. HTTP requires TCP; combining `http_port` with `disable_tcp` is an error.
Unix-socket gRPC remains available independently.

Equivalent shared-listener YAML:

```yaml
port: "127.0.0.1:50051"
http_port: "127.0.0.1:50051"
basic_auth: "mylogin:mysecret" # Local example only; protect the configuration file.
```

Addresses are compared after expanding a bare port to `127.0.0.1:PORT`.
Use identical host spelling: DNS aliases are not resolved for this comparison.
Equal `127.0.0.1:0` values share one allocated ephemeral port, reported in the
startup logs. Different addresses still create separate listeners.

The multiplexer routes plaintext **HTTP/1** to the gateway and native HTTP/2 or
TLS connections to gRPC. gRPC streaming and reflection use the native server.
HTTP/2 REST, HTTPS, and gRPC-Web are not supported by this shared listener.
With `tls: true`, gRPC uses TLS, but the HTTP gateway remains plaintext; do not
send Basic credentials over it across an untrusted network. Use a trusted TLS
reverse proxy if HTTPS is required. The gateway's internal gRPC connection uses
TLS too, trusting the configured server certificate and verifying its name and
validity period (a DNS/IP SAN is required).

Protocol classification and gRPC transport handshakes each have a five-second
timeout. Closing the shared listener drops incomplete classifications, not
connections already handed to a protocol server. On shutdown, HTTP handlers
are drained before gRPC; the process waits for shutdown completion.

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
    	Listen address (default random port)
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
