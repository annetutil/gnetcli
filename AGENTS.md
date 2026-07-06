# AGENTS.md

## Project overview

Gnetcli is a Go project for automating interactive network-device CLIs. It contains:

- Go library APIs under `pkg/`.
- CLI binaries under `cmd/`:
  - `cmd/cli` - command-line client.
  - `cmd/gnetcli_server` - gRPC/HTTP gateway server.
  - `cmd/gswitch` and `cmd/gvendor` - auxiliary tools.
- Device implementations under `pkg/device/*` for vendors such as Huawei, Cisco, Juniper, NX-OS, RouterOS, FortiOS, Arista, H3C, Eltex, ASA, Netconf, and generic CLI.
- Transport/connectors under `pkg/streamer/*` for SSH, telnet, console, RFC2217, and common streamer abstractions.
- gRPC server implementation and generated protobuf files under `pkg/server` and `pkg/server/proto`.
- Python gRPC SDK under `grpc_sdk/python`.
- Documentation sources under `docs/`, built with MkDocs into `site/`.
- Examples under `examples/` and benchmark code under `benchmarks/`.

Core architecture: high-level `device.Device` implementations execute `pkg/cmd.Cmd` over low-level `streamer.Connector` transports. Most vendor support is built on `pkg/device/genericcli`, which uses regular expressions from `pkg/expr` to detect prompts, errors, pagers, questions, login/password prompts, and command echo.

## Repository conventions

- Go module: `github.com/annetutil/gnetcli`.
- Go version in `go.mod`: `1.25`.
- Keep Go code formatted with `gofmt`/`go test` conventions.
- Use existing functional-option style for constructors and configuration (`With...` options).
- Prefer adding behavior through public interfaces and options instead of reaching into private fields.
- Tests use the standard Go `testing` package plus `github.com/stretchr/testify` where already present.
- Mock CLI/device interaction tests should follow `pkg/testutils/mock` patterns used in `pkg/device/*/*_test.go`.
- Python SDK style is governed by `grpc_sdk/python/pyproject.toml` and `tox.ini`:
  - Ruff line length is 120.
  - Flake8 max line length is 140.
  - Generated `.pb2.py` and `.pb2_grpc.py` are excluded from flake8.

## Important files and packages

- `pkg/device/device.go` - main `Device` interface.
- `pkg/device/genericcli/genericcli.go` - regex-driven generic CLI implementation and device options.
- `pkg/cmd/cmd.go` - command and command-result interfaces, command options, question handling.
- `pkg/streamer/streamer.go` - `Connector` interface and common read/write/file abstractions.
- `pkg/expr/expr.go` - expression matching helpers.
- `pkg/server/proto/server.proto` - gRPC API definition.
- `pkg/server/*.go` - server business logic.
- `cmd/gnetcli_server/server.go` - server entry point, auth, TLS, gRPC/HTTP setup.
- `grpc_sdk/python/gnetclisdk/` - Python client SDK.
- `Makefile` - main build/test/protobuf commands.
- `docs/architecture.md` - architecture and device-development guidance.
- `docs/dev.md` - docs and Python package build notes.

## Build and test commands

Use the narrowest relevant command while iterating, then run broader checks before finishing.

### Go

```sh
go test ./...
```

Race tests used by the project Makefile:

```sh
make testrace
```

Full project target:

```sh
make all
```

`make all` runs build, protobuf generation, and race tests. It requires Docker and a local `proto_builder:tag` image for the `proto` target.

### Protobuf generation

Build the protobuf builder image first if needed:

```sh
make build-proto-docker
```

Regenerate protobuf outputs:

```sh
make proto
```

Generated files live in `pkg/server/proto/` and include Go, grpc-gateway, and Python artifacts. Do not manually edit generated protobuf outputs unless explicitly requested.

### Docker

```sh
make build-docker
```

or:

```sh
docker build -f image/Dockerfile -t gnetcli-server .
```

### Python SDK

From `grpc_sdk/python`:

```sh
tox -e ci
```

Package build:

```sh
make build
```

Publishing targets exist (`publish-test`, `publish-prod`), but do not run them unless explicitly requested.

### Documentation

Docs are MkDocs sources in `docs/`. See `docs/dev.md` for the Docker-based build flow. The generated `site/` directory is build output.

## Development guidance

### Adding or changing a device vendor

1. Prefer implementing a vendor with `genericcli.MakeGenericCLI` unless the protocol is fundamentally different.
2. Define precise regexes for:
   - prompt detection,
   - command errors,
   - pager prompts,
   - questions/confirmations,
   - login/password prompts when transport-level auth is not enough.
3. Use `expr.NewSimpleExprLast200().FromPattern(...)` for prompt/error/pager/question expressions when matching terminal tail output.
4. Add auto-commands with `genericcli.WithAutoCommands` only when the device commonly needs session setup, and make them tolerate unsupported commands with `cmd.WithErrorIgnore()` where appropriate.
5. Add tests with `pkg/testutils/mock` dialogs that cover:
   - successful command execution,
   - invalid command/error parsing,
   - pager handling if supported,
   - questions/answers if supported,
   - login edge cases if relevant.
6. Do not rely on a real network device in unit tests.

### Working with command execution

- Prefer `Device.ExecuteCtx` for new code; `Execute` is marked legacy in the interface.
- Preserve command output semantics:
  - `CmdRes.Output()` is command output without prompt/echo/control artifacts.
  - `CmdRes.Error()` contains parsed device errors.
  - `CmdRes.Status()` is `0` for success and non-zero for command/device errors.
- Use `cmd.NewCmd(..., cmd.With...)` options for timeouts, answers, callbacks, agent forwarding, and error handling.

### Working with transports

- Implement `streamer.Connector` for new transports.
- Keep transport authentication, read/write, tracing, file transfer, and agent forwarding concerns inside connector implementations.
- Return `streamer.ErrNotSupported` or feature checks via `HasFeature` for unsupported transport operations.

### Working with server/protobuf API

- Edit `pkg/server/proto/server.proto` first for API changes.
- Regenerate protobuf outputs with `make proto` instead of editing generated files manually.
- Update Go server code in `pkg/server` and `cmd/gnetcli_server` after proto changes.
- Update Python SDK code and tests under `grpc_sdk/python` when API shape changes.

### Working with Python SDK

- Keep the async client API in `grpc_sdk/python/gnetclisdk/client.py` consistent with the protobuf API.
- Add/adjust tests under `grpc_sdk/python/tests`.
- Run `tox -e ci` from `grpc_sdk/python` for Python checks.

## Files and directories to avoid modifying casually

- Generated protobuf outputs in `pkg/server/proto/*.pb.go`, `*.pb.gw.go`, `server_pb2.py`, `server_pb2_grpc.py`, `server_pb2.pyi`.
- Build artifacts and local binaries such as `server`, `cmd/*/*` compiled binaries, `benchmarks/*_linux`.
- Python virtualenv/cache/build outputs: `.venv/`, `.tox/`, `.pytest_cache/`, `.ruff_cache/`, `dist/`, `*.egg-info/`, `__pycache__/`.
- Generated docs output `site/` unless the task explicitly asks to update built documentation.

## Security notes

- Do not commit real credentials, private keys, tokens, device hostnames, or customer/device output unless explicitly sanitized.
- Do not run publishing commands or push Docker/PyPI artifacts without explicit user approval.

## Suggested completion checklist

Before finishing code changes, run the relevant subset of:

```sh
gofmt -w <changed-go-files>
go test ./...
```

For device-regex changes, include focused tests for the changed package, for example:

```sh
go test ./pkg/device/huawei
```

For Python SDK changes, from `grpc_sdk/python` run:

```sh
tox -e ci
```

For protobuf/API changes, regenerate protobuf files and then run both Go and Python checks.
