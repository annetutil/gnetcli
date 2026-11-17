# Starlark models

Models collect structured data using the existing device transports. Commands,
platform selection, parsing and calculations live in external `.star` files.
There is no embedded model registry and no dependency on Glavnoc or Godograf.

For a step-by-step authoring guide with parsing and test examples, see
[the models README](https://github.com/annetutil/gnetcli/blob/main/models/README.md).

## CLI

Run from the repository root, or provide an absolute models directory:

```sh
go run ./cmd/cli -hostname switch.example.net -devtype huawei \
  -models-dir ./models -model uptime -use-ssh-config
```

Model mode always prints a JSON object. It cannot be combined with `-command`
or `-test`. `-question` is supported as a default answer for model commands.
The existing CLI's 30-second context covers connection and collection.

## Server and Python

```yaml
models_dir: /etc/gnetcli/models
```

The server also accepts `--models-dir`. An explicitly supplied flag overrides
YAML, including `--models-dir=` to disable models. An empty directory setting
leaves ordinary command RPCs available but disables model RPCs. Paths are
relative to the process working directory, not the configuration file.

`CollectModel` takes `host`, `model` and optional `host_params`. The device type,
credentials and transport follow the same resolution rules as command execution.
The corresponding HTTP endpoint is `POST /api/v1/collect_model`:

```json
{"host":"switch.example.net","model":"uptime","host_params":{"device":"huawei"}}
```

The response's `json` string contains a JSON object. It is deliberately not a
protobuf Struct: a floating-point representation would lose nanosecond precision.
HTTP clients must parse this nested string with an integer-preserving decoder.

```python
result = await client.collect_model(
    "switch.example.net", "uptime", host_params=HostParams(device="huawei"),
)
print(result["up-time"])  # Python int, nanoseconds
```

## Go API

```go
runner, err := models.New("./models")
if err != nil {
    return err
}
// The caller connects and closes dev. Collect never owns the connection.
result, err := runner.Collect(ctx, dev, "huawei", "uptime")
```

The result is `json.RawMessage`; decode into integer fields or use
`json.Decoder.UseNumber`, not `map[string]any` with default float64 decoding.
Options include `WithMaxExecutionSteps` (default 1,000,000, must be positive)
and `WithCommandOptions` (defaults applied to every executed command).
Separate devices are needed for concurrent calls unless the device supports
concurrent execution itself.

## Writing a model

Model names match `[A-Za-z0-9][A-Za-z0-9_-]*`. A request for `sample` loads
`<models_dir>/sample.star`:

```python
load("re.star", "re")

def collect(device):
    output = device.execute("show version")
    return {"device-type": device.type, "version": output.strip()}
```

`device.type` is the resolved gnetcli device type. `device.execute(command)`
returns cleaned command output as a string. Transport errors and nonzero device
command status abort the model; no partial result is returned. The function
`collect` must return a JSON-compatible dict with string keys. Integers are
encoded exactly. The runner is not aware of model names, vendors or schemas.

There is currently no YANG or model-schema validation. Required fields, types,
ranges and unknown fields are not checked by the runner; each model must validate
its parsed values and test its result shape explicitly.

Imports are relative to the model directory, not the importing file. For example,
`load("lib/helpers.star", "parse")`. Each collection reloads source files and
has isolated globals and an import cache. There is no process-wide module cache;
cyclic imports fail. Deploy coherent directory versions rather than modifying
multiple live files during a collection.

Available standard modules:

- `load("re.star", "re")`: `re.search(pattern, text)` uses Go/RE2 expressions;
  returns `None` or `[whole_match, group_1, ...]`. Unmatched optional groups are
  empty strings. Inline flags such as `(?m)` are supported.
- `load("time.star", "time")`: `time.parse_ns(value, layout, location="UTC")`
  parses a Go time layout and optional IANA location, returning integer Unix
  nanoseconds. Invalid/unknown timezones and values outside nonnegative int64
  nanoseconds fail. Zoneinfo is included, independent of the host installation.
- `load("json.star", "json")`: Starlark's standard JSON encode/decode module.

These three import names are reserved. Models can only read `.star` modules
inside the configured directory. Absolute paths, traversal and symlink escapes
are rejected. Models have no shell, filesystem or arbitrary network builtins.
Only administrators should install scripts: device.execute can issue any CLI
command, and the step limit is not a memory limit or a CPU limit for native
builtins. Do not put credentials or production device output in scripts/tests.
Context cancellation interrupts Starlark and is passed to device execution.
The server bounds connection setup to 20 seconds; collection uses the RPC context
and configured default command/read timeouts.

## Uptime

The supplied model supports `huawei` and `juniper`:

- Huawei: `display version` and `display clock`. Uses the first system uptime,
  not subsequent board uptimes. An explicit StartupTime is preferred; absent
  StartupTime is derived from device clock minus uptime. StartupTime without a
  timezone inherits the device clock's timezone.
- Juniper: `show system uptime`. Uses Current time and System booted, not Node
  booted, to calculate elapsed time.

Fields `up-time`, `boot-time`, `current-datetime` are nonnegative integer
nanoseconds. The latter two are Unix timestamps. Device clocks are never replaced
with the collector's clock. Explicit numeric UTC offsets (including negative
ones) take precedence over timezone labels; UTC/GMT/Z and MSK are supported.
Unsupported device types, unknown zones, missing data and negative intervals fail.
Huawei uptime rounded to minutes can differ from clock minus explicit StartupTime.

## Testing and protobuf generation

Tests execute real Starlark using Go `testing`/`require`, fake command results,
and mock SSH dialogs. Run `go test ./pkg/models/...`.

Use `make proto` with the project Docker image. Without Docker, the same target
can use local generators:

```sh
make proto proto_runner=
```

Install the generator versions declared in `proto_builder/Makefile` and the
Python grpcio-tools/protobuf versions in `proto_builder/Dockerfile`. Override
`protoc_bin` and `protoc_cmd` when those executables are not on PATH.
