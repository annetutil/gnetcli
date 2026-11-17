# Writing Starlark models

A model turns network-device CLI output into a JSON object. All model-specific
logic lives in `.star` files: device selection, commands, parsing, calculations
and result fields. Go provides the interpreter and the connection to gnetcli.
Adding a model does not require changing Go code or rebuilding the binary.

This directory contains the [uptime model](uptime.star). See also the
[configuration and API reference](../docs/models.md).

## Directory layout and loading

```text
models/
├── uptime.star          # Entry point for -model uptime
└── lib/
    ├── huawei.star      # Huawei uptime collection
    ├── juniper.star     # Juniper uptime collection
    └── uptime.star      # Shared uptime parsing and result construction
```

A model name matches `[A-Za-z0-9][A-Za-z0-9_-]*`. Requesting `uptime` loads
`<models_dir>/uptime.star` and calls `collect(device)`.

All `load()` paths are relative to **the configured models directory**, not the
importing file. For example, even inside `lib/huawei.star`, use
`load("lib/uptime.star", "timestamp")`, not `load("uptime.star", "timestamp")`.
Only `.star` imports inside that directory are allowed; absolute paths, `..`,
symlink escapes and circular imports fail.

Every collection reloads the files and gets a fresh execution environment.
Imported modules are cached only within that collection. Globals are frozen;
create mutable lists/dicts inside functions rather than updating global state.
Deploy a complete, consistent set of files together.

## Model interface

```python
def collect(device):
    output = device.execute("show version")
    return {"output": output.strip()}
```

The object passed to `collect` exposes:

| Member | Meaning |
| --- | --- |
| `device.type` | Resolved gnetcli device type, such as `huawei` or `juniper` |
| `device.execute(command)` | Execute one command and return its cleaned output as a string |

The caller owns the connection. Models do not connect, authenticate or close it.
`execute()` uses `Device.ExecuteCtx`; transport errors and nonzero command status
abort collection. There is no partial result. Command echo, prompt and terminal
control sequences are handled by the device driver, not the model parser.

`collect` must return a JSON-compatible `dict` with string keys. Nested dicts,
lists, strings, integers, finite floats, booleans and `None` can represent the
result. Use integers for counters and nanoseconds to avoid precision loss.
Use `fail("descriptive error")` for unsupported devices or invalid data instead
of returning an empty dict, zero or `None` as a substitute for missing data.

### Current contract validation

**There is no YANG or model-schema validation yet.** The runner checks that
`collect` is callable, that its result is a dict, and that JSON encoding succeeds.
It does not enforce required fields, field types, units, ranges or reject extra
fields. For example, `{"up-time": "wrong type"}` passes these structural checks.
`Runner.Check(name)` only checks the model name and source-file readability; it
is not a schema validator.

Define and document a stable result shape for each model, validate parsed values
in Starlark, and test the exact output. Such checks are model code, not a mandatory
independent schema validation layer. Declaring a `schema` variable alone has no
effect in the current runner.

## Example 1: collect raw version text

Create `models/version_text.star`:

```python
def collect(device):
    if device.type == "huawei":
        command = "display version"
    elif device.type == "juniper":
        command = "show version"
    else:
        fail("version_text: unsupported device type: " + device.type)

    output = device.execute(command).strip()
    if not output:
        fail("version_text: empty command output")
    return {"device-type": device.type, "version-text": output}
```

Run from the repository root, using credentials from your SSH configuration:

```sh
go run ./cmd/cli -hostname switch.example.net -devtype huawei \
  -use-ssh-config -models-dir ./models -model version_text
```

Model mode always prints JSON; `-json` is unnecessary. Do not combine `-model`
with `-command` or `-test`. The latter tests device configuration, not models.

## Example 2: parse a field and share a helper

Create `models/lib/version_parser.star`:

```python
load("re.star", "re")

def parse_version(output, pattern):
    matched = re.search(pattern, output)
    if matched == None:
        fail("version: expected version line is missing")
    version = matched[1].strip()
    if not version:
        fail("version: empty version")
    return version
```

Create `models/version.star`:

```python
load("lib/version_parser.star", "parse_version")

def collect(device):
    if device.type == "huawei":
        command = "display version"
        pattern = r"(?m)^VRP \(R\) software, Version ([^\r\n]+)$"
    elif device.type == "juniper":
        command = "show version"
        pattern = r"(?m)^Junos: ([^\r\n]+)$"
    else:
        fail("version: unsupported device type: " + device.type)

    output = device.execute(command)
    return {"version": parse_version(output, pattern)}
```

These tutorial patterns intentionally support only these example formats, not
every software release:

```text
VRP (R) software, Version 8.180 (LAB)
Junos: 23.4R1.9
```

With the Juniper example, the result is:

```json
{"version": "23.4R1.9"}
```

Launch it with `-model version`. Add sanitized fixtures and extend the patterns
when supporting additional device output formats. Starlark is not Python:
use `load`, not `import`; Python packages and `try`/`except` are unavailable.
Commands can depend on earlier responses because the entire collection scenario
runs inside `collect`.

## Available modules

Only the following standard modules are exposed; Python's standard library is
not available. Their import names are reserved.

| Import | API | Result |
| --- | --- | --- |
| `load("re.star", "re")` | `re.search(pattern, text)` | `None` or `[whole_match, group_1, ...]`; optional unmatched groups are empty strings |
| `load("time.star", "time")` | `time.parse_ns(value, layout, location="UTC")` | Integer Unix nanoseconds; layout uses Go's reference date, not Python `%Y`-style formats |
| `load("json.star", "json")` | `json.decode(text)`, `json.encode(value)` | Decode device JSON or encode JSON text |

Regexes use Go/RE2 syntax, including inline flags such as `(?m)`. They do not
support lookaround or backreferences. Use raw strings (`r"..."`) for patterns.

For a timestamp with an explicit UTC offset:

```python
load("time.star", "time")

def collect(device):
    return {
        "timestamp": time.parse_ns(
            "2026-01-01 03:00:00+03:00",
            "2006-01-02 15:04:05-07:00",
        ),
    }
```

This example returns `{"timestamp": 1767225600000000000}`. `time.parse_ns`
rejects invalid dates, unknown timezones and timestamps outside nonnegative
signed 64-bit nanoseconds. For dates without an offset, pass the device's known
IANA timezone explicitly rather than guessing from the collector's local time.

If a device returns JSON, decode it to inspect fields, but return a dict from
`collect`, not the string produced by `json.encode`.

## Uptime as a complete model

The shipped [uptime.star](uptime.star) selects one of two vendor collectors.
Both return the same fields:

| Field | Meaning | Unit |
| --- | --- | --- |
| `up-time` | Time since the operating system started | Integer nanoseconds |
| `boot-time` | System boot timestamp relative to Unix Epoch | Integer nanoseconds |
| `current-datetime` | Device clock relative to Unix Epoch | Integer nanoseconds |

[Huawei](lib/huawei.star) executes `display version` and `display clock`. It uses
the first system uptime, not a later board uptime. It prefers explicit
`StartupTime`, otherwise computes `boot-time = current-datetime - up-time`.
StartupTime without a timezone inherits the device clock's timezone.

[Juniper](lib/juniper.star) executes `show system uptime` and uses `Current time`
and `System booted`, not `Node booted`. It derives uptime from their difference.
The [shared helpers](lib/uptime.star) parse timestamps and reject negative values
or a boot time after the current device time. These checks do not enforce the
whole output schema. Huawei's minute-rounded uptime can differ from the
interval between its explicit boot timestamp and clock.

## Test without a real device

After saving Example 2's files, add `pkg/models/version_example_test.go`:

```go
package models_test

import (
    "context"
    "encoding/json"
    "testing"

    "github.com/annetutil/gnetcli/pkg/cmd"
    "github.com/annetutil/gnetcli/pkg/models"
    "github.com/stretchr/testify/require"
)

type versionExampleExecutor func(context.Context, cmd.Cmd) (cmd.CmdRes, error)

func (f versionExampleExecutor) ExecuteCtx(ctx context.Context, command cmd.Cmd) (cmd.CmdRes, error) {
    return f(ctx, command)
}

func TestVersionExample(t *testing.T) {
    runner, err := models.New("../../models")
    require.NoError(t, err)

    for _, tc := range []struct {
        name, deviceType, command, output, expected string
        wantError bool
    }{
        {"huawei", "huawei", "display version", "VRP (R) software, Version 8.180 (LAB)\n", "8.180 (LAB)", false},
        {"juniper", "juniper", "show version", "Junos: 23.4R1.9\n", "23.4R1.9", false},
        {"invalid output", "juniper", "show version", "unexpected output\n", "", true},
    } {
        t.Run(tc.name, func(t *testing.T) {
            calls := 0
            fake := versionExampleExecutor(func(_ context.Context, command cmd.Cmd) (cmd.CmdRes, error) {
                calls++
                require.Equal(t, tc.command, string(command.Value()))
                return cmd.NewCmdRes([]byte(tc.output)), nil
            })
            result, err := runner.Collect(t.Context(), fake, tc.deviceType, "version")
            require.Equal(t, 1, calls)
            if tc.wantError {
                require.Error(t, err)
                require.Nil(t, result)
                return
            }
            require.NoError(t, err)
            var got map[string]string
            require.NoError(t, json.Unmarshal(result, &got))
            require.Equal(t, map[string]string{"version": tc.expected}, got)
        })
    }
}
```

Run from the repository root:

```sh
go test ./pkg/models -run '^TestVersionExample$'
go test ./pkg/models/...
```

The test runs the actual `.star` files through the public API; it does not
reimplement the parser in Go. Follow [uptime_test.go](../pkg/models/uptime_test.go)
for fixtures and end-to-end mock SSH dialogs. Cover successful parsing, alternate
formats, missing/malformed fields, unsupported devices, command failures and
exact output types/units. Never commit unsanitized production output.

## Server and Python SDK

Install the whole models directory on the **server**, including helper files.
Configure its path in YAML:

```yaml
models_dir: /etc/gnetcli/models
```

Or pass `--models-dir /etc/gnetcli/models` to `gnetcli_server`. Relative paths are
resolved against the process working directory. An empty setting disables model
RPCs without disabling ordinary command RPCs. No model source or client-side
filesystem path is sent over RPC: the client selects an installed model by name.

Inside your async application:

```python
from gnetclisdk import Gnetcli, HostParams

client = Gnetcli(server="localhost:50051", insecure_grpc=True)
result = await client.collect_model(
    "switch.example.net",
    "uptime",
    host_params=HostParams(device="juniper"),
)
print(result["up-time"])
```

This local example assumes device credentials are configured on the server.
Use the deployment's TLS/authentication settings outside local development.
The SDK returns a Python dict with exact integer values. Raw gRPC/HTTP responses
wrap the object in a `json` string; do not decode nanoseconds through `float64`
or JavaScript Number if exact precision is required.

## Execution limits and safety

Only trusted administrators should install models. There is no shell, arbitrary
network or filesystem builtin, but `device.execute` can issue **any** command
allowed by the device credentials. The model runner is not a read-only CLI guard.

The default limit is 1,000,000 Starlark steps per collection, including imports.
Go callers can use `models.WithMaxExecutionSteps` to change it. This is not a
memory limit or a timeout for native builtins. Context cancellation is propagated
to the interpreter and command execution. CLI collection has a 30-second context;
the server bounds connection setup to 20 seconds and uses the RPC context and
configured command/read timeouts for collection.
