# gswitch

`gswitch` is a small Cisco-like CLI emulator for tests. It supports SSH password
and public-key authentication, optional Telnet, and an in-memory running
configuration. It is not a production SSH server or a full IOS emulator.

## Start a test device

```sh
# From the Gnetcli checkout:
go install ./cmd/gswitch
export PATH="$(go env GOPATH)/bin:$PATH"
gswitch -host 127.0.0.1 -port 2223 -username test -password test
```

These are test credentials. Do not expose the emulator on an untrusted network.
Use `-authorized-keys /path/to/authorized_keys` to also permit public-key auth.
For a container-only test network, bind to `-host 0.0.0.0` without publishing
its SSH port on the host.

## Configuration survives reconnects

All SSH sessions served by one listener share the device configuration. The CLI
process also shares it with Telnet when `-enable-telnet` is set. Modes and the
selected interface remain local to each session, and concurrent reads/writes
are synchronized.

An initial configuration can be loaded with `-config-file`:

```text
interface Ethernet1
 description before
!
```

```sh
gswitch -host 127.0.0.1 -port 2223 -username test -password test \
  -config-file initial.cfg -ready-file /tmp/gswitch-ready.json
```

The supported configuration subset is intentionally small:

- `conf t` / `configure terminal` enters global configuration mode.
- `interface NAME` selects or creates an interface; the prompt becomes `(config-if)#`.
- `description TEXT` replaces the interface's previous description.
- `no description` or `no description TEXT` removes its description.
- `exit` leaves interface mode, then global configuration mode; `end` leaves both.
- `no interface NAME` removes an interface and its configuration.
- Other simple global/interface lines are stored as text; `no LINE` removes the
  corresponding stored line. This is not a complete model of IOS defaults or syntax.
- `show running-config` renders a stable, sorted snapshot with interface indentation.
- `copy running-config startup-config` and `write memory` are accepted no-ops.
- `show version` and `show clock` provide fixed test output.

Unknown operational commands return an error recognized by Gnetcli's Cisco
driver. The config-file format supports flat global statements and indented
interface blocks, with optional `!`/`end` separators; other nested blocks are
not supported. Configuration changes stay in memory and do not modify the
input file or survive process restart.

A test can configure an interface, disconnect, reconnect, and fetch the updated
configuration. This supports Annet's `diff -> patch -> deploy -> empty diff`
scenario using a Cisco device (`breed: ios12`) and Cisco generators. The separate
Annet Arista example must be adapted before switching its test fixture to gswitch.

## Readiness and lifecycle testing

`-ready-file PATH` writes a JSON object after all requested listeners are bound:

```json
{"ssh":"127.0.0.1:2223","telnet":"127.0.0.1:2224"}
```

Only enabled transports are included. `-port 0` and `-telnet-port 0` allocate
free ports and the file reports their actual addresses. The file is replaced
atomically and removed on normal SIGINT/SIGTERM shutdown. Use a dedicated file
path: an old readiness file at that path is removed on startup.

`-command-delay 30s` delays each command, including session setup, for tests that
need an operation to remain in flight. Cancellation interrupts the delay and
closes active connections. The default delay is zero.

## Library use

`SSHServerOptions.Config` accepts a `*RunningConfig`. Its `Load(string) error`
method initializes a configuration fragment; `String()` returns a synchronized,
deterministic snapshot. A failed load does not replace the current configuration.

A nil `Config` creates a separate device state per `ServeSSH`/`ServeTelnet` call.
Pass the same `NewRunningConfig()` pointer to both functions to share one device
between transports. Listener and connection ownership belongs to the serving
function; context cancellation closes them.

## Tests

From the Gnetcli repository:

```sh
go test -race ./pkg/gswitch ./cmd/gswitch
go test -race ./...
```
