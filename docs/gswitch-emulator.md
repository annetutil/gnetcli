# Declarative gswitch emulator (experimental)

The opt-in emulator models stateful CLI interactions, not a switch's forwarding
or routing implementation. Without `-profile`, gswitch retains its legacy CLI.
The included profiles are **synthetic, incomplete lab profiles**, not certified
IOS XE or VRP emulations. No hardware captures are included.

## Run

From the gnetcli repository:

```sh
go run ./cmd/gswitch \
  -host 127.0.0.1 -port 2223 -console-port 2224 \
  -username test -password secret \
  -profile examples/gswitch/iosxe.yaml \
  -scenario examples/gswitch/noisy.yaml
```

Connect to management SSH or to the persistent raw console:

```sh
ssh -p 2223 test@127.0.0.1
nc 127.0.0.1 2224
```

The console has its own username/password dialogue. SSH authenticates at the
transport layer and passes the authenticated identity into the CLI. Each SSH
shell has independent mode, pagination and transaction state. Both transports
share the same running/startup configuration.

The raw console is **not Telnet**: it does not negotiate IAC or serial parameters.
One client may own `console0` at a time. Disconnecting the client leaves the
console's login, mode, partial input and pending command intact. Reattaching
redraws the current prompt; old output is not replayed. `exit` logs out from the
console without destroying the transport, while SSH logout closes the channel.

Use `enable`, `configure terminal`, `interface Ethernet1`, `description TEXT`,
`end`, `show running-config` and `write memory` to exercise shared state. Try
`show slow` to see a log between its header and delayed body. `reload` opens a
confirmation dialogue; an empty answer reboots the device.

`-profile examples/gswitch/huawei.yaml` selects a candidate-config demonstration:
`system-view`, `sysname lab-sw1`, `interface GE0/0/1`, `description TEXT`, `commit`, `return`,
`display current-configuration`, and interactive `save`.

In system-view, `sysname ?` shows `TEXT<1-246>  Host name (1 to 246 characters)`.
`sysname NAME` takes one word of 1–246 characters, preserving case. The candidate
prompt immediately becomes `[*NAME]`; `commit` publishes the name and changes it
to `[~NAME]`. `return`, or `quit` from system-view, discard uncommitted changes.
User-view prompts and `display current-configuration` use the committed name; `save` also persists it
in startup configuration for the emulator's next reboot.

`aaa` enters `[~HOST-aaa]` from system-view. Like interface view, `quit` returns
to system-view without discarding the candidate; `return` discards the candidate
and returns to user-view. `commit` works in all three configuration views.

The Huawei profile explicitly shares its `display` commands across user, system,
interface and AAA views. `dis<Tab>` expands to `display `, and `dis this` executes
the abbreviated form. `display this` is additionally declared in the three
configuration views. In system-view it renders the entire configuration tree,
including AAA and every configured interface. In a subview it renders only the
selected interface or AAA section. A bare `dis` is still incomplete; it does not
implicitly execute `display this`.

`display this` reads committed running configuration, not pending candidate
changes; `display current-configuration` includes the committed AAA section too.
The former ends with `#` and `return` as text, without leaving the current view.
See Huawei's [configuration file guide](https://info.support.huawei.com/enterprise/en/doc/EDOC1100419273/7cea5c40/managing-configuration-files)
and [AAA display example](https://info.support.huawei.com/network/ptmngsys/Web/tsrev_ar/en/content/ar/25_edesk_ssh_cannot_log_in/edesk_ssh_cannot_log_in_edesk003.html).

The initial AAA values reproduce the supplied lab capture, not universal NOS
defaults. The following supported commands update candidate fields under `aaa`:

- `local-user policy security-enhance` / `undo local-user policy security-enhance`
- `default-domain admin NAME`
- `service-type terminal force-domain NAME`

These are configuration emulation only: no AAA backend, user database or domain
validation is implemented, and SSH/console credentials remain controlled by the
emulator's launch options. Existing `display interface`/`info-center` output
stubs remain explicit errors even when called from a nested view.

The same `-scenario examples/gswitch/noisy.yaml` works with both profiles. Its
`after-header` checkpoint is emitted by the synthetic `show slow` command on
IOS XE and `display slow` on Huawei. Both commands demonstrate a log between
output chunks; they are not claims about real vendor commands. Unknown scenario
checkpoint references remain errors rather than being silently ignored.

`-console-port 0` and `-port 0` allocate free ports. `-ready-file PATH` atomically
publishes listener addresses; it means **listeners are bound**, not that the
emulated NOS has finished booting. SSH shell admission may fail before login
readiness. SSH transport authentication itself is not gated by boot readiness.

Profile mode rejects the legacy `-enable-telnet`, `-config-file` and
`-command-delay` flags rather than silently applying them to another engine.
Represent delays with actions/scenarios. Credentials are for isolated tests;
do not expose this service to an untrusted network or use real device secrets.

## Aruba Instant and noisy AP boot

The `aruba.yaml` profile is an **Instant AP** subset, not ArubaOS-CX or a wireless
controller. Prompts use a locally administered lab MAC (`02:00:00:00:00:01# `)
and `User: `/`Password: ` login. Its command syntax follows the official
[Instant CLI overview](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/preface/access-iap-cli.htm),
[show version](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/showversion.htm),
[show aps](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/showap.htm),
[IP interfaces](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/sh-ip-interface.htm),
[name](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/name.htm),
[syslocation](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/syslocation.htm),
and [commit](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/commit.htm).

Supported commands:

- `show version`, `show running-config`, `show aps`, `show ip interface brief`.
- `configure terminal`, `name NAME`, `syslocation TEXT`, `end`, `exit`.
- `commit apply` (apply and save), `commit apply no-save`, `write memory`.
- `reload` with a `y`/`n` confirmation; `exit` in exec logs out.

Configuration is session-local until commit; applied changes become visible to
other sessions. The output tables/version and link-local IP are synthetic and
shortened; no WLAN, cluster, radio or DHCP client runs. The lab reload dialogue
always confirms reboot and discards unsaved changes, omitting the real device's
conditional save question/timeout. `commit revert` and support bundles are not
modeled. Omitting `-scenario` gives an immediately operational AP for CLI tests.

Run the [NOCDEV-22469](https://st.yandex-team.ru/NOCDEV-22469) reproduction:

```sh
ya tool go run ./cmd/gswitch \
  -host 127.0.0.1 -port 2223 -console-port 2224 \
  -profile examples/gswitch/aruba.yaml \
  -scenario examples/gswitch/aruba-dhcp.yaml \
  -username admin -password secret
```

Connect immediately with `nc 127.0.0.1 2224` (raw TCP, **not Telnet/RFC2217**).
The separate SSH CLI is on port 2223; its shell is unavailable until login is
ready. A ready-file only reports bound listeners, not completion of AP boot.

The scenario is a deterministic, **10x compressed text-derived replay**, not an
exact binary console capture or proof that GlavNOC's detector now works:

- 0–17 s: boot output and six DHCP Discover rounds, including `No lease`.
  Missing cycles between ticket excerpts are interpolated; log timestamps retain
  the source clock. Hardware identifiers/addresses are sanitized.
- At 17 s: `User: ` is appended directly to `USB Modem is not presen`, matching
  the prompt/log collision. Login is enabled but lifecycle remains `degraded`.
- 20 ms after each username submission: kernel noise follows `Password: `,
  without echoing, replacing or consuming secret input.
- At 20.7 s: `Internal error 8-0` and a real console CLI reset discard pending
  credentials, candidate, editor/history and delayed actions. TCP stays open.
  The subsequent Conductor line overwrites the freshly emitted `User: ` line.
- Authentication emits a degraded-state warning using redraw; 100 ms later a
  DHCP burst interrupts the console again, including a partially typed command.
  These phase-relative injections are deliberate, not original wall-clock timing.
- Configuration and `write memory` fail with the errors understood by the
  `aruos` driver; show commands remain available. There is no automatic recovery
  or endless DHCP loop: this finite trace ends degraded. `reload` replays it.

Connect before boot to observe all events; no historical console output is
replayed to late attachments. For tests, use `Advance` instead of sleeping.
The scenario does not contact the lab AP, DHCP server or any real network device.

## SSH console, PTY, and local test control

Profile mode now has two SSH attachment modes:

- `-ssh-mode cli` (default): an authenticated management session; unavailable
  while device login readiness is false, and closed by device reboot.
- `-ssh-mode console`: the persistent `console0` line through an authenticated
  SSH terminal-server connection. It accepts connections during boot, forwards
  console events without changing scenario routes, survives reboot/CLI restart,
  and retains login/mode/input/history after disconnect. Only one attachment can
  own the line, shared with `-console-port`; busy SSH callers get a diagnostic.

SSH credentials use `-username`/`-password`. Optional `-console-username` and
`-console-password` select the device account independently (empty flag values
inherit the SSH account). SSH authentication does **not** bypass console login.
Neither transport replays boot bytes emitted before attachment.

For the Aruba scenario through SSH:

```sh
ya tool go run ./cmd/gswitch \
  -profile examples/gswitch/aruba.yaml \
  -scenario examples/gswitch/aruba-dhcp.yaml \
  -host 127.0.0.1 -port 2223 -ssh-mode console \
  -username terminal-user -password terminal-secret \
  -console-username admin -console-password secret \
  -control-port 8088 -control-token local-test-control-token
```

Then connect with `ssh -p 2223 terminal-user@127.0.0.1`. The control API is always
bound to `127.0.0.1`, independently of `-host`; omit `-control-port` to disable it.
`-ready-file` includes a `control` address when enabled. Its token must have at
least 16 characters with no whitespace. This is a trusted **test-only** API:
state can contain configuration data; do not expose it or use production secrets.

Every request needs `Authorization: Bearer TOKEN`. Mutations require POST,
`Content-Type: application/json`, one object, known fields, and at most 64 KiB.
Browser `Origin` requests are rejected; CORS is not enabled. HTTP connections
have bounded read/header/write/idle timeouts.

| Endpoint | Request | Result |
| --- | --- | --- |
| `GET /v1/state` | No body | Lifecycle/readiness, running/startup/candidate, sessions and terminal size |
| `GET /v1/trace` | No body | Last 256 semantic events; no raw/password input |
| `POST /v1/events` | `{"kind":"log","route":"console","policy":"raw","text":"noise"}` | Inject one immediate event; files, nonzero times, and session routes are rejected |
| `POST /v1/lifecycle` | `{"state":"operational"}` | Change command/service readiness state |
| `POST /v1/event-output` | `{"enabled":false}` | Suppress asynchronous raw/log event output, not CLI output, readiness or reset events |
| `POST /v1/reboot` | `{}` | Reboot and replay existing boot/scenario timelines |

```sh
curl -H 'Authorization: Bearer local-test-control-token' \
  http://127.0.0.1:8088/v1/state
curl -H 'Authorization: Bearer local-test-control-token' \
  -H 'Content-Type: application/json' \
  -d '{"kind":"log","route":"console","policy":"raw","text":"DHCP test noise"}' \
  http://127.0.0.1:8088/v1/events
```

JSON state uses lower-camel-case fields; `now`/trace `at` are logical nanoseconds.
HTTP tokens and terminal password buffers are not included. Tests can instead
use `ControlHandler`, `SetEventOutput`, `Inject`, `Snapshot` and `Trace` directly.
`ServeControl` rejects non-loopback listeners. No HTTP clock acceleration,
repeat/branch operators or scenario scheduling changes are introduced here.

PTY size and `window-change` update each attached session. `SSHSessionHandler`
is the PTY-aware alternative to the existing `SSHHandler`; configure only one.
`Session.Resize` accepts 0 (keep dimension) through 4096 character cells. A
console retains geometry through reconnect/reboot. Positive page lengths are
capped by terminal rows minus one pager row; explicit zero still disables paging.
Help descriptions use the live width; pure Profile rendering uses profile width.
This follows [RFC 4254 PTY/window messages](https://www.rfc-editor.org/rfc/rfc4254.html#section-6.7).
Terminal mode flags/pixel dimensions, wide/combining glyphs and a full terminal
screen/scrollback model are not implemented; ANSI CSI styling is ignored for
pager cell counting. Resize notifications are bounded/coalesced snapshots.

## Declarative configuration sections

All included profiles share one configuration definition for full and scoped
output. It is not inferred from arbitrary state keys:

```yaml
configuration:
  id: root
  children:
    - id: system
      lines: ["sysname {{ .Config.hostname }}"]
      footer: "#"
    - id: interfaces
      path: [interfaces]
      each: true
      header: "interface {{ .Key }}"
      lines: ['{{ if index .Value "description" }} description {{ .Value.description }}{{ end }}']
      footer: "#"
```

`path` selects keys relative to the parent value; `each` iterates a map in sorted
order. Header/lines/footer are templates receiving `.Config` (whole snapshot),
`.Value` (selected node), `.Key` (current map key) and `.Keys` (ancestor selections).
Empty rendered lines are omitted, nonempty ones are LF-terminated. Children
render between lines and footer. IDs are globally unique; at most 256 sections,
32 levels/path components, 256 lines per section, and 1 MiB aggregate output.

```yaml
actions:
  - op: render-config
    name: interfaces
    config: running
    context: {interfaces: "{{ .Context.ifname }}"}
    prefix: "#\n"
    suffix: "return\n"
```

`name` selects a subtree (omitting it selects the root). `context` maps `each`
section IDs to key templates, retaining the existing mode context independently.
Sources are `running` (default), `effective` (candidate if open, otherwise running)
and `startup`. Prefix/suffix only wrap output; they never execute commands.
`Profile.RenderConfiguration(name, selections, snapshot)` exposes the pure renderer.
Missing paths are skipped; an explicitly selected new map key renders an empty
node/header before it has a committed object. Non-map `each` values are errors.
Existing fixtures/actions remain supported for profiles without a section tree.

## Runtime boundaries

`pkg/gswitch/emulator` has no dependency on SSH, Telnet or Gnetcli client drivers.

- `LoadProfile` strictly decodes one YAML document, checks references/types,
  resolves bounded fixture files and compiles grammar/templates.
- `New` creates independent device state from an immutable shared profile.
- `Attach` creates a management session or attaches a persistent console line.
- `Session.Input` consumes arbitrary byte chunks. `Session.Read` or `Output`
  delivers the serialized byte stream; do not mix these output APIs.
- `Advance` drives logical time deterministically without sleeping.
- `Run` drives the same scheduler using wall-clock time with a 5 ms tick.
  Manual `Advance` is rejected while `Run` is active.
- `Inject`, `Reboot`, `Snapshot` and `Trace` form an in-process test-control API.
- `Serve` adapts an `io.ReadWriteCloser`; `ServeConsole` serves raw TCP.

A serialized state machine owns configuration, console/session state and a
stable timestamp/sequence event queue. It never performs blocking network I/O.
Each attachment has one writer and a bounded output queue. Overflow disconnects
only that attachment with `ErrSlowConsumer`; it does not stop other sessions.
The semantic trace is bounded to 256 entries and omits raw input/passwords.

`Run` does not accelerate an external client's timeouts. There is no random
fault model in v1: explicit event schedules and input order are reproducible,
but the arrival order of concurrent real network inputs is not guaranteed.

## Profile format

See `examples/gswitch/iosxe.yaml` and `huawei.yaml` for complete profiles.
Unknown YAML keys, multiple YAML documents, unknown modes/actions/types, duplicate
command IDs or equivalent syntax, and invalid fixture paths fail loading.
Files in the CLI are opened through `os.OpenRoot`; fixtures cannot escape that
root through `..` or symlinks. Library users must supply a suitably confined FS.
Profile YAML is limited to 4 MiB, each fixture/render/output batch to 1 MiB,
input to 4096 bytes by default and mode nesting to 32 frames.

The initial state is a string-keyed tree of maps, lists and scalar values.
State updates use path components rather than evaluating arbitrary expressions:

```yaml
- id: description
  modes: [interface]
  syntax: "description <text:rest>"
  actions:
    - op: set
      path: [interfaces, "{{ .Context.ifname }}", description]
      value: "{{ .Args.text }}"
```

Grammar keywords are case-insensitive. `abbreviations: true` enables unique
keyword prefixes; exact keywords take precedence. Ambiguity is checked at each
token, including against commands which would need more arguments. Modes have
explicit command sets: there is no implicit parent-mode command inheritance.
A command's optional `abbreviations: false` overrides the profile policy for
execution while still allowing Tab to insert the full canonical command. The
Aruba profile uses this for `end` and `exit`; an explicit true can enable a command
when profile abbreviations are disabled.

Parameter types:

- `word`: one whitespace-delimited argument, preserving case.
- `uint`: a decimal unsigned 32-bit integer.
- `ip`, `ipv4`, `ipv6`: an address of the specified family; zones/DNS names are not accepted.
- `mac`: a six-byte MAC address accepted by Go `net.ParseMAC`, including colon/dot notation.
- `rest`: the remaining original line, preserving internal spaces and quotes;
  it must be the final parameter.

A command can declare a display-only hint and length bounds for `word` arguments:

```yaml
- id: sysname
  modes: [system]
  syntax: "sysname <name:word>"
  help: ["Set host name", "Host name (1 to 246 characters)"]
  arguments:
    name: {hint: "TEXT<1-246>", minLength: 1, maxLength: 246}
  actions:
    - {op: set, path: [hostname], value: "{{ .Args.name }}"}
```

`hint` replaces the default argument label (such as `<name:word>`) in `?` and Tab lists but is never inserted or parsed
as a keyword. `minLength`/`maxLength` count Unicode code points in the parser
(the terminal editor remains ASCII-only); zero means no additional bound.
Invalid complete values are rejected at the argument's position **before** actions
or candidate mutation. Partial input shorter than `minLength` can still request
help. State-backed suggestions are filtered through the same bounds.
Specifications are scoped by mode and grammar prefix, shared by longer command
leaves, and may be omitted by siblings. Conflicting declarations, non-word or
unknown argument names, invalid ranges and unsafe hints fail profile loading.

Word arguments can additionally declare `enum: [up, down]`: parsing requires an
exact case-sensitive value, while help/Tab offer those canonical values with
case-insensitive prefix filtering. Enum values are at most 64 unique printable
ASCII words of 1–256 bytes; an enum cannot share a prefix with a state completion
source. `uint` arguments support optional `minValue`/`maxValue` (inclusive,
unsigned 32-bit); length/enum constraints remain word-only. Hints also work for
typed IP/MAC/numeric arguments; matching always uses the actual grammar type.

```yaml
syntax: "priority <value:uint>"
arguments:
  value: {hint: "INTEGER<1-100>", minValue: 1, maxValue: 100}
```

`Tab` completes command keywords and declared argument values using the current
mode's grammar:

- One match expands the current word and adds a space: `sh<Tab>` becomes `show `,
  `show ru<Tab>` becomes `show running-config ` in the IOS profile.
- Multiple matches expand their common prefix and print a sorted choice list,
  then restore the prompt/input. For example, `show <Tab>` lists the available
  show commands; typing a longer prefix and pressing Tab narrows the choices.
- Exact keywords take precedence over longer siblings. Previous words must be
  valid according to the parser's abbreviation and argument-type rules.
- No match rings the bell without changing the input. Expansion respects
  `terminal.maxInput`. Case-insensitive matches use canonical keyword spelling.
- Argument hints such as `<name:word>` and `<cr>` may be displayed but are never
  inserted. Free-form arguments without a completion source, including
  descriptions, are not rewritten.
- Tab edits the word at the cursor, preserving subsequent words, and never executes a command:
  press Enter to run it. Login/password/dialogue, pager and running-command
  interactions do not invoke completion.
- Completion honors character/line/no-echo settings and survives log redraw or
  a console reconnect. With line/no echo, inserted text is not echoed immediately.

`Profile.Complete(mode, line)` exposes the pure operation using the profile's
initial state; `CompleteWithState(mode, line, state)` uses the supplied snapshot.
No separate command list needs to be maintained. Keywords retain the spelling
from `syntax` (for example `LoopBack`), while parsing stays case-insensitive.

To offer configuration map keys for a `word` argument in both `?` and Tab:

```yaml
- id: interface
  modes: [system]
  syntax: "interface <name:word>"
  help: ["Enter interface view", "Interface name"]
  completions:
    name:
      statePath: [interfaces]
  actions:
    - {op: push, mode: interface, context: {ifname: "{{ .Args.name }}"}}
```

`statePath` is a literal key path, not a template or executable expression.
Live sessions resolve it from their effective configuration: candidate if open,
otherwise running. Pending interfaces are visible only in that candidate;
committed changes appear to other sessions when they start a fresh candidate.
The source is shared across command leaves with the same grammar prefix;
conflicting sources fail profile loading. Missing/empty/non-map sources fall
back to the argument hint. Only printable ASCII single-word keys that fit
`terminal.maxInput` are offered. Suggestions are **advisory**, not an enum:
arbitrary valid arguments still parse, allowing new virtual interfaces.

The Huawei `interface ?` combines these names with declared family keywords
(`100GE`, `25GE`, `Ethernet`, `LoopBack`, `MEth`, `NULL`, `Vlanif`). Each family's
number argument can use the same map without duplicating its inventory:

```yaml
- id: interface-loopback
  modes: [system]
  syntax: "interface LoopBack <number:word>"
  completions:
    number:
      statePath: [interfaces]
      prefix: LoopBack
      stripPrefix: true
  actions:
    - {op: push, mode: interface, context: {ifname: "LoopBack{{ .Args.number }}"}}
```

The case-sensitive `prefix` filters stored keys, and `stripPrefix` removes it
from suggestions: `LoopBack123` offers `123` after `interface LoopBack `.
Typing `interface LoopBack 123` selects the same context as `interface LoopBack123`.
The prototype does not validate physical port existence or vendor number ranges;
a new map entry appears when an interface setting is actually written.

`?` provides stable grammar-derived help without executing the command. It shows
**only one grammar level**: `?` lists `display` once, `disp?` filters that level,
`display ?` lists immediate children such as `current-configuration`, `interface`,
`info-center`, `slow`, and `version`, and
`display version ?` offers `<cr>`. Parent command words are not repeated in the
child list, and deeper descendants are not flattened into it.

A command may supply one help description per syntax token:

```yaml
commands:
  - id: display-version
    modes: [user]
    syntax: display version
    help:
      - Display current system information
      - Display system version
    actions:
      - {op: output, text: "Synthetic version\n"}
  - id: display-config
    modes: [user]
    syntax: display current-configuration
    help:
      - Display current system information
      - Display current configuration
    actions:
      - {op: output, text: "Synthetic configuration\n"}
```

Descriptions belong to a grammar prefix in a particular mode, not the entire
leaf command. A description supplied by one leaf is shared with its siblings;
empty descriptions may be omitted using an empty string in the list. Conflicting
non-empty descriptions for the same prefix/mode, incorrect list lengths and
control characters fail profile loading. A description can differ between modes.

The Huawei example enables a header and aligned descriptions for `?`:

```yaml
terminal:
  help:
    rootHeader: "Current view commands:"
    indent: 2
    keywordWidth: 18
    echoQuestion: true
```

`rootHeader` is emitted only for an empty/whitespace-only input buffer.
`keywordWidth` is the minimum padded keyword column; it grows to fit the longest
entry at the current level with at least two spaces before descriptions.
An optional `nestedKeywordWidth` overrides that minimum after a preceding command
word; zero means automatic sizing. `tailOrder` moves only matching, existing
entries to the end in the specified order. `blankLineAfter` inserts a blank line
before the restored prompt. The Huawei profile uses:

```yaml
terminal:
  help:
    rootHeader: "Current view commands:"
    indent: 2
    keywordWidth: 18
    nestedKeywordWidth: 0
    lineWidth: 80
    tailOrder: ["|", ">", ">>", "<cr>"]
    blankLineAfter: true
    echoQuestion: true
```

`lineWidth` word-wraps descriptions at a fixed profile width, aligning continuation
lines with the description column. Zero disables wrapping; long unbreakable words
are preserved. This is not yet tied to SSH window-size changes.

The Huawei `display interface ?` reproduces the supplied one-level family and
subcommand list, including `brief`'s wrapped description and the trailing
`|`, `>`, `>>`, `<cr>`. Its display handlers are **grammar-only fixtures** that
return an explicit not-implemented error; they do not generate interface status
or execute filters/file redirection. The configuration-view family commands do
enter the existing interface view and support its configuration actions.

A grammar prefix can be both an executable command and the parent of longer
commands. Declare `display info-center` alongside its longer forms: the existing
parser then offers `<cr>` as well as the next-level alternatives. The formatter
does not invent `<cr>` or add operators not present in the grammar.

The example's `display info-center ?` reproduces this captured help layout:

```text
  channel     Set the name of information channel
  statistics  Information statistics data of all modules
  |           Matching output
  >           Redirect the output to a file
  >>          Redirect the output to a file in append mode
  <cr>
```

These `info-center` entries are **grammar-only fixtures**, not working NOS
implementations. Pressing Enter returns an explicit `Error: ... not implemented`
response without changing state or disconnecting. Filters and redirects require
an argument but are not executed; no host file is created, overwritten or
appended to. Further channel/filter argument syntax has not been captured and
is not advertised as complete. The purpose here is to reproduce help/navigation
without falsely claiming that an operation succeeded.

`echoQuestion` echoes the question mark in character-echo mode without storing
it in the input. The prompt and original buffer are restored after the list.
Tab keeps compact completion candidates rather than descriptions. Profiles
without `terminal.help` retain the previous plain output byte-for-byte.

`Profile.HelpEntries(mode, line)` exposes token/description/kind records;
`Profile.RenderHelp(mode, line)` produces LF-terminated help without the prompt.
The existing `Profile.Help` and `Complete` APIs still return plain candidates.
These methods use initial state; `HelpWithState`, `HelpEntriesWithState`, and
`RenderHelpWithState` accept a caller-owned configuration snapshot for live values.
`Profile.Parse` exposes structured invalid/incomplete/ambiguous errors. Profile
`errors` templates receive `.Line`, `.Offset`, `.Prompt`, `.Caret`, and
`.ExpectedCaret`. `.Offset` remains the parser's byte offset within the command;
`.Caret` includes the width of the last CLI prompt actually emitted to this
session, so it points under the offending token even with a longer hostname or
configuration-view prompt. `.ExpectedCaret` additionally reserves one separating
space for an incomplete command that does not already end in whitespace. The
Huawei incomplete-command template uses it to point at the missing argument:

```text
<lab-vla-1s1>display
                     ^
Error: Incomplete command found at '^' position.
```

This is the existing single-line, plain-prompt column model, not full ANSI color,
wide-character or terminal-wrapping emulation. Profile/template files are loaded
once at startup: changing their bytes does not update a running gswitch process.
Restart `go run` (or rebuild/restart a binary) to apply profile or renderer changes.
If `?` still produces an unindented list without the header, check the running
process/profile rather than removing the formatting from the YAML.

Templates are Go `text/template` with `missingkey=error`, no added functions,
and bounded output. They see `.Config`, `.Running`, `.Startup`, `.Args`,
`.Context`, `.Username`, `.Dirty`, `.Input`. `.Config` is the session candidate
when present, otherwise running state. Rendering/action defects terminate the
attachment with an explicit emulator error rather than pretending that the
NOS rejected a valid command. This is not a CEL implementation.

### Actions

| Operation | Meaning |
| --- | --- |
| `push`, `pop`, `mode` | Push/pop a mode frame or replace the stack; `context` supplies frame variables |
| `set`, `delete` | Update `.Config` using a list of path components |
| `output` | Render `text` or `file`, convert LF to terminal newline, paginate |
| `raw` | Emit `text` or fixture `file` byte-for-byte, without templates/paging |
| `pause` | Wait for `after` without producing output |
| `checkpoint` | Emit a named semantic checkpoint |
| `pager` | Set per-session page-line count; zero disables paging |
| `echo` | Select `character`, `line` or `none` echo for non-secret input |
| `monitor` | Enable/disable delivery of monitor-routed events to this session |
| `begin` | Take a session-local candidate snapshot and base revision |
| `commit` | Replace running with candidate if its base revision is current |
| `abort` | Discard the candidate |
| `save` | Copy running to startup; candidate is not implicitly committed |
| `dialog` | Suspend execution for an exact answer from a named dialogue |
| `logout` | Close a management session, or reset console login |
| `disconnect` | Detach the transport; a console line keeps its state |
| `reboot` | Restore startup; disconnect management sessions; restart console login/boot |

Every action may have a nonnegative `after` delay. The delay is relative to the
preceding action's completion, not command submission. Commands yield during
these waits; background events and other sessions continue to work.

Dialogue answers run their actions, then resume the original command. Unknown
answers repeat the prompt. `secret: true` disables answer echo and prevents log
redraw from disclosing partial input. Login is a separate built-in dialogue
whose prompts, failure text and attempt limit are profile properties.

The generic candidate algorithm rejects revision conflicts. It is not intended
to claim the exact commit/merge/locking semantics of every NOS. In the example
Huawei profile, `return`/system `quit` explicitly discard pending changes; real
VRP's uncommitted-change confirmation is not yet reproduced.

## Session command history

Up/Down arrows select previously submitted commands. Up starts with the newest
entry, then moves to older entries; Down moves forward and restores the draft
that was being edited before the first Up. Reaching either end rings the bell
without changing the input. Selecting a line never executes it: press Enter to
submit it. Backspace, Ctrl-U, Tab and `?` work on the recalled input as usual.

History is owned by each logical CLI session, not by the device or username.
Even two shell channels of one SSH connection are independent. A new management
session starts empty. For a persistent console, reconnect preserves history
along with its authenticated CLI session; logout or reboot clears it.

The default capacity is 100 commands. Configure a limit from 0 to 1000:

```yaml
terminal:
  historySize: 100
```

Zero disables storage; when full, the oldest entry is dropped. Non-empty command
lines are stored on Enter, including rejected commands and repeated submissions,
with their original spelling and spacing. Blank lines, unsubmitted drafts,
help/completion/navigation keystrokes, login/password input and dialogue answers
are not entries. Commands that themselves contain sensitive arguments are not
automatically redacted; avoid putting real secrets into test profiles/sessions.
History is not added to the semantic trace or snapshot API and is not written to
a file.

Editing a recalled command does not modify its stored entry. Moving to another
history entry discards that temporary edit; returning past the newest entry
restores the original draft. Enter records the edited command as a new entry;
Ctrl-C clears the draft and navigation position without deleting history.

Both CSI (`ESC [ A/B`, also explicit count 1) and SS3 (`ESC O A/B`)
Up/Down sequences are supported, including sequences split between network reads.
Modified cursor keys and other unsupported CSI/SS3 sequences are consumed without
inserting their bytes into a command. History navigation is inactive during
boot, login, password entry, dialogues, pagination and running commands.
Character echo redraws the current prompt and selected line; line/no-echo modes
update the buffer without displaying it immediately. Background log redraw
preserves the selected input. The existing single-line editor/wrapping limits
still apply.

## Starlark configuration validation

An optional `validation` section defines an invariant of the complete device
configuration. Both example profiles enable unique, non-empty interface
`description` values through the shared file
`examples/gswitch/validators/unique-descriptions.star`:

```yaml
validation:
  file: validators/unique-descriptions.star
  maxSteps: 100000
```

Alternatively, put the Starlark source directly in the YAML profile:

```yaml
validation:
  starlark: |
    def validate(config):
        seen = {}
        interfaces = config.get("interfaces", {})
        for name in sorted(interfaces):
            description = interfaces[name].get("description", "")
            if not description:
                continue
            if description in seen:
                return "description %r is used by both %s and %s" % (description, seen[description], name)
            seen[description] = name
        return None
```

Exactly one of `starlark` and `file` is required. File paths use the same confined
profile filesystem as output fixtures; scripts are loaded/compiled once, not
re-read for every command. `validate(config)` must take one positional argument:

- Return `None` to accept.
- Return a non-empty string (up to 4096 bytes) to reject and explain why.
- Any interpreter exception, step exhaustion or other return type also rejects
  the operation with a visible Starlark error; it never silently accepts it.

The callback receives only the proposed complete configuration, not credentials,
transport objects or session arguments. Maps become Starlark dictionaries with
sorted string keys, lists become lists, and scalar types are preserved. The
copy and all module globals are recursively frozen. Scripts may create local
mutable collections such as `seen`, but cannot change the device's configuration
or persist side effects between validations.

### When checks run

- The initial state is checked during profile loading; invalid profiles fail
  before listeners are opened.
- In immediate mode, each `set`/`delete` action checks the proposed state before
  publishing it. A rejected action does not change running/startup or increment
  its revision; remaining actions of that command are skipped.
- Candidate edits may temporarily violate invariants. `commit` validates the
  entire candidate after checking the base revision. On rejection, running and
  startup remain unchanged, and the candidate stays available for correction
  or `abort`.
- `save` copies the already validated running state, not an uncommitted candidate.

Validation is atomic per state-changing action, not a rollback of earlier,
accepted actions in a multi-action immediate command. Use candidate/commit when
several edits must become visible together (for example, swapping descriptions).

CLI sessions stay connected after rejections. The default error is
`% Invalid input: MESSAGE`. A profile can override its format:

```yaml
errors:
  validation: "Error: {{ .Message }}\n"
```

This lets Cisco/Huawei client drivers detect the error using their existing
vendor-specific patterns. `Profile.ValidateConfiguration` is also available to
check rules directly in Go tests; intentional string rejections have the error
type `*emulator.ValidationError`, while interpreter errors do not.

The example rule ignores missing/empty descriptions and compares non-empty
strings exactly, including case and whitespace. It reports both interface names.
It is a **test policy**, not a claim that real IOS XE/VRP requires uniqueness.

### Execution limits

Each module initialization and each call has its own instruction budget:
100,000 steps by default, configurable with `maxSteps` up to 1,000,000. Source
is limited to 1 MiB. Imports via `load()` are disabled, no host I/O functions
are registered, `print()` output is discarded, and recursion/while extensions
are not enabled. A fresh interpreter thread is used for every check; compiled,
frozen functions can be shared across devices.

Validators run synchronously under the device state lock. These are trusted
profile scripts, **not an OS/process sandbox for hostile code**: instruction
budgets do not bound every builtin allocation or the duration of one native
builtin call. Keep expensive validation out of profiles and use process-level
resource isolation when running untrusted profiles.

## Cursor editing

The ASCII editor supports Left/Right, Home/End, Delete, Backspace, Ctrl-U and
CSI/SS3 cursor forms. Insert/delete works at the cursor; Enter submits the whole
buffer, not only its prefix. Tab and `?` use the grammar position before the
cursor. History restores the draft cursor as well as text; redraw logs and
console reconnect retain it. Unsupported/modified ANSI sequences are consumed,
not inserted. Cursor navigation/editing is disabled during passwords/dialogues,
paging and command execution. Password characters remain append-only and secret.

Wrapping-aware redraw clears bounded rows and restores the editing cursor. The
editor is not a full screen emulator: arbitrary raw event cursor controls and
lines scrolling beyond the viewport are not tracked perfectly. PTY-less sessions
preserve the previous single-line behavior.

## Boot, scenarios and asynchronous output

Profile `boot` and scenario `timeline` contain timed events relative to device
creation/reboot, not connection/login. Reboot clears old scheduled events and
reschedules these timelines. CLI availability and lifecycle are independent:
`ready` can permit login while lifecycle still says `booting`.

Event kinds are `raw`, `log`, `ready` (`text: "true"` or `"false"`) and
`lifecycle` (a state name), and `console-reset` (restart console CLI/login without
closing its transport). `console-reset` requires route `console`, with no text,
file or logging policy; emit accompanying messages as separate events. Sources are diagnostic labels, not a
complete vendor logging/severity implementation. Routes:

- `console`: persistent console lines, independent of monitor settings.
- `monitor`: sessions which enabled monitor output.
- `all`: every existing session.
- `session`: the triggering session; only valid in triggers.

Trigger names are `authenticated`, `login:password`, `command:COMMAND_ID` and
`checkpoint:NAME`. They can schedule an event using `after`. A zero-delay
checkpoint event is delivered before the next output action. `login:password`
fires on transition to password entry after username submission, not on prompt
redraw/reconnect; it never exposes the password to templates or trace.

Use `{op: require-lifecycle, value: operational, text: "Not ready\n"}` before
stateful actions to reject a command's remaining actions without disconnecting.
This checks at that action's execution time; it is not a security policy or a
continuous guard for later delayed actions. `.Lifecycle` is available to output
and prompt templates. Login readiness and command/service readiness stay separate.

Logging policies:

- `raw`: insert the log into the stream without restoring input.
- `redraw`: clear the current line and restore its prompt and visible input;
  an executing command is not given an extra prompt.
- `defer`: queue up to 64 messages until an interaction completes; overflow is
  recorded as `log-dropped`. It is not a device-wide unbounded queue.

Raw output preserves exact bytes. Log text gets terminal newline conversion
and a trailing newline. The IOS fixture demonstrates the raw path; the Aruba replay is derived from
ticket text and is not an exact binary boot capture.

## Current limits

This is a vertical prototype, not the entire research design:

- Only the included command subsets; no automatic import of vendor CLI trees.
- No shell or RouterOS grammar, Starlark command handlers, YANG/CEL or profile inheritance.
- No RFC2217, Telnet in profile mode, bootloader commands, BREAK or serial timing.
- No gRPC control API, persistent configuration files or raw transcript recorder; the HTTP API and semantic trace are test-only.
- ASCII editor with CR/LF/CRLF, cursor insertion/deletion, Home/End, Ctrl-U/C/D,
  Tab, `?` and Up/Down history. No Ctrl-Z, UTF-8 input, wide-glyph rendering or full viewport/scrollback model.
- Pager counts soft wraps/code points, not wide/combining terminal cells.
- SSH implements PTY character dimensions and resize, but not terminal mode flags,
  pixels, exec, subsystems, forwarding or keyboard-interactive auth.
- The IOS sample's terminal-width command is an explicit compatibility no-op.
- Input during a delayed command is discarded except Ctrl-C; no typeahead queue.
- The built-in login uses one configured test account; no external AAA backend.
- Beyond explicit lifecycle guards, no individual-service readiness model,
  configuration schema, interface inventory validation or ordered ACL/list mutations.
- A console has one owner and no historical-output buffer.

## Verification

```sh
go test ./pkg/gswitch/... ./cmd/gswitch
go test -race ./pkg/gswitch/... ./cmd/gswitch
go vet ./pkg/gswitch/... ./cmd/gswitch
```

Tests cover grammar/errors, strict profile loading, state isolation, candidate
conflicts, persistence across reboot, exact fixtures, boot/login overlap,
password-safe redraw, async command checkpoints, cancellation, dialogue/pager,
fragmented input, slow consumers, reconnect and shutdown. Integration tests use
the real Gnetcli Cisco/Huawei/Aruba SSH drivers and a raw TCP console. A process test
starts the opt-in CLI with a noisy scenario and validates graceful termination.
Starlark tests cover immediate/commit rejections, unchanged revisions/state,
read-only input/globals, script errors, limits, typed values and shared profiles.

Completion tests cover shared parser precedence, modes, common prefixes, typed
arguments, unchanged descriptions, non-execution, echo/input limits, log redraw,
console reconnect, fragmented input and an SSH shell.

History tests cover independent sessions/SSH channels, draft restoration, editing,
limits, login/dialogue exclusion, logout/reboot/reconnect, echo, log redraw and
fragmented CSI/SS3 arrow sequences.
