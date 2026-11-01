# Gnetcli CLI drivers

Paths below are relative to the Gnetcli root. Verify symbols in the current
checkout.

## Source map

- `docs/architecture.md`, `docs/new_device.md`: CLI design and byte-level discovery.
- `docs/gop/gop1.md`: primitives; `gop2.md`: console login instead of EOF;
  `gop3.md`: repeated questions; `gop4.md`: prompt redraw before a complete echo.
- `pkg/device/device.go`: the `device.Device` contract, including `ExecuteCtx`.
- `pkg/device/genericcli/genericcli.go`: options, deferred `connectCLI`, execution loop.
- `pkg/cmd/cmd.go`: `CmdRes`, questions, read/command timeouts, and error handlers.
- `pkg/devconf/devconf.go`: YAML schema and `InitDefaultDeviceMapping`.
- `pkg/device/huawei/huawei.go`, `huawei_test.go`, `huawei_mock_test.go`,
  `huawei_mock_console_test.go`: normal/console login and negative regex cases.
- `pkg/device/nxos/device.go`, `device_mock_test.go`: unusual CR sequences in echo.
- `pkg/device/juniper/device.go`, `device_mock_test.go`: spaces after echo and pagers.
- `pkg/device/ros/device.go`, `device_mock_test.go`: complex redraw behavior;
  do not copy vendor-specific callbacks to another CLI without evidence.

## Choose a Go driver or YAML

For permanent built-in support, add `pkg/device/<vendor>/` using the closest CLI
as a model. If CLI/server selection by `devtype` is required, add an import and
an entry in `pkg/devconf/devconf.go:InitDefaultDeviceMapping` using
`GenericCLIWrapper`. Library-only usage does not require global registration.

An external YAML file is suitable for a prototype using standard primitives:
`devices[].name`, `prompt_expression`, `error_expression`, `pager_expression`,
`question_expression`, `features`, and `tests`. Do not replace a requested Go
driver with YAML; custom login, options, or complex behavior require code.

In the current `DevConf.Make`, the auto-command feature key is **`autocmds`**,
not the `autocmd` shown in older `docs/new_device.md` examples. YAML uses ordinary
quotes, not Go backticks. External YAML cannot override a built-in name:
`InitDeviceMapping` rejects duplicates. Do not enable `any_echo` as a general fix:
it treats the first line as echo and can hide data loss.

Constructor outline:

```go
func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
    cli := genericcli.MakeGenericCLI(
        expr.NewSimpleExprLast200().FromPattern(promptExpression),
        expr.NewSimpleExprLast200().FromPattern(errorExpression),
        // Add WithPager/WithQuestion/WithLoginExprs based on the observed CLI.
    )
    return genericcli.MakeGenericDevice(cli, connector, opts...)
}
```

This is an outline, not a complete driver: derive expressions from actual data.
Constructors commonly return a value; when a `device.Device` is required, return
`&dev`, as existing wrappers and mock tests do. For a different protocol, consult
the current `device.Device`, not an outdated copy in the documentation.

## Primitives and invariants

1. **Prompt.** Distinguish operational/admin/config/subconfig and dirty modes.
   Match a real boundary, not any `>`/`#` inside output. `$` means the end of the
   current buffer, not the end of a future network line. Data may arrive one
   character at a time: test false prompts in partial echo. Restrict hostname/path
   patterns so they cannot consume CR/LF. Define the structure of an intentionally
   multiline prompt explicitly. Use `(?P<prompt>...)` as existing drivers do.
2. **Regex window.** `NewSimpleExprLast200` is common, not mandatory everywhere:
   RouterOS uses larger windows. A short window can truncate a long prompt/error;
   test the actual `expr.Expr`, not just a raw regexp. For a `store` capture, check
   newline preservation: the loop returns that group to output after a
   prompt/pager match.
3. **Echo.** The default expression uses `regexp.QuoteMeta(command.Value())` and
   a newline. Use `WithEchoExprFn` for confirmed extra spaces/CR; quote the command
   rather than interpreting it as a regexp or replacing it with `.*`. The current
   code restores the buffer for prompt-before-echo. Do not duplicate core logic
   in a driver without a reproduction and demonstrated need.
4. **Errors.** Cover unknown/incomplete commands, wrong arguments, permission
   errors, and negative cases containing the word error in ordinary output.
   A completed command with a CLI error normally returns `err == nil`,
   `Status() == 1`, data in `Error()`, and an empty `Output()`.
   Transport/login/timeout/cancellation failures return a separate Go error.
   Do not conflate these paths.
5. **Pager.** If present in the dialog, add `WithPager` and test percentage,
   ANSI, and pager-erasure variants. The current `GenericExecute` answers a pager
   with a **space**, not the Enter shown in an older diagram. If the device needs
   another key, changing a regexp does not change the response: investigate an
   appropriate mechanism. Preserve both pages without the marker or lost data.
6. **Questions.** `WithQuestion` recognizes a question; it does not authorize
   answering yes. Supply operation-specific answers with
   `cmd.WithAnswers`/`WithAddAnswers` and
   `cmd.NewAnswerWithNL`/`NewAnswer(..., notSendNL)`. In `cmd.Answer`, a `/.../`
   string is a regexp; other strings are matched exactly. Preserve repeated
   question limits rather than retrying forever.
7. **Login/console.** SSH often provides `AutoLogin`; telnet/console may need
   `WithLoginExprs`, callbacks, or `WithManualAuth`. Do not force manual auth on
   every transport. Use `WithLoginEOFExpr` for a confirmed logout marker:
   execution treats it as EOF on a `LoginInsteadEOF` connector, not as a successful
   prompt. Test invalid passwords and unexpected password-change prompts.
8. **Initialization.** `WithAutoCommands` configures session-local terminal
   behavior; it is not configuration persistence. `cmd.WithErrorIgnore()` is
   appropriate for an optional unsupported terminal command, not for hiding
   user-command failures. Enable `WithTerminalParams`/`WithWriteNewLine`/SFTP
   because the device needs them, not because a copied driver had them.
9. **Lifecycle.** `Connect(ctx)` initializes the connector; CLI login/autocommands
   are deferred until the first `ExecuteCtx`. The current connect deadline limits
   `connectCLI`, not the ordinary command. Distinguish connect timeout,
   `WithReadTimeout`, `WithCmdTimeout`, and the caller's context; preserve
   cancellation.

## Verification

For regexes, `pkg/testutils/expr.go` provides `ExprTester`, `ExprTesterFalse`,
and `ExprTesterExtended`, which can check the prefix before a match. The helper
uses the full input by default; also test the production matching window.

For behavior, use `pkg/testutils/mock`, not `internal/mock` from older docs:
`m.Send`, `m.Expect`, `m.SendEcho`, and `m.Close`.
Use `RunDialogWithDefaultCreds` for simple output checks, `RunDialogCMD` for a
configured `cmd.Cmd`, and `RunCmd` or a custom harness through the public `Device`
for status/error/context checks. The ordinary `RunDialogCMD` checks output but
does not independently guarantee the correct status. Verify helper names rather
than copying the nonexistent `RunErrorDialog` from the docs.

Cover the selected capabilities:

- Success and exact output/status/error, including an empty result.
- A CLI error followed by a successful command in the same session.
- Prompt-like output and hostname-like text spanning multiple lines.
- Echo/response/prompt arriving together and separately; device-specific redraw.
  Multiple `m.Send` calls do not guarantee transport fragmentation: use a
  deterministic harness or synchronization for regression tests.
- Multiple pages, questions with/without an answer, and repeated-question limits.
- Login failure, console logout, and cancellation when those paths change.
- Availability of the new `devtype` through the mapping, if added.

Run from the Gnetcli root; replace `<vendor>` with the actual directory:

```sh
gofmt -w pkg/device/<vendor>/*.go
go test -mod=readonly -count=1 ./pkg/device/<vendor>
go test -mod=readonly -race -count=1 ./pkg/device/<vendor> ./pkg/device/genericcli ./pkg/devconf
go test -mod=readonly ./...
```

For core changes, include the relevant `pkg/expr`, `pkg/terminal`, and
`pkg/streamer/...` packages. Full-project race tests correspond to `make testrace`.
Format changed mapping files separately. For YAML, also run positive cases
without network access:

```sh
go run -mod=readonly ./cmd/cli -dev-conf /path/to/vendor.yaml -test
```

YAML variants do not replace negative and mock-dialog tests. Read the Go version
from the current `go.mod` and CI. `make all` includes protobuf codegen/Docker and
is not a mandatory first step for vendor-only changes. If broader tests fail on
unchanged dependencies, report the exact error and the focused tests that passed.
Do not claim full success or update dependencies without a separate justification.
Hardware validation and releases are separate from local tests.
