# GOP 2 – Login Expression Detection in Execution Loop for Console Streamers

- **Author:** The GOP Editors
- **Status:** Accepted
- **Type:** Standards Track
- **Topic:** Drivers/Transports
- **Created:** 2026-03-15
- **Last-Modified:** 2026-03-15

## Abstract

When using a console streamer, executing a logout command (`exit`, `quit`) does not cause an EOF as it does with SSH or Telnet. Instead the device drops back to the login screen, sending a login prompt (e.g., `Username:`). This GOP introduces an optional check for the login expression inside the `GenericExecute` command execution loop. When the streamer reports the `LoginInsteadEOF` feature, a matched login expression during command execution is treated as an EOF, allowing graceful session termination.

## Motivation

SSH and Telnet transports close the underlying connection when the user logs out, producing an EOF that gnetcli handles naturally. Console connections (serial/RS-232) are persistent physical links — there is no connection to close. After `exit` or `quit`, the device simply returns to its login prompt:

```
write "exit\n"
read  "exit\r\n"          ← echo
read  "Username: "        ← login prompt instead of EOF
```

Without this change, `GenericExecute` returns read error.

## Goals

- Detect logout on console connections by recognizing the login prompt during command execution.
- Translate a login prompt match into an `EOFException`, keeping the error handling consistent with SSH/Telnet EOF behavior.
- Keep this behavior opt-in so that SSH and Telnet streamers are not affected.

## Non-Goals

- Automatic re-login after logout on console. This is a higher-level concern.
- Changes to the login procedure itself.

## Proposal

### Streamer Feature Flag

A new feature constant `LoginInsteadEOF` is added to the `streamer` package:

```go
const LoginInsteadEOF Const
```

Console streamers return `true` for `HasFeature(LoginInsteadEOF)`. SSH and Telnet streamers continue to return `false`.

### Execution Loop Change

In `GenericExecute`, when building the named expression list for the read loop, the login expression is conditionally appended:

```go
if connector.HasFeature(streamer.LoginInsteadEOF) && cli.login != nil {
    checkExprs = append(checkExprs, expr.NamedExpr{
        Name: loginExprName,
        Exprs: []expr.Expr{cli.login},
    })
}
```

When the login expression matches during the execution loop, the behavior depends on the feature flag:

```go
} else if matchName == loginExprName {
    if connector.HasFeature(streamer.LoginInsteadEOF) {
        return nil, streamer.ThrowEOFException(match.GetMatched())
    }
    return nil, fmt.Errorf("caught login expression during execution")
}
```

### Compatibility

- **SSH/Telnet streamers**: unaffected — `HasFeature(LoginInsteadEOF)` returns `false`, login expression is never added to the execution loop.
- **Console streamer**: gains the ability to properly detect logout via login prompt.
- **Existing device drivers**: no changes required unless they use console transport and need logout detection. In that case they must already have login expressions configured via `WithLoginExprs()`.

## Rationale

Using the `HasFeature` mechanism keeps the change scoped to streamers that need it. The login expression is already available in `GenericCLI` (set via `WithLoginExprs`), so no additional configuration is required — only the streamer must declare the feature.

Translating the match into `EOFException` (rather than a new error type) ensures that upstream code handling EOF from SSH/Telnet works identically for console logout.

## Alternatives

1. **Do nothing** — console logout commands would time out, requiring workarounds in user code.
2. **Always check login expression in the execution loop** — risks false positives on SSH/Telnet if the output contains text matching the login pattern.
3. **New dedicated expression type for logout detection** — adds complexity without clear benefit, since the login expression already serves this purpose on console.

## Testing Plan

Tests are located in `pkg/device/genericcli/gop2_login_instead_eof_test.go`:

- `TestExitCmdLoginPromptOnConsole` — verifies that executing `exit` on a `LoginInsteadEOF` connector returns an `EOFException` when the device responds with a login prompt.
- `TestExitCmdLoginPromptOnSSH` — verifies that on a standard SSH connector (no `LoginInsteadEOF`), the login expression is not checked in the execution loop.
- `TestCmdThenExitOnConsole` — verifies that a regular command executes normally, followed by `exit` producing an `EOFException`.

## References

- `pkg/streamer/streamer.go` — `LoginInsteadEOF` constant.
- `pkg/streamer/console/console.go` — `HasFeature` returns `true` for `LoginInsteadEOF`.
- `pkg/device/genericcli/genericcli.go` — `GenericExecute` changes.
