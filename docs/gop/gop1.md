# GOP 1 – Core Primitives

- **Author:** The GOP Editors
- **Status:** Active
- **Type:** Informational
- **Topic:** Core
- **Created:** 2026-03-15
- **Last-Modified:** 2026-03-15

## Abstract

This document defines the core primitives of `GenericCLI` — the regex-based device driver implementation provided by gnetcli. The project supports different approaches to device interaction (including custom `Device` interface implementations and protocol-specific drivers like NETCONF), but the majority of built-in drivers are built on `GenericCLI`. Each such driver is described as a composition of primitives — regular-expression-based matchers that identify meaningful parts of the terminal data stream. This GOP covers only the `GenericCLI` primitives; other device abstractions are out of scope.

## Motivation

Gnetcli provides several ways to implement the `Device` interface: a fully custom implementation, protocol-specific drivers (e.g., NETCONF), and `GenericCLI` — a universal regex-driven engine. `GenericCLI` is the most common approach and is used by the majority of built-in drivers (Huawei, Cisco, Juniper, Arista, etc.). It works by pattern-matching the raw byte stream received from a device against a known set of expressions. Each expression type has a distinct role in the command execution lifecycle: detecting prompts, recognizing errors, handling pagination, answering interactive questions, and so on.

Without a clear reference document, contributors must reverse-engineer the meaning of each primitive from code. This GOP serves as the canonical reference.

## Terminology

- **Expr** — an object implementing the `expr.Expr` interface. It wraps one or more compiled regular expressions and exposes a `Match(data []byte) (*MatchRes, bool)` method. Named capture groups in the regex are accessible through `MatchRes.GroupDict`.
- **GenericCLI** — the struct (in `pkg/device/genericcli`) that holds all primitive expressions and orchestrates the read/write loop against a device.
- **Connector** — a transport-level abstraction (SSH, Telnet, console) that provides raw read/write access to a device session.

## Primitives

### 1. Prompt Expression

| Attribute | Value |
|---|---|
| Required | **Yes** |
| GenericCLI field | `prompt` |
| YAML key | `prompt_expression` |

The prompt expression is the single most important primitive. It identifies the device's command-line prompt — the string that signals "the device is ready to accept a new command". Every command execution cycle ends when the prompt expression matches the incoming data.

The expression **must be as specific as possible** to avoid false positives against command output. Because data arrives incrementally (sometimes character by character), the expression should not rely on being evaluated against a complete line.

**Best practices:**

- Anchor the expression to follow a newline (`\r\n` or `\n`) or `^` to avoid matching substrings inside command output.
- Use named capture group `(?P<prompt>...)` so the matched prompt value can be extracted.
- Cover all prompt modes: user, admin/enable, configuration, configuration sub-modes.
- `NewSimpleExprLast200()` is recommended so matching is only attempted against the last 200 bytes — a significant performance optimization for long outputs.

**Examples:**

```
# Huawei
(\r\n|^)(?P<prompt>(<[/\w\-.:]+>|\[[~*]?[/\w\-.:]+\]))$

# Cisco IOS
(?P<prompt>[\w\-.:/]+(\(conf(ig)?(-[^)]+)*\))?)(>|#)$

# Juniper
(\r\n({master}\[edit\]|{master}|{master:\d}|\[edit\]))?\r\n(?P<prompt>[\w\-.]+@[\w\-.]+[>#]) $
```

### 2. Error Expression

| Attribute | Value |
|---|---|
| Required | **Yes** (stub `$.^` if none) |
| GenericCLI field | `error` |
| YAML key | `error_expression` |

The error expression matches error messages in the command output. After a command completes (prompt is seen), the entire output is checked against this expression. If it matches, the command result receives `Status = 1` and the output is placed in the error field of `CmdRes`.

It is also checked during read-timeout situations — if a timeout occurs, gnetcli inspects the last read data for an error match, providing a more descriptive failure than a raw timeout.

If a device has no detectable error patterns, use the impossible-to-match stub `$.^`.

**Examples:**

```
# Huawei
(\^\r\nError: (?P<error>.+) at '\^' position\.|Error: You do not have permission ...)

# Cisco IOS
(\r\n% Invalid input detected at '\^' marker.\r\n|...)

# Juniper
(\n|^)(syntax error\.|unknown command\.|error: ...)\r\n
```

### 3. Pager Expression

| Attribute | Value |
|---|---|
| Required | No |
| GenericCLI field | `pager` |
| YAML key | `pager_expression` |
| Option constructor | `WithPager(expr)` |

Many devices paginate long output, displaying a "More" prompt and waiting for a keypress. The pager expression detects this prompt. When matched, `GenericCLI` automatically sends a space character (` `) to advance to the next page and continues reading.

The optional named capture group `store` allows preserving parts of the matched text (typically the preceding newline) in the output buffer, so that the final result has correct line breaks.

**Examples:**

```
# Huawei
(?P<store>(\r\n|\n))?  ---- More ----$

# Cisco IOS
\r\n --More-- $

# Juniper
\n---\(more( \d+%)?\)---$
```

### 4. Question Expression

| Attribute | Value |
|---|---|
| Required | No |
| GenericCLI field | `question` |
| YAML key | `question_expression` |
| Option constructor | `WithQuestion(expr)` |

Some commands require interactive confirmation (e.g., "Reboot the system? [yes,no]"). The question expression detects such prompts. When matched during command execution:

1. The command's answer list is consulted (`cmd.Answer`). Answers can be specified as exact strings or regex patterns (prefixed and suffixed with `/`).
2. If a matching answer is found, it is sent to the device.
3. If no answer is found, a `QuestionException` is raised.

Questions can also appear during the login/connect phase (before the first prompt), where they are handled by `defaultAnswers` set via `WithAnswers()`.

**Examples:**

```
# Huawei
(?P<question>.*(privilege level|Continue)\s?\?\s?\[Y/N\]:?)$

# Cisco IOS
\n(?P<question>.*Continue\? \[Y/N\]:)$

# YAML-configured device
\n.+\? \[yes,no\] \(no\) $
```

### 5. Login Expression

| Attribute | Value |
|---|---|
| Required | No (only for manual auth) |
| GenericCLI field | `login` |
| Option constructor | `WithLoginExprs(login, password, passwordError)` |

The login expression matches the username prompt during authentication. It is only used when the transport does **not** provide its own authentication mechanism (e.g., Telnet, serial console) or when `WithManualAuth()` is set.

When matched, gnetcli retrieves the username from the configured credentials and sends it followed by a newline.

**Examples:**

```
# Huawei
.*Username:$

# Cisco IOS
.*Username:\s?$
```

### 6. Password Expression

| Attribute | Value |
|---|---|
| Required | No (only for manual auth) |
| GenericCLI field | `password` |
| Option constructor | `WithLoginExprs(login, password, passwordError)` |

The password expression matches the password prompt during manual authentication. When matched, gnetcli sends the next password from the credentials password list followed by a newline. Multiple passwords are tried sequentially.

**Examples:**

```
# Huawei
(\r\n|^)Password:$

# Cisco IOS
.*Password:\s?$
```

### 7. Password Error Expression

| Attribute | Value |
|---|---|
| Required | No (only for manual auth) |
| GenericCLI field | `passwordError` |
| Option constructor | `WithLoginExprs(login, password, passwordError)` |

The password error expression detects authentication failure during the manual login procedure. When all passwords have been exhausted and the prompt has not appeared, an `AuthException` is raised.

When a password error is matched between password attempts, the login loop continues with the next password.

**Examples:**

```
# Huawei
.*(Error: Username or password error\.\r\n|.*Authentication fail...)

# Cisco IOS
\n\% Authentication failed(\r\n|\n)
```

### 8. Echo

| Attribute | Value |
|---|---|
| Required | Automatic |
| GenericCLI field | `echoExprFormat` |
| Option constructor | `WithEchoExprFn(fn)` |

When a command is sent to a device, the terminal echoes it back. Gnetcli must detect and strip this echo so it does not appear in the command result. By default, the echo expression is generated automatically:

```
<regexp.QuoteMeta(command)> + (\r\n|\n)
```

Some devices modify the echo (add trailing spaces, insert ANSI escape sequences, add extra carriage returns). The echo expression generator can be overridden with `WithEchoExprFn()`. Predefined variants are available as YAML features:

| Feature | Pattern | Use case |
|---|---|---|
| `spaces_after_echo` | `<cmd> *\r\n` | Device appends spaces after command echo (e.g., Juniper) |
| `extra_cr_echo` | `<cmd>\r*\n` | Device sends extra `\r` characters |
| `ansi_esc_seq_echo` | `<cmd>(?:\x1b\[...)+\r\n` | Device injects ANSI escape sequences into echo |

If echo detection fails, an `EchoReadException` is raised.

### 9. Auto Commands

| Attribute | Value |
|---|---|
| Required | No |
| GenericCLI field | `autoCommands` |
| YAML key | feature `autocmd` |
| Option constructor | `WithAutoCommands(cmds)` |

Auto commands are executed immediately after a successful login, before any user commands. They are typically used to configure the terminal session:

- Disable pagination (`terminal length 0`, `screen-length 0 temporary`).
- Set terminal width (`terminal width 0`, `set cli screen-width 1024`).
- Disable logging to the terminal (`undo terminal monitor`, `terminal no monitor`).
- Disable auto-completion side effects (`set cli complete-on-space off`).

Each auto command is a regular `cmd.Cmd` and goes through the full execution pipeline (echo reading, prompt detection, error checking). Commands can be marked with `cmd.WithErrorIgnore()` to tolerate failures.

### 10. Login Callbacks

| Attribute | Value |
|---|---|
| Required | No |
| GenericCLI field | `loginCB` |
| Option constructor | `WithLoginCallbacks(cb)` / `WithAdditionalLoginCallbacks(cb)` |

Login callbacks handle unexpected messages that appear during the connection phase (after transport connects but before the first prompt). Each callback is an `ExprCallback` — a pair of a regex pattern and a response to send when matched.

A common use case is dismissing MOTD (Message of the Day) banners or system notifications that appear at login, like `*Mar 1 00:04:21.011: %Login: Someone logged in`.

### 11. Default Answers

| Attribute | Value |
|---|---|
| Required | No |
| GenericCLI field | `defaultAnswers` |
| Option constructor | `WithAnswers(answers)` |

Default answers handle questions that appear during the login/connect phase (before the first prompt). When a question expression matches during `connectCLI`, the default answers list is consulted. If a matching answer is found, it is sent; otherwise a `QuestionException` is thrown.

This is distinct from per-command answers (set via `cmd.WithAddAnswers()`), which are used during command execution.

## Expr System

All primitives are built on the `expr.Expr` interface from `pkg/expr`:

```go
type Expr interface {
    Match(data []byte) (mRes *MatchRes, ok bool)
    Repr() string
}
```

### Builders

| Builder | Behavior |
|---|---|
| `NewSimpleExpr()` | Matches against the entire data buffer |
| `NewSimpleExprLast(n)` | Matches against only the last *n* bytes — important for performance on large outputs |
| `NewSimpleExprLast200()` | Shorthand for `NewSimpleExprLast(200)` — the recommended default for prompt/error/question expressions |
| `NewSimpleExprFirst(n)` | Matches against only the first *n* bytes |

### Construction Methods

| Method | Description |
|---|---|
| `FromPattern(pattern)` | Compiles a regex string; panics on invalid pattern |
| `FromPatternAndExclude(pattern, exclude)` | Matches `pattern` but rejects if `exclude` also matches |
| `FromRegex(regex)` | Uses a pre-compiled `*regexp.Regexp` |
| `FromRegexAndExclude(regex, exclude)` | Combines match and exclude from pre-compiled regexes |

### Expression Lists

During command execution, multiple expressions must be checked simultaneously (prompt, pager, question, echo). The `ExprList` interface groups them:

- `NewSimpleExprListNamedOrdered([]NamedExpr)` — ordered list with named entries. Used in the main execution loop to check echo, prompt, pager, and question in priority order.
- `NewSimpleExprListNamed(map[string][]Expr)` — unordered named list. Used during the auto-login phase.

Each entry has a name (e.g., `"prompt"`, `"pager"`, `"question"`, `"echo"`) so `GenericExecute` can dispatch on the match result.

## Command Execution Lifecycle

To understand how the primitives work together, here is the high-level flow of `GenericExecute`:

1. **Write command** — the command text and a newline are sent to the device.
2. **Read echo** — wait for data matching the echo expression. Strip it from the result.
3. **Read loop** — repeatedly read data and match against (in order):
   - **Echo** (until consumed) — stripped from output.
   - **Prompt** — signals command completion. Output before the match is the command result.
   - **Pager** — send space, continue reading.
   - **Question** — consult answer list, send answer, continue reading.
   - **Callback** — send callback response, continue reading.
4. **Error check** — scan the collected output against the error expression.
5. **Terminal parsing** — strip terminal control sequences and normalize newlines.
6. **Return** — `CmdRes` with output, error text, and status code.

## YAML Device Configuration

Devices can be defined via YAML configuration files (loaded by the `devconf` package) without writing Go code:

```yaml
devices:
  - name: myvendor
    prompt_expression: '\n(?P<prompt>[\w]+@[\w-]+[>#]) $'
    error_expression: '\^\r\nunknown command\.\r\n'
    pager_expression: '---\(more( \d+%)?\)---'
    question_expression: '\n.+\? \[yes,no\] \(no\) $'
    features:
      - spaces_after_echo
      - autocmd:
          - set cli screen-length 0
          - set cli screen-width 1024
    tests:
      prompt_expression_variants:
        - "\r\nuser@device> "
      error_expression_variants:
        - "  ^\r\nunknown command.\r\n"
      pager_expression_variants:
        - "---(more)---"
        - "---(more 76%)---"
```

Available features: `spaces_after_echo`, `extra_cr_echo`, `ansi_esc_seq_echo`, `autocmd`.

## Summary Table

| # | Primitive | Required | Field | YAML key | When checked |
|---|---|---|---|---|---|
| 1 | Prompt | Yes | `prompt` | `prompt_expression` | Execution loop, login |
| 2 | Error | Yes | `error` | `error_expression` | After command output, on timeout |
| 3 | Pager | No | `pager` | `pager_expression` | Execution loop |
| 4 | Question | No | `question` | `question_expression` | Execution loop, login |
| 5 | Login | No | `login` | — | Manual auth only |
| 6 | Password | No | `password` | — | Manual auth only |
| 7 | Password Error | No | `passwordError` | — | Manual auth only |
| 8 | Echo | Auto | `echoExprFormat` | features | Execution loop |
| 9 | Auto Commands | No | `autoCommands` | `autocmd` feature | After login |
| 10 | Login Callbacks | No | `loginCB` | — | During login |
| 11 | Default Answers | No | `defaultAnswers` | — | During login |

## References

- `pkg/device/genericcli/genericcli.go` — `GenericCLI` struct and `GenericExecute` function.
- `pkg/expr/` — `Expr` interface, builders, and expression lists.
- `pkg/devconf/devconf.go` — YAML device configuration loader.
- `docs/architecture.md` — architectural overview and expression examples.
- `docs/new_device.md` — step-by-step guide for creating a new device driver.
