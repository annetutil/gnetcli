# GOP 4 – Recovering Command Echo After a Transient Prompt

- **Author:** Reydant
- **Status:** Accepted
- **Type:** Standards Track
- **Topic:** Core
- **Created:** 2026-08-12
- **Last-Modified:** 2026-08-12

## Abstract

Some interactive CLIs redraw their prompt while they receive a command. If a transport read ends at that redraw, `GenericExecute` can match the prompt before it has observed the complete command echo and return an `EchoReadException`.

This GOP adds recovery for that condition. When a prompt is matched before the command echo, gnetcli preserves the consumed bytes by prepending them to the connector's unread buffer, then continues reading. This lets the normal echo matcher evaluate the preserved bytes together with later terminal output.

## Motivation

RouterOS redraws the command line while each character is being entered. A stream can contain data such as:

```
\r[robot@router] > /user exp
```

At a network-read boundary, the `\r[robot@router] > ` part is indistinguishable from a final prompt. The command echo is incomplete, however, and more redraw data or the submitted command echo may arrive later.

Previously, matching this prompt before the expected echo caused command execution to fail immediately with `echo read error`.

## Failure dialog from RouterOS logs

The following is a shortened and sanitized dialog from the original failure. Runs of terminal-padding spaces are replaced with `…`; `\x1b[K` clears the rest of the line.

```text
client -> /user export\n

device -> \r[robot@router] > /user exp\r\r[robot@router] > <space>
                                         ^ prompt matcher stops here

device -> \x1b[K\r[robot@router] > /user ex\r\r[robot@router] > /user ex…
device -> \x1b[K\r[robot@router] > /user exp\r\r[robot@router] > /user exp…
```

The first read ends immediately after a redraw prompt. At that point `/user exp` is only a partial line, so it cannot match the expected `/user export\r\n` echo. Before GOP 4, `GenericExecute` returned `EchoReadException` at the marked prompt and never read the later redraw data.

## Proposal

`streamer.Connector` provides:

```go
PrependBuffer(data []byte) error
```

Each connector prepends `data` to its internal unread buffer. The next `Read` or `ReadTo` consumes these bytes before reading from the network.

During `GenericExecute`:

1. gnetcli writes the command and waits for echo, prompt, pager, question, login, and callbacks as usual.
2. If the complete echo is matched, execution proceeds normally.
3. If a prompt is matched before echo, gnetcli attempts to reconstruct the echo from the bytes before that prompt.
4. If reconstruction fails, gnetcli records the associated `EchoReadException`, prepends those bytes through `PrependBuffer`, and continues reading with the same expression set.
5. If the complete echo later matches, normal execution resumes. If reading ends or times out first, gnetcli returns the saved echo error; a device error detected in a read timeout still takes precedence.

The behavior applies to all `streamer.Connector` implementations. SSH returns an error if `PrependBuffer` is called before its shell session is initialized; `GenericExecute` propagates that failure.

## Compatibility

- Normal command execution is unchanged when echo is received before prompt.
- `Read(n)` retains its existing meaning: it returns immediately when at least `n` bytes are already buffered, including prepended bytes. This is required for protocol readers such as NETCONF chunk framing.
- `PrependBuffer` is a new method on the public `streamer.Connector` interface. Third-party connector implementations must add it.

## Rationale

The connector already owns unread transport bytes. Returning consumed pre-prompt data to that buffer preserves the existing command-execution matcher order and avoids adding a separate pre-echo state machine to `GenericExecute`.

The alternative of disabling prompt matching until echo is found avoids the premature match, but changes matching behavior and requires managing separate matcher states. Buffer restoration instead retries with the original expressions and preserves the normal execution flow.

## Alternatives

### Explicit pre-echo state machine

`GenericExecute` could track separate phases such as `awaitEchoWithPrompt`, `awaitEchoWithoutPrompt`, and `afterEcho`. After a prompt arrives before echo, it would rebuild its expression list without the prompt matcher; after echo is found, it would rebuild the normal prompt-first matcher.

This makes the execution phases explicit, but it adds state transitions, duplicates matcher construction, and requires care to restore the correct matcher after every transition, including questions and callbacks. It also changes the expressions that are active during execution.

The accepted approach keeps the existing matcher set and returns consumed bytes to the transport's unread buffer. The next read evaluates the original expressions against the complete reconstructed stream, so the recovery logic stays localized to the prompt-before-echo case.

## Testing Plan

- RouterOS mock tests split a redraw sequence at a prompt boundary and verify that the complete command echo is later recognized.
- Streamer tests verify that buffered data is consumed before network data and that `Read(n)` preserves its total-buffer size semantics.

## References

- `pkg/device/genericcli/genericcli.go` — `GenericExecute` echo recovery.
- `pkg/streamer/streamer.go` — `Connector` and unread-buffer handling.
- `pkg/device/ros/device_mock_test.go` — RouterOS redraw regression test.
