package genericcli_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type contextConnector struct {
	streamer.Connector
	reads    int
	onPrompt func()
	writes   []string
	read     func(context.Context, expr.Expr) (streamer.ReadRes, error)
}

func (c *contextConnector) Init(context.Context) error { return nil }
func (c *contextConnector) SetCredentialsInterceptor(func(credentials.Credentials) credentials.Credentials) {
}
func (c *contextConnector) HasFeature(f streamer.Const) bool { return f == streamer.AutoLogin }
func (c *contextConnector) Close()                           {}
func (c *contextConnector) Write(data []byte) error {
	c.writes = append(c.writes, string(data))
	return nil
}
func (c *contextConnector) SetReadTimeout(time.Duration) time.Duration { return time.Second }
func (c *contextConnector) ReadTo(ctx context.Context, pattern expr.Expr) (streamer.ReadRes, error) {
	c.reads++
	if c.reads == 1 {
		data := []byte("lab#")
		match, ok := pattern.Match(data)
		if !ok {
			return nil, errors.New("initial prompt did not match")
		}
		if c.onPrompt != nil {
			c.onPrompt()
		}
		return streamer.NewReadResImpl(nil, nil, match.GroupDict, data, match.PatternNo), nil
	}
	return c.read(ctx, pattern)
}
func contextDevice(t *testing.T, c *contextConnector, opts ...genericcli.GenericCLIOption) *genericcli.GenericDevice {
	t.Helper()
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExpr().FromPattern(`lab#$`), expr.NewSimpleExpr().FromPattern(`^ERROR`), opts...)
	dev := genericcli.MakeGenericDevice(cli, c)
	require.NoError(t, dev.Connect(t.Context()))
	t.Cleanup(dev.Close)
	return &dev
}

func TestExecuteCtxCancelsCommandAndAutoCommands(t *testing.T) {
	for _, auto := range []bool{false, true} {
		name := "command"
		if auto {
			name = "auto commands"
		}
		t.Run(name, func(t *testing.T) {
			reading := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			c := &contextConnector{read: func(ctx context.Context, _ expr.Expr) (streamer.ReadRes, error) {
				close(reading)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
					return nil, errors.New("test cleanup")
				}
			}}
			var opts []genericcli.GenericCLIOption
			if auto {
				opts = append(opts, genericcli.WithAutoCommands([]cmd.Cmd{cmd.NewCmd("setup"), cmd.NewCmd("never")}))
			}
			dev := contextDevice(t, c, opts...)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := dev.ExecuteCtx(ctx, cmd.NewCmd("show")); done <- err }()
			select {
			case <-reading:
			case <-time.After(time.Second):
				t.Fatal("command did not reach ReadTo")
			}
			cancel()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("ExecuteCtx did not cancel command read")
			}
			expected := "show"
			if auto {
				expected = "setup"
			}
			require.Equal(t, []string{expected, "\n"}, c.writes)
		})
	}
}

func TestExecuteCtxAlreadyCanceled(t *testing.T) {
	c := &contextConnector{}
	dev := contextDevice(t, c)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := dev.ExecuteCtx(ctx, cmd.NewCmd("must not execute"))
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, c.writes)
	require.Zero(t, c.reads)
}

func TestExecuteCtxDeadlinePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name            string
		parent, command time.Duration
	}{
		{"caller first", 20 * time.Millisecond, time.Second},
		{"command first", time.Second, 20 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &contextConnector{read: func(ctx context.Context, _ expr.Expr) (streamer.ReadRes, error) { <-ctx.Done(); return nil, ctx.Err() }}
			dev := contextDevice(t, c)
			ctx, cancel := context.WithTimeout(t.Context(), tc.parent)
			defer cancel()
			_, err := dev.ExecuteCtx(ctx, cmd.NewCmd("show", cmd.WithCmdTimeout(tc.command)))
			require.ErrorIs(t, err, context.DeadlineExceeded)
		})
	}
}

func TestExecuteCtxDoesNotApplyConnectTimeoutToCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	stop := errors.New("end of test")
	c := &contextConnector{read: func(ctx context.Context, _ expr.Expr) (streamer.ReadRes, error) {
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.Equal(t, wantDeadline, deadline)
		return nil, stop
	}}
	dev := contextDevice(t, c, genericcli.WithConnectTimeout(time.Second))
	_, err := dev.ExecuteCtx(ctx, cmd.NewCmd("show"))
	require.ErrorIs(t, err, stop)
}

func TestGenericExecuteKeepsCommandTimeout(t *testing.T) {
	c := &contextConnector{reads: 1, read: func(ctx context.Context, _ expr.Expr) (streamer.ReadRes, error) { <-ctx.Done(); return nil, ctx.Err() }}
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExpr().FromPattern(`lab#$`), expr.NewSimpleExpr().FromPattern(`^ERROR`))
	_, err := genericcli.GenericExecute(context.Background(), cmd.NewCmd("show", cmd.WithCmdTimeout(20*time.Millisecond)), c, cli, zap.NewNop())
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestExecuteCtxCancelsInitialWait(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &contextConnector{onPrompt: cancel}
	dev := contextDevice(t, c, genericcli.WithInitialWait(time.Hour))
	done := make(chan error, 1)
	go func() { _, err := dev.ExecuteCtx(ctx, cmd.NewCmd("must not execute")); done <- err }()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("initial wait ignored cancellation")
	}
	require.Empty(t, c.writes)
}

func TestExecuteCtxBoundsAutoCommandInitialization(t *testing.T) {
	c := &contextConnector{read: func(ctx context.Context, _ expr.Expr) (streamer.ReadRes, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	dev := contextDevice(t, c, genericcli.WithConnectTimeout(20*time.Millisecond),
		genericcli.WithAutoCommands([]cmd.Cmd{cmd.NewCmd("setup")}))
	_, err := dev.ExecuteCtx(t.Context(), cmd.NewCmd("must not execute"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotContains(t, c.writes, "must not execute")
}

func TestGenericExecuteAlreadyCanceled(t *testing.T) {
	c := &contextConnector{}
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExpr().FromPattern(`lab#$`), expr.NewSimpleExpr().FromPattern(`^ERROR`))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := genericcli.GenericExecute(ctx, cmd.NewCmd("must not execute"), c, cli, zap.NewNop())
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, c.writes)
	require.Zero(t, c.reads)
}
