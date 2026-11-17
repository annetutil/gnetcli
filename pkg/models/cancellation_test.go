package models_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/stretchr/testify/require"
)

// Use the real GenericDevice execution path rather than a fake ExecuteCtx,
// which would conceal context loss between the model and connector.ReadTo.
type cancellationConnector struct {
	streamer.Connector
	reads   int
	reading chan struct{}
	release chan struct{}
}

func (c *cancellationConnector) Init(context.Context) error { return nil }
func (c *cancellationConnector) SetCredentialsInterceptor(func(credentials.Credentials) credentials.Credentials) {
}
func (c *cancellationConnector) HasFeature(f streamer.Const) bool           { return f == streamer.AutoLogin }
func (c *cancellationConnector) Close()                                     {}
func (c *cancellationConnector) Write([]byte) error                         { return nil }
func (c *cancellationConnector) SetReadTimeout(time.Duration) time.Duration { return time.Second }
func (c *cancellationConnector) ReadTo(ctx context.Context, pattern expr.Expr) (streamer.ReadRes, error) {
	c.reads++
	if c.reads == 1 {
		data := []byte("lab#")
		match, ok := pattern.Match(data)
		if !ok {
			return nil, errors.New("initial prompt did not match")
		}
		return streamer.NewReadResImpl(nil, nil, match.GroupDict, data, match.PatternNo), nil
	}
	close(c.reading)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.release:
		return nil, errors.New("test cleanup")
	}
}

func TestCollectCancelsGenericDeviceCommand(t *testing.T) {
	r, _ := runner(t, `def collect(device):
    device.execute("show version")
    fail("must not reach the next statement")
`)
	connector := &cancellationConnector{reading: make(chan struct{}), release: make(chan struct{})}
	defer close(connector.release)
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExpr().FromPattern(`lab#$`), expr.NewSimpleExpr().FromPattern(`^ERROR`))
	dev := genericcli.MakeGenericDevice(cli, connector)
	require.NoError(t, dev.Connect(t.Context()))
	defer dev.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		result, err := r.Collect(ctx, &dev, "test", "test")
		if result != nil {
			err = errors.New("unexpected partial result")
		}
		done <- err
	}()
	select {
	case <-connector.reading:
	case <-time.After(time.Second):
		t.Fatal("model command not started")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("model command ignored cancellation")
	}
}
