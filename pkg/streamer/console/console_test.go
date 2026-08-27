package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/stretchr/testify/require"
)

func TestPrependBufferReturnsConsumedBytesToNextRead(t *testing.T) {
	consoleStreamer := NewStreamer("unused", "ttyS1", nil, nil)
	consoleStreamer.PrependBuffer([]byte("Password:"))

	res, err := consoleStreamer.XRead(context.Background(), len("Password:"), time.Second, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("Password:"), res.BytesRes)
	require.Empty(t, consoleStreamer.GetBuffer())
}

func TestXReadPollingDurationDoesNotBecomeReadTimeout(t *testing.T) {
	consoleStreamer := NewStreamer("unused", "ttyS1", nil, nil)
	consoleStreamer.SetReadTimeout(100 * time.Millisecond)

	for range 20 {
		res, err := consoleStreamer.XRead(context.Background(), 1, time.Millisecond, nil)
		require.NoError(t, err)
		require.Equal(t, streamer.Timeout, res.RetType)
	}
}

func TestParseInfoLine(t *testing.T) {
	line := "ttyS16:consoles-dc.domain,147,10102:/:/dev/ttyMI23,9600n,4::up:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:"
	res, err := parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS16")
	require.Equal(t, res.port, 10102)
	// locked
	line = "ttyS11:consoles-dc.domain,147,10102:/:/dev/ttyMI18,9600n,9:w@login@dc1-srv.net@22:up:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:\n"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS11")
	require.Equal(t, res.port, 10102)
	// old console ?
	line = "ttyS32:consoles-dc1.domains,12833,10102:/:/dev/ttyS32,9600n,4::up:rw:,log,noact,nobrk,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS32")
	require.Equal(t, res.port, 10102)
	line = "ttyS11:consoles-1.domain,151,10102:/:/dev/ttyMI18,9600n,-1::down:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS11")
	require.Equal(t, res.iostate, "down")
	require.Equal(t, res.port, 10102)
	line = "ttyS23:consoles-1.yndx.net,194,10103:/:/dev/ttyMI14,9600n,13:w@login@::ffff:10.0.0.1@1:up:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:\n"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS23")
	require.Equal(t, res.iostate, "up")
	require.Equal(t, res.port, 10103)
}

type partialWriteConn struct {
	bytes.Buffer
	maxWrite int
}

func (c *partialWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *partialWriteConn) Close() error                     { return nil }
func (c *partialWriteConn) LocalAddr() net.Addr              { return nil }
func (c *partialWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *partialWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *partialWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *partialWriteConn) SetWriteDeadline(time.Time) error { return nil }

func (c *partialWriteConn) Write(data []byte) (int, error) {
	if len(data) > c.maxWrite {
		data = data[:c.maxWrite]
	}
	return c.Buffer.Write(data)
}

func TestWriteRetriesPartialWrites(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 3}
	consoleStreamer := NewStreamer("unused", "ttyS1", nil, nil)
	consoleStreamer.conn = conn
	payload := []byte("0123456789")

	err := consoleStreamer.Write(payload)

	require.NoError(t, err)
	require.Equal(t, payload, conn.Bytes())
}

func TestWithSetupReadTimeout(t *testing.T) {
	consoleStreamer := NewStreamer("unused", "ttyS1", nil, nil, WithSetupReadTimeout(42*time.Second))

	require.Equal(t, 42*time.Second, consoleStreamer.setupReadTimeout)
}

func TestValidateRedirectExitAcceptsExpectedConnectionClose(t *testing.T) {
	expectedErrors := []error{
		io.EOF,
		net.ErrClosed,
		io.ErrClosedPipe,
		syscall.EPIPE,
		streamer.ThrowReadTimeoutException(nil),
		streamer.ThrowEOFException(nil),
		fmt.Errorf("wrapped: %w", syscall.EPIPE),
	}
	for _, err := range expectedErrors {
		t.Run(err.Error(), func(t *testing.T) {
			require.NoError(t, validateRedirectExit(nil, err))
		})
	}
}

func TestValidateRedirectExitChecksResponseAndUnexpectedErrors(t *testing.T) {
	require.NoError(t, validateRedirectExit([]byte(ansGoodbye), nil))
	require.ErrorContains(t, validateRedirectExit([]byte("unexpected\r\n"), nil), "expected: goodbye")

	unexpectedErr := errors.New("authentication failed")
	err := validateRedirectExit(nil, unexpectedErr)
	require.ErrorIs(t, err, unexpectedErr)
}

type teardownErrorConn struct{}

func (c *teardownErrorConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *teardownErrorConn) Write(data []byte) (int, error)   { return len(data), nil }
func (c *teardownErrorConn) Close() error                     { return errors.New("close failed") }
func (c *teardownErrorConn) LocalAddr() net.Addr              { return nil }
func (c *teardownErrorConn) RemoteAddr() net.Addr             { return nil }
func (c *teardownErrorConn) SetDeadline(time.Time) error      { return errors.New("deadline failed") }
func (c *teardownErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *teardownErrorConn) SetWriteDeadline(time.Time) error { return nil }

func TestCloseForChangePortIgnoresDiscardedConnectionErrors(t *testing.T) {
	consoleStreamer := NewStreamer("unused", "ttyS1", nil, nil)
	consoleStreamer.conn = &teardownErrorConn{}

	err := consoleStreamer.closeForChangePort()

	require.NoError(t, err)
	require.Nil(t, consoleStreamer.conn)
}
