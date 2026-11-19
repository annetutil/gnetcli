package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

// timeoutErr is a minimal net.Error reporting a timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestClassifyExecError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ExecErrorType
	}{
		{
			// The whole point of the type-based check: EOFException.Error()
			// is "eof error …" (lowercase), so a substring match on "EOF"
			// would miss it.
			name: "eof",
			err:  streamer.ThrowEOFException([]byte("last")),
			want: ErrorTypeEOF,
		},
		{
			// errors.As must see through wrapping.
			name: "eof wrapped",
			err:  fmt.Errorf("execute failed: %w", streamer.ThrowEOFException([]byte("last"))),
			want: ErrorTypeEOF,
		},
		{
			name: "question",
			err:  device.ThrowQuestionException([]byte("Are you sure? [Y/N]:")),
			want: ErrorTypeQuestion,
		},
		{
			name: "echo",
			err:  device.ThrowEchoReadException([]byte("garbled"), false, false),
			want: ErrorTypeEcho,
		},
		{
			name: "cmd timeout",
			err:  streamer.ThrowCmdTimeoutException([]byte("last")),
			want: ErrorTypeExecTimeout,
		},
		{
			name: "read timeout",
			err:  streamer.ThrowReadTimeoutException([]byte("last")),
			want: ErrorTypeExecTimeout,
		},
		{
			name: "exec exception",
			err:  device.ThrowExecException("% bad command"),
			want: ErrorTypeExec,
		},
		{
			name: "unknown",
			err:  errors.New("something else entirely"),
			want: ErrorTypeUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classifyExecError(tc.err))
		})
	}
}

func TestClassifyConnectError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ExecErrorType
	}{
		{
			name: "refused",
			err:  fmt.Errorf("dial tcp 10.0.0.1:22: %w", syscall.ECONNREFUSED),
			want: ErrorTypeRefused,
		},
		{
			name: "host unreachable",
			err:  fmt.Errorf("dial tcp: %w", syscall.EHOSTUNREACH),
			want: ErrorTypeUnreachable,
		},
		{
			name: "net timeout",
			err:  fmt.Errorf("failed to connect to host: %w", timeoutErr{}),
			want: ErrorTypeConnectTimeout,
		},
		{
			name: "deadline exceeded",
			err:  fmt.Errorf("failed to connect to host: %w", context.DeadlineExceeded),
			want: ErrorTypeConnectTimeout,
		},
		{
			name: "auth",
			err:  errors.New("failed to connect to host: ssh: unable to authenticate, attempted methods [none password]"),
			want: ErrorTypeAuth,
		},
		{
			name: "handshake",
			err:  errors.New("failed to connect to host: ssh: handshake failed: no common algorithm for host key"),
			want: ErrorTypeHandshake,
		},
		{
			name: "unclassified",
			err:  errors.New("failed to connect to host: weird transport error"),
			want: ErrorTypeConnect,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classifyConnectError(tc.err))
		})
	}
}

// reasonOf extracts ErrorInfo.Reason from a gRPC status error.
func reasonOf(t *testing.T, err error) string {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error, got %v", err)
	require.Equal(t, codes.Internal, st.Code())
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	t.Fatalf("no ErrorInfo detail on %v", err)
	return ""
}

func TestMakeGRPCErrorsCarryReason(t *testing.T) {
	execErr := makeGRPCDeviceExecError(streamer.ThrowEOFException([]byte("x")))
	require.Equal(t, string(ErrorTypeEOF), reasonOf(t, execErr))

	connErr := makeGRPCConnectError(fmt.Errorf("dial: %w", syscall.ECONNREFUSED))
	require.Equal(t, string(ErrorTypeRefused), reasonOf(t, connErr))

	// The original message is preserved in the status and ErrorInfo metadata.
	st, _ := status.FromError(execErr)
	require.Contains(t, st.Message(), "eof error")
}
