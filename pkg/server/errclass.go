package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

// ExecErrorType is the stable value surfaced via ErrorInfo.Reason so that
// callers (e.g. the Python SDK) can branch on the failure class without parsing
// human-readable error strings.
type ExecErrorType string

const (
	// Execution phase (a session was established, the command failed).
	ErrorTypeEOF         ExecErrorType = "error_eof"          // device closed the session mid-command
	ErrorTypeQuestion    ExecErrorType = "error_question"     // an interactive question went unanswered
	ErrorTypeEcho        ExecErrorType = "error_echo"         // command echo could not be read back
	ErrorTypeExecTimeout ExecErrorType = "error_exec_timeout" // read/command timeout during execution
	ErrorTypeExec        ExecErrorType = "error_exec"         // device reported a command error (error expression matched)
	ErrorTypeUnknown     ExecErrorType = "error_unknown"      // unclassified execution error

	// Connect phase (the session could not be established).
	ErrorTypeAuth           ExecErrorType = "error_auth"            // authentication rejected by the device
	ErrorTypeHandshake      ExecErrorType = "error_handshake"       // SSH handshake / host-key / algorithm failure
	ErrorTypeRefused        ExecErrorType = "error_refused"         // connection refused
	ErrorTypeConnectTimeout ExecErrorType = "error_connect_timeout" // timed out connecting
	ErrorTypeUnreachable    ExecErrorType = "error_unreachable"     // no route / network unreachable
	ErrorTypeConnect        ExecErrorType = "error_connect"         // unclassified connect error
)

// classifyExecError maps an execution-phase error to a fine-grained reason by
// its concrete type (via errors.As), not by matching its message text — the
// error strings carry variable payloads (e.g. the last bytes read) and differ
// in case, so text matching is fragile.
func classifyExecError(err error) ExecErrorType {
	var (
		eofErr      *streamer.EOFException
		questionErr *device.QuestionException
		echoErr     *device.EchoReadException
		cmdTimeErr  *streamer.CmdTimeoutException
		readTimeErr *streamer.ReadTimeoutException
		execErr     *device.ExecException
	)
	switch {
	case errors.As(err, &eofErr):
		return ErrorTypeEOF
	case errors.As(err, &questionErr):
		return ErrorTypeQuestion
	case errors.As(err, &echoErr):
		return ErrorTypeEcho
	case errors.As(err, &cmdTimeErr) || errors.As(err, &readTimeErr):
		return ErrorTypeExecTimeout
	case errors.As(err, &execErr):
		return ErrorTypeExec
	default:
		return ErrorTypeUnknown
	}
}

// classifyConnectError maps a connect-phase error to a fine-grained reason.
// Network failures are classified by type (net.Error / syscall errno via
// errors.As/errors.Is). SSH does not export typed values for authentication and
// handshake failures, so those two sub-cases fall back to the message text.
func classifyConnectError(err error) ExecErrorType {
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrorTypeRefused
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		return ErrorTypeUnreachable
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return ErrorTypeConnectTimeout
	}
	// No typed SSH auth/handshake errors are exported upstream; inspect the
	// message for these two classes only.
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"),
		strings.Contains(msg, "no supported methods"),
		strings.Contains(msg, "permission denied"):
		return ErrorTypeAuth
	case strings.Contains(msg, "handshake"),
		strings.Contains(msg, "no common algorithm"),
		strings.Contains(msg, "host key"),
		strings.Contains(msg, "knownhosts"):
		return ErrorTypeHandshake
	}
	return ErrorTypeConnect
}

// grpcErrorWithReason wraps err into a codes.Internal status carrying an
// ErrorInfo detail with the given reason and the original message.
func grpcErrorWithReason(err error, reason ExecErrorType) error {
	st := status.New(codes.Internal, err.Error())
	withDetails, detErr := st.WithDetails(
		&errdetails.ErrorInfo{
			Reason:   string(reason),
			Metadata: map[string]string{"err": err.Error()},
		},
	)
	if detErr != nil {
		return st.Err()
	}
	return withDetails.Err()
}

// makeGRPCDeviceExecError converts an execution-phase error into a gRPC status
// with a classified ErrorInfo.Reason.
func makeGRPCDeviceExecError(err error) error {
	return grpcErrorWithReason(err, classifyExecError(err))
}

// makeGRPCConnectError converts a connect-phase error into a gRPC status with a
// classified ErrorInfo.Reason.
func makeGRPCConnectError(err error) error {
	return grpcErrorWithReason(err, classifyConnectError(err))
}
