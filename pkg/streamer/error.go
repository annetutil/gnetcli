package streamer

import (
	"fmt"
)

type ReadTimeoutException struct {
	LastRead []byte
	Cause    error
}

func (m *ReadTimeoutException) Error() string {
	if m.Cause != nil {
		return fmt.Sprintf("read timeout error caused by %v. last seen: %q", m.Cause, string(m.LastRead))
	}
	return fmt.Sprintf("read timeout error. last seen: %q", string(m.LastRead))
}

func (m *ReadTimeoutException) Unwrap() error {
	return m.Cause
}

func (m *ReadTimeoutException) Is(target error) bool {
	if _, ok := target.(*ReadTimeoutException); ok {
		return true
	}
	return false
}

type EOFException struct {
	LastRead []byte
}

func (m *EOFException) Error() string {
	return fmt.Sprintf("eof error. last seen: %q", string(m.LastRead))
}

func (m *EOFException) Is(target error) bool {
	if _, ok := target.(*EOFException); ok {
		return true
	}
	return false
}

func ThrowReadTimeoutException(lastRead []byte, cause ...error) error {
	var err error
	if len(cause) > 0 {
		err = cause[0]
	}
	return &ReadTimeoutException{LastRead: lastRead, Cause: err}
}

func ThrowEOFException(lastRead []byte) error {
	return &EOFException{LastRead: lastRead}
}

type CmdTimeoutException struct {
	lastRead []byte
}

func (e *CmdTimeoutException) Error() string {
	return fmt.Sprintf("cmd timeout error. last seen: %q", string(e.lastRead))
}

func ThrowCmdTimeoutException(lastRead []byte) error {
	return &CmdTimeoutException{lastRead: lastRead}
}
