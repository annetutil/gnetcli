package streamer

import (
	"fmt"
)

type ReadTimeoutException struct {
	LastRead []byte
}

func (m *ReadTimeoutException) Error() string {
	return fmt.Sprintf("read timeout error. last seen: %q", string(m.LastRead))
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

func ThrowReadTimeoutException(lastRead []byte) error {
	return &ReadTimeoutException{LastRead: lastRead}
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
