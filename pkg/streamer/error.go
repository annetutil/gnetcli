package streamer

import (
	"fmt"
)

type ReadTimeoutException struct {
	LastRead []byte
}

func (m *ReadTimeoutException) Error() string {
	return fmt.Sprintf("read timeout error. last seen: \"%s\"", string(m.LastRead))
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
	return fmt.Sprintf("read timeout error. last seen: \"%s\"", string(m.LastRead))
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
	return fmt.Sprintf("cmd timeout error. last seen: \"%s\"", string(e.lastRead))
}

func ThrowCmdTimeoutException(lastRead []byte) error {
	return &CmdTimeoutException{lastRead: lastRead}
}

type BadConsolePortException struct {
	lastRead []byte
}

func (e *BadConsolePortException) Error() string {
	return fmt.Sprintf("bad console port error. last seen %s", string(e.lastRead))
}

func ThrowBadConsolePortException(lastRead []byte) error {
	return &BadConsolePortException{lastRead: lastRead}
}

type ConsoleException struct {
	lastRead []byte
}

func (e *ConsoleException) Error() string {
	return fmt.Sprintf("console error. last seen %s", string(e.lastRead))
}

func ThrowConsoleException(lastRead []byte) error {
	return &ConsoleException{lastRead: lastRead}
}

type ConsolePortIsLockedException struct {
	lastRead []byte
}

func (m *ConsolePortIsLockedException) Error() string {
	return fmt.Sprintf("console port is locked error. last seen %s", string(m.lastRead))
}

func (m *ConsolePortIsLockedException) Is(target error) bool {
	if _, ok := target.(*ConsolePortIsLockedException); ok {
		return true
	}
	return false
}

func ThrowConsolePortIsLockedException(lastRead []byte) error {
	return &ConsolePortIsLockedException{lastRead: lastRead}
}

type ConsolePortIsBusyException struct {
	lastRead []byte
}

func (e *ConsolePortIsBusyException) Error() string {
	return fmt.Sprintf("console port is locked error. last seen %s", string(e.lastRead))
}

func ThrowConsolePortIsBusyException(lastRead []byte) error {
	return &ConsolePortIsBusyException{lastRead: lastRead}
}
