package console

import (
	"fmt"
)

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

type ConsolePortDownError struct {
}

func (e *ConsolePortDownError) Error() string {
	return "console port is down"
}

func NewConsolePortDownError() error {
	return &ConsolePortDownError{}
}
