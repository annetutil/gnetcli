package mock

import (
	"fmt"
	"io"
	"time"

	"golang.org/x/exp/slices"
)

var ErrReadFailed = fmt.Errorf("failed to read data")

type Action interface {
	Exec(reader io.ReadWriteCloser) error
}

// Expect action
type ExpectAction struct {
	data string
}

func Expect(data string) ExpectAction {
	return ExpectAction{data}
}

func (a ExpectAction) Exec(c io.ReadWriteCloser) error {
	buf := make([]byte, len(a.data))

	n, err := io.ReadAtLeast(c, buf, len(a.data))
	if err != nil {
		return ErrReadFailed
	}

	if n != len(a.data) {
		return fmt.Errorf("read data length mismatch")
	}

	if !slices.Equal(buf, []byte(a.data)) {
		return fmt.Errorf("read data content mismatch: expected %#v, got %#v", a.data, string(buf))
	}

	return nil
}

// Sleep action
type SleepAction struct {
	count int
}

func Sleep(count int) SleepAction {
	return SleepAction{count}
}

func (a SleepAction) Exec(c io.ReadWriteCloser) error {
	time.Sleep(time.Duration(a.count) * time.Second)
	return nil
}

// Send action
type SendAction struct {
	data string
}

func Send(data string) SendAction {
	return SendAction{data}
}

func (a SendAction) Exec(c io.ReadWriteCloser) error {
	_, err := io.WriteString(c, a.data)

	return err
}

// Send echo action
type SendEchoAction struct {
	data string
}

func SendEcho(data string) SendEchoAction {
	return SendEchoAction{data}
}

func (a SendEchoAction) Exec(c io.ReadWriteCloser) error {
	_, err := io.WriteString(c, a.data)

	return err
}

// Close action
type CloseAction struct{}

func Close() CloseAction {
	return CloseAction{}
}

func (a CloseAction) Exec(c io.ReadWriteCloser) error {
	return c.Close()
}
