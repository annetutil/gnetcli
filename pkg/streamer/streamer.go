/*
Package streamer describes interface for interaction on network level.
*/
package streamer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	"go.uber.org/multierr"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/trace"
)

var ErrNotSupported = errors.New("not supported")

type Connector interface {
	Init(context.Context) error
	GetCredentials() credentials.Credentials
	SetCredentialsInterceptor(func(credentials.Credentials) credentials.Credentials)
	SetTrace(trace.CB)
	SetReadTimeout(time.Duration) time.Duration
	Close()
	ReadTo(context.Context, expr.Expr) (ReadRes, error)
	Read(ctx context.Context, n int) ([]byte, error)
	Cmd(ctx context.Context, cmd string) (cmd.CmdRes, error)
	Write([]byte) error
	HasFeature(Const) bool
	Download(paths []string, recurse bool) (map[string]File, error)
	Upload(map[string]File) error
	InitAgentForward() error
}

type ReadRes interface {
	GetBefore() []byte
	GetAfter() []byte
	GetMatchedGroups() map[string][]byte
	GetMatched() []byte
	GetPatternNo() int
}

const readBufferSize = 1024

type File struct {
	Data  []byte
	Mode  *os.FileMode
	Chmod *Chmod
	Err   error
}

func NewFileData(data []byte) File {
	return NewFile(data, nil, nil)
}

type Chmod struct {
	UID int
	GID int
}

func NewFile(data []byte, fileMode *os.FileMode, chmod *Chmod) File {
	return File{
		Data:  data,
		Mode:  fileMode,
		Chmod: chmod,
		Err:   nil,
	}
}

func NewFileError(err error) File {
	var f File
	f.Err = err
	return f
}

type Const int

const (
	AutoLogin Const = iota
	Cmd
)

type ReadResImpl struct {
	before        []byte
	after         []byte
	matchedGroups map[string][]byte
	matched       []byte
	patternNo     int
}

func (m ReadResImpl) GetBefore() []byte {
	return m.before
}

func (m ReadResImpl) GetAfter() []byte {
	return m.after
}

func (m ReadResImpl) GetMatchedGroups() map[string][]byte {
	return m.matchedGroups
}

func (m ReadResImpl) GetMatched() []byte {
	return m.matched
}

func (m ReadResImpl) GetPatternNo() int {
	return m.patternNo
}

func NewReadResImpl(before, after []byte, matchedGroups map[string][]byte, matched []byte, patternNo int) ReadResImpl {
	return ReadResImpl{before: before, after: after, matchedGroups: matchedGroups, matched: matched, patternNo: patternNo}
}

// TCPDialCtx net.Dial version with context arg
func TCPDialCtx(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// CloserCTX calls fn if ctx is cancelled. Returns cancel function.
func CloserCTX(ctx context.Context, fn func()) context.CancelFunc {
	innerCtx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-ctx.Done():
			fn()
			return
		case <-innerCtx.Done():
			return
		}
	}()

	return cancel
}

func splitBytes(data []byte, index int) ([]byte, []byte) {
	if len(data) <= index {
		return data, []byte{}
	}
	first := data[:index]
	second := data[index:]
	return first, second
}

func GetLastBytes(data []byte, last int) []byte {
	if len(data) > last {
		return data[len(data)-last:]
	}
	return data
}

type ReadXRes struct {
	RetType   ReadXType
	ExprRes   ReadRes
	BytesRes  []byte
	ExprAfter []byte
}

type ReadXType int64

const (
	Size ReadXType = iota
	Expr
	Timeout
	EOF
)

func NewReadXRes(retType ReadXType, bytesRes []byte, exprRes ReadRes, after []byte) *ReadXRes {
	return &ReadXRes{
		RetType:   retType,
		BytesRes:  bytesRes,
		ExprRes:   exprRes,
		ExprAfter: after,
	}
}

func NewTimerWithDefault(duration time.Duration) *time.Timer {
	newMaxDuration := time.Duration(1<<63 - 1)
	if duration > 0 {
		newMaxDuration = duration
	}
	return time.NewTimer(newMaxDuration)
}

func StopTimer(timer *time.Timer) {
	if !timer.Stop() {
		<-timer.C
	}
}

// GenericReadX reads from readCh till expr matched, exceeded time or read more than size.
// Returns error if nothing was read during readTimeout or ctx was Done
// readSize - maximum read size
// maxDuration - maximum time for reading
// regExpr - read till regex match
// Returns read res, left bytes, read bytes, error
func GenericReadX(ctx context.Context, inBuffer []byte, readCh chan []byte, readSize int, readTimeout time.Duration,
	regExpr expr.Expr, maxReadSize int, maxDuration time.Duration) (*ReadXRes, []byte, []byte, error) {
	if maxDuration == 0 && maxReadSize == 0 && regExpr == nil {
		return nil, nil, nil, fmt.Errorf("specify maxDuration, maxReadSize or regExpr")
	}
	buffer := slices.Clone(inBuffer)
	maxDurationTimeout := NewTimerWithDefault(maxDuration)
	for {
		readIterTimeout := NewTimerWithDefault(readTimeout)
		// check size
		if maxReadSize > 0 && len(buffer) >= maxReadSize {
			data, extra := splitBytes(buffer, maxReadSize)
			StopTimer(readIterTimeout)
			StopTimer(maxDurationTimeout)
			return NewReadXRes(Size, data, nil, []byte{}), extra, buffer[len(inBuffer):], nil
		}

		if regExpr != nil {
			// check expr
			mRes, ok := regExpr.Match(buffer)
			if ok {
				res := NewReadResImpl(buffer[:mRes.Start], buffer[mRes.End:], mRes.GroupDict, buffer[mRes.Start:mRes.End], mRes.PatternNo)
				after := buffer[mRes.End:]
				StopTimer(readIterTimeout)
				StopTimer(maxDurationTimeout)
				return NewReadXRes(Expr, buffer, res, after), after, buffer[len(inBuffer):], nil
			}
		}
		select {
		case <-ctx.Done():
			StopTimer(readIterTimeout)
			StopTimer(maxDurationTimeout)
			return nil, buffer, buffer[len(inBuffer):], multierr.Combine(ctx.Err(), ThrowReadTimeoutException(GetLastBytes(buffer, readSize)))
		case readData, ok := <-readCh:
			StopTimer(readIterTimeout)
			buffer = append(buffer, readData...)
			if !ok {
				return NewReadXRes(EOF, buffer, nil, []byte{}), buffer, buffer[len(inBuffer):], nil
			}
		case <-maxDurationTimeout.C:
			// check maxDuration
			StopTimer(readIterTimeout)
			return NewReadXRes(Timeout, buffer, nil, []byte{}), buffer, buffer[len(inBuffer):], nil
		case <-readIterTimeout.C:
			StopTimer(maxDurationTimeout)
			return nil, buffer, buffer[len(inBuffer):], ThrowReadTimeoutException(GetLastBytes(buffer, readSize))
		}
	}
}

// NetReader reads data from connection and put it into channel
func NetReader(ctx context.Context, buff chan []byte, conn net.Conn, logger *zap.Logger) error {
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			for {
				err := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if err != nil {
					return err
				}
				readBuffer := make([]byte, readBufferSize)
				readLen, err := conn.Read(readBuffer)
				if err, ok := err.(net.Error); ok && err.Timeout() {
					break
				}
				if err != nil {
					return err
				}
				logger.Debug("read", zap.ByteString("data", readBuffer[:readLen]))
				buff <- readBuffer[:readLen]
			}
		}
	}
}
