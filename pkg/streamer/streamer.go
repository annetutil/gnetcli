/*
Package streamer describes interface for interaction on network level.
*/

package streamer

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/trace"
	"go.uber.org/zap"
)

var ErrNotSupported = errors.New("not supported")

type Connector interface {
	Init(context.Context) error
	GetCredentials() credentials.Credentials
	SetCredentialsInterceptor(func(credentials.Credentials) credentials.Credentials)
	SetTrace(trace.CB)
	SetReadTimeout(time.Duration) time.Duration
	PrependBuffer([]byte) error
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
	GetUnderlyingRes() ReadRes // may be nil
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
	LoginInsteadEOF
)

type ReadResImpl struct {
	before        []byte
	after         []byte
	matchedGroups map[string][]byte
	matched       []byte
	patternNo     int
	underlyingRes ReadRes
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

func (m ReadResImpl) GetUnderlyingRes() ReadRes {
	return m.underlyingRes
}

func NewReadResImplWithUnder(before, after []byte, matchedGroups map[string][]byte, matched []byte, patternNo int, underlying ReadRes) ReadResImpl {
	return ReadResImpl{
		before:        before,
		after:         after,
		matchedGroups: matchedGroups,
		matched:       matched,
		patternNo:     patternNo,
		underlyingRes: underlying,
	}
}

func NewReadResImpl(before, after []byte, matchedGroups map[string][]byte, matched []byte, patternNo int) ReadResImpl {
	return ReadResImpl{before: before, after: after, matchedGroups: matchedGroups, matched: matched, patternNo: patternNo}
}

// TCPDialCtx net.Dial version with context arg
func TCPDialCtx(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
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

func (m ReadXType) String() string {
	switch m {
	case Size:
		return "size"
	case Expr:
		return "expr"
	case Timeout:
		return "timeout"
	case EOF:
		return "EOF"
	}
	return "unknown"
}

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

// flushCh returns all data currently queued in channel
func flushCh(ch <-chan []byte) []byte {
	res := []byte{}
	for {
		select {
		case readData, ok := <-ch:
			if !ok {
				return res
			}
			res = append(res, readData...)
		default:
			return res
		}
	}
}

type GenericReadConfig struct {
	maxDuration time.Duration
	minReadSize int
	maxReadSize int
	regExpr     expr.Expr
}

// WithMinReadSize stops reading as soon as at least minReadSize bytes are buffered.
// Combine it with WithMaxReadSize to return all currently buffered data up to a limit.
func WithMinReadSize(minReadSize int) GenericReadOption {
	return func(grc *GenericReadConfig) {
		grc.minReadSize = minReadSize
	}
}

type GenericReadOption func(*GenericReadConfig)

// WithRegExpr stops read on regExpr match
func WithRegExpr(regExpr expr.Expr) GenericReadOption {
	return func(grc *GenericReadConfig) {
		grc.regExpr = regExpr
	}
}

// WithMaxDuration specifies maximum time for reading. Results in timeout result without error
func WithMaxDuration(maxDuration time.Duration) GenericReadOption {
	return func(grc *GenericReadConfig) {
		grc.maxDuration = maxDuration
	}
}

// WithMaxReadSize specifies maximum size of bytes returned. Any leftover bytes from read will be returned as left bytes
func WithMaxReadSize(maxReadSize int) GenericReadOption {
	return func(grc *GenericReadConfig) {
		grc.maxReadSize = maxReadSize
	}
}

// GenericReadX reads from readCh till expr matched, exceeded time or read more than size.
// Returns error if nothing was read during readTimeout or ctx was Done
// Returns read res, left bytes, read bytes, error
func GenericReadX(ctx context.Context, inBuffer []byte, readCh chan []byte, readSize int, readTimeout time.Duration,
	requiredOpt GenericReadOption, opts ...GenericReadOption) (*ReadXRes, []byte, []byte, error) {
	cfg := GenericReadConfig{}
	for _, v := range append(opts, requiredOpt) {
		v(&cfg)
	}
	if cfg.maxDuration == 0 && cfg.minReadSize == 0 && cfg.maxReadSize == 0 && cfg.regExpr == nil {
		return nil, nil, nil, errors.New("specify maxDuration, minReadSize, maxReadSize or regExpr via options")
	}
	if cfg.minReadSize < 0 {
		return nil, nil, nil, errors.New("minReadSize must not be negative")
	}
	if cfg.maxReadSize > 0 && cfg.minReadSize > cfg.maxReadSize {
		return nil, nil, nil, errors.New("minReadSize must not exceed maxReadSize")
	}
	buffer := inBuffer
	maxDurationTimeout := NewTimerWithDefault(cfg.maxDuration)
	for {
		select {
		case <-ctx.Done():
			StopTimer(maxDurationTimeout)
			buffer = append(buffer, flushCh(readCh)...)
			return nil, buffer, buffer[len(inBuffer):], ThrowReadTimeoutException(GetLastBytes(buffer, readSize), ctx.Err())
		default:
		}
		readIterTimeout := NewTimerWithDefault(readTimeout)
		// check size
		if cfg.maxReadSize > 0 && len(buffer) >= cfg.maxReadSize {
			data, extra := splitBytes(buffer, cfg.maxReadSize)
			StopTimer(readIterTimeout)
			StopTimer(maxDurationTimeout)
			return NewReadXRes(Size, data, nil, []byte{}), extra, buffer[len(inBuffer):], nil
		}
		if cfg.minReadSize > 0 && len(buffer) >= cfg.minReadSize {
			returnSize := len(buffer)
			if cfg.maxReadSize > 0 {
				returnSize = min(returnSize, cfg.maxReadSize)
			}
			data, extra := splitBytes(buffer, returnSize)
			StopTimer(readIterTimeout)
			StopTimer(maxDurationTimeout)
			return NewReadXRes(Size, data, nil, []byte{}), extra, buffer[len(inBuffer):], nil
		}

		if cfg.regExpr != nil {
			// check expr
			mRes, ok := cfg.regExpr.Match(buffer)
			if ok {
				var underlyingRes ReadRes
				if mRes.Underlying != nil {
					underlyingRes = NewReadResImpl(buffer[:mRes.Underlying.Start], buffer[mRes.Underlying.End:], mRes.Underlying.GroupDict, buffer[mRes.Underlying.Start:mRes.End], mRes.Underlying.PatternNo)
				}
				res := NewReadResImplWithUnder(buffer[:mRes.Start], buffer[mRes.End:], mRes.GroupDict, buffer[mRes.Start:mRes.End], mRes.PatternNo, underlyingRes)
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
			buffer = append(buffer, flushCh(readCh)...)
			return nil, buffer, buffer[len(inBuffer):], ThrowReadTimeoutException(GetLastBytes(buffer, readSize), ctx.Err())
		case readData, ok := <-readCh:
			StopTimer(readIterTimeout)
			if ok {
				buffer = append(buffer, readData...)
				// check whether if we have something else in channel
				// maybe we spent long time between GenericReadX() calls
			L:
				for {
					select {
					case readData, ok := <-readCh:
						if ok {
							buffer = append(buffer, readData...)
						} else {
							break L
						}
					default:
						break L
					}
				}
			}
			if !ok {
				return NewReadXRes(EOF, buffer, nil, []byte{}), []byte{}, buffer[len(inBuffer):], nil
			}
		case <-maxDurationTimeout.C:
			// check maxDuration
			StopTimer(readIterTimeout)
			return NewReadXRes(Timeout, buffer, nil, []byte{}), []byte{}, buffer[len(inBuffer):], nil
		case <-readIterTimeout.C:
			StopTimer(maxDurationTimeout)
			buffer = append(buffer, flushCh(readCh)...)
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
