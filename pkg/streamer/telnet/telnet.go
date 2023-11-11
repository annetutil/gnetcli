/*
Package telnet implements telnet transport at very basic level.
*/
package telnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/trace"
)

var _ streamer.Connector = (*Streamer)(nil)

const (
	defaultReadSize    = 4096
	defaultReadTimeout = 20 * time.Second
	defaultPort        = 23
)

type Streamer struct {
	credentials            credentials.Credentials
	logger                 *zap.Logger
	host                   string
	conn                   net.Conn
	stdoutBuffer           chan []byte
	stdoutBufferExtra      []byte
	credentialsInterceptor func(credentials.Credentials) credentials.Credentials
	trace                  trace.CB
	readTimeout            time.Duration
}

func (m *Streamer) InitAgentForward() error {
	return errors.New("agent forwarding is not supported")
}

func (m *Streamer) SetReadTimeout(duration time.Duration) time.Duration {
	prev := m.readTimeout
	m.readTimeout = duration
	return prev
}

func (m *Streamer) SetTrace(cb trace.CB) {
	m.trace = cb
}

func (m *Streamer) Download(paths []string, recurse bool) (map[string]streamer.File, error) {
	return nil, streamer.ErrNotSupported
}

func (m *Streamer) Upload(m2 map[string]streamer.File) error {
	return streamer.ErrNotSupported

}

func (m *Streamer) SetCredentialsInterceptor(inter func(credentials.Credentials) credentials.Credentials) {
	m.credentialsInterceptor = inter
}

func (m *Streamer) Init(ctx context.Context) error {
	m.logger.Debug("open connection", zap.String("host", m.host))
	conn, err := streamer.TCPDialCtx(ctx, "tcp", fmt.Sprintf("%s:%d", m.host, defaultPort))
	if err != nil {
		return err
	}
	m.conn = conn
	eg, _ := errgroup.WithContext(ctx)
	eg.Go(func() error { return m.stdoutReader(m.conn) })
	return nil
}

func (m *Streamer) GetCredentials() credentials.Credentials {
	return m.credentials
}

func NewStreamer(host string, credentials credentials.Credentials, opts ...StreamerOption) *Streamer {
	h := &Streamer{
		credentials:            credentials,
		logger:                 zap.NewNop(),
		host:                   host,
		conn:                   nil,
		stdoutBuffer:           nil,
		stdoutBufferExtra:      nil,
		credentialsInterceptor: nil,
		trace:                  nil,
		readTimeout:            defaultReadTimeout,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (m *Streamer) Cmd(context.Context, string) (gcmd.CmdRes, error) {
	return nil, errors.New("execute is not supported by telnet")
}

func (m *Streamer) Write(text []byte) error {
	text = append(text, byte('\n'))
	if m.trace != nil {
		m.trace(trace.Write, text)
	}
	written, err := m.conn.Write(text)
	if err != nil {
		return err
	}
	m.logger.Debug("write", zap.ByteString("text", text), zap.Int("written", written))
	return nil
}

func (m *Streamer) Read(context.Context, int) ([]byte, error) {
	return nil, errors.New("read is not supported by telnet")
}

func (m *Streamer) ReadTo(ctx context.Context, expr expr.Expr) (streamer.ReadRes, error) {
	m.logger.Debug("read to", zap.String("expr", expr.Repr()))
	res, extra, read, err := streamer.GenericReadX(ctx, m.stdoutBufferExtra, m.stdoutBuffer, defaultReadSize, m.readTimeout, expr, 0, 0)
	if m.trace != nil {
		m.trace(trace.Read, read)
	}
	m.stdoutBufferExtra = extra
	if err != nil {
		return nil, err
	}
	if res.RetType == streamer.Timeout {
		return nil, streamer.ThrowReadTimeoutException(streamer.GetLastBytes(read, defaultReadSize))
	}
	return res.ExprRes, nil
}

type StreamerOption func(*Streamer)

func WithLogger(log *zap.Logger) StreamerOption {
	return func(h *Streamer) {
		h.logger = log
	}
}

func WithTrace(trace trace.CB) StreamerOption {
	return func(h *Streamer) {
		h.trace = trace
	}
}

func (m *Streamer) Close() {
	if m.conn != nil {
		_ = m.conn.Close()
	}
}

func (m Streamer) HasFeature(feature streamer.Const) bool {
	if feature == streamer.AutoLogin {
		return false
	}
	return false
}

// It's impossible to set timeout for Read, so read here and put in channel
func (m *Streamer) stdoutReader(reader io.Reader) error {
	for {
		readBuffer := make([]byte, defaultReadSize)
		readLen, err := reader.Read(readBuffer)
		if err != nil {
			return err
		}
		m.logger.Debug("read", zap.ByteString("data", readBuffer[:readLen]))
		m.stdoutBuffer <- readBuffer[:readLen]
	}
}
