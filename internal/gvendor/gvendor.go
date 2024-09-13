package gvendor

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	defaultReadSize = 4096
	readTimeout     = 25 * time.Second
)

// from golang.org/x/crypto/ssh/testdata/keys.go
var defaultPrivateKey = []byte(`
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAwa48yfWFi3uIdqzuf9X7C2Zxfea/Iaaw0zIwHudpF8U92WVIiC5l
oEuW1+OaVi3UWfIEjWMV1tHGysrHOwtwc34BPCJqJknUQO/KtDTBTJ4Pryhw1bWPC999Lz
a+yrCTdNQYBzoROXKExZgPFh9pTMi5wqpHDuOQ2qZFIEI3lT0AAAIQWL0H31i9B98AAAAH
c3NoLXJzYQAAAIEAwa48yfWFi3uIdqzuf9X7C2Zxfea/Iaaw0zIwHudpF8U92WVIiC5loE
uW1+OaVi3UWfIEjWMV1tHGysrHOwtwc34BPCJqJknUQO/KtDTBTJ4Pryhw1bWPC999Lza+
yrCTdNQYBzoROXKExZgPFh9pTMi5wqpHDuOQ2qZFIEI3lT0AAAADAQABAAAAgCThyTGsT4
IARDxVMhWl6eiB2ZrgFgWSeJm/NOqtppWgOebsIqPMMg4UVuVFsl422/lE3RkPhVkjGXgE
pWvZAdCnmLmApK8wK12vF334lZhZT7t3Z9EzJps88PWEHo7kguf285HcnUM7FlFeissJdk
kXly34y7/3X/a6Tclm+iABAAAAQE0xR/KxZ39slwfMv64Rz7WKk1PPskaryI29aHE3mKHk
pY2QA+P3QlrKxT/VWUMjHUbNNdYfJm48xu0SGNMRdKMAAABBAORh2NP/06JUV3J9W/2Hju
X1ViJuqqcQnJPVzpgSL826EC2xwOECTqoY8uvFpUdD7CtpksIxNVqRIhuNOlz0lqEAAABB
ANkaHTTaPojClO0dKJ/Zjs7pWOCGliebBYprQ/Y4r9QLBkC/XaWMS26gFIrjgC7D2Rv+rZ
wSD0v0RcmkITP1ZR0AAAAYcHF1ZXJuYUBMdWNreUh5ZHJvLmxvY2FsAQID
-----END OPENSSH PRIVATE KEY-----
`)

type Client interface {
	ReadTo(ctx context.Context, expr expr.Expr) (streamer.ReadRes, error)
	Write(text []byte) error
	Close() error
}

type Action interface {
	Exec(client Client) error
}

type ActionSend struct {
	data         []byte
	perByteWrite bool
	sleep        time.Duration
}

func (m ActionSend) String() string {
	return fmt.Sprintf("'%s'", m.data)
}

func (m ActionSend) Exec(client Client) error {
	if m.sleep > 0 {
		time.Sleep(m.sleep)
	}
	if m.perByteWrite {
		for _, b := range m.data {
			err := client.Write([]byte{b})
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		return client.Write(m.data)
	}
}

func Send(data string) *ActionSend {
	return &ActionSend{
		data:         []byte(data),
		sleep:        0,
		perByteWrite: false,
	}
}

func SendSleep(data string, sleep time.Duration) *ActionSend {
	return &ActionSend{
		data:         []byte(data),
		sleep:        sleep,
		perByteWrite: false,
	}
}

func SendBytes(data []byte, sleep time.Duration, perByteWrite bool) *ActionSend {
	return &ActionSend{
		data:         data,
		sleep:        sleep,
		perByteWrite: perByteWrite,
	}
}

func SendLine(data string) *ActionSend {
	return &ActionSend{
		data: []byte(data + "\r\n"),
	}
}

type ActionExpectLine struct {
	data []byte
}

func (m ActionExpectLine) Exec(client Client) error {
	res, err := client.ReadTo(context.Background(), expr.NewSimpleExpr().FromPattern("(?P<data>.+)(\r\n|\n)"))
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("empty res")
	}
	matched := res.GetMatchedGroups()["data"]
	if slices.Compare(matched, m.data) != 0 {
		return fmt.Errorf("line mismatch '%s' expected='%s'", matched, m.data)
	}
	return nil
}

func ExpectLine(data string) *ActionExpectLine {
	return &ActionExpectLine{
		data: []byte(data),
	}
}

type ActionClose struct {
}

func (a ActionClose) Exec(client Client) error {
	client.Close()
	return nil
}

func Close() *ActionClose {
	return &ActionClose{}
}

type Server struct {
	dialog     []Action
	config     *ssh.ServerConfig
	listener   net.Listener
	username   string
	password   string
	privateKey []byte
	log        *zap.Logger
}

type ServerOption func(*Server)

func WithUser(username string) ServerOption {
	return func(m *Server) {
		m.username = username
	}
}

func WithLogger(logger *zap.Logger) ServerOption {
	return func(m *Server) {
		m.log = logger
	}
}

func WithListener(listener net.Listener) ServerOption {
	return func(m *Server) {
		m.listener = listener
	}
}

func WithPassword(password string) ServerOption {
	return func(m *Server) {
		m.password = password
	}
}

func WithPrivateKey(privateKey []byte) ServerOption {
	return func(m *Server) {
		m.privateKey = privateKey
	}
}

func New(dialog []Action, opts ...ServerOption) (*Server, error) {
	server := &Server{
		dialog:     dialog,
		listener:   nil,
		config:     nil,
		username:   "",
		password:   "",
		privateKey: defaultPrivateKey,
		log:        zap.NewNop(),
	}

	for _, opt := range opts {
		opt(server)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true,

		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if c.User() == server.username && string(pass) == server.password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	private, err := ssh.ParsePrivateKey(server.privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	if server.listener == nil {
		listener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			return nil, fmt.Errorf("failed to listen for connection: %w", err)
		}
		server.listener = listener
	}

	server.config = config
	return server, nil
}

func (m *Server) GetAddress() (string, int) {
	address := strings.Split(m.listener.Addr().String(), ":")
	portNum, _ := strconv.Atoi(address[1])
	return address[0], portNum
}

func (m *Server) Run(ctx context.Context) error {
	host, port := m.GetAddress()
	m.log.Debug("listening", zap.String("host", host), zap.Int("port", port))
	for {
		tcpConn, err := m.listener.Accept()
		start := time.Now()
		if err != nil {
			m.log.Info("failed to accept incoming connection: %w", zap.Error(err))
		}
		err = m.handeConn(ctx, tcpConn)
		m.log.Info("conn finished", zap.Error(err), zap.Duration("duration", time.Since(start)))
	}
}

func (m *Server) handeConn(ctx context.Context, tcpConn net.Conn) error {
	// Before use, a handshake must be performed on the incoming net.Conn.
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, m.config)
	if err != nil {
		return fmt.Errorf("failed to handshake: %w", err)
	}
	m.log.Debug("New SSH connection", zap.String("addr", sshConn.RemoteAddr().String()), zap.ByteString("version", sshConn.ClientVersion()))

	// Discard all global out-of-band Requests
	go ssh.DiscardRequests(reqs)

	// Accept all channels
	return m.handleChannels(ctx, chans)
}

func (m *Server) handleChannels(ctx context.Context, chans <-chan ssh.NewChannel) error {
	for newChannel := range chans {
		err := m.handleChannel(ctx, newChannel)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *connWrapper) cb(read []byte) {
	m.log.Debug("echo", zap.ByteString("read", read))
	_, _ = m.conn.Write(read)
}

func (m *Server) handleChannel(ctx context.Context, newChannel ssh.NewChannel) error {
	// Since we're handling a shell, we expect a
	// channel type of "session".
	if t := newChannel.ChannelType(); t != "session" {
		err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		if err != nil {
			return fmt.Errorf("unknown channel type: %w", err)
		}
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		return fmt.Errorf("could not accept channel: %w", err)
	}
	defer connection.Close()
	connWr := makeConnWrapper(connection, m.log)
	var errRes error

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env".
	// Here we handle any request.
	seenShell := semaphore.NewWeighted(1)
	err = seenShell.Acquire(ctx, 1)
	if err != nil {
		return err
	}

	go func(in <-chan *ssh.Request) {
		for req := range in {
			err := req.Reply(true, nil)
			if req.Type == "shell" {
				seenShell.Release(1)
			}
			if err != nil {
				errRes = err
				return
			}
		}
	}(requests)

	err = seenShell.Acquire(ctx, 1)
	if err != nil {
		return err
	}

	for _, action := range m.dialog {
		m.log.Debug("exec", zap.String("action", fmt.Sprintf("%T", action)), zap.String("data", fmt.Sprintf("%s", action)))
		err = action.Exec(connWr)
		m.log.Debug("exec ok", zap.Error(err))

		if err != nil {
			_, _ = connection.Stderr().Write([]byte(fmt.Sprintf("scenario error %s", err.Error())))
			return err
		}
	}
	return errRes
}

// TODO: reuse chanReader from streamer
// It's impossible to set timeout for Read, so read here and put in channel
func chanReader(ctx context.Context, reader io.Reader, stdoutBuffer chan []byte, readTimeout time.Duration, cb func(read []byte), logger *zap.Logger) error {
	tmpBuffer := make(chan []byte, defaultReadSize)
	wg, wCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		return chanAgg(wCtx, tmpBuffer, stdoutBuffer, readTimeout/10)
	})
	for {
		readBuffer := make([]byte, defaultReadSize)
		readLen, err := reader.Read(readBuffer)
		if err != nil {
			// flush
			close(tmpBuffer)
			_ = wg.Wait()
			return err
		}
		rb := readBuffer[:readLen]
		logger.Debug("read", zap.ByteString("data", rb))
		cb(rb)
		tmpBuffer <- readBuffer[:readLen]
	}
}

// TODO: reuse chanAgg from streamer
// chanAgg accumulate data from in channel and write larger chunks to channels
func chanAgg(ctx context.Context, in, out chan []byte, readTimeout time.Duration) (err error) {
	lastWrite := time.Now()
	buffer := []byte{}
	buffCounter := 0
L:
	for {
		sinceLastWrite := time.Since(lastWrite)
		iterReadTimeout := readTimeout / 10
		if buffCounter > 10 { // extensive data read
			iterReadTimeout = readTimeout
		}
		wait := time.Duration(0)
		if sinceLastWrite < iterReadTimeout {
			wait = iterReadTimeout - sinceLastWrite
		}
		select {
		case <-ctx.Done():
			err = ctx.Err()
			break L
		case <-time.After(wait):
			lastWrite = time.Now()
			if len(buffer) > 0 {
				out <- buffer
				buffer = []byte{}
			}
			buffCounter = 0
		case data := <-in:
			if data == nil {
				break L
			}
			buffCounter++
			buffer = append(buffer, data...)
		}
	}

	if len(buffer) > 0 {
		out <- buffer
	}
	return err
}

func makeConnWrapper(conn ssh.Channel, logger *zap.Logger) *connWrapper {
	stdoutBuffer := make(chan []byte, 100)
	newCtx, cancel := context.WithCancel(context.Background())
	res := &connWrapper{
		log:               logger,
		stdoutBufferExtra: nil,
		conn:              conn,
		stdoutBuffer:      stdoutBuffer,
	}
	go func() { // will be closed after closing stdout
		err := chanReader(newCtx, conn, stdoutBuffer, time.Second, res.cb, logger)
		if err != nil {
			logger.Debug("sessionStdoutReader error", zap.Error(err))
			close(stdoutBuffer)
		}
		cancel()
	}()
	return res
}

type connWrapper struct {
	log               *zap.Logger
	stdoutBufferExtra []byte
	conn              ssh.Channel
	stdoutBuffer      chan []byte
}

func (m *connWrapper) Write(text []byte) error {
	written, err := m.conn.Write(text)
	if err != nil {
		return err
	}
	m.log.Debug("write", zap.ByteString("text", text), zap.Int("written", written))
	return nil
}

func (m *connWrapper) Close() error {
	m.log.Debug("close")
	return m.conn.Close()
}

func (m *connWrapper) ReadTo(ctx context.Context, expr expr.Expr) (streamer.ReadRes, error) {
	m.log.Debug("read to", zap.String("expr", expr.Repr()))
	res, extra, read, err := streamer.GenericReadX(ctx, m.stdoutBufferExtra, m.stdoutBuffer, defaultReadSize, readTimeout, expr, 0, 0)
	m.stdoutBufferExtra = extra
	if err != nil {
		return nil, err
	}
	if res.RetType == streamer.Timeout {
		return nil, streamer.ThrowReadTimeoutException(streamer.GetLastBytes(read, defaultReadSize))
	}
	return res.ExprRes, nil
}
