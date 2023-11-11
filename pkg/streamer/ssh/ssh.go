/*
Package ssh implements SSH transport.
*/
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/errgroup"

	"go.uber.org/multierr"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/gerror"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/trace"
)

const (
	defaultPort        = 22
	defaultReadTimeout = 20 * time.Second
	defaultReadSize    = 4096
	sftpServerPaths    = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/openssh:/usr/libexec"
)

var _ streamer.Connector = (*Streamer)(nil)

type sshSession struct {
	stdin             io.WriteCloser
	stderr            io.Reader
	stdout            io.Reader
	session           *ssh.Session
	stdoutBuffer      chan []byte
	stdoutBufferExtra []byte
	chanReaderCancel  context.CancelFunc
}

func newSSHSession(stdin io.WriteCloser, stdout, stderr io.Reader, session *ssh.Session, logger *zap.Logger) *sshSession {
	stdoutBuffer := make(chan []byte, 100)
	newCtx, cancel := context.WithCancel(context.Background())
	go func() { // will be closed after closing stdout
		err := chanReader(newCtx, stdout, stdoutBuffer, time.Second, logger)
		if err != nil {
			logger.Debug("sessionStdoutReader error", zap.Error(err))
			close(stdoutBuffer)
		}
	}()
	return &sshSession{
		stdin:             stdin,
		stderr:            stderr,
		stdout:            stdout,
		session:           session,
		stdoutBuffer:      stdoutBuffer,
		stdoutBufferExtra: nil,
		chanReaderCancel:  cancel,
	}
}

type Streamer struct {
	host                   string
	port                   int
	credentials            credentials.Credentials
	logger                 *zap.Logger
	conn                   *ssh.Client
	program                string // session params
	programData            string
	env                    map[string]string
	tunnel                 Tunnel
	credentialsInterceptor func(credentials.Credentials) credentials.Credentials
	session                *sshSession
	onSessionOpenCallbacks []func(*ssh.Session) error
	onChanCloseCallbacks   []func(*ssh.Session) error
	inited                 bool
	trace                  trace.CB
	sftpEnabled            bool
	readTimeout            time.Duration
	forwardAgent           agent.Agent
	hostKeyCallback        ssh.HostKeyCallback
}

func (m *Streamer) SetTrace(cb trace.CB) {
	m.trace = cb
}

func (m *Streamer) SetReadTimeout(timeout time.Duration) time.Duration {
	prev := m.readTimeout
	m.readTimeout = timeout
	return prev
}

func (m *Streamer) EnableSFTP() {
	m.sftpEnabled = true
}

func (m *Streamer) SetCredentialsInterceptor(inter func(credentials.Credentials) credentials.Credentials) {
	m.credentialsInterceptor = inter
}

func NewStreamer(host string, credentials credentials.Credentials, opts ...StreamerOption) *Streamer {
	h := &Streamer{
		host:                   host,
		port:                   defaultPort,
		credentials:            credentials,
		logger:                 nil,
		conn:                   nil,
		program:                "shell",
		programData:            "",
		env:                    map[string]string{},
		tunnel:                 nil,
		credentialsInterceptor: nil,
		session:                nil,
		onSessionOpenCallbacks: nil,
		onChanCloseCallbacks:   nil,
		inited:                 false,
		trace:                  nil,
		sftpEnabled:            false,
		readTimeout:            defaultReadTimeout,
		hostKeyCallback:        ssh.InsecureIgnoreHostKey(),
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.logger == nil {
		h.logger = zap.NewNop()
	}
	return h
}

func NewNetconfStreamer(host string, credentials credentials.Credentials, opts ...StreamerOption) *Streamer {
	opts = append(opts, WithSSHNetconf())
	return NewStreamer(host, credentials, opts...)
}

func (m *Streamer) Write(text []byte) error {
	if m.session == nil {
		err := m.startSession()
		if err != nil {
			return err
		}
	}
	if m.trace != nil {
		m.trace(trace.Write, text)
	}
	written, err := m.session.stdin.Write(text)
	if err != nil {
		return err
	}
	m.logger.Debug("write", zap.ByteString("text", text), zap.Int("written", written))
	return nil
}

// It's impossible to set timeout for Read, so read here and put in channel
func chanReader(ctx context.Context, reader io.Reader, stdoutBuffer chan []byte, readTimeout time.Duration, logger *zap.Logger) error {
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
		logger.Debug("read", zap.ByteString("data", readBuffer[:readLen]))
		tmpBuffer <- readBuffer[:readLen]
	}
}

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

func (m *Streamer) Read(ctx context.Context, size int) ([]byte, error) {
	m.logger.Debug("read", zap.Int("size", size))
	if m.session == nil {
		err := m.startSession()
		if err != nil {
			return nil, err
		}
	}
	res, extra, read, err := streamer.GenericReadX(ctx, m.session.stdoutBufferExtra, m.session.stdoutBuffer, defaultReadSize, m.readTimeout, nil, size, 0)
	if m.trace != nil {
		m.trace(trace.Read, read)
	}
	m.session.stdoutBufferExtra = extra
	if err != nil {
		return nil, err
	}

	if res.RetType == streamer.Timeout {
		return nil, streamer.ThrowReadTimeoutException(streamer.GetLastBytes(read, defaultReadSize))
	}
	return res.BytesRes, nil
}

func (m *Streamer) ReadTo(ctx context.Context, expr expr.Expr) (streamer.ReadRes, error) {
	m.logger.Debug("read to", zap.String("expr", expr.Repr()))
	if m.session == nil {
		err := m.startSession()
		if err != nil {
			return nil, err
		}
	}
	res, extra, read, err := streamer.GenericReadX(ctx, m.session.stdoutBufferExtra, m.session.stdoutBuffer, defaultReadSize, m.readTimeout, expr, 0, 0)
	if m.trace != nil {
		m.trace(trace.Read, read)
	}
	m.session.stdoutBufferExtra = extra
	if err != nil {
		return nil, err
	}

	if res.RetType == streamer.Timeout {
		return nil, streamer.ThrowReadTimeoutException(streamer.GetLastBytes(read, defaultReadSize))
	}
	if res.RetType == streamer.EOF {
		return nil, streamer.ThrowEOFException(streamer.GetLastBytes(read, defaultReadSize))
	}
	return res.ExprRes, nil
}

func (m *Streamer) HasFeature(feature streamer.Const) bool {
	if feature == streamer.AutoLogin || feature == streamer.Cmd {
		return true
	}
	return false
}

type StreamerOption func(*Streamer)

func WithSSHNetconf() StreamerOption {
	return func(h *Streamer) {
		h.program = "subsystem"
		h.programData = "netconf"
	}
}

func WithKnownHostsFiles(files ...string) (StreamerOption, error) {
	hostKeyCallback, err := knownhosts.New(files...)
	if err != nil {
		return nil, err
	}
	return func(h *Streamer) {
		h.hostKeyCallback = hostKeyCallback
	}, nil
}

func WithProgram(program, programData string) StreamerOption {
	return func(h *Streamer) {
		h.program = program
		h.programData = programData
	}
}

func WithLogger(log *zap.Logger) StreamerOption {
	return func(h *Streamer) {
		h.logger = log
	}
}

func WithPort(port int) StreamerOption {
	return func(h *Streamer) {
		h.port = port
	}
}

// WithSSHTunnel sets tunnel as ssh proxy. We do not close after usage because it can be shared with other connections.
func WithSSHTunnel(tunnel Tunnel) StreamerOption {
	return func(h *Streamer) {
		h.tunnel = tunnel
	}
}

func WithTrace(trace trace.CB) StreamerOption {
	return func(h *Streamer) {
		h.trace = trace
	}
}

func WithEnv(key, value string) StreamerOption {
	return func(h *Streamer) {
		h.env[key] = value
	}
}

func (m *Streamer) Close() {
	if m.session != nil && m.session.session != nil {
		err := m.onSessionClose(m.session.session)
		if err != nil {
			m.logger.Error("onSessionClose error", zap.Error(err))
		}
		_ = m.session.stdin.Close()
		_ = m.session.session.Close()
	}
	if m.conn != nil {
		_ = m.conn.Close()
	}
	// cancel chanReader goroutine
	if m.session != nil && m.session.chanReaderCancel != nil {
		m.session.chanReaderCancel()
	}
}

func (m *Streamer) Cmd(ctx context.Context, cmd string) (gcmd.CmdRes, error) {
	m.logger.Debug("run cmd", zap.String("cmd", cmd))
	session, err := m.conn.NewSession()
	if err != nil {
		return nil, err
	}
	err = m.onSessionOpen(session)
	if err != nil {
		if e := session.Close(); e != nil {
			m.logger.Error("session closer error", zap.Error(err))
		}
		return nil, fmt.Errorf("onSessionOpen error %w", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	session.Stdin = r

	for name, value := range m.env {
		err := session.Setenv(name, value)
		if err != nil {
			m.logger.Debug("unable to set PATH env", zap.Error(err))
		}
	}

	defer session.Close()

	cancel := streamer.CloserCTX(ctx, func() {
		_ = session.Close()
	})
	err = session.Run(cmd)
	cancel()
	onSessionCloseErr := m.onSessionCloseCallbacks(session)
	if onSessionCloseErr != nil {
		m.logger.Error("onSessionCloseCallbacks error %w", zap.Error(err))
	}
	status := 0
	if err != nil {
		var errCode *ssh.ExitError
		if errors.As(err, &errCode) {
			status = errCode.ExitStatus()
		} else {
			return nil, err
		}
	}

	stdoutBytes := stdout.Bytes()
	stderrBytes := stderr.Bytes()
	res := gcmd.NewCmdResFull(stdoutBytes, stderrBytes, status, nil)
	return res, nil
}

func (m *Streamer) GetConfig(ctx context.Context) (*ssh.ClientConfig, error) {
	creds := m.credentials
	if m.credentialsInterceptor != nil {
		creds = m.credentialsInterceptor(creds)
	}
	username, err := creds.GetUsername()
	var auths []ssh.AuthMethod
	if err != nil {
		return nil, err
	}
	passwords := creds.GetPasswords()
	if len(passwords) > 0 {
		auths = append(auths, ssh.RetryableAuthMethod(ssh.PasswordCallback(m.passwordCallbackWrapper(passwords)), len(passwords)))
		auths = append(auths, ssh.RetryableAuthMethod(ssh.KeyboardInteractive(m.passwordKICallbackWrapper(passwords)), len(passwords)))
	}

	var signers []ssh.Signer
	key := creds.GetPrivateKey()
	if len(key) > 0 {
		signer, err := ssh.ParsePrivateKey(key)
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			passphrase := creds.GetPassphrase()
			if len(passphrase) > 0 {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
			}
		}
		if err != nil {
			return nil, err
		}
		signers = append(signers, NewSSHSignersLogger(signer, m.logger))
	}
	if creds.AgentEnabled() {
		socket := os.Getenv("SSH_AUTH_SOCK")
		if len(socket) > 0 {
			var d net.Dialer
			m.logger.Debug("connect to agent", zap.String("socket", socket))
			conn, err := d.DialContext(ctx, "unix", socket)
			if err != nil {
				return nil, err
			}
			agentClient := agent.NewClient(conn)
			agentSigners, err := agentClient.Signers()
			if err != nil {
				return nil, err
			}
			for _, s := range agentSigners {
				if as, ok := s.(ssh.AlgorithmSigner); ok {
					signers = append(signers, NewSSHSignersAlgorithmSignerLogger(as, m.logger))
				} else {
					signers = append(signers, NewSSHSignersLogger(s, m.logger))
				}
			}
		} else {
			m.logger.Debug("SSH_AUTH_SOCK is not specified")
		}
	}
	if len(signers) != 0 {
		auths = append(auths, ssh.PublicKeys(signers...))
	}

	sshConf := ssh.Config{}
	sshConf.SetDefaults()
	sshConf.KeyExchanges = append(
		sshConf.KeyExchanges,
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
	)
	sshConf.Ciphers = append(
		sshConf.Ciphers,
		"aes128-cbc",
		"3des-cbc",
		"aes192-cbc",
		"aes256-cbc",
	)
	conf := &ssh.ClientConfig{
		User:            username,
		Auth:            auths,
		HostKeyCallback: m.hostKeyCallback,
		Config:          sshConf,
		Timeout:         15 * time.Second,
	}

	return conf, err
}

func (m *Streamer) openConnect(ctx context.Context) (*ssh.Client, error) {
	conf, err := m.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	remote := m.host + ":" + strconv.Itoa(m.port)
	m.logger.Debug("open connection", zap.String("remote", remote))
	var conn *ssh.Client
	if m.tunnel != nil {
		if !m.tunnel.IsConnected() {
			err := m.tunnel.CreateConnect(ctx)
			if err != nil {
				return nil, err
			}
		}

		tunConn, err := m.tunnel.StartForward(remote)
		if err != nil {
			return nil, err
		}

		conn, err = DialConnCtx(ctx, tunConn, remote, conf)
		if err != nil {
			return nil, err
		}
	} else {
		conn, err = DialCtx(ctx, "tcp", remote, conf)
	}

	return conn, err
}

func (m *Streamer) onSessionOpen(sess *ssh.Session) error {
	var errs []error
	for _, cb := range m.onSessionOpenCallbacks {
		err := cb(sess)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

func (m *Streamer) onSessionClose(sess *ssh.Session) error {
	var errs []error
	for _, cb := range m.onChanCloseCallbacks {
		err := cb(sess)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

func (m *Streamer) onSessionCloseCallbacks(sess *ssh.Session) error {
	var errs []error
	for _, cb := range m.onChanCloseCallbacks {
		m.logger.Debug("call callback", zap.Any("cb", cb))
		err := cb(sess)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return multierr.Combine(errs...)
}

func (m *Streamer) openSession() (*sshSession, error) {
	var stdin io.WriteCloser
	var stdout, stderr io.Reader

	session, err := m.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session error %w", err)
	}
	err = m.onSessionOpen(session)
	if err != nil {
		return nil, fmt.Errorf("onSessionOpen error %w", err)
	}
	stdin, err = session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("StdinPipe error %w", err)
	}
	stdout, err = session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("StdoutPipe error %w", err)
	}
	stderr, err = session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("StderrPipe error %w", err)
	}
	for name, value := range m.env {
		err := session.Setenv(name, value)
		if err != nil {
			stdoutBuf := make([]byte, defaultReadSize)
			stderrBuf := make([]byte, defaultReadSize)
			stdoutRead, _ := stdout.Read(stdoutBuf)
			stderrRead, _ := stderr.Read(stderrBuf)
			return nil, fmt.Errorf("unable to set env %s: %s %s %w", name, string(stdoutBuf[0:stdoutRead]), string(stderrBuf[0:stderrRead]), err)
		}
	}
	m.logger.Debug("request", zap.String("program", m.program), zap.String("program_data", m.programData))
	switch m.program {
	case "shell":
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}
		if err := session.RequestPty("xterm", 0, 200, modes); err != nil {
			return nil, fmt.Errorf("RequestPty error %w", err)
		}
		err := session.Shell()
		if err != nil {
			return nil, fmt.Errorf("shell request error %w", err)
		}
	case "subsystem":
		err := session.RequestSubsystem(m.programData)
		if err != nil {
			return nil, fmt.Errorf("subsystem %s requst error %w", m.programData, err)
		}
	default:
		return nil, fmt.Errorf("unknown ssh session program %s", m.program)
	}

	sess := newSSHSession(stdin, stdout, stderr, session, m.logger)
	return sess, nil
}

func (m *Streamer) GetCredentials() credentials.Credentials {
	return m.credentials
}

func (m *Streamer) Init(ctx context.Context) error {
	if m.inited {
		return fmt.Errorf("already inited")
	}
	if m.credentials == nil {
		return fmt.Errorf("empty credentials")
	}
	m.inited = true

	conn, err := m.openConnect(ctx)
	if err != nil {
		return err
	}
	m.conn = conn

	return nil
}

func (m *Streamer) InitAgentForward() error {
	m.WithOpenSessionCallback(m.startForwarding)
	m.WithCloseSessionCallback(m.stopForwarding)
	return nil
}

func (m *Streamer) WithOpenSessionCallback(fn func(*ssh.Session) error) {
	m.onSessionOpenCallbacks = append(m.onSessionOpenCallbacks, fn)
}

func (m *Streamer) WithCloseSessionCallback(fn func(*ssh.Session) error) {
	m.onChanCloseCallbacks = append(m.onChanCloseCallbacks, fn)
}

func (m *Streamer) startForwarding(sess *ssh.Session) error {
	privKey, err := ssh.ParseRawPrivateKey(m.credentials.GetPrivateKey())
	if _, ok := err.(*ssh.PassphraseMissingError); ok {
		passphrase := m.credentials.GetPassphrase()
		if len(passphrase) > 0 {
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(m.credentials.GetPrivateKey(), []byte(passphrase))
			if err != nil {
				return err
			}
		}
	} else if err != nil {
		return fmt.Errorf("unable to parse private key: %s", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privKey}); err != nil {
		return fmt.Errorf("error adding private key: %s", err)
	}
	if err := agent.RequestAgentForwarding(sess); err != nil {
		return fmt.Errorf("error RequestAgentForwarding: %v", err)
	}
	if err := agent.ForwardToAgent(m.conn, keyring); err != nil {
		return fmt.Errorf("error ForwardToAgent: %v", err)
	}
	m.forwardAgent = keyring
	return nil
}

func (m *Streamer) stopForwarding(sess *ssh.Session) error {
	if m.forwardAgent != nil {
		return m.forwardAgent.RemoveAll()
	}
	return nil
}

func (m *Streamer) startSession() error {
	if m.session == nil {
		m.logger.Debug("open session")
		sess, err := m.openSession()
		if err != nil {
			return err
		}
		m.session = sess
	}
	return nil
}

func (m *Streamer) passwordKICallbackWrapper(passwords []credentials.Secret) func(name, instruction string, questions []string, echos []bool) ([]string, error) {
	passwordIndex := 0
	return func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		m.logger.Debug("passwordCallback", zap.String("name", name), zap.String("instruction", instruction), zap.Strings("questions", questions))
		if len(questions) > 1 {
			return nil, errors.New("unexpected number of questions")
		} else if len(questions) == 0 {
			return []string{}, nil
		}
		if passwordIndex >= len(passwords) { // prevent endless loop
			return nil, gerror.NewAuthException("password auth error")
		}
		password := passwords[passwordIndex]
		passwordIndex++
		return []string{password.Value()}, nil
	}
}

func (m *Streamer) passwordCallbackWrapper(passwords []credentials.Secret) func() (secret string, err error) {
	passwordIndex := 0
	return func() (secret string, err error) {
		m.logger.Debug("passwordCallback", zap.Int("passwordIndex", passwordIndex))
		if passwordIndex >= len(passwords) { // prevent endless loop
			return "", gerror.NewAuthException("password auth error")
		}
		password := passwords[passwordIndex]
		passwordIndex++
		return password.Value(), nil
	}
}

func (m *Streamer) makeSftpClient(useSudo bool) (sc *sftp.Client, stop func(), err error) {
	if !useSudo {
		sc, err = sftp.NewClient(m.conn)
		if err == nil {
			stop = func() {
				_ = sc.Close()
			}
		}
		return
	}

	ctx := context.Background()
	res, err := m.Cmd(ctx, fmt.Sprintf("PATH=%s which sftp-server", sftpServerPaths))
	if err != nil {
		return
	} else if res.Status() != 0 {
		err = fmt.Errorf("sftp-server status %d error %s", res.Status(), res.Error())
		return
	}

	cmd := strings.TrimSpace(string(res.Output()))
	m.logger.Debug("resolved sftp-server", zap.String("path", cmd))
	session, err := m.conn.NewSession()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			_ = session.Close()
		}
	}()

	pw, err := session.StdinPipe()
	if err != nil {
		return
	}
	pr, err := session.StdoutPipe()
	if err != nil {
		return
	}
	err = session.Start("sudo " + cmd)
	if err != nil {
		m.logger.Warn("cannot run sudo sftp-server", zap.Error(err))
		return
	}
	sc, err = sftp.NewClientPipe(pr, pw)
	if err != nil {
		m.logger.Warn("cannot create client for sudo sftp-server", zap.Error(err))
		return
	}
	stop = func() {
		_ = sc.Close()
		_ = session.Close()
	}
	return
}

func (m *Streamer) Download(filePaths []string, recurse bool) (map[string]streamer.File, error) {
	if !m.sftpEnabled {
		return nil, device.ErrorStreamerNotSupportedByDevice
	}

	files, err := m.sftpDownload(filePaths, recurse, false)
	if err != nil {
		return nil, err
	}

	// Retry with sudo files with "permission denied"
	var filePathsWithSudo []string
	for path, file := range files {
		if errors.Is(file.Err, os.ErrPermission) {
			filePathsWithSudo = append(filePathsWithSudo, path)
		}
	}
	if len(filePathsWithSudo) != 0 {
		filesWithSudo, err := m.sftpDownload(filePathsWithSudo, recurse, true)
		if err != nil {
			return nil, err
		}
		for path, file := range filesWithSudo {
			files[path] = file
		}
	}
	return files, nil
}

func (m *Streamer) sftpDownload(filePaths []string, recurse bool, useSudo bool) (map[string]streamer.File, error) {
	sc, stop, err := m.makeSftpClient(useSudo)
	if err != nil {
		return nil, err
	}
	defer stop()

	res := map[string]streamer.File{}
	for _, filePath := range filePaths {
		info, err := sc.Stat(filePath)
		if err != nil {
			res[filePath] = streamer.NewFileError(err)
			continue
		}
		if info.IsDir() {
			if !recurse {
				res[filePath] = streamer.NewFileError(fmt.Errorf("%s is a directory", filePath))
				continue
			}
			walker := sc.Walk(filePath)
			for walker.Step() {
				if walker.Stat().IsDir() {
					continue
				}
				fullPath := walker.Path()
				res[fullPath] = m.sftpDownloadFile(sc, fullPath)
			}
		} else {
			res[filePath] = m.sftpDownloadFile(sc, filePath)
		}
	}

	return res, nil
}

func (m *Streamer) sftpDownloadFile(sc *sftp.Client, filePath string) streamer.File {
	stat, err := sc.Stat(filePath)
	if err != nil {
		return streamer.NewFileError(err)
	}
	fileMode := stat.Mode()
	m.logger.Debug("file", zap.String("path", filePath), zap.Any("stat", stat))
	if fileMode.Type() == fs.ModeSocket {
		return streamer.NewFileError(fmt.Errorf("skip socket file"))
	}
	srcFile, err := sc.OpenFile(filePath, os.O_RDONLY)
	if err != nil {
		return streamer.NewFileError(err)
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(srcFile)
	if err != nil {
		return streamer.NewFileError(err)
	}
	return streamer.NewFile(buf.Bytes(), &fileMode, nil)
}

func (m *Streamer) Upload(filePaths map[string]streamer.File) error {
	if m.sftpEnabled {
		return m.uploadSftp(filePaths, true)
	}
	return device.ErrorStreamerNotSupportedByDevice
}

func (m *Streamer) uploadSftp(filePaths map[string]streamer.File, useSudo bool) error {
	sc, stop, err := m.makeSftpClient(useSudo)
	if err != nil {
		return err
	}
	defer stop()
	for filePath, fileData := range filePaths {
		f, err := sc.Create(filePath)
		if err != nil {
			return err
		}

		_, err = f.Write(fileData.Data)
		if err != nil {
			return err
		}
		if fileData.Mode != nil {
			err = f.Chmod(*fileData.Mode)
			if err != nil {
				return err
			}
		}
		if fileData.Chmod != nil {
			err = f.Chown(fileData.Chmod.UID, fileData.Chmod.GID)
			if err != nil {
				return fmt.Errorf("chmod error %s %v", filePath, fileData.Chmod)
			}
		}
	}
	return nil
}

// DialCtx ssh.Dial version with context arg
func DialCtx(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := streamer.TCPDialCtx(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return DialConnCtx(ctx, conn, addr, config)
}

func DialConnCtx(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-lctx.Done():
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		}
	}()
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// SSHSignersLogger wraps ssh.Signer interface in order to log actions relateds to keys
type SSHSignersLogger struct {
	s   ssh.Signer
	log *zap.Logger
}

type SSHSignersLoggerAlgorithmSigner struct {
	s   ssh.AlgorithmSigner
	log *zap.Logger
}

func (m SSHSignersLogger) PublicKey() ssh.PublicKey {
	// it doesn't necessary means that we called in validateKey(), but it is better than nothing
	m.log.Debug("check", zap.Any("pubkey", m.s.PublicKey()))
	return m.s.PublicKey()
}

func (m SSHSignersLogger) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	m.log.Debug("sign", zap.Any("pubkey", m.s.PublicKey()))
	return m.s.Sign(rand, data)
}

func NewSSHSignersLogger(s ssh.Signer, logger *zap.Logger) *SSHSignersLogger {
	return &SSHSignersLogger{s: s, log: logger}
}

func (m SSHSignersLoggerAlgorithmSigner) PublicKey() ssh.PublicKey {
	m.log.Debug("check", zap.Any("pubkey", m.s.PublicKey()))
	return m.s.PublicKey()
}

func (m SSHSignersLoggerAlgorithmSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	m.log.Debug("sign", zap.Any("pubkey", m.s.PublicKey()))
	return m.s.Sign(rand, data)
}

func (m SSHSignersLoggerAlgorithmSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	m.log.Debug("sign", zap.Any("pubkey", m.s.PublicKey()))
	return m.s.SignWithAlgorithm(rand, data, algorithm)
}

func NewSSHSignersAlgorithmSignerLogger(s ssh.AlgorithmSigner, logger *zap.Logger) *SSHSignersLoggerAlgorithmSigner {
	return &SSHSignersLoggerAlgorithmSigner{
		s:   s,
		log: logger,
	}
}
