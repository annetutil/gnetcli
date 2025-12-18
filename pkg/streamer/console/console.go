package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	sshtunnel "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/annetutil/gnetcli/pkg/trace"
	"golang.org/x/sync/errgroup"

	tlshack "github.com/annetutil/gnetcli/internal/tls_hack"
	"go.uber.org/zap"
)

const (
	defaultConserverPort = 10101
	newLine              = "\r\n"
	defaultRedirectLimit = 10
	defattn              = "\x05"
	defesc               = "c"
	cmdStart             = defattn + defesc
	anonymous            = "anonymous"
	ok                   = "ok" + newLine
	ssl                  = "ssl"
	cmdForceAttache      = "f"
	cmdSu                = "su"
	cmdSd                = "sd"
	cmdAttache           = "a"
	cmdExit              = "exit"
	cmdLogin             = "login "
	cmdCall              = "call "
	cmdMasterGroups      = "groups"
	cmdGroupInfo         = "info"
	cmdGroupHelp         = "help"
	cmdInfo              = "i"
	ansSpy               = "[spy]" + newLine
	ansGoodbye           = "goodbye" + newLine
	ansReadOnly          = "[read-only -- initializing]" + newLine
	ansAttached          = "[attached]" + newLine
	ansConnected         = "[connected]" + newLine
	ansInfo              = "[info]" + newLine
	ansOk                = "[ok]" + newLine
	ansUp                = "[up]" + newLine

	readBufferSize     = 256
	readBufferLen      = 100
	defaultReadTimeout = 10 * time.Minute

	regExErrors = `\[((spying|no|line down|read-only|forced to|up|attached|connected|down|unknown|bumped)[^\[\]]*)\]\r\n`
)

type Streamer struct {
	consolePort     string
	speed           int
	currentSpeed    int
	redirectLimit   int
	redirectNo      int
	port            int
	forceAttach     bool
	host            string
	addresses       []net.IP
	credentials     credentials.Credentials
	portCredentials credentials.Credentials
	logger          *zap.Logger
	conn            net.Conn
	// connectedAddress is the first address that Streamer actually managed to connect.
	// Needed to not iterate again over each address during port discovery
	connectedAddress       string
	buffer                 chan []byte
	readerWg               *errgroup.Group
	readerCancel           context.CancelFunc
	bufferExtra            []byte
	conMsgChecker          bool
	ssl                    bool
	tunnel                 sshtunnel.Tunnel
	tunnelHost             string // we manage a tunnel
	credentialsInterceptor func(credentials.Credentials) credentials.Credentials
	readTimeout            time.Duration
	trace                  trace.CB
}

func (m *Streamer) InitAgentForward() error {
	return errors.New("agent forwarding is not supported")
}

func (m *Streamer) SetTrace(cb trace.CB) {
	m.trace = cb
}

func (m *Streamer) SetCredentialsInterceptor(inter func(credentials.Credentials) credentials.Credentials) {
	m.credentialsInterceptor = inter
}

func (m *Streamer) SetReadTimeout(readTimeout time.Duration) time.Duration {
	prev := m.readTimeout
	m.readTimeout = readTimeout
	return prev
}

func (m *Streamer) GetBuffer() []byte {
	return m.bufferExtra
}

func (m *Streamer) FlushBuffer() {
	m.bufferExtra = []byte{}
}

var _ streamer.Connector = (*Streamer)(nil)

func NewStreamer(host, consolePort string, credentials credentials.Credentials, portCredentials credentials.Credentials, opts ...StreamerOption) *Streamer {
	h := &Streamer{
		consolePort:            consolePort,
		speed:                  0,
		currentSpeed:           0,
		redirectLimit:          defaultRedirectLimit,
		redirectNo:             0,
		forceAttach:            false,
		host:                   host,
		port:                   defaultConserverPort,
		addresses:              nil,
		credentials:            credentials,
		portCredentials:        portCredentials,
		logger:                 nil,
		conn:                   nil,
		connectedAddress:       "",
		buffer:                 nil, // buffer for catching console's messages
		readerWg:               &errgroup.Group{},
		readerCancel:           nil,
		bufferExtra:            nil,
		conMsgChecker:          false,
		ssl:                    false,
		tunnel:                 nil,
		tunnelHost:             "",
		credentialsInterceptor: nil,
		readTimeout:            defaultReadTimeout,
		trace:                  nil,
	}

	for _, opt := range opts {
		opt(h)
	}
	if h.logger == nil {
		logConfig := zap.NewDevelopmentConfig()
		logger := zap.Must(logConfig.Build())
		h.logger = logger
	}

	return h
}

type StreamerOption func(*Streamer)

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

// WithAddresses makes streamer use given addresses for connection instead of host resolution
func WithAddresses(addresses []net.IP) StreamerOption {
	return func(h *Streamer) {
		h.addresses = addresses
	}
}

func WithForceAttache() StreamerOption {
	return func(h *Streamer) {
		h.forceAttach = true
	}
}

func WithHackedSSL() StreamerOption {
	return func(h *Streamer) {
		h.ssl = true
	}
}

func WithSpeed(speed int) StreamerOption {
	return func(h *Streamer) {
		h.speed = speed
	}
}

func WithTrace(trace trace.CB) StreamerOption {
	return func(h *Streamer) {
		h.trace = trace
	}
}

func WithSSHTunnelConn(tunnel sshtunnel.Tunnel) StreamerOption {
	return func(h *Streamer) {
		h.tunnel = tunnel
	}
}

func WithSSHTunnel(tunnelHost string) StreamerOption {
	return func(h *Streamer) {
		h.tunnelHost = tunnelHost
	}
}

func (m *Streamer) readLine(ctx context.Context) ([]byte, error) {
	readRes, err := m.ReadTo(ctx, expr.NewSimpleExpr().FromPattern("^.*"+newLine+"$"))
	if err != nil {
		return nil, err
	}

	return readRes.GetMatched(), nil
}

func (m *Streamer) ConsoleCmd(ctx context.Context, command string, sendNewLine bool) ([]byte, error) {
	if sendNewLine {
		command = command + newLine
	}
	err := m.Write([]byte(command))
	if err != nil {
		return nil, err
	}

	return m.readLine(ctx)
}

func (m *Streamer) SendCharacter(ctx context.Context, char byte) ([]byte, error) {
	//  \ooo    send character by octal code
	command := fmt.Sprintf("\x05c\\%03o", char)
	err := m.Write([]byte(command))
	if err != nil {
		return nil, err
	}
	return m.Read(ctx, 11)
}

func makeHackTLS(conn net.Conn, host string) *tlshack.Conn {
	sslConn := tlshack.Client(conn, &tlshack.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tlshack.TLS_DH_anon_WITH_AES_256_GCM_SHA384,
			tlshack.TLS_DH_anon_WITH_AES_256_CBC_SHA,
			tlshack.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
		},
		Rand:                        nil,
		Time:                        nil,
		Certificates:                nil,
		NameToCertificate:           nil,
		GetCertificate:              nil,
		GetClientCertificate:        nil,
		GetConfigForClient:          nil,
		VerifyPeerCertificate:       nil,
		GetPSKIdentityHint:          nil,
		GetPSKIdentity:              nil,
		GetPSKKey:                   nil,
		RootCAs:                     nil,
		NextProtos:                  nil,
		ClientAuth:                  0,
		ClientCAs:                   nil,
		PreferServerCipherSuites:    false,
		SessionTicketsDisabled:      false,
		SessionTicketKey:            [32]byte{},
		ClientSessionCache:          nil,
		MinVersion:                  0,
		MaxVersion:                  0,
		CurvePreferences:            []tlshack.CurveID{tlshack.CurveP256, tlshack.CurveP384, tlshack.CurveP521}, // disable X25519
		DhParameters:                nil,
		DynamicRecordSizingDisabled: false,
		Renegotiation:               0,
		KeyLogWriter:                nil,
	})
	return sslConn
}

func (m *Streamer) setSSL(ctx context.Context) (net.Conn, error) {
	sslConn := makeHackTLS(m.conn, m.host)
	doneCh := make(chan interface{})
	go func() {
		select {
		case <-ctx.Done():
			_ = sslConn.SetDeadline(time.Now())
		case <-doneCh:
			return
		}
	}()

	err := sslConn.Handshake()
	if err != nil {
		return nil, err
	}

	return sslConn, nil
}

func (m *Streamer) login(ctx context.Context) (err error) {
	login := anonymous
	if m.credentials != nil {
		login, err = m.credentials.GetUsername()
		if err != nil {
			return err
		}
	}

	res, err := m.ConsoleCmd(ctx, cmdLogin+login, true)
	if err != nil {
		return err
	}

	if string(res) != ok {
		return ThrowConsoleException([]byte("unexpected data " + string(res) + " expected: " + ok))
	}
	return nil
}

func (m *Streamer) connectConsolePort(ctx context.Context) (err error) {
	res, err := m.ConsoleCmd(ctx, cmdCall+m.consolePort, true)
	if err != nil {
		return err
	}

	switch {
	case bytes.HasPrefix(res, []byte("ambiguous console abbreviation")) ||
		bytes.HasSuffix(res, []byte(" not found\r\n")):
		return ThrowBadConsolePortException(res)
	case bytes.HasPrefix(res, []byte("@")) || unicode.IsDigit(rune(res[0])):
		//redirect
		newPort, err := strconv.Atoi(strings.TrimSpace(string(res)))
		if err != nil {
			return err
		}
		exitCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		res, err = m.ConsoleCmd(exitCtx, cmdExit, true)
		if err != nil {
			//nolint:exhaustivestruct
			if !errors.Is(err, &streamer.ReadTimeoutException{}) {
				return err
			}
		} else {
			if string(res) != ansGoodbye {
				return ThrowConsoleException([]byte("unexpected data " + string(res) + " expected: " + "goodbye" + newLine))
			}
		}

		m.redirectNo++
		if m.redirectNo > m.redirectLimit {
			return ThrowConsoleException([]byte("forwarding level too deep!"))
		}

		err = m.closeForChangePort()
		if err != nil {
			return err
		}

		m.port = newPort

		err = m.Init(ctx)
		if err != nil {
			return err
		}

		return nil

	case string(res) == ansSpy:
		if !m.forceAttach {
			// trying to attach to discover some debug information
			res, err = m.ConsoleCmd(ctx, cmdStart+cmdAttache, false)
			if err != nil {
				return err
			}

			m.Close()
			return ThrowConsolePortIsLockedException([]byte("console is locked by " + strings.TrimSpace(string(res))))
		}

		res, err = m.ConsoleCmd(ctx, cmdStart+cmdForceAttache, false)
		if err != nil {
			return err
		}

		if !bytes.HasPrefix(res, []byte("[bumped ")) {
			return ThrowConsoleException([]byte("unexpected data " + string(res)))
		}
	case string(res) == ok || string(res) == ansReadOnly:
		// Humph, someone else is on or we have an old version of the server (4.X)
		return ThrowConsolePortIsBusyException([]byte(strings.TrimSpace(string(res))))
	case string(res) != ansAttached:
		return ThrowConsoleException([]byte("unexpected data " + string(res)))
	}

	res, err = m.ConsoleCmd(ctx, cmdStart+"=", false)
	if err != nil {
		return err
	}

	if strings.Contains(string(res), " console is down]") { // like [`cuauUSB1' -- console is down]
		return NewConsolePortDownError()
	}
	if string(res) != ansUp {
		return ThrowConsoleException([]byte("unexpected data " + string(res) + " expected: " + ansUp))
	}

	res, err = m.ConsoleCmd(ctx, cmdStart+";", false)
	if err != nil {
		return err
	}

	if string(res) != ansConnected {
		return ThrowConsoleException([]byte("unexpected data " + string(res) + " expected: " + ansConnected))
	}

	m.conMsgChecker = true

	if m.speed != 0 {
		err = m.setSpeed(ctx, m.speed)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Streamer) setSpeed(ctx context.Context, speed int) (err error) {
	if speed != 9600 && speed != 19200 && speed != 38400 && speed != 57600 && speed != 115200 {
		return errors.New("not supported speed")
	}

	if m.currentSpeed == 0 {
		info, err := m.getInformationDump(ctx)
		if err != nil {
			return err
		}
		m.currentSpeed = info[m.consolePort]
	}

	switch {
	case m.currentSpeed < speed:
		err = m.Write([]byte(cmdStart + cmdSu))
		if err != nil {
			return err
		}
	case m.currentSpeed > speed:
		err = m.Write([]byte(cmdStart + cmdSd))
		if err != nil {
			return err
		}
	default:
		return nil
	}

	res, err := m.readLine(ctx)
	if err != nil {
		return err
	}

	r, err := regexp.Compile(`\[serialcfg baud @ (\d+)\]\r\n`)
	if err != nil {
		return err
	}

	if r.MatchString(string(res)) {
		r, err = regexp.Compile(`(\d+)`)
		if err != nil {
			return err
		}

		m.currentSpeed, err = strconv.Atoi(r.FindString(string(res)))
		if err != nil {
			return err
		}
	}

	return m.setSpeed(ctx, speed)
}

func (m *Streamer) getInformationDump(ctx context.Context) (map[string]int, error) {
	res, err := m.ConsoleCmd(ctx, cmdStart+cmdInfo, false)
	if err != nil {
		return nil, err
	}

	if string(res) != ansInfo {
		return nil, ThrowConsoleException([]byte("unexpected data " + string(res) + " expected: " + "[info]\r\n"))
	}

	result := make(map[string]int)

	line, err := m.ConsoleCmd(ctx, cmdStart+cmdAttache, false)
	if err != nil {
		return nil, err
	}

	for string(line) != ansOk {
		if !bytes.HasPrefix(line, []byte("ttyS")) ||
			!bytes.HasSuffix(line, []byte(":\\n\r\n")) {
			return nil, errors.New("unknown line " + string(line))
		}
		lineData, err := m.parseInformationLine(string(line))
		if err != nil {
			return nil, err
		}
		result[lineData["terminal"]], err = strconv.Atoi(lineData["speed"])
		if err != nil {
			return nil, err
		}

		line, err = m.readLine(ctx)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (m *Streamer) parseInformationLine(line string) (res map[string]string, err error) {
	data := strings.Split(line, ":")
	res = make(map[string]string)
	res["terminal"] = data[0]

	r, err := regexp.Compile(`((\d+)n)`)
	if err != nil {
		return nil, err
	}
	speed := r.FindString(data[3])
	res["speed"] = speed[:len(speed)-1]

	return res, nil
}

func (m *Streamer) startBufferReader(ctx context.Context) error {
	if m.buffer != nil {
		close(m.buffer)
	}
	m.bufferExtra = []byte{}
	m.buffer = make(chan []byte, readBufferLen)
	ctxCancel, cancel := context.WithCancel(ctx)
	wg, wCtx := errgroup.WithContext(ctxCancel)
	m.readerWg = wg
	m.readerCancel = cancel

	wg.Go(func() error {
		return streamer.NetReader(wCtx, m.buffer, m.conn, m.logger)
	})
	return nil
}

func (m *Streamer) stopBufferReader() error {
	err := m.conn.SetDeadline(time.Now())
	if err != nil {
		return err
	}
	m.readerCancel()
	_ = m.readerWg.Wait()
	err = m.conn.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	close(m.buffer)
	m.buffer = nil
	return nil
}

type endpoint struct {
	address string
	port    int
}

func (e *endpoint) HostPort() string {
	return net.JoinHostPort(e.address, strconv.Itoa(e.port))
}

func (m *Streamer) getEndpoints() []endpoint {
	if len(m.connectedAddress) != 0 {
		return []endpoint{{
			address: m.connectedAddress,
			port:    m.port,
		}}
	}
	if len(m.addresses) != 0 {
		endpoints := make([]endpoint, 0, len(m.addresses))
		for _, v := range m.addresses {
			endpoints = append(endpoints, endpoint{
				address: v.String(),
				port:    m.port,
			})
		}
		return endpoints
	}
	return []endpoint{
		{
			address: m.host,
			port:    m.port,
		},
	}
}

func (m *Streamer) setupConnection(ctx context.Context) error {
	logger := m.logger.With(zap.String("host", m.host), zap.Int("port", m.port))
	endpoints := m.getEndpoints()
	if m.tunnel != nil || len(m.tunnelHost) > 0 {
		if m.tunnel == nil {
			logger.Debug("open tunnel", zap.String("tunnel", m.tunnelHost))
			m.tunnel = sshtunnel.NewSSHTunnel(m.tunnelHost, m.credentials)
		}
		if !m.tunnel.IsConnected() {
			err := m.tunnel.CreateConnect(ctx)
			if err != nil {
				return err
			}
		}
		for i, v := range endpoints {
			logger.Debug("open tunnel connection", zap.String("host", v.HostPort()))
			conn, err := m.tunnel.StartForward(v.HostPort())
			if err == nil {
				m.connectedAddress = v.address
				m.conn = conn
				break
			}
			if i == len(endpoints)-1 {
				return fmt.Errorf("tunnel forward error %w", err)
			}
			logger.Debug("failed to connect endpoint, trying next", zap.String("remote endpoint", v.HostPort()), zap.Error(err))
		}
	} else {
		logger.Debug("open connection")
		for i, v := range endpoints {
			conn, err := streamer.TCPDialCtx(ctx, "tcp", v.HostPort())
			if err == nil {
				m.connectedAddress = v.address
				m.conn = conn
				break
			}
			if i == len(endpoints)-1 {
				return fmt.Errorf("failed to dial all given endpoints: %w", err)
			}
			logger.Debug("failed to connect endpoint, trying next", zap.String("remote endpoint", v.HostPort()), zap.Error(err))
		}
	}

	err := m.startBufferReader(ctx)
	if err != nil {
		return err
	}

	// initial ok read
	res, err := m.readLine(ctx)
	if err != nil {
		return err
	}

	if string(res) != ok {
		return fmt.Errorf("not ok answer: %q", res)
	}
	if m.ssl {
		res, err = m.ConsoleCmd(ctx, ssl, true)
		if err != nil {
			return err
		}

		if string(res) != ok {
			return errors.New("ssl connection answer not ok")
		}

		_ = m.stopBufferReader()
		sslConn, err := m.setSSL(ctx)
		if err != nil {
			return err
		}
		m.conn = sslConn
		err = m.startBufferReader(ctx)
		if err != nil {
			return err
		}
	}

	err = m.login(ctx)
	if err != nil {
		return err
	}
	return nil
}

const commandInfoPattern = `^(?P<server>[^:]+?):` +
	`(?P<myhost>[^,]+?),` +
	`(?P<pid>[^,]+?),` +
	`(?P<port>[^:]+?):` +
	`/:` + //  case DEVICE
	`(?P<device>[^,]+?),` +
	`(?P<baud>[\d]+?)(?P<flow_control>.),` +
	`(?P<parity>[-\d]+?):` +
	// :%s:%s:%s,%s,%s,%s,%s,%d,%d:%d:%s:
	`(?P<pCLwr>.*?):` + // client that is writing on console. Format "w@%s@%ld",
	`(?P<iostate>(up|down|init)):` + // up, init or down
	`(?P<fronly>[^:]+?):` + // ro rw
	`(?P<logfile>[^,]*?),` +
	`(?P<nolog>[^,]+?),` + // "nolog" : "log"),
	`(?P<activitylog>[^,]+?),` + // "act" : "noact"),
	`(?P<breaklog>[^,]+?),` + //  "brk" : "nobrk"),
	`(?P<tasklog>(task|notask),)?` + // "task" : "notask")
	`(?P<mark>[\d-]+?),` +
	`(?P<fd>[^:]+?):` + // fd or -1
	`(?P<breakNum>[^:]+?):` + // fd or -1
	`(?P<autoReUp>[^:]+?):` + //  "autoup" : "noautoup"
	// ":%s:%s:%d:%s\r\n",
	`:(?P<s>[^:]*?):` + //  reinitoncc, reinitoncc, ...
	`(?P<initcmd>[^:]*?):` +
	`(?P<idletimeout>[\d]*?):` +
	`(?P<idlestring>[^:]*?)$`

type CommandInfoResult struct {
	portName string
	iostate  string
	port     int
	speed    int
	pCLwr    string
}

var _ CommandInfoPort = (*CommandInfoResult)(nil)

func (m CommandInfoResult) GetPort() int {
	return m.port
}
func (m CommandInfoResult) GetSpeed() int {
	return m.speed
}

func (m CommandInfoResult) GetPCLwr() string {
	for _, lString := range strings.Split(m.pCLwr, ",") {
		if len(lString) > 0 && lString[0] == 'w' { // r - spy
			return lString
		}
	}
	return ""
}

func (m CommandInfoResult) GetPortName() string {
	return m.portName
}

type CommandInfoPort interface {
	GetPort() int
	GetSpeed() int
	GetPCLwr() string
}

type CommandsInfoResult map[string]CommandInfoPort

func parseInfoLine(data []byte) (*CommandInfoResult, error) {
	lp := expr.NewSimpleExpr().FromPattern(commandInfoPattern)
	res, ok := lp.Match(data)
	if !ok {
		return nil, fmt.Errorf("parse error")
	}
	port, err := strconv.Atoi(string(res.GroupDict["port"]))
	if err != nil {
		return nil, err
	}
	speed, err := strconv.Atoi(string(res.GroupDict["baud"]))
	if err != nil {
		return nil, err
	}
	return &CommandInfoResult{
		portName: string(res.GroupDict["server"]),
		iostate:  string(res.GroupDict["iostate"]),
		port:     port,
		pCLwr:    string(res.GroupDict["pCLwr"]),
		speed:    speed,
	}, nil
}

func (m *Streamer) DiscoveryAllPorts(ctx context.Context) (CommandsInfoResult, error) {
	res := map[string]CommandInfoPort{}
	err := m.setupConnection(ctx)
	if err != nil {
		return nil, err
	}
	groupsRes, err := m.ConsoleCmd(ctx, cmdMasterGroups, true)
	if err != nil {
		return nil, err
	}
	groups := strings.Trim(string(groupsRes), "\r\n")
	m.logger.Debug("found groups", zap.String("groups", groups))
	portsSlice := strings.Split(groups, ":")
	for _, port := range portsSlice {
		_ = m.stopBufferReader()
		portParsed, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		m.port = portParsed
		err = m.setupConnection(ctx)
		if err != nil {
			return nil, err
		}
		err = m.Write([]byte(cmdGroupInfo + "\r\n")) // multiline answer
		if err != nil {
			return nil, err
		}
		// there is no definitive end of output, so we rely on help's answer
		err = m.Write([]byte(cmdGroupHelp + "\r\n"))
		if err != nil {
			return nil, err
		}
		info, err := m.ReadTo(ctx, expr.NewSimpleExpr().FromPattern("send broadcast message")) // start of help message
		if err != nil {
			return nil, err
		}
		_ = m.Write([]byte("exit\r\n"))
		read := info.GetBefore()
		lines := bytes.Split(read, []byte("\r\n"))
		lines = lines[:len(lines)-1] // drop last line with help message
		for _, line := range lines {
			lineRes, err := parseInfoLine(line)
			if err != nil {
				return nil, fmt.Errorf("parse line='%s' error: %s", line, err)
			}
			res[lineRes.GetPortName()] = lineRes
		}
	}
	return res, nil
}

func (m *Streamer) Init(ctx context.Context) error {
	err := m.setupConnection(ctx)
	if err != nil {
		return err
	}
	err = m.connectConsolePort(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (m *Streamer) GetCredentials() credentials.Credentials {
	return m.portCredentials
}

func (m *Streamer) UpdatePortCredentials(creds credentials.Credentials) {
	m.portCredentials = creds
}

func (m *Streamer) Close() {
	if m.conn != nil {
		_ = m.conn.Close()
	}

	if m.tunnel != nil && len(m.tunnelHost) > 0 {
		m.tunnel.Close()
	}
}

func (m *Streamer) closeForChangePort() error {
	if m.conn != nil {
		err := m.conn.Close()
		if err != nil {
			return err
		}
	}
	m.conn = nil

	return nil
}

func (m *Streamer) ReadTo(ctx context.Context, exp expr.Expr) (streamer.ReadRes, error) {
	m.logger.Debug("read to", zap.String("expr", exp.Repr()))
	exprs := expr.NewSimpleExprList(exp, expr.NewSimpleExpr().FromPattern(regExErrors))
	res, extra, read, err := streamer.GenericReadX(ctx, m.bufferExtra, m.buffer, readBufferSize, m.readTimeout, exprs, 0, 0)
	if m.trace != nil {
		m.trace(trace.Read, read)
	}
	m.bufferExtra = extra
	if err != nil {
		return nil, err
	}
	if res.RetType != streamer.Expr {
		// TODO: uncomment after update
		//return nil, fmt.Errorf("unexpected read res type %v", res.RetType.String())
		return nil, fmt.Errorf("unexpected read res type %v", res.RetType)
	}

	if !m.conMsgChecker {
		return res.ExprRes, nil
	}
	if res.ExprRes.GetPatternNo() == 1 {
		return nil, ThrowConsoleException(res.ExprRes.GetBefore())
	}
	underlyingRes := res.ExprRes.GetUnderlyingRes()
	if underlyingRes == nil {
		return nil, fmt.Errorf("empty underlyingRes")
	}
	return underlyingRes, nil
}

func (m *Streamer) CheckConsoleError(readRes streamer.ReadRes) error {
	res := readRes.GetMatched()

	r, err := regexp.Compile(regExErrors)
	if err != nil {
		return err
	}

	if r.MatchString(string(res)) {
		return ThrowConsoleException(res)
	}
	return nil
}

func (m *Streamer) Read(ctx context.Context, size int) ([]byte, error) {
	m.logger.Debug("read", zap.Int("size", size))
	res, extra, read, err := streamer.GenericReadX(ctx, m.bufferExtra, m.buffer, readBufferSize, m.readTimeout, nil, size, 0)
	if err == nil && res.RetType != streamer.Size {
		return nil, fmt.Errorf("unexpected res type %d", res.RetType)
	}
	if m.trace != nil {
		m.trace(trace.Read, read)
	}
	m.bufferExtra = extra
	return res.BytesRes, err
}

func (m *Streamer) XRead(ctx context.Context, size int, duration time.Duration, expr expr.Expr) (*streamer.ReadXRes, error) {
	m.logger.Debug("read to", zap.Int("size", size), zap.Any("expr", expr), zap.Duration("duration", duration))
	res, extra, read, err := streamer.GenericReadX(ctx, m.bufferExtra, m.buffer, size, duration, expr, size, duration)
	m.bufferExtra = extra
	if m.trace != nil {
		m.trace(trace.Read, read)
	}
	return res, err
}

func (m *Streamer) Cmd(ctx context.Context, str string) (cmd.CmdRes, error) {
	return nil, errors.New("execute is not supported by console")
}

func (m *Streamer) Write(text []byte) error {
	if m.conn == nil {
		return errors.New("no connection")
	}
	if m.trace != nil {
		m.trace(trace.Write, text)
	}
	written, err := m.conn.Write(text)
	m.logger.Debug("write", zap.ByteString("text", text), zap.Int("written", written))
	if err != nil {
		return err
	}

	return nil
}

func (m *Streamer) Download(paths []string, recurse bool) (map[string]streamer.File, error) {
	return nil, streamer.ErrNotSupported
}

func (m *Streamer) Upload(m2 map[string]streamer.File) error {
	return streamer.ErrNotSupported

}

func (m *Streamer) HasFeature(feature streamer.Const) bool {
	return false
}
