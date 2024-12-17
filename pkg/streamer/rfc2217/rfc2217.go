// https://www.rfc-editor.org/rfc/rfc2217.html
package rfc2217

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/telnet"
	"github.com/annetutil/gnetcli/pkg/trace"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

var _ streamer.Connector = (*Streamer)(nil)

const (
	defaultReadSize    = 4096
	defaultReadTimeout = 20 * time.Second
	defaultPort        = 4001
)
const (
	COM_PORT_OPTION  = "\x2c"
	BCOM_PORT_OPTION = 44
	// TelnetOption and TelnetSubnegotiation states
	REQUESTED       = "REQUESTED"
	ACTIVE          = "ACTIVE"
	INACTIVE        = "INACTIVE"
	REALLY_INACTIVE = "REALLY_INACTIVE"
	// Client to Access Server
	SET_BAUDRATE        = "\x01"
	SET_DATASIZE        = "\x02"
	SET_PARITY          = "\x03"
	SET_STOPSIZE        = "\x04"
	SET_CONTROL         = "\x05"
	NOTIFY_LINESTATE    = "\x06"
	NOTIFY_MODEMSTATE   = "\x07"
	FLOWCONTROL_SUSPEND = "\x08"
	FLOWCONTROL_RESUME  = "\x09"
	SET_LINESTATE_MASK  = "\x0a"
	SET_MODEMSTATE_MASK = "\x0b"
	PURGE_DATA          = "\x0c"

	SERVER_SET_BAUDRATE        = "\x65"
	SERVER_SET_DATASIZE        = "\x66"
	SERVER_SET_PARITY          = "\x67"
	SERVER_SET_STOPSIZE        = "\x68"
	SERVER_SET_CONTROL         = "\x69"
	SERVER_NOTIFY_LINESTATE    = "\x6a"
	SERVER_NOTIFY_MODEMSTATE   = "\x6b"
	SERVER_FLOWCONTROL_SUSPEND = "\x6c"
	SERVER_FLOWCONTROL_RESUME  = "\x6d"
	SERVER_SET_LINESTATE_MASK  = "\x6e"
	SERVER_SET_MODEMSTATE_MASK = "\x6f"
	SERVER_PURGE_DATA          = "\x70"
)

type Streamer struct {
	credentials            credentials.Credentials
	logger                 *zap.Logger
	host                   string
	port                   int
	conn                   net.Conn
	stdoutBuffer           chan []byte
	stdoutBufferExtra      []byte
	credentialsInterceptor func(credentials.Credentials) credentials.Credentials
	trace                  trace.CB
	readTimeout            time.Duration
	// rfc
	linestate           int
	modemstate          int
	modemstate_timeout  time.Duration
	remote_suspend_flow bool
	is_open             bool
	expectedTelnet      []telnetOption
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
	m.logger.Debug("open connection", zap.String("host", m.host), zap.Int("port", m.port))
	conn, err := streamer.TCPDialCtx(ctx, "tcp", net.JoinHostPort(m.host, strconv.Itoa(m.port)))
	if err != nil {
		return err
	}
	m.conn = conn
	// https://github.com/pyserial/pyserial/blob/master/serial/rfc2217.py#L430
	mandadoryOptions := []telnetOption{
		NewTelnetOption("we-BINARY", telnet.BBINARY, telnet.BWILL, telnet.BWONT, telnet.BDO, telnet.BDONT, INACTIVE, nil),
		NewTelnetOption("we-RFC2217", BCOM_PORT_OPTION, telnet.BWILL, telnet.BWONT, telnet.BDO, telnet.BDONT, REQUESTED, nil),
	}
	// all supported telnet options
	telnetOptions := []telnetOption{
		NewTelnetOption("ECHO", telnet.BECHO, telnet.BDO, telnet.BDONT, telnet.BWILL, telnet.BWONT, REQUESTED, nil),
		NewTelnetOption("we-SGA", telnet.BSGA, telnet.BWILL, telnet.BWONT, telnet.BDO, telnet.BDONT, REQUESTED, nil),
		NewTelnetOption("they-SGA", telnet.BSGA, telnet.BDO, telnet.BDONT, telnet.BWILL, telnet.BWONT, REQUESTED, nil),
		NewTelnetOption("they-BINARY", telnet.BBINARY, telnet.BDO, telnet.BDONT, telnet.BWILL, telnet.BWONT, INACTIVE, nil),
		NewTelnetOption("they-RFC2217", BCOM_PORT_OPTION, telnet.BDO, telnet.BDONT, telnet.BWILL, telnet.BWONT, REQUESTED, nil),
	}
	opts := make([]telnetOption, 0, len(telnetOptions)+len(mandadoryOptions))
	opts = append(opts, telnetOptions...)
	opts = append(opts, mandadoryOptions...)
	// RFC 2217 specific states
	// COM port settings
	rfc2217_port_settings := map[string]subNegotiation{
		"baudrate": NewSubNegotiation("baudrate", SET_BAUDRATE, SERVER_SET_BAUDRATE),
		"datasize": NewSubNegotiation("datasize", SET_DATASIZE, SERVER_SET_DATASIZE),
		"parity":   NewSubNegotiation("parity", SET_PARITY, SERVER_SET_PARITY),
		"stopsize": NewSubNegotiation("stopsize", SET_STOPSIZE, SERVER_SET_STOPSIZE),
	}
	// There are more subnegotiation objects, combine all in one dictionary
	// for easy access
	rfc2217_options := map[string]subNegotiation{
		"purge":   NewSubNegotiation("purge", PURGE_DATA, SERVER_PURGE_DATA),
		"control": NewSubNegotiation("control", SET_CONTROL, SERVER_SET_CONTROL),
	}
	rfc2217Opts := make(map[string]subNegotiation, len(rfc2217_options)+len(rfc2217_port_settings))
	for k, v := range rfc2217_options {
		rfc2217Opts[k] = v
	}
	for k, v := range rfc2217_port_settings {
		rfc2217Opts[k] = v
	}
	// cache for line and modem states that the server sends to us
	m.linestate = 0
	m.modemstate = 0
	m.modemstate_timeout = time.Duration(0)
	// RFC 2217 flow control between server and client
	m.remote_suspend_flow = false
	m.is_open = true
	for _, option := range opts {
		if option.state == REQUESTED {
			m.sendTelnetOption(option)
			m.addExpectedTelnetNeg(option)
		}
	}
	m.logger.Debug("connection opened")
	eg, _ := errgroup.WithContext(ctx)
	eg.Go(func() error { return m.reader(m.conn) })
	time.Sleep(time.Second)
	return nil
}

func (m *Streamer) addExpectedTelnetNeg(option telnetOption) {
	m.expectedTelnet = append(m.expectedTelnet, option)
}

func (m *Streamer) sendTelnetOption(option telnetOption) {
	m.logger.Debug("send option", zap.String("option", option.name))
	m.internalRawWrite([]byte{telnet.BIAC, option.send_yes, option.option})
}

func (m *Streamer) internalRawWrite(data []byte) {
	m.logger.Debug("write", zap.ByteString("data", data))
	m.conn.Write(data)
}

func (m *Streamer) GetCredentials() credentials.Credentials {
	return m.credentials
}

func NewStreamer(host string, port int, credentials credentials.Credentials, opts ...StreamerOption) *Streamer {
	stdoutBuffer := make(chan []byte, 100)
	h := &Streamer{
		credentials:            credentials,
		logger:                 zap.NewNop(),
		host:                   host,
		port:                   port,
		conn:                   nil,
		stdoutBuffer:           stdoutBuffer,
		stdoutBufferExtra:      nil,
		credentialsInterceptor: nil,
		trace:                  nil,
		readTimeout:            defaultReadTimeout,
		expectedTelnet:         []telnetOption{},
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

const (
	MNormal = iota
	IACSeen
	MNegotiate
)

func (m *Streamer) processSubnegotiation(subopts []byte) {
	// TODO: write some code
	m.logger.Debug("processSubnegotiation", zap.Any("subopts", subopts))
}

func (m *Streamer) negotiateOption(command byte, option byte) {
	// check our registered telnet options and forward command to them
	// they know themselves if they have to answer or not
	m.logger.Debug("negotiate option", zap.Any("command", command), zap.Any("option", option))

	known := false
	for _, item := range m.expectedTelnet {
		if item.option == option {
			m.logger.Debug("process option", zap.Any("name", item.name), zap.Any("command", command))
			item.process(m, command)
			known = true
		}
	}
	if !known {
		// handle unknown options
		// only answer to positive requests and deny them
		if command == telnet.BWILL || command == telnet.BDO {
			m.logger.Debug("reject option", zap.Any("cmd", command), zap.Any("option", option))
			if command == telnet.BWILL {
				m.sendTelnetOption(telnetOption{option: option, send_yes: telnet.BWONT})
			} else {
				m.sendTelnetOption(telnetOption{option: option, send_yes: telnet.BDONT})
			}
		}
	}
}

func (m *Streamer) telnetProcessCommand(subopts byte) {
	m.logger.Debug("telnet_process_command", zap.Any("subopts", subopts))
}

// It"s impossible to set timeout for Read, so read here and put in channel
func (m *Streamer) reader(reader io.Reader) error {
	mode := MNormal
	suboption := []byte{}
	var telnetCommand byte

	buffered := bufio.NewReader(reader)
	for {
		var b byte
		b, err := buffered.ReadByte()
		if nil != err {
			return err
		}
		m.logger.Debug("read", zap.Any("data", b))
		switch mode {
		case MNormal:
			if b == telnet.BIAC {
				mode = IACSeen
			} else {
				// store data in read buffer or sub option buffer
				// depending on state
				if len(suboption) > 0 {
					suboption = append(suboption, b)
				} else {
					m.stdoutBuffer <- []byte{b}
				}
			}
		case IACSeen:
			switch b {
			case telnet.BIAC:
				// interpret as command doubled -> insert character itself
				if len(suboption) != 0 {
					suboption = append(suboption, byte(telnet.BIAC))
				} else {
					// self._read_buffer.put(IAC)
					m.logger.Debug("read", zap.ByteString("data", []byte{telnet.BIAC}))
					m.stdoutBuffer <- []byte{telnet.BIAC}
				}
				mode = MNormal
			case telnet.BSB:
				// sub option start
				suboption = []byte{}
				mode = MNormal
			case telnet.BSE:
				// sub option end -> process it now
				m.processSubnegotiation(suboption)
				suboption = []byte{}
				mode = MNormal
			case telnet.BDO, telnet.BDONT, telnet.BWILL, telnet.BWONT:
				// negotiation
				telnetCommand = b
				mode = MNegotiate
			default:
				// other telnet commands
				m.telnetProcessCommand(b)
				mode = MNormal
			}
		case MNegotiate: // DO, DONT, WILL, WONT was received, option now following
			m.negotiateOption(telnetCommand, b)
			mode = MNormal
		}
	}
}

type telnetOption struct {
	name                string
	option              byte
	send_yes            byte
	send_no             byte
	ack_yes             byte
	ack_no              byte
	state               string
	active              bool
	activation_callback func()
}

func NewTelnetOption(name string, option byte, send_yes byte, send_no byte, ack_yes, ack_no byte, initial_state string, activation_callback func()) telnetOption {
	return telnetOption{
		name:                name,
		option:              option,
		send_yes:            send_yes,
		send_no:             send_no,
		ack_yes:             ack_yes,
		ack_no:              ack_no,
		state:               initial_state,
		activation_callback: activation_callback,
	}
}

func (m *telnetOption) process(s *Streamer, command byte) error {
	//A DO/DONT/WILL/WONT was received for this option, update state and
	// answer when needed.
	if command == m.ack_yes {
		if m.state == REQUESTED {
			m.state = ACTIVE
			m.active = true
			if m.activation_callback != nil {
				m.activation_callback()
			}
		} else if m.state == ACTIVE {
		} else if m.state == INACTIVE {
			m.state = ACTIVE
			s.sendTelnetOption(telnetOption{option: m.option, send_yes: m.send_yes})
			m.active = true
			if m.activation_callback != nil {
				m.activation_callback()
			}
		} else if m.state == REALLY_INACTIVE {
			s.sendTelnetOption(telnetOption{option: m.option, send_yes: m.send_yes})
		} else {
			return fmt.Errorf("option in illegal state")
		}
	} else if command == m.ack_no {
		if m.state == REQUESTED {
			m.state = INACTIVE
			m.active = false
		} else if m.state == ACTIVE {
			m.state = INACTIVE
			s.sendTelnetOption(telnetOption{option: m.option, send_no: m.send_no})
			m.active = false
		} else if m.state == INACTIVE {
		} else if m.state == REALLY_INACTIVE {

		} else {
			return fmt.Errorf("option in illegal state")
		}
	}
	return nil
}

type subNegotiation struct {
	name       string
	option     string
	ack_option string
}

func NewSubNegotiation(name, option, ack_option string) subNegotiation {
	return subNegotiation{
		name:       name,
		option:     option,
		ack_option: ack_option,
	}
}
