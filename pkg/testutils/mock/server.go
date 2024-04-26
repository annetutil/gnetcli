package mock

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/semaphore"
)

type MockSSHServer struct {
	dialog     []Action
	config     *ssh.ServerConfig
	listener   net.Listener
	username   string
	password   string
	privateKey []byte
	log        *zap.Logger
}

func NewMockSSHServer(dialog []Action, opts ...MockSSHServerOption) (*MockSSHServer, error) {
	server := &MockSSHServer{
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

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen for connection: %w", err)
	}

	server.config = config
	server.listener = listener

	return server, nil
}

func (m *MockSSHServer) GetAddress() (string, int) {
	// ipv6 case
	if v6EndIdx := strings.Index(m.listener.Addr().String(), "]"); v6EndIdx != -1 {
		address := m.listener.Addr().String()[0 : v6EndIdx+1]
		portNum, _ := strconv.Atoi(m.listener.Addr().String()[v6EndIdx+2:])
		return address, portNum
	}

	parts := strings.Split(m.listener.Addr().String(), ":")
	address := parts[0]
	portNum, _ := strconv.Atoi(parts[1])
	return address, portNum
}

func (m *MockSSHServer) Run(ctx context.Context) error {
	host, port := m.GetAddress()
	m.log.Debug("Listening", zap.String("host", host), zap.Int("port", port))

	tcpConn, err := m.listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}

	return m.handeConn(ctx, tcpConn)
}

func (m *MockSSHServer) handeConn(ctx context.Context, tcpConn net.Conn) error {
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

func (m *MockSSHServer) handleChannels(ctx context.Context, chans <-chan ssh.NewChannel) error {
	for newChannel := range chans {
		err := m.handleChannel(ctx, newChannel)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *MockSSHServer) handleChannel(ctx context.Context, newChannel ssh.NewChannel) error {
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
		m.log.Debug("exec", zap.String("action", fmt.Sprintf("%T", action)), zap.String("data", fmt.Sprintf("%v", action)))
		err = action.Exec(connection)
		m.log.Debug("exec ok", zap.Error(err))

		if err != nil {
			return err
		}
	}

	return errRes
}
