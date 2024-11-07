package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"

	"github.com/annetutil/gnetcli/pkg/credentials"
)

type Tunnel interface {
	Close()
	IsConnected() bool
	CreateConnect(context.Context) error
	StartForward(network Network, addr string) (net.Conn, error)
}

type SSHTunnel struct {
	Server      Endpoint
	Config      *ssh.ClientConfig
	svrConn     *ssh.Client
	isOpen      bool
	credentials credentials.Credentials
	logger      *zap.Logger
	mu          sync.Mutex
}

func NewSSHTunnel(host string, credentials credentials.Credentials, opts ...SSHTunnelOption) *SSHTunnel {
	h := &SSHTunnel{
		Server:      NewEndpoint(host, defaultPort, TCP),
		Config:      nil,
		svrConn:     nil,
		isOpen:      false,
		credentials: credentials,
		logger:      zap.NewNop(),
		mu:          sync.Mutex{},
	}

	for _, opt := range opts {
		opt(h)
	}
	return h
}

type SSHTunnelOption func(m *SSHTunnel)

func SSHTunnelWithLogger(log *zap.Logger) SSHTunnelOption {
	return func(h *SSHTunnel) {
		h.logger = log
	}
}

func SSHTunnelWithNetwork(network Network) SSHTunnelOption {
	return func(h *SSHTunnel) {
		h.Server.Network = network
	}
}

func SSHTunnelWitPort(port int) SSHTunnelOption {
	return func(h *SSHTunnel) {
		h.Server.Port = port
	}
}

func (m *SSHTunnel) CreateConnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	connector := NewStreamer(m.Server.Host, m.credentials, WithLogger(m.logger))
	conf, err := connector.GetConfig(ctx)
	if err != nil {
		m.logger.Error(err.Error())
		return err
	}

	m.Config = conf

	serverConn, err := DialCtx(ctx, m.Server, nil, m.Config, m.logger)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			m.logger.Error(err.Error())
		}
		return err
	}
	m.logger.Debug("connected to tunnel", zap.String("server", m.Server.String()))
	m.svrConn = serverConn
	m.isOpen = true
	return nil
}

func (m *SSHTunnel) StartForward(network Network, remoteAddr string) (net.Conn, error) {
	if !m.isOpen {
		return nil, errors.New("connection is closed")
	}
	lconn, rconn, err := m.makeSocketFromSocketPair()
	if err != nil {
		return nil, err
	}
	remoteConn, err := m.svrConn.Dial(string(network), remoteAddr)
	if err != nil {
		return nil, err
	}

	m.logger.Debug("start forward", zap.String("to", remoteAddr), zap.String("from", m.svrConn.RemoteAddr().String()))

	copyConn := func(writer, reader net.Conn) error {
		_, err := io.Copy(writer, reader)
		m.logger.Debug("done", zap.Error(err))
		return err
	}
	wg, _ := errgroup.WithContext(context.Background())
	wg.Go(func() error {
		err := copyConn(rconn, remoteConn)
		_ = rconn.Close()
		return err
	})
	wg.Go(func() error {
		err := copyConn(remoteConn, rconn)
		_ = remoteConn.Close()
		return err
	})

	go func() {
		err := wg.Wait()
		m.logger.Debug("tunnel done", zap.String("remote", remoteAddr), zap.Error(err))
	}()

	// There is no easy way to make key string from unix conn, so we can't track forwarded cons
	return lconn, nil
}

func (m *SSHTunnel) IsConnected() bool {
	return m.isOpen
}

func (m *SSHTunnel) Close() {
	if !m.isOpen {
		err := errors.New("connection is closed")
		m.logger.Error(err.Error())
		return
	}

	m.isOpen = false

	m.logger.Debug("closing the serverConn")
	err := m.svrConn.Close()
	if err != nil {
		m.logger.Error(err.Error())
	}

	m.logger.Debug("tunnel closed")
}

func (m *SSHTunnel) makeSocketFromSocketPair() (net.Conn, net.Conn, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}

	f0 := os.NewFile(uintptr(fds[0]), "socketpair-0")
	defer f0.Close()
	c0, err := net.FileConn(f0)
	if err != nil {
		return nil, nil, err
	}
	f1 := os.NewFile(uintptr(fds[1]), "socketpair-0")
	defer f1.Close()
	c1, err := net.FileConn(f1)
	if err != nil {
		return nil, nil, err
	}

	return c0, c1, nil
}
