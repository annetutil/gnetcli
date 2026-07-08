package gswitch

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync/atomic"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type connections struct {
	inFlight            atomic.Int32
	done                atomic.Int32
	username            string
	password            string
	authCallback        AuthCallback
	connectionErrorProb float64
}

func newConnections(username, password string, authCallback AuthCallback, connectionErrorProb float64) *connections {
	return &connections{
		inFlight:            atomic.Int32{},
		done:                atomic.Int32{},
		username:            username,
		password:            password,
		authCallback:        authCallback,
		connectionErrorProb: connectionErrorProb,
	}
}

func (c *connections) shouldSimulateConnectionError() bool {
	if c.connectionErrorProb <= 0 {
		return false
	}
	return rand.Float64() < c.connectionErrorProb
}

func (c *connections) handleSSHConnection(ctx context.Context, tcpConn net.Conn, config *ssh.ServerConfig, logger *zap.Logger) error {
	defer tcpConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
	if err != nil {
		return fmt.Errorf("failed to handshake: %w", err)
	}
	defer sshConn.Close()

	logger.Debug("new SSH connection", zap.String("addr", sshConn.RemoteAddr().String()), zap.Int32("inFlight", c.inFlight.Load()))
	defer logger.Debug("SSH connection closed", zap.String("addr", sshConn.RemoteAddr().String()))
	c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	defer c.done.Add(1)
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			c.handleSessionChannel(ctx, newChannel, logger)
		case "direct-tcpip":
			c.handleDirectTCPIPChannel(ctx, newChannel, logger)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}

	return nil
}

func (c *connections) handleSessionChannel(ctx context.Context, newChannel ssh.NewChannel, logger *zap.Logger) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Error("could not accept channel", zap.Error(err))
		return
	}

	go func() {
		defer channel.Close()

		go func() {
			for req := range requests {
				req.Reply(req.Type == "shell" || req.Type == "pty-req" || req.Type == "auth-agent-req@openssh.com", nil)
			}
		}()

		logger.Debug("start CLI session")
		session := NewCLISession(channel, c.username, c.password, logger, vendors["cisco"])
		err := session.Run(ctx)
		if err != nil {
			logger.Debug("CLI session ended", zap.Error(err))
		}
	}()
}

type directTCPIPChannelData struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

func (c *connections) handleDirectTCPIPChannel(ctx context.Context, newChannel ssh.NewChannel, logger *zap.Logger) {
	var channelData directTCPIPChannelData
	if err := ssh.Unmarshal(newChannel.ExtraData(), &channelData); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("invalid direct-tcpip data: %s", err))
		return
	}
	remoteAddr := fmt.Sprintf("%s:%d", channelData.RAddr, channelData.RPort)
	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = remoteConn.Close()
		logger.Error("could not accept direct-tcpip channel", zap.Error(err))
		return
	}
	go ssh.DiscardRequests(requests)

	go func() {
		defer channel.Close()
		defer remoteConn.Close()

		logger.Debug("start direct-tcpip", zap.String("remote", remoteAddr))
		copyDone := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(channel, remoteConn)
			copyDone <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(remoteConn, channel)
			copyDone <- struct{}{}
		}()

		select {
		case <-ctx.Done():
		case <-copyDone:
		}
		logger.Debug("direct-tcpip closed", zap.String("remote", remoteAddr))
	}()
}

// TelnetConnection implements ssh.Channel over a Telnet TCP connection.
type TelnetConnection struct {
	conn net.Conn
}

func (t *TelnetConnection) Read(data []byte) (n int, err error) {
	return t.conn.Read(data)
}

func (t *TelnetConnection) Write(data []byte) (n int, err error) {
	return t.conn.Write(data)
}

func (t *TelnetConnection) Close() error {
	return t.conn.Close()
}

func (t *TelnetConnection) CloseWrite() error {
	if conn, ok := t.conn.(*net.TCPConn); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (t *TelnetConnection) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func (t *TelnetConnection) Stderr() io.ReadWriter {
	return t
}

func (c *connections) handleTelnetConnection(ctx context.Context, tcpConn net.Conn, logger *zap.Logger) error {
	defer tcpConn.Close()

	logger.Debug("new telnet connection", zap.String("addr", tcpConn.RemoteAddr().String()))
	defer logger.Debug("telnet connection closed", zap.String("addr", tcpConn.RemoteAddr().String()))
	c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	defer c.done.Add(1)

	telnetConn := &TelnetConnection{conn: tcpConn}

	err := sendTelnetNegotiation(tcpConn, logger)
	if err != nil {
		logger.Error("Failed to send Telnet negotiation", zap.Error(err))
		return err
	}

	logger.Debug("start Telnet CLI session")
	session := newCLISessionWithAuth(telnetConn, c.username, c.password, c.authCallback, logger)
	err = session.Run(ctx)
	if err != nil {
		logger.Debug("Telnet CLI session ended", zap.Error(err))
	}

	return nil
}

func sendTelnetNegotiation(conn net.Conn, logger *zap.Logger) error {
	negotiations := [][]byte{
		{255, 251, 1},
		{255, 251, 3},
		{255, 253, 24},
		{255, 253, 31},
	}

	for _, neg := range negotiations {
		_, err := conn.Write(neg)
		if err != nil {
			return fmt.Errorf("failed to send telnet negotiation: %w", err)
		}
		logger.Debug("sent telnet negotiation", zap.String("command", fmt.Sprintf("% x", neg)))
	}

	return nil
}
