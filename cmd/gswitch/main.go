package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

// SSH and Telnet Server code
func main() {
	debug := flag.Bool("debug", false, "Set debug log level")
	host := flag.String("host", "localhost", "Server host")
	port := flag.Int("port", 2223, "SSH server port")
	telnetPort := flag.Int("telnet-port", 2223, "Telnet server port")
	enableTelnet := flag.Bool("enable-telnet", true, "Enable Telnet server")
	enableSSH := flag.Bool("enable-ssh", true, "Enable SSH server")
	username := flag.String("username", "cisco", "Username for authentication")
	password := flag.String("password", "cisco", "Password for authentication")
	flag.Parse()

	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}
	logger := zap.Must(logConfig.Build())

	ctx := context.Background()
	wg, wCtx := errgroup.WithContext(ctx)
	conns := newConnections(*username, *password)
	// SSH Server
	if *enableSSH {
		// SSH server configuration
		config := &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				if c.User() == *username && string(pass) == *password {
					return nil, nil
				}
				return nil, fmt.Errorf("password rejected for %q", c.User())
			},
		}

		// Generate or use existing key
		privateKey := []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----`)

		private, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			log.Fatal("Failed to parse private key: ", err)
		}

		config.AddHostKey(private)

		// Listen for SSH connections
		sshAddr := fmt.Sprintf("%s:%d", *host, *port)
		sshListener, err := net.Listen("tcp", sshAddr)
		if err != nil {
			log.Fatal("Failed to listen on SSH ", sshAddr, ": ", err)
		}

		logger.Warn("SSH server listening on", zap.String("addr", sshAddr))

		wg.Go(func() error {
			for {
				tcpConn, err := sshListener.Accept()
				if err != nil {
					logger.Error("Failed to accept SSH connection", zap.Error(err))
					continue
				}

				go func() {
					err := conns.handleSSHConnection(wCtx, tcpConn, config, logger)
					if err != nil {
						logger.Error("SSH connection error", zap.Error(err))
					}
				}()
			}
		})
	}

	// Telnet Server
	if *enableTelnet {
		telnetAddr := fmt.Sprintf("%s:%d", *host, *telnetPort)
		telnetListener, err := net.Listen("tcp", telnetAddr)
		if err != nil {
			log.Fatal("Failed to listen on Telnet ", telnetAddr, ": ", err)
		}

		logger.Warn("Telnet server listening on", zap.String("addr", telnetAddr))

		wg.Go(func() error {
			for {
				tcpConn, err := telnetListener.Accept()
				if err != nil {
					logger.Error("Failed to accept Telnet connection", zap.Error(err))
					continue
				}

				go func() {
					err := conns.handleTelnetConnection(wCtx, tcpConn, logger)
					if err != nil {
						logger.Error("Telnet connection error", zap.Error(err))
					}
				}()
			}
		})
	}

	if !*enableSSH && !*enableTelnet {
		logger.Fatal("At least one server (SSH or Telnet) must be enabled")
	}

	err := wg.Wait()
	if err != nil {
		logger.Fatal("server error", zap.Error(err))
	}
}

type connections struct {
	inFlight atomic.Int32
	done     atomic.Int32
	username string
	password string
}

func newConnections(username, password string) *connections {
	return &connections{
		inFlight: atomic.Int32{},
		done:     atomic.Int32{},
		username: username,
		password: password,
	}
}

func (c *connections) handleSSHConnection(ctx context.Context, tcpConn net.Conn, config *ssh.ServerConfig, logger *zap.Logger) error {
	defer tcpConn.Close()

	// SSH handshake
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
	// Discard all global out-of-band Requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			logger.Error("could not accept channel", zap.Error(err))
			continue
		}

		go func() {
			defer channel.Close()

			// Handle session requests
			go func() {
				for req := range requests {
					req.Reply(req.Type == "shell" || req.Type == "pty-req", nil)
				}
			}()

			// Start CLI session
			logger.Debug("start CLI session")
			session := NewCLISession(channel, c.username, c.password, logger, vendors["cisco"])
			err := session.Run(ctx)
			if err != nil {
				logger.Debug("CLI session ended", zap.Error(err))
			}
		}()
	}

	return nil
}

// TelnetConnection represents a Telnet connection implementing ssh.Channel interface
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
	// Telnet does not support SSH requests
	return false, nil
}

func (t *TelnetConnection) Stderr() io.ReadWriter {
	// Telnet uses the same stream for stderr
	return t
}

// handleTelnetConnection handles Telnet connections
func (c *connections) handleTelnetConnection(ctx context.Context, tcpConn net.Conn, logger *zap.Logger) error {
	defer tcpConn.Close()

	logger.Debug("new telnet connection", zap.String("addr", tcpConn.RemoteAddr().String()))
	defer logger.Debug("telnet connection closed", zap.String("addr", tcpConn.RemoteAddr().String()))
	c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	defer c.done.Add(1)
	// Create wrapper for Telnet connection
	telnetConn := &TelnetConnection{conn: tcpConn}

	// Send Telnet negotiation commands
	err := sendTelnetNegotiation(tcpConn, logger)
	if err != nil {
		logger.Error("Failed to send Telnet negotiation", zap.Error(err))
		return err
	}

	// Start CLI session
	logger.Debug("start Telnet CLI session")
	session := NewCLISessionWithAuth(telnetConn, c.username, c.password, logger)
	err = session.Run(ctx)
	if err != nil {
		logger.Debug("Telnet CLI session ended", zap.Error(err))
	}

	return nil
}

// sendTelnetNegotiation sends basic Telnet negotiation commands
func sendTelnetNegotiation(conn net.Conn, logger *zap.Logger) error {
	// Telnet commands
	// IAC = 255 (0xFF), WILL = 251 (0xFB), WONT = 252 (0xFC), DO = 253 (0xFD), DONT = 254 (0xFE)
	// ECHO = 1, SUPPRESS_GO_AHEAD = 3, TERMINAL_TYPE = 24, WINDOW_SIZE = 31

	negotiations := [][]byte{
		{255, 251, 1},  // IAC WILL ECHO - server will echo
		{255, 251, 3},  // IAC WILL SUPPRESS_GO_AHEAD - suppress go-ahead
		{255, 253, 24}, // IAC DO TERMINAL_TYPE - request terminal type
		{255, 253, 31}, // IAC DO WINDOW_SIZE - request window size
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
