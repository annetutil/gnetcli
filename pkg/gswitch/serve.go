package gswitch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type AuthMethod string

const (
	AuthMethodPassword  AuthMethod = "password"
	AuthMethodPublicKey AuthMethod = "public_key"
	AuthMethodTelnet    AuthMethod = "telnet"
)

// AuthRequest describes a gswitch authentication attempt.
type AuthRequest struct {
	Method    AuthMethod
	Username  string
	Password  string
	PublicKey ssh.PublicKey
}

// AuthCallback checks a gswitch authentication attempt. Return nil to allow auth.
type AuthCallback func(AuthRequest) error

// SSHServerOptions configures the mock SSH switch listener.
type SSHServerOptions struct {
	Logger *zap.Logger
	// Username and Password are used for password-based client auth when AuthCallback is nil.
	Username string
	Password string
	// AuthCallback, when set, is used to validate SSH password, SSH public-key,
	// and telnet login/password authentication attempts.
	AuthCallback AuthCallback
	// ConnectionErrorProb is the probability (0–1) to drop a connection right after accept.
	ConnectionErrorProb float64
	// AuthorizedKeys, when non-empty, enables public-key client auth for Username.
	AuthorizedKeys []ssh.PublicKey
}

func (o *SSHServerOptions) logger() *zap.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return zap.NewNop()
}

// buildSSHServerConfig builds server-side SSH config (host key + client auth).
func buildSSHServerConfig(opts SSHServerOptions) (*ssh.ServerConfig, error) {
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-gswitch",
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if opts.AuthCallback != nil {
				err := opts.AuthCallback(AuthRequest{
					Method:   AuthMethodPassword,
					Username: c.User(),
					Password: string(pass),
				})
				if err != nil {
					return nil, err
				}
				return nil, nil
			}
			if c.User() == opts.Username && string(pass) == opts.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}
	if opts.AuthCallback != nil || len(opts.AuthorizedKeys) > 0 {
		allowed := opts.AuthorizedKeys
		config.PublicKeyCallback = func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if opts.AuthCallback != nil {
				err := opts.AuthCallback(AuthRequest{
					Method:    AuthMethodPublicKey,
					Username:  c.User(),
					PublicKey: pubKey,
				})
				if err != nil {
					return nil, err
				}
				return nil, nil
			}
			if c.User() != opts.Username {
				return nil, fmt.Errorf("unknown user %q", c.User())
			}
			for _, k := range allowed {
				if bytes.Equal(k.Marshal(), pubKey.Marshal()) {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("public key not authorized for %q", c.User())
		}
	}

	private, err := ssh.ParsePrivateKey(embeddedHostPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	config.AddHostKey(private)
	return config, nil
}

// ServeSSH accepts SSH connections on ln until ln is closed or ctx is cancelled.
func ServeSSH(ctx context.Context, ln net.Listener, opts SSHServerOptions) error {
	log := opts.logger()
	cfg, err := buildSSHServerConfig(opts)
	if err != nil {
		return err
	}
	conns := newConnections(opts.Username, opts.Password, opts.AuthCallback, opts.ConnectionErrorProb)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tcpConn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Error("failed to accept SSH connection", zap.Error(err))
			continue
		}

		log.Debug("new connection", zap.String("addr", tcpConn.RemoteAddr().String()))
		if conns.shouldSimulateConnectionError() {
			log.Debug("Simulating SSH connection error after accept")
			_ = tcpConn.Close()
			continue
		}
		go func() {
			err := conns.handleSSHConnection(ctx, tcpConn, cfg, log)
			if err != nil {
				log.Error("SSH connection error", zap.Error(err))
			}
		}()
	}
}

// ServeTelnet accepts Telnet connections on ln until ln is closed or ctx is cancelled.
func ServeTelnet(ctx context.Context, ln net.Listener, opts SSHServerOptions) error {
	log := opts.logger()
	conns := newConnections(opts.Username, opts.Password, opts.AuthCallback, opts.ConnectionErrorProb)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tcpConn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Error("Failed to accept Telnet connection", zap.Error(err))
			continue
		}

		if conns.shouldSimulateConnectionError() {
			log.Debug("Simulating Telnet connection error after accept")
			_ = tcpConn.Close()
			continue
		}

		go func() {
			err := conns.handleTelnetConnection(ctx, tcpConn, log)
			if err != nil {
				log.Error("Telnet connection error", zap.Error(err))
			}
		}()
	}
}
