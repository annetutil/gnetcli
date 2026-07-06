package server

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/annetutil/gnetcli/pkg/credentials"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"go.uber.org/zap"
)

type authAppConfig struct {
	Login      string             `yaml:"login"`
	Password   credentials.Secret `yaml:"password"`
	PrivateKey string             `yaml:"private_key"` // path to private key file
	ProxyJump  string             `yaml:"proxy_jump"`
	UseAgent   bool               `yaml:"use_agent"`
	SshConfig  bool               `yaml:"ssh_config"` // use OpenSSH client configuration file
}

type authApp struct {
	config    authAppConfig
	log       *zap.Logger
	sshConfig sshConfigReader
}

type proxyConfig struct {
	proxyJump   string
	controlPath string
	connectHost string
	ip          netip.Addr
}

func (m authApp) resolveProxyConfig(host string, ip netip.Addr) proxyConfig {
	cfg := proxyConfig{ip: ip}

	// Priority: explicit ProxyJump from app config > SSH config settings
	if len(m.config.ProxyJump) > 0 {
		cfg.proxyJump = m.config.ProxyJump
	} else if m.config.SshConfig && m.sshConfig != nil {
		// Read all SSH config settings when enabled
		cfg.proxyJump = m.sshConfig.Get(host, "ProxyJump")
		cfg.controlPath = m.sshConfig.Get(host, "ControlPath")
		if realHost := m.sshConfig.Get(host, "Hostname"); len(realHost) > 0 {
			cfg.connectHost = realHost
			// Clear IP to ensure we connect to Hostname from config, not IP received from client
			cfg.ip = netip.Addr{}
		}
	}
	return cfg
}

func (m authApp) GetHostParams(host string, params *pb.HostParams) (hostParams, error) {
	ip, port, err := makeHostConnectionParams(params)
	if err != nil {
		return hostParams{}, fmt.Errorf("host connection params: %w", err)
	}

	cfg := m.resolveProxyConfig(host, ip)

	creds, err := m.Get(host)
	if err != nil {
		return hostParams{}, fmt.Errorf("get credentials for %q: %w", host, err)
	}

	return NewHostParams(
		creds, params.GetDevice(),
		cfg.ip, port,
		cfg.proxyJump, cfg.controlPath, cfg.connectHost,
		params.GetStreamerType(),
	), nil
}

func (m authApp) Get(host string) (credentials.Credentials, error) {
	if m.config.SshConfig {
		sshConfigPassphrase := "" // TODO: pass it
		// here we read ssh config each call
		cred, err := BuildCredsFromSSHConfig(m.config.Login, m.config.Password.Value(), host, sshConfigPassphrase, m.config.PrivateKey, m.log)
		if err != nil {
			return nil, err
		}
		return cred, nil
	}

	login := m.config.Login
	if len(login) == 0 { // use current login
		newLogin := credentials.GetLogin()
		login = newLogin
	}
	opts := []credentials.CredentialsOption{
		credentials.WithUsername(login),
	}
	opts = append(opts, credentials.WithLogger(m.log))
	if m.config.UseAgent {
		opts = append(opts, credentials.WithSSHAgentSocket(credentials.GetDefaultAgentSocket()))
	}
	if len(m.config.Password) > 0 {
		opts = append(opts, credentials.WithPassword(credentials.Secret(m.config.Password)))
	}
	if len(m.config.PrivateKey) > 0 {
		key, err := os.ReadFile(m.config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("read dev_auth private_key %s: %w", m.config.PrivateKey, err)
		}
		opts = append(opts, credentials.WithPrivateKeys([][]byte{key}))
	}
	creds := credentials.NewSimpleCredentials(opts...)
	return creds, nil
}

func NewAuthApp(config authAppConfig, logger *zap.Logger) authApp {
	return authApp{
		config:    config,
		log:       logger,
		sshConfig: realSSHConfigReader{},
	}
}
