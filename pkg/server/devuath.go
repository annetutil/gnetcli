package server

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/annetutil/gnetcli/pkg/credentials"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/kevinburke/ssh_config"
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

	// Priority: explicit ProxyJump from app config > SSH config settings.
	if len(m.config.ProxyJump) > 0 {
		cfg.proxyJump = m.config.ProxyJump
	} else if m.config.SshConfig && m.sshConfig != nil {
		cfg.proxyJump = m.sshConfig.Get(host, "ProxyJump")
		cfg.controlPath = m.sshConfig.Get(host, "ControlPath")
		if realHost := m.sshConfig.Get(host, "Hostname"); len(realHost) > 0 {
			cfg.connectHost = realHost
			// Clear IP to ensure we connect to Hostname from config, not IP received from client.
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

	if port == 0 && m.config.SshConfig && m.sshConfig != nil {
		configPort := m.sshConfig.Get(host, "Port")
		if len(configPort) > 0 {
			parsedPort, err := strconv.Atoi(configPort)
			if err != nil {
				return hostParams{}, fmt.Errorf("invalid ssh config port for %s: %w", host, err)
			}
			port = parsedPort
		}
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
		cred, err := m.buildCredsFromSSHConfig(m.config.Login, m.config.Password.Value(), host, sshConfigPassphrase, m.config.PrivateKey)
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

func NewAuthAppWithSSHConfig(config authAppConfig, logger *zap.Logger, sshConfigText string) (authApp, error) {
	parsedConfig, err := ssh_config.Decode(strings.NewReader(sshConfigText))
	if err != nil {
		return authApp{}, err
	}
	return authApp{config: config, log: logger, sshConfig: parsedSSHConfigReader{config: parsedConfig}}, nil
}

func (m authApp) getSSHConfig(host, key string) string {
	if m.sshConfig == nil {
		return ""
	}
	return m.sshConfig.Get(host, key)
}

func (m authApp) getSSHConfigAll(host, key string) []string {
	if m.sshConfig == nil {
		return nil
	}
	return m.sshConfig.GetAll(host, key)
}

func (m authApp) buildCredsFromSSHConfig(login, password, host, sshConfigPassphrase, privateKeyPath string) (credentials.Credentials, error) {
	var privateKeys [][]byte
	if len(privateKeyPath) > 0 {
		key, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, err
		}
		privateKeys = [][]byte{key}
	} else {
		var err error
		privateKeys, err = m.getPrivateKeysFromSSHConfig(host)
		if err != nil {
			return nil, err
		}
	}
	if len(login) == 0 {
		configLogin := m.getSSHConfig(host, "User")
		if len(configLogin) == 0 {
			newLogin := credentials.GetLogin()
			m.log.Debug("Use system login", zap.String("configLogin", newLogin))
			login = newLogin
		} else {
			login = configLogin
			m.log.Debug("Use login from config", zap.String("configLogin", configLogin))
		}
	} else {
		m.log.Debug("Use login from input", zap.String("login", login))
	}
	agentSocket, err := m.getAgentSocketFromSSHConfig(host)
	if err != nil {
		return nil, err
	}

	opts := []credentials.CredentialsOption{
		credentials.WithUsername(login),
		credentials.WithLogger(m.log),
		credentials.WithSSHAgentSocket(agentSocket),
	}
	if len(password) > 0 {
		opts = append(opts, credentials.WithPassword(credentials.Secret(password)))
	}
	if len(privateKeys) > 0 {
		opts = append(opts, credentials.WithPrivateKeys(privateKeys))
	}
	if len(sshConfigPassphrase) > 0 {
		opts = append(opts, credentials.WithPassphrase(credentials.Secret(sshConfigPassphrase)))
	}

	return credentials.NewSimpleCredentials(opts...), nil
}

func (m authApp) getPrivateKeysFromSSHConfig(host string) ([][]byte, error) {
	switch m.sshConfig.(type) {
	case nil, realSSHConfigReader:
		return credentials.GetPrivateKeysFromConfig(host)
	}

	identityFiles := m.getSSHConfigAll(host, "IdentityFile")
	privKeys := make([][]byte, 0, len(identityFiles))
	for _, v := range identityFiles {
		content, err := os.ReadFile(v)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity file %s: %w", v, err)
		}
		privKeys = append(privKeys, content)
	}
	return privKeys, nil
}

func (m authApp) getAgentSocketFromSSHConfig(host string) (string, error) {
	switch m.sshConfig.(type) {
	case nil, realSSHConfigReader:
		return credentials.GetAgentSocketFromConfig(host)
	}

	ia := m.getSSHConfig(host, "IdentityAgent")
	if ia == "none" {
		return "", nil
	}
	if ia == "SSH_AUTH_SOCK" || len(ia) == 0 {
		if m.getSSHConfig(host, "ForwardAgent") == "yes" || ia == "SSH_AUTH_SOCK" {
			return credentials.GetDefaultAgentSocket(), nil
		}
		return "", nil
	}
	return ia, nil
}
