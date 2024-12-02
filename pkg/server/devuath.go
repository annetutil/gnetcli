package server

import (
	"github.com/annetutil/gnetcli/pkg/credentials"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/kevinburke/ssh_config"
	"go.uber.org/zap"
)

type authAppConfig struct {
	Login     string             `yaml:"login"`
	Password  credentials.Secret `yaml:"password"`
	ProxyJump string             `yaml:"proxy_jump"`
	UseAgent  bool               `yaml:"use_agent"`
	SshConfig string             `yaml:"ssh_config"` // use OpenSSH client configuration file
}

type authApp struct {
	config authAppConfig
	log    *zap.Logger
}

func (m authApp) GetHostParams(host string, params *pb.HostParams) (hostParams, error) {
	ip, port, err := makeHostConnectionParams(params)
	if err != nil {
		return hostParams{}, err
	}
	proxyJump := ""
	if len(m.config.ProxyJump) > 0 {
		proxyJump = m.config.ProxyJump
	} else if len(m.config.SshConfig) > 0 {
		proxyJump = ssh_config.Get(host, "ProxyJump")
	}
	creds, err := m.Get(host)
	if err != nil {
		return hostParams{}, err
	}
	res := NewHostParams(creds, params.GetDevice(), ip, port, proxyJump)
	return res, nil
}

func (m authApp) Get(host string) (credentials.Credentials, error) {
	login := m.config.Login
	if len(login) == 0 { // use current login
		newLogin := credentials.GetLogin()
		login = newLogin
	}

	if len(m.config.SshConfig) > 0 {
		sshConfigPassphrase := "" // TODO: pass it
		// here we read ssh config each call
		cred, err := BuildCredsFromSSHConfig(login, "", host, sshConfigPassphrase, m.log)
		if err != nil {
			return nil, err
		}
		return cred, nil
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
	creds := credentials.NewSimpleCredentials(opts...)
	return creds, nil
}

func NewAuthApp(config authAppConfig, logger *zap.Logger) authApp {
	return authApp{config: config, log: logger}
}
