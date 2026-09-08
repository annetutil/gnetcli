package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/annetutil/gnetcli/pkg/credentials"
	sshstreamer "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/kevinburke/ssh_config"
	"go.uber.org/zap"
)

const defaultSSHPort = 22

type managedTunnel struct {
	tunnel sshstreamer.Tunnel
	once   sync.Once
	err    error
}

func (t *managedTunnel) EnsureConnected(ctx context.Context, timeout time.Duration) error {
	t.once.Do(func() {
		connectCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		t.err = t.tunnel.CreateConnect(connectCtx)
	})
	if t.err != nil {
		return fmt.Errorf("unable to connect to SSH jump host: %w", t.err)
	}
	return nil
}

func (t *managedTunnel) Tunnel() sshstreamer.Tunnel {
	return t.tunnel
}

func (t *managedTunnel) Close() {
	if t.tunnel.IsConnected() {
		t.tunnel.Close()
	}
}

func makeJumpTunnel(cfg config, logger *zap.Logger) (*managedTunnel, error) {
	if cfg.jumpHost == "" {
		return nil, nil
	}
	explicitUser, alias, err := splitJumpTarget(cfg.jumpHost)
	if err != nil {
		return nil, err
	}
	host := alias
	port := defaultSSHPort
	if cfg.useSSHConfig {
		host, port, err = jumpEndpointFromSSHConfig(alias)
		if err != nil {
			return nil, err
		}
	}
	creds, err := makeJumpCredentials(cfg, alias, explicitUser, logger)
	if err != nil {
		return nil, err
	}
	tunnel := sshstreamer.NewSSHTunnel(
		host,
		creds,
		sshstreamer.SSHTunnelWithPort(port),
		sshstreamer.SSHTunnelWithLogger(logger),
	)
	logger.Debug("configured SSH jump host", zap.String("alias", alias), zap.String("host", host), zap.Int("port", port), zap.Bool("ssh_config", cfg.useSSHConfig))
	return &managedTunnel{tunnel: tunnel}, nil
}

func splitJumpTarget(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", errors.New("invalid jump host: empty value")
	}
	username := ""
	host := value
	if index := strings.LastIndex(value, "@"); index >= 0 {
		username = value[:index]
		host = value[index+1:]
		if username == "" || host == "" {
			return "", "", fmt.Errorf("invalid jump host %q: expected [user@]host", value)
		}
	}
	return username, host, nil
}

func jumpEndpointFromSSHConfig(alias string) (string, int, error) {
	host, err := ssh_config.GetStrict(alias, "Hostname")
	if err != nil {
		return "", 0, fmt.Errorf("read Hostname for %s from SSH config: %w", alias, err)
	}
	if host == "" {
		host = alias
	} else {
		host = strings.ReplaceAll(host, "%h", alias)
	}
	portValue, err := ssh_config.GetStrict(alias, "Port")
	if err != nil {
		return "", 0, fmt.Errorf("read Port for %s from SSH config: %w", alias, err)
	}
	if portValue == "" {
		return host, defaultSSHPort, nil
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid SSH config Port %q for %s", portValue, alias)
	}
	return host, port, nil
}

func makeJumpCredentials(cfg config, alias, explicitUser string, logger *zap.Logger) (credentials.Credentials, error) {
	username := explicitUser
	options := []credentials.CredentialsOption{credentials.WithLogger(logger)}
	if cfg.useSSHConfig {
		privateKeys, err := credentials.GetPrivateKeysFromConfig(alias)
		if err != nil {
			return nil, err
		}
		agentSocket, err := credentials.GetAgentSocketFromConfig(alias)
		if err != nil {
			return nil, err
		}
		if username == "" {
			username = credentials.GetUsernameFromConfig(alias)
		}
		if len(privateKeys) > 0 {
			options = append(options, credentials.WithPrivateKeys(privateKeys))
		}
		if cfg.sshPassphrase != "" {
			options = append(options, credentials.WithPassphrase(credentials.Secret(cfg.sshPassphrase)))
		}
		options = append(options, credentials.WithSSHAgentSocket(agentSocket))
	} else {
		options = append(options, credentials.WithSSHAgentSocket(credentials.GetDefaultAgentSocket()))
	}
	if username == "" {
		username = credentials.GetLogin()
	}
	options = append(options, credentials.WithUsername(username))
	return credentials.NewSimpleCredentials(options...), nil
}
