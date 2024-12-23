package ssh

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/annetutil/gnetcli/internal/tssh"
	"github.com/mitchellh/go-homedir"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var userHomeDir string

func resolveHomeDir(path string) string {
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return filepath.Join(userHomeDir, path[2:])
	}
	return path
}

func dialControlMasterConf(ctx context.Context, controlFile string, endpoint Endpoint, conf *ssh.ClientConfig, logger *zap.Logger) (*ssh.Client, error) {
	params := tssh.NewSshParam(endpoint.Host, strconv.Itoa(endpoint.Port), conf.User, nil)
	expandedPath, err := tssh.ExpandTokens(controlFile, params, "%CdhijkLlnpru")
	if err != nil {
		return nil, err
	}
	resolvedPath := resolveHomeDir(expandedPath)
	logger.Debug("dialControlMaster", zap.String("path", resolvedPath))
	conn, err := dialControlMaster(ctx, resolvedPath)
	return conn, err
}

func dialControlMaster(_ context.Context, filePath string) (*ssh.Client, error) {
	conn, err := net.Dial("unix", filePath)
	if err != nil {
		return nil, err
	}

	ncc, chans, reqs, err := tssh.NewControlClientConn(conn)
	if err != nil {
		return nil, err
	}

	client := ssh.NewClient(ncc, chans, reqs)
	return client, nil
}

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		if hHomeDir, err := homedir.Dir(); err == nil {
			userHomeDir = hHomeDir
		}
	} else {
		userHomeDir = homeDir
	}
}
