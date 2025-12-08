package ssh

import (
	"context"
	"fmt"
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

func dialControlMasterConf(_ context.Context, controlFile string, host string, port int, conf *ssh.ClientConfig, logger *zap.Logger) (*ControlConn, error) {
	params := tssh.NewSshParam(host, strconv.Itoa(port), conf.User, nil)
	expandedPath, err := tssh.ExpandTokens(controlFile, params, "%CdhijkLlnpru")
	if err != nil {
		return nil, err
	}
	resolvedPath := resolveHomeDir(expandedPath)
	logger.Debug("open control file", zap.String("path", resolvedPath))
	c, err := OpenControl(resolvedPath)
	if err != nil {
		return nil, err
	}
	return c, err
}

type ControlConn struct {
	conn *net.UnixConn
}

// OpenControl opens a connection to the control socket.
func OpenControl(filePath string) (*ControlConn, error) {
	conn, err := net.Dial("unix", filePath)
	if err != nil {
		return nil, err
	}
	uConn := conn.(*net.UnixConn)
	return &ControlConn{conn: uConn}, nil
}

func (m *ControlConn) Close() error {
	return m.conn.Close()
}

// NewSession implements sshClient interface.
func (m *ControlConn) NewSession() (*ssh.Session, error) {
	return nil, fmt.Errorf("not supported")
}

// DialControlStdioForward establishes tunnel over an ControlMaster socket in Stdio Forward mode.
func (m *ControlConn) DialControlStdioForward(host string, port int) (*tssh.ConnectionForward, error) {
	// Stdio forwarding MUX_C_NEW_STDIO_FWD
	forward, err := tssh.NewControlStdioForward(m.conn, host, port)
	if err != nil {
		return nil, err
	}

	return forward, nil
}

// DialControlMasterForward establishes tunnel over an ControlMaster socket in Proxy mode.
func (m *ControlConn) DialControlMasterForward() (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	// Proxy mode, MUX_C_PROXY.
	//
	// While this mode provides all the benefits of SSH it comes with a huge problem, which makes this mode useless in some cases.
	// SSHD contains a bug or feature. If you are using NewControlClientConn() (proxy mode, MUX_C_PROXY)
	// and trying to connect to unreachable host this will happen:
	// client negotiates proxy request
	// client opens direct-tcpip channel to unreachable host
	// server trying to connect to unreachable host (channel is not created at this point)
	// client closes file descriptor (because of timeout)
	// server tries to close channel:
	//   debug2: channel 6: send_close2
	//   chan_send_close2: channel 6: no remote_id
	//   debug3: mux_client_read_packet_timeout: read header failed: Broken pipe
	//   debug2: Control master terminated unexpectedly
	// server closes ssh-connection because of this unexpected error
	conn, ch, ch2, err := tssh.NewControlClientConn(m.conn)
	if err != nil {
		return nil, nil, nil, err
	}

	return conn, ch, ch2, err
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
