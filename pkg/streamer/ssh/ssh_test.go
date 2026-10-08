package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/annetutil/gnetcli/pkg/credentials"

	"github.com/annetutil/gnetcli/pkg/streamer"
)

func TestSSHInterface(t *testing.T) {
	val := Streamer{}

	_, ok := interface{}(&val).(streamer.Connector)
	assert.True(t, ok, "not a Connector interface")
}

func TestSSHAgentConnectionClosedAfterInit(t *testing.T) {
	for _, acceptKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "authenticated", false: "authentication failed"}[acceptKey], func(t *testing.T) {
			socket, connections, keyring, signer := newTestAgent(t)
			serveTestAgent(t, socket, connections, keyring)
			port := newTestSSHServer(t, signer, acceptKey)
			s := NewStreamer("127.0.0.1", testAgentCredentials(socket), WithPort(port))
			t.Cleanup(s.Close)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := s.Init(ctx)
			if acceptKey {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			assertAgentConnectionClosed(t, connections)
			runtime.KeepAlive(s)
		})
	}
}

func TestSSHAgentConnectionClosedWithStreamer(t *testing.T) {
	socket, connections, keyring, _ := newTestAgent(t)
	serveTestAgent(t, socket, connections, keyring)
	s := NewStreamer("localhost", testAgentCredentials(socket))
	t.Cleanup(s.Close)

	var configs []*gossh.ClientConfig
	for i := 0; i < 3; i++ {
		config, err := s.GetConfig(context.Background())
		require.NoError(t, err)
		configs = append(configs, config)
	}
	s.Close()
	s.Close()
	for range configs {
		assertAgentConnectionClosed(t, connections)
	}
	runtime.KeepAlive(configs)
}

func TestSSHAgentConnectionClosedOnConfigError(t *testing.T) {
	for _, failList := range []bool{true, false} {
		t.Run(map[bool]string{true: "list failed", false: "config callback failed"}[failList], func(t *testing.T) {
			socket, connections, keyring, _ := newTestAgent(t)
			var handler agent.Agent = keyring
			if failList {
				handler = failingListAgent{Agent: keyring}
			}
			serveTestAgent(t, socket, connections, handler)
			s := NewStreamer("localhost", testAgentCredentials(socket), WithOnConfig(func(*gossh.ClientConfig) error {
				return errors.New("config callback failed")
			}))
			t.Cleanup(s.Close)

			_, err := s.GetConfig(context.Background())
			require.Error(t, err)
			assertAgentConnectionClosed(t, connections)
			runtime.KeepAlive(s)
		})
	}
}

func TestSSHTunnelClosesAgentConnection(t *testing.T) {
	for _, acceptKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "authenticated", false: "authentication failed"}[acceptKey], func(t *testing.T) {
			socket, connections, keyring, signer := newTestAgent(t)
			serveTestAgent(t, socket, connections, keyring)
			port := newTestSSHServer(t, signer, acceptKey)
			tunnel := NewSSHTunnel("127.0.0.1", testAgentCredentials(socket), SSHTunnelWithPort(port))
			t.Cleanup(tunnel.Close)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := tunnel.CreateConnect(ctx)
			if acceptKey {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			assertAgentConnectionClosed(t, connections)
			runtime.KeepAlive(tunnel)
		})
	}
}

type failingListAgent struct {
	agent.Agent
}

func (failingListAgent) List() ([]*agent.Key, error) {
	return nil, errors.New("list failed")
}

func testAgentCredentials(socket string) *credentials.SimpleCredentials {
	return credentials.NewSimpleCredentials(credentials.WithUsername("test"), credentials.WithSSHAgentSocket(socket))
}

func newTestAgent(t *testing.T) (string, chan chan struct{}, agent.Agent, gossh.Signer) {
	t.Helper()
	// Keep the Unix socket path below the platform-specific length limit.
	dir, err := os.MkdirTemp("", "agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: privateKey}))
	return filepath.Join(dir, "sock"), make(chan chan struct{}, 3), keyring, signer
}

func serveTestAgent(t *testing.T, socket string, connections chan chan struct{}, handler agent.Agent) {
	t.Helper()
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	var mu sync.Mutex
	var clients []net.Conn
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range clients {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			clients = append(clients, conn)
			mu.Unlock()
			closed := make(chan struct{})
			connections <- closed
			go func() {
				defer close(closed)
				defer conn.Close()
				_ = agent.ServeAgent(handler, conn)
			}()
		}
	}()
}

func assertAgentConnectionClosed(t *testing.T, connections chan chan struct{}) {
	t.Helper()
	select {
	case closed := <-connections:
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Error("SSH agent connection is still open")
		}
	case <-time.After(time.Second):
		t.Error("SSH agent did not accept a connection")
	}
}

func newTestSSHServer(t *testing.T, signer gossh.Signer, acceptKey bool) int {
	t.Helper()
	config := &gossh.ServerConfig{PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if acceptKey && bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
			return nil, nil
		}
		return nil, errors.New("key rejected")
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				sshConn, channels, requests, err := gossh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go gossh.DiscardRequests(requests)
				for ch := range channels {
					_ = ch.Reject(gossh.Prohibited, "not used by this test")
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
