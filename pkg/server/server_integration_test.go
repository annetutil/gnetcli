package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/annetutil/gnetcli/pkg/server"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
)

// DevAuth private_key from config is used for SSH to the device (gswitch).
func TestDevAuthPrivateKeyUsedForSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	ln, sshPort := newSSHServerPort(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	tmp := t.TempDir()
	privPath := filepath.Join(tmp, "id_ed25519")
	require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0o600))

	const user = "gnetuser"
	swLogger := zap.NewNop()
	if testing.Verbose() {
		swLogger = zap.Must(zap.NewDevelopmentConfig().Build())
	}

	ctx := t.Context()

	go func() {
		_ = gswitch.ServeSSH(ctx, ln, gswitch.SSHServerOptions{
			Logger: swLogger,
			AuthCallback: func(req gswitch.AuthRequest) error {
				if req.Method != gswitch.AuthMethodPublicKey {
					return fmt.Errorf("unexpected auth method %q", req.Method)
				}
				if req.Username != user {
					return fmt.Errorf("unexpected user %q", req.Username)
				}
				if req.PublicKey == nil || !bytes.Equal(req.PublicKey.Marshal(), sshPub.Marshal()) {
					return fmt.Errorf("unexpected public key")
				}
				return nil
			},
			ConnectionErrorProb: 0,
		})
	}()

	logger := zap.NewNop()
	var devAuth server.Config
	devAuth.DevAuth.Login = user
	devAuth.DevAuth.PrivateKey = privPath
	devAuth.DevAuth.UseAgent = false

	client := newGnetcliTestClient(t, devAuth, logger)
	res, err := client.Exec(ctx, &pb.CMD{
		Host: "mock-sw",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:     "127.0.0.1",
			Port:   sshPort,
			Device: "cisco",
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(res.GetOut()), "Cisco IOS Software")
}

// DevAuth login and password from config are used for SSH to the device (gswitch).
func TestDevAuthLoginPasswordUsedForSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	ln, sshPort := newSSHServerPort(t)
	ctx := t.Context()

	const user = "switchadmin"
	const pass = "correct-horse-battery-staple"

	swLogger := zap.NewNop()
	if testing.Verbose() {
		swLogger = zap.Must(zap.NewDevelopmentConfig().Build())
	}

	go func() {
		_ = gswitch.ServeSSH(ctx, ln, gswitch.SSHServerOptions{
			Logger: swLogger,
			AuthCallback: func(req gswitch.AuthRequest) error {
				if req.Method != gswitch.AuthMethodPassword {
					return fmt.Errorf("unexpected auth method %q", req.Method)
				}
				if req.Username != user || req.Password != pass {
					return fmt.Errorf("bad credentials for %q", req.Username)
				}
				return nil
			},
			ConnectionErrorProb: 0,
		})
	}()

	logger := zap.NewNop()
	var devAuth server.Config
	devAuth.DevAuth.Login = user
	devAuth.DevAuth.Password = credentials.Secret(pass)
	devAuth.DevAuth.UseAgent = false

	client := newGnetcliTestClient(t, devAuth, logger)
	res, err := client.Exec(context.Background(), &pb.CMD{
		Host: "mock-sw",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:     "127.0.0.1",
			Port:   sshPort,
			Device: "cisco",
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(res.GetOut()), "Cisco IOS Software")
}

func TestDevAuthWrongPasswordSSHRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	ln, sshPort := newSSHServerPort(t)
	ctx := t.Context()

	const user = "switchadmin"
	go func() {
		_ = gswitch.ServeSSH(ctx, ln, gswitch.SSHServerOptions{
			Logger: zap.NewNop(),
			AuthCallback: func(req gswitch.AuthRequest) error {
				if req.Method != gswitch.AuthMethodPassword {
					return fmt.Errorf("unexpected auth method %q", req.Method)
				}
				if req.Username != user || req.Password != "server-real-pass" {
					return fmt.Errorf("bad credentials for %q", req.Username)
				}
				return nil
			},
			ConnectionErrorProb: 0,
		})
	}()

	logger := zap.NewNop()
	var devAuth server.Config
	devAuth.DevAuth.Login = user
	devAuth.DevAuth.Password = credentials.Secret("wrong-pass")
	devAuth.DevAuth.UseAgent = false

	client := newGnetcliTestClient(t, devAuth, logger)
	_, err := client.Exec(context.Background(), &pb.CMD{
		Host: "mock-sw",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:     "127.0.0.1",
			Port:   sshPort,
			Device: "cisco",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to authenticate")
}

func newGnetcliTestClient(t *testing.T, devAuth server.Config, logger *zap.Logger) pb.GnetcliClient {
	t.Helper()

	authApp := server.NewAuthApp(devAuth.DevAuth, logger)
	svc, err := server.New(authApp, "", server.WithLogger(logger))
	require.NoError(t, err)

	auth := server.NewAuthInsecure(logger)
	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(grpcmiddleware.ChainUnaryServer(
			grpczap.UnaryServerInterceptor(logger),
			auth.AuthenticateUnary,
		)),
		grpc.StreamInterceptor(grpcmiddleware.ChainStreamServer(
			grpczap.StreamServerInterceptor(logger),
			auth.AuthenticateStream,
		)),
	)
	pb.RegisterGnetcliServer(grpcSrv, svc)

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = grpcLn.Close() })
	go func() { _ = grpcSrv.Serve(grpcLn) }()
	t.Cleanup(func() { grpcSrv.Stop() })

	conn, err := grpc.Dial(grpcLn.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return pb.NewGnetcliClient(conn)
}

func newSSHServerPort(t *testing.T) (net.Listener, int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	_, sshPortStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	v, err := strconv.Atoi(sshPortStr)
	require.NoError(t, err)
	return ln, int32(v)
}

func newTelnetServerPort(t *testing.T) (net.Listener, int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	_, telnetPortStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	v, err := strconv.Atoi(telnetPortStr)
	require.NoError(t, err)
	return ln, int32(v)
}

// TestTelnetBasicExecution tests basic command execution via Telnet streamer
func TestTelnetBasicExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	ln, telnetPort := newTelnetServerPort(t)
	ctx := t.Context()

	const user = "telnetadmin"
	const pass = "telnet-password"

	swLogger := zap.NewNop()
	if testing.Verbose() {
		swLogger = zap.Must(zap.NewDevelopmentConfig().Build())
	}

	go func() {
		_ = gswitch.ServeTelnet(ctx, ln, gswitch.SSHServerOptions{
			Logger:              swLogger,
			Username:            user,
			Password:            pass,
			ConnectionErrorProb: 0,
		})
	}()

	logger := zap.NewNop()
	var devAuth server.Config
	devAuth.DevAuth.Login = user
	devAuth.DevAuth.Password = credentials.Secret(pass)
	devAuth.DevAuth.UseAgent = false

	client := newGnetcliTestClient(t, devAuth, logger)
	res, err := client.Exec(ctx, &pb.CMD{
		Host: "mock-telnet-sw",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:           "127.0.0.1",
			Port:         telnetPort,
			Device:       "cisco",
			StreamerType: pb.StreamerType_StreamerType_telnet,
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(res.GetOut()), "Cisco IOS Software")
}

// TestTelnetCustomPort tests Telnet connection with custom port
func TestTelnetCustomPort(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	ln, telnetPort := newTelnetServerPort(t)
	ctx := t.Context()

	const user = "telnetuser"
	const pass = "custom-port-pass"

	swLogger := zap.NewNop()
	if testing.Verbose() {
		swLogger = zap.Must(zap.NewDevelopmentConfig().Build())
	}

	go func() {
		_ = gswitch.ServeTelnet(ctx, ln, gswitch.SSHServerOptions{
			Logger:              swLogger,
			Username:            user,
			Password:            pass,
			ConnectionErrorProb: 0,
		})
	}()

	logger := zap.NewNop()
	var devAuth server.Config
	devAuth.DevAuth.Login = user
	devAuth.DevAuth.Password = credentials.Secret(pass)
	devAuth.DevAuth.UseAgent = false

	client := newGnetcliTestClient(t, devAuth, logger)

	// Test that custom port is properly used
	res, err := client.Exec(ctx, &pb.CMD{
		Host: "custom-port-device",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:           "127.0.0.1",
			Port:         telnetPort, // Using custom port
			Device:       "cisco",
			StreamerType: pb.StreamerType_StreamerType_telnet,
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(res.GetOut()), "Cisco IOS Software")
}

// TestStreamerTypeSelection tests explicit streamer type selection between SSH and Telnet
func TestStreamerTypeSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	// Setup SSH server
	sshLn, sshPort := newSSHServerPort(t)
	// Setup Telnet server
	telnetLn, telnetPort := newTelnetServerPort(t)

	ctx := t.Context()

	const user = "multiuser"
	const pass = "multi-pass"

	swLogger := zap.NewNop()
	if testing.Verbose() {
		swLogger = zap.Must(zap.NewDevelopmentConfig().Build())
	}

	// Start SSH server
	go func() {
		_ = gswitch.ServeSSH(ctx, sshLn, gswitch.SSHServerOptions{
			Logger:              swLogger,
			Username:            user,
			Password:            pass,
			ConnectionErrorProb: 0,
		})
	}()

	// Start Telnet server
	go func() {
		_ = gswitch.ServeTelnet(ctx, telnetLn, gswitch.SSHServerOptions{
			Logger:              swLogger,
			Username:            user,
			Password:            pass,
			ConnectionErrorProb: 0,
		})
	}()

	logger := zap.NewNop()
	var devAuth server.Config
	devAuth.DevAuth.Login = user
	devAuth.DevAuth.Password = credentials.Secret(pass)
	devAuth.DevAuth.UseAgent = false

	client := newGnetcliTestClient(t, devAuth, logger)

	// Test SSH streamer (default behavior - streamer_type not specified)
	sshRes, err := client.Exec(ctx, &pb.CMD{
		Host: "ssh-device",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:     "127.0.0.1",
			Port:   sshPort,
			Device: "cisco",
			// StreamerType not specified - should default to SSH
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(sshRes.GetOut()), "Cisco IOS Software")

	// Test explicit SSH streamer
	sshExplicitRes, err := client.Exec(ctx, &pb.CMD{
		Host: "ssh-explicit-device",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:           "127.0.0.1",
			Port:         sshPort,
			Device:       "cisco",
			StreamerType: pb.StreamerType_StreamerType_ssh,
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(sshExplicitRes.GetOut()), "Cisco IOS Software")

	// Test Telnet streamer
	telnetRes, err := client.Exec(ctx, &pb.CMD{
		Host: "telnet-device",
		Cmd:  "show version",
		HostParams: &pb.HostParams{
			Ip:           "127.0.0.1",
			Port:         telnetPort,
			Device:       "cisco",
			StreamerType: pb.StreamerType_StreamerType_telnet,
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(telnetRes.GetOut()), "Cisco IOS Software")
}
