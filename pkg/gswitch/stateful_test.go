package gswitch_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/cisco"
	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/annetutil/gnetcli/pkg/streamer"
	sshstream "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/annetutil/gnetcli/pkg/streamer/telnet"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

func startSwitch(t *testing.T, opts gswitch.SSHServerOptions, useTelnet bool) (string, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		if useTelnet {
			done <- gswitch.ServeTelnet(ctx, ln, opts)
		} else {
			done <- gswitch.ServeSSH(ctx, ln, opts)
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		select {
		case err := <-done:
			if err != nil {
				require.ErrorIs(t, err, context.Canceled)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("switch did not stop")
		}
	})
	return ln.Addr().String(), cancel
}

func connect(ctx context.Context, address string, creds credentials.Credentials, useTelnet bool) (device.Device, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	var conn streamer.Connector = sshstream.NewStreamer(host, creds, sshstream.WithPort(n))
	if useTelnet {
		conn = telnet.NewStreamer(host, creds, telnet.WithPort(n))
	}
	dev := cisco.NewDevice(conn)
	if err := dev.Connect(ctx); err != nil {
		dev.Close()
		return nil, err
	}
	return &dev, nil
}

func passwordCredentials() credentials.Credentials {
	return credentials.NewSimpleCredentials(credentials.WithUsername("test"), credentials.WithPassword("secret"))
}

func openDevice(t *testing.T, address string, creds credentials.Credentials, useTelnet bool) device.Device {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dev, err := connect(ctx, address, creds, useTelnet)
	require.NoError(t, err)
	t.Cleanup(dev.Close)
	return dev
}

func execute(t *testing.T, dev device.Device, commands ...string) string {
	t.Helper()
	var output string
	for _, command := range commands {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result, err := dev.ExecuteCtx(ctx, cmd.NewCmd(command))
		cancel()
		require.NoError(t, err, command)
		require.Zero(t, result.Status(), "%s: %s", command, result.Error())
		output = strings.ReplaceAll(string(result.Output()), "\r\n", "\n")
	}
	return output
}

func TestConfigSurvivesReconnectAndSupportsRemoval(t *testing.T) {
	address, _ := startSwitch(t, gswitch.SSHServerOptions{Username: "test", Password: "secret"}, false)
	first := openDevice(t, address, passwordCredentials(), false)
	execute(t, first, "conf t", "interface Ethernet1", "description before", "exit", "exit", "copy running-config startup-config")
	first.Close()
	second := openDevice(t, address, passwordCredentials(), false)
	require.Contains(t, execute(t, second, "show running-config"), "interface Ethernet1\n description before")
	execute(t, second, "configure terminal", "interface Ethernet1", "description after", "end", "write memory")
	output := execute(t, second, "show running-config")
	require.Contains(t, output, "description after")
	require.NotContains(t, output, "description before")
	execute(t, second, "conf t", "interface Ethernet1", "no description after", "end")
	require.NotContains(t, execute(t, second, "show running-config"), "description")
	execute(t, second, "conf t", "interface Ethernet1", "description new", "no description", "end")
	require.NotContains(t, execute(t, second, "show running-config"), "description")
	execute(t, second, "conf t", "no interface Ethernet1", "logging buffered", "no logging buffered", "end")
	require.Empty(t, strings.TrimSpace(execute(t, second, "show running-config")))
	result, err := second.ExecuteCtx(t.Context(), cmd.NewCmd("invalid command"))
	require.NoError(t, err)
	require.NotZero(t, result.Status())
}

func TestSessionModesAndServersAreIndependent(t *testing.T) {
	opts := gswitch.SSHServerOptions{Username: "test", Password: "secret"}
	address, _ := startSwitch(t, opts, false)
	a, b := openDevice(t, address, passwordCredentials(), false), openDevice(t, address, passwordCredentials(), false)
	execute(t, a, "conf t", "interface Ethernet1")
	require.Contains(t, execute(t, b, "show running-config"), "interface Ethernet1")
	execute(t, b, "conf t", "interface Ethernet2")
	execute(t, a, "description one", "exit", "exit")
	execute(t, b, "description two", "end")
	output := execute(t, a, "show running-config")
	require.Contains(t, output, "interface Ethernet1\n description one")
	require.Contains(t, output, "interface Ethernet2\n description two")
	for i := 0; i < 5; i++ {
		require.Equal(t, output, execute(t, b, "show running-config"))
	}
	other, _ := startSwitch(t, opts, false)
	independent := openDevice(t, other, passwordCredentials(), false)
	require.Empty(t, strings.TrimSpace(execute(t, independent, "show running-config")))
}

func TestConfigSharedBetweenSSHAndTelnet(t *testing.T) {
	config := gswitch.NewRunningConfig()
	require.NoError(t, config.Load("interface Ethernet1\n description initial\n!\n"))
	opts := gswitch.SSHServerOptions{Username: "test", Password: "secret", Config: config}
	sshAddress, _ := startSwitch(t, opts, false)
	telnetAddress, _ := startSwitch(t, opts, true)
	sshDevice := openDevice(t, sshAddress, passwordCredentials(), false)
	telnetDevice := openDevice(t, telnetAddress, passwordCredentials(), true)
	execute(t, sshDevice, "conf t", "interface Ethernet1", "description updated", "end")
	require.Contains(t, execute(t, telnetDevice, "show running-config"), "description updated")
	execute(t, telnetDevice, "conf t", "interface Ethernet1", "no description", "end")
	require.NotContains(t, execute(t, sshDevice, "show running-config"), "description")
}

func TestConcurrentSessions(t *testing.T) {
	config := gswitch.NewRunningConfig()
	address, _ := startSwitch(t, gswitch.SSHServerOptions{Username: "test", Password: "secret", Config: config}, false)
	group, ctx := errgroup.WithContext(t.Context())
	for i := 0; i < 12; i++ {
		group.Go(func() error {
			dev, err := connect(ctx, address, passwordCredentials(), false)
			if err != nil {
				return err
			}
			defer dev.Close()
			for _, text := range []string{"conf t", fmt.Sprintf("interface Ethernet%d", i), fmt.Sprintf("description port-%d", i), "end", "show running-config"} {
				result, err := dev.ExecuteCtx(ctx, cmd.NewCmd(text))
				if err != nil {
					return err
				}
				if result.Status() != 0 {
					return fmt.Errorf("%s: %s", text, result.Error())
				}
			}
			return nil
		})
	}
	require.NoError(t, group.Wait())
	for i := 0; i < 12; i++ {
		require.Contains(t, config.String(), fmt.Sprintf("interface Ethernet%d\n description port-%d\n", i, i))
	}
}

func TestPublicKeyAndRejectedCredentials(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	encoded, err := ssh.MarshalPrivateKey(key, "")
	require.NoError(t, err)
	address, _ := startSwitch(t, gswitch.SSHServerOptions{Username: "test", Password: "secret", AuthorizedKeys: []ssh.PublicKey{signer.PublicKey()}}, false)
	creds := credentials.NewSimpleCredentials(credentials.WithUsername("test"), credentials.WithPrivateKey(pem.EncodeToMemory(encoded)))
	dev := openDevice(t, address, creds, false)
	require.Contains(t, execute(t, dev, "show version"), "Cisco IOS Software")
	_, err = ssh.Dial("tcp", address, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("wrong")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.Error(t, err)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ssh.NewSignerFromKey(otherKey)
	require.NoError(t, err)
	_, err = ssh.Dial("tcp", address, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(otherSigner)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.Error(t, err)
}

func TestCancelStopsDelayedCommand(t *testing.T) {
	address, cancel := startSwitch(t, gswitch.SSHServerOptions{Username: "test", Password: "secret", CommandDelay: time.Minute}, false)
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.NoError(t, err)
	defer client.Close()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	stdin, err := session.StdinPipe()
	require.NoError(t, err)
	stdout, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.Shell())
	reader := bufio.NewReader(stdout)
	_, err = reader.ReadString('#')
	require.NoError(t, err)
	_, err = io.WriteString(stdin, "show version\n")
	require.NoError(t, err)
	_, err = reader.ReadString('\n')
	require.NoError(t, err) // Echo received, command now delayed.
	cancel()
	done := make(chan struct{})
	go func() { _, _ = io.ReadAll(reader); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt delayed command")
	}
}
