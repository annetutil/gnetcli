package gswitch_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/huawei"
	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	sshstream "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newEmulatedSwitch(t *testing.T, name string) *emulator.Device {
	t.Helper()
	root, err := os.OpenRoot("../../examples/gswitch")
	require.NoError(t, err)
	defer root.Close()
	f, err := root.Open(name)
	require.NoError(t, err)
	defer f.Close()
	p, err := emulator.LoadProfile(f, root.FS())
	require.NoError(t, err)
	d, err := emulator.New(p, emulator.Options{Username: "test", Password: "secret"})
	require.NoError(t, err)
	require.NoError(t, d.Advance(time.Second))
	t.Cleanup(func() { d.Close() })
	return d
}

func emulatedOptions(d *emulator.Device) gswitch.SSHServerOptions {
	return gswitch.SSHServerOptions{Username: "test", Password: "secret", SSHHandler: func(ctx context.Context, stream io.ReadWriteCloser, user string) error {
		return d.Serve(ctx, stream, emulator.AttachOptions{Authenticated: true, Username: user})
	}}
}

func TestDeclarativeSSHWithCiscoClient(t *testing.T) {
	d := newEmulatedSwitch(t, "iosxe.yaml")
	address, _ := startSwitch(t, emulatedOptions(d), false)
	first := openDevice(t, address, passwordCredentials(), false)
	execute(t, first, "conf t", "interface Ethernet1", "description changed via client", "end", "write memory")
	require.Contains(t, execute(t, first, "show running-config"), "description changed via client")
	first.Close()
	second := openDevice(t, address, passwordCredentials(), false)
	require.Contains(t, execute(t, second, "show running-config"), "changed via client")
	result, err := second.ExecuteCtx(t.Context(), cmd.NewCmd("invalid command"))
	require.NoError(t, err)
	require.NotZero(t, result.Status())
	require.NoError(t, d.Reboot())
	require.NoError(t, d.Advance(time.Second))
	third := openDevice(t, address, passwordCredentials(), false)
	require.Contains(t, execute(t, third, "show running-config"), "changed via client")
}

func TestDeclarativeSSHWithHuaweiClient(t *testing.T) {
	d := newEmulatedSwitch(t, "huawei.yaml")
	address, _ := startSwitch(t, emulatedOptions(d), false)
	host, port, _ := net.SplitHostPort(address)
	n, err := strconv.Atoi(port)
	require.NoError(t, err)
	dev := huawei.NewDevice(sshstream.NewStreamer(host, passwordCredentials(), sshstream.WithPort(n)))
	defer dev.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, dev.Connect(ctx))
	execute(t, &dev, "system-view", "interface GE0/0/1", "description pending change")
	require.Equal(t, "initial", d.Snapshot().Running["interfaces"].(map[string]any)["GE0/0/1"].(map[string]any)["description"])
	execute(t, &dev, "commit", "return")
	require.Contains(t, execute(t, &dev, "display current-configuration"), "description pending change")
}

func TestDeclarativeSSHRejectsExecAndForwarding(t *testing.T) {
	d := newEmulatedSwitch(t, "iosxe.yaml")
	address, _ := startSwitch(t, emulatedOptions(d), false)
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.NoError(t, err)
	defer client.Close()
	s, err := client.NewSession()
	require.NoError(t, err)
	defer s.Close()
	require.Error(t, s.Run("show version"))
	_, err = client.Dial("tcp", "127.0.0.1:22")
	require.Error(t, err)
}

func readConsoleUntil(t *testing.T, c net.Conn, r *bufio.Reader, suffix string) string {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
	var out strings.Builder
	for !strings.HasSuffix(out.String(), suffix) {
		b, err := r.ReadByte()
		require.NoError(t, err)
		out.WriteByte(b)
	}
	return out.String()
}

func TestRawConsoleReconnectAndShutdown(t *testing.T) {
	d := newEmulatedSwitch(t, "iosxe.yaml")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.ServeConsole(ctx, listener, "tty0") }()
	c, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	r := bufio.NewReader(c)
	readConsoleUntil(t, c, r, "Username: ")
	_, err = io.WriteString(c, "test\n")
	require.NoError(t, err)
	readConsoleUntil(t, c, r, "Password: ")
	_, err = io.WriteString(c, "secret\n")
	require.NoError(t, err)
	require.NotContains(t, readConsoleUntil(t, c, r, "sw1>"), "secret")
	_, err = io.WriteString(c, "enable\nconfigure terminal\n")
	require.NoError(t, err)
	readConsoleUntil(t, c, r, "sw1(config)#")
	require.NoError(t, c.Close())
	require.Eventually(t, func() bool { sessions := d.Snapshot().Sessions; return len(sessions) == 1 && !sessions[0].Attached }, time.Second, time.Millisecond)
	c, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	r = bufio.NewReader(c)
	require.Equal(t, "sw1(config)#", readConsoleUntil(t, c, r, "sw1(config)#"))
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "console", Source: "kernel", Text: "after reconnect"}))
	require.Contains(t, readConsoleUntil(t, c, r, "sw1(config)#"), "after reconnect")
	cancel()
	select {
	case err := <-done:
		require.True(t, err == nil || errors.Is(err, context.Canceled))
	case <-time.After(time.Second):
		t.Fatal("console server did not join workers")
	}
}
