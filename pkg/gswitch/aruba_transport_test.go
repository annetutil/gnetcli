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
	"github.com/annetutil/gnetcli/pkg/device/aruos"
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	sshstream "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/stretchr/testify/require"
)

func noisyArubaSwitch(t *testing.T) *emulator.Device {
	t.Helper()
	root, err := os.OpenRoot("../../examples/gswitch")
	require.NoError(t, err)
	defer root.Close()
	f, err := root.Open("aruba.yaml")
	require.NoError(t, err)
	defer f.Close()
	p, err := emulator.LoadProfile(f, root.FS())
	require.NoError(t, err)
	f, err = root.Open("aruba-dhcp.yaml")
	require.NoError(t, err)
	defer f.Close()
	scenario, err := emulator.LoadScenario(f, root.FS())
	require.NoError(t, err)
	d, err := emulator.New(p, emulator.Options{Username: "test", Password: "secret", Scenario: scenario})
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	return d
}

func TestArubaSSHDriverOperationalAndDegraded(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		t.Run(strconv.FormatBool(degraded), func(t *testing.T) {
			var d *emulator.Device
			if degraded {
				d = noisyArubaSwitch(t)
				require.NoError(t, d.Advance(21*time.Second))
			} else {
				d = newEmulatedSwitch(t, "aruba.yaml")
			}
			address, _ := startSwitch(t, emulatedOptions(d), false)
			host, port, err := net.SplitHostPort(address)
			require.NoError(t, err)
			n, err := strconv.Atoi(port)
			require.NoError(t, err)
			dev := aruos.NewDevice(sshstream.NewStreamer(host, passwordCredentials(), sshstream.WithPort(n)))
			defer dev.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, dev.Connect(ctx))
			require.Contains(t, execute(t, &dev, "show version"), "ArubaOS (MODEL: 305)")
			if degraded {
				before := d.Snapshot()
				for _, command := range []string{"configure terminal", "write memory"} {
					res, err := dev.ExecuteCtx(ctx, cmd.NewCmd(command))
					require.NoError(t, err)
					require.NotZero(t, res.Status())
					require.Contains(t, string(res.Error()), "degraded state")
				}
				require.Equal(t, before, d.Snapshot())
			} else {
				execute(t, &dev, "configure terminal", "name ap-test", "syslocation test-room", "end", "commit apply")
				require.Contains(t, execute(t, &dev, "show running-config"), "name ap-test")
				require.Equal(t, "ap-test", d.Snapshot().Startup["hostname"])
			}
			require.Contains(t, execute(t, &dev, "show aps"), "1 Access Point")
		})
	}
}

func TestArubaNoisyRawConsoleBootAndCLIRestart(t *testing.T) {
	d := noisyArubaSwitch(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.ServeConsole(ctx, listener, "tty0") }()
	c, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	r := bufio.NewReader(c)
	require.Eventually(t, func() bool { return len(d.Snapshot().Sessions) == 1 }, time.Second, time.Millisecond)
	require.NoError(t, d.Advance(17*time.Second))
	boot := readConsoleUntil(t, c, r, "User: ")
	require.Contains(t, boot, "No lease, forking to background.")
	require.Equal(t, 18, strings.Count(boot, "Sending discover..."))
	require.True(t, strings.HasSuffix(boot, "USB Modem is not presenUser: "))
	send := func(text string) { _, err := io.WriteString(c, text); require.NoError(t, err) }
	const prompt = "02:00:00:00:00:01# "
	const loginEnd = "please debug with caution.\r\n" + prompt
	send("test\n")
	require.Equal(t, "test\r\nPassword: ", readConsoleUntil(t, c, r, "Password: "))
	require.NoError(t, d.Advance(20*time.Millisecond))
	require.Equal(t, "ble_ready NOT present @init ....\r\n", readConsoleUntil(t, c, r, "....\r\n"))
	send("secret\n")
	require.NotContains(t, readConsoleUntil(t, c, r, loginEnd), "secret")
	send("sh")
	require.Equal(t, "sh", readConsoleUntil(t, c, r, "sh"))
	require.NoError(t, d.Advance(100*time.Millisecond))
	require.NotContains(t, readConsoleUntil(t, c, r, "Sending discover...\r\n"), prompt)
	send("ow version\n")
	require.Contains(t, readConsoleUntil(t, c, r, prompt), "ArubaOS")
	require.NoError(t, d.Advance(20700*time.Millisecond-d.Snapshot().Now))
	require.Contains(t, readConsoleUntil(t, c, r, "User: "), "Internal error 8-0")
	require.NoError(t, d.Advance(10*time.Millisecond))
	readConsoleUntil(t, c, r, "!!! Init ---> Conductor\r\n")
	send("test\n")
	readConsoleUntil(t, c, r, "Password: ")
	send("secret\n")
	readConsoleUntil(t, c, r, loginEnd)
	send("write memory\n")
	require.Contains(t, readConsoleUntil(t, c, r, prompt), "Write memory is not allowed when CLI is running in a degraded state.")
	cancel()
	select {
	case err := <-done:
		require.True(t, err == nil || errors.Is(err, context.Canceled))
	case <-time.After(time.Second):
		t.Fatal("console server did not stop")
	}
}
