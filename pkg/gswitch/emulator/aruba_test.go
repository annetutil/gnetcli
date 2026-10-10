package emulator_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const arubaPrompt = "02:00:00:00:00:01# "

func arubaDevice(t *testing.T, noisy bool) *emulator.Device {
	t.Helper()
	root, err := os.OpenRoot("../../../examples/gswitch")
	require.NoError(t, err)
	defer root.Close()
	f, err := root.Open("aruba.yaml")
	require.NoError(t, err)
	defer f.Close()
	p, err := emulator.LoadProfile(f, root.FS())
	require.NoError(t, err)
	options := emulator.Options{Username: "admin", Password: "secret"}
	if noisy {
		f, err := root.Open("aruba-dhcp.yaml")
		require.NoError(t, err)
		defer f.Close()
		options.Scenario, err = emulator.LoadScenario(f, root.FS())
		require.NoError(t, err)
	}
	d, err := emulator.New(p, options)
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	return d
}

func TestArubaProfileCommandsAndPersistence(t *testing.T) {
	d := arubaDevice(t, false)
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true, Username: "admin"})
	require.NoError(t, err)
	require.Equal(t, arubaPrompt, drain(s))
	for _, tc := range []struct{ command, want string }{
		{"show version", "ArubaOS (MODEL: 305)"}, {"show aps", "1 Access Point"},
		{"show ip interface brief", "169.254.100.10 / 255.255.0.0"},
	} {
		require.Contains(t, input(t, s, tc.command+"\n"), tc.want)
	}
	before := d.Snapshot()
	require.Contains(t, input(t, s, "show ?"), "running-config")
	require.Equal(t, before, d.Snapshot())
	input(t, s, "\x03conf\tt\t\nname ap-lab\nsyslocation test room\nend\n")
	require.Equal(t, "02:00:00:00:00:01", d.Snapshot().Running["hostname"])
	input(t, s, "commit apply no-save\n")
	require.Contains(t, input(t, s, "show running-config\n"), "name ap-lab\r\nsyslocation test room\r\n")
	require.Equal(t, before.Startup, d.Snapshot().Startup)
	input(t, s, "write memory\nconfigure terminal\nname saved-ap\nend\ncommit apply\n")
	require.Equal(t, "saved-ap", d.Snapshot().Startup["hostname"])
	input(t, s, "reload\nn\n")
	require.NoError(t, s.Err())
	input(t, s, "reload\ny\n")
	require.ErrorIs(t, s.Err(), emulator.ErrReboot)
	require.Equal(t, "saved-ap", d.Snapshot().Running["hostname"])
}

func TestArubaDHCPBootPasswordNoiseResetAndDegradedCLI(t *testing.T) {
	d := arubaDevice(t, true)
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Empty(t, drain(s))
	require.Empty(t, input(t, s, "ignored during boot\n"))
	_, err = d.Attach(emulator.AttachOptions{Authenticated: true})
	require.ErrorIs(t, err, emulator.ErrNotReady)
	require.NoError(t, d.Advance(4100*time.Millisecond))
	out := drain(s)
	require.Contains(t, out, "Starting DHCP\r\nGetting an IP address...")
	require.Equal(t, 3, strings.Count(out, "Sending discover..."))
	require.Contains(t, out, "No lease, forking to background.")
	require.NotContains(t, out, "User:")
	require.NoError(t, d.Advance(12900*time.Millisecond))
	out = drain(s)
	require.Equal(t, 15, strings.Count(out, "Sending discover..."))
	require.True(t, strings.HasSuffix(out, "USB Modem is not presenUser: "))
	require.True(t, d.Snapshot().LoginReady)
	require.Equal(t, "degraded", d.Snapshot().Lifecycle)
	require.Equal(t, "admin\r\nPassword: ", input(t, s, "admin\n"))
	require.Empty(t, input(t, s, "sec"))
	require.NoError(t, d.Advance(20*time.Millisecond))
	require.Equal(t, "ble_ready NOT present @init ....\r\n", drain(s))
	out = input(t, s, "ret\n")
	require.Contains(t, out, "Warning: CLI module is running in a degraded state.")
	require.True(t, strings.HasSuffix(out, arubaPrompt))
	require.NotContains(t, out, "secret")
	before := d.Snapshot()
	require.Contains(t, input(t, s, "configure terminal\n"), "Configuration is not allowed when CLI is running in a degraded state.")
	require.Contains(t, input(t, s, "write memory\n"), "Write memory is not allowed when CLI is running in a degraded state.")
	require.Contains(t, input(t, s, "commit apply\n"), "Configuration is not allowed")
	require.Equal(t, before, d.Snapshot())
	input(t, s, "sh")
	require.NoError(t, d.Advance(100*time.Millisecond))
	out = drain(s)
	require.Contains(t, out, "Sending discover...")
	require.NotContains(t, out, arubaPrompt) // Raw logs don't repair the interrupted line.
	require.Contains(t, input(t, s, "ow version\n"), "ArubaOS")

	require.NoError(t, d.Advance(20700*time.Millisecond-d.Snapshot().Now))
	require.Equal(t, "\r\nInternal error 8-0, please contact support\r\nUser: ", drain(s))
	require.NoError(t, d.Advance(10*time.Millisecond))
	require.Contains(t, drain(s), "!!! Init ---> Conductor")
	input(t, s, "admin\n")
	require.NoError(t, s.Close())
	s, err = d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Equal(t, "Password: ", drain(s))
	require.Contains(t, input(t, s, "secret\n"), arubaPrompt)
	require.NotContains(t, fmt.Sprint(d.Trace()), "secret")
	input(t, s, "reload\ny\n")
	require.False(t, d.Snapshot().LoginReady)
	require.Empty(t, drain(s))
	require.NoError(t, d.Advance(17*time.Second))
	require.True(t, strings.HasSuffix(drain(s), "USB Modem is not presenUser: "))
}
