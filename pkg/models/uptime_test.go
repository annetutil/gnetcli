package models_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/huawei"
	"github.com/annetutil/gnetcli/pkg/device/juniper"
	"github.com/annetutil/gnetcli/pkg/models"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name + ".txt")
	require.NoError(t, err)
	return string(data)
}

func uptimeRunner(t *testing.T) *models.Runner {
	t.Helper()
	r, err := models.New("../../models")
	require.NoError(t, err)
	return r
}

func checkUptime(t *testing.T, result json.RawMessage, clock time.Time, duration time.Duration, boot time.Time) {
	t.Helper()
	var got map[string]int64
	require.NoError(t, json.Unmarshal(result, &got))
	require.Equal(t, map[string]int64{"up-time": int64(duration), "boot-time": boot.UnixNano(), "current-datetime": clock.UnixNano()}, got)
}

func TestUptime(t *testing.T) {
	for _, tc := range []struct {
		name, kind, version, clock, system string
		expectedClock                      time.Time
		duration                           time.Duration
		boot                               time.Time
	}{
		{name: "huawei boards and weeks", kind: "huawei", version: fixture(t, "huawei-version"), clock: fixture(t, "huawei-clock"), expectedClock: time.Date(2026, 1, 20, 7, 30, 0, 0, time.UTC), duration: 9*24*time.Hour + 3*time.Hour + 4*time.Minute},
		{name: "huawei singular", kind: "huawei", version: "HUAWEI lab uptime is 0 day, 1 hour, 1 minute\n", clock: "2026-01-20 10:30:00\nTime Zone(UTC) : UTC\n", expectedClock: time.Date(2026, 1, 20, 10, 30, 0, 0, time.UTC), duration: 61 * time.Minute},
		{name: "huawei separate offset", kind: "huawei", version: "HUAWEI lab uptime is 0 days, 0 hours, 0 minutes\n", clock: "2026-01-20 10:30:00\nTime Zone(MSK) : UTC+03:00\n", expectedClock: time.Date(2026, 1, 20, 7, 30, 0, 0, time.UTC)},
		{name: "huawei negative offset", kind: "huawei", version: "HUAWEI lab uptime is 0 days, 1 hour, 0 minutes\n", clock: "2026-01-20 10:30:00-05:00\n", expectedClock: time.Date(2026, 1, 20, 15, 30, 0, 0, time.UTC), duration: time.Hour},
		{name: "huawei DST offset wins", kind: "huawei", version: "HUAWEI lab uptime is 0 days, 1 hour, 0 minutes\n", clock: "2026-01-20 10:30:00+04:00 DST\nTime Zone(MSK) : UTC+03:00\n", expectedClock: time.Date(2026, 1, 20, 6, 30, 0, 0, time.UTC), duration: time.Hour},
		{name: "huawei startup local", kind: "huawei", version: "HUAWEI lab uptime is 0 days, 1 hour, 0 minutes\n StartupTime 2026/01/20   09:29:45\n", clock: "2026-01-20 10:30:00+03:00", expectedClock: time.Date(2026, 1, 20, 7, 30, 0, 0, time.UTC), duration: time.Hour, boot: time.Date(2026, 1, 20, 6, 29, 45, 0, time.UTC)},
		{name: "huawei startup explicit", kind: "huawei", version: "HUAWEI lab uptime is 0 days, 1 hour, 0 minutes\n StartupTime 2026/01/20   09:30:00+02:00\n", clock: "2026-01-20 10:30:00+02:00", expectedClock: time.Date(2026, 1, 20, 8, 30, 0, 0, time.UTC), duration: time.Hour},
		{name: "juniper multiple weeks", kind: "juniper", system: fixture(t, "juniper-uptime"), expectedClock: time.Date(2026, 1, 20, 10, 30, 0, 0, time.UTC), duration: 19 * 24 * time.Hour},
		{name: "juniper short MSK", kind: "juniper", system: "Current time: 2026-01-20 10:30:00 MSK\nSystem booted: 2026-01-20 10:29:55 MSK (00:05 ago)\n", expectedClock: time.Date(2026, 1, 20, 7, 30, 0, 0, time.UTC), duration: 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands := []string{"display version", "display clock"}
			outputs := []string{tc.version, tc.clock}
			if tc.kind == "juniper" {
				commands = []string{"show system uptime"}
				outputs = []string{tc.system}
			}
			calls := 0
			res, err := uptimeRunner(t).Collect(t.Context(), executor(func(_ context.Context, c cmd.Cmd) (cmd.CmdRes, error) {
				require.Less(t, calls, len(commands))
				require.Equal(t, commands[calls], string(c.Value()))
				out := outputs[calls]
				calls++
				return cmd.NewCmdRes([]byte(out)), nil
			}), tc.kind, "uptime")
			require.NoError(t, err)
			require.Equal(t, len(commands), calls)
			boot := tc.boot
			if boot.IsZero() {
				boot = tc.expectedClock.Add(-tc.duration)
			}
			checkUptime(t, res, tc.expectedClock, tc.duration, boot)
		})
	}
}

func TestUptimeInvalid(t *testing.T) {
	for _, tc := range []struct{ name, kind, version, clock, system string }{
		{name: "empty huawei", kind: "huawei"},
		{name: "malformed system must not use board", kind: "huawei", version: "HUAWEI lab uptime is malformed\nLAB(Master) 1 : uptime is 0 days, 1 hour, 0 minutes\n", clock: "2026-01-20 10:30:00UTC"},
		{name: "empty clock", kind: "huawei", version: "HUAWEI lab uptime is 0 days, 1 hour, 0 minutes\n"},
		{name: "unknown timezone", kind: "juniper", system: "Current time: 2026-01-20 10:30:00 UNKNOWN\nSystem booted: 2026-01-20 10:00:00 UTC (00:30 ago)\n"},
		{name: "invalid date", kind: "juniper", system: "Current time: 2026-13-20 10:30:00 UTC\nSystem booted: 2026-01-20 10:00:00 UTC (00:30 ago)\n"},
		{name: "negative duration", kind: "juniper", system: "Current time: 2026-01-20 10:30:00 UTC\nSystem booted: 2026-01-21 10:00:00 UTC (00:30 ago)\n"},
		{name: "node only", kind: "juniper", system: "Current time: 2026-01-20 10:30:00 UTC\nNode booted: 2026-01-20 10:00:00 UTC (00:30 ago)\n"},
		{name: "malformed startup", kind: "huawei", version: "HUAWEI lab uptime is 0 days, 1 hour, 0 minutes\n StartupTime invalid\n", clock: "2026-01-20 10:30:00UTC"},
		{name: "unsupported", kind: "cisco"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := executor(func(_ context.Context, c cmd.Cmd) (cmd.CmdRes, error) {
				require.NotEqual(t, "cisco", tc.kind)
				outputs := map[string]string{"display version": tc.version, "display clock": tc.clock, "show system uptime": tc.system}
				return cmd.NewCmdRes([]byte(outputs[string(c.Value())])), nil
			})
			result, err := uptimeRunner(t).Collect(t.Context(), fake, tc.kind, "uptime")
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
}

func TestUptimeSSHDialogs(t *testing.T) {
	for _, kind := range []string{"huawei", "juniper"} {
		t.Run(kind, func(t *testing.T) {
			prompt := "<lab>"
			setup := []string{"screen-length 0 temporary", "terminal echo-mode line", "undo terminal monitor"}
			commands := []string{"display version", "display clock"}
			outputs := []string{fixture(t, "huawei-version"), fixture(t, "huawei-clock")}
			clock := time.Date(2026, 1, 20, 7, 30, 0, 0, time.UTC)
			duration := 9*24*time.Hour + 3*time.Hour + 4*time.Minute
			if kind == "juniper" {
				prompt = "user@lab> "
				setup = []string{"set cli complete-on-space off", "set cli screen-length 0", "set cli screen-width 1024", "set cli terminal ansi"}
				commands = []string{"show system uptime"}
				outputs = []string{fixture(t, "juniper-uptime")}
				clock = time.Date(2026, 1, 20, 10, 30, 0, 0, time.UTC)
				duration = 19 * 24 * time.Hour
			}
			dialog := []m.Action{m.Send(prompt)}
			for _, command := range setup {
				dialog = append(dialog, m.Expect(command+"\n"), m.SendEcho(command+"\r\n"), m.Send("\r\n"+prompt))
			}
			for i, command := range commands {
				dialog = append(dialog, m.Expect(command+"\n"), m.SendEcho(command+"\r\n"), m.Send(strings.ReplaceAll(outputs[i], "\n", "\r\n")), m.Send("\r\n"+prompt))
			}
			server, err := m.NewMockSSHServer(dialog)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- server.Run(ctx) }()
			host, port := server.GetAddress()
			connector := ssh.NewStreamer(host, credentials.NewSimpleCredentials(), ssh.WithPort(port))
			var dev device.Device
			if kind == "huawei" {
				d := huawei.NewDevice(connector)
				dev = &d
			} else {
				d := juniper.NewDevice(connector)
				dev = &d
			}
			defer dev.Close()
			require.NoError(t, dev.Connect(ctx))
			result, err := uptimeRunner(t).Collect(ctx, dev, kind, "uptime")
			require.NoError(t, err)
			checkUptime(t, result, clock, duration, clock.Add(-duration))
			dev.Close()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
