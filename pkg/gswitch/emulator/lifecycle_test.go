package emulator_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

func TestLifecycleGuardRejectsRemainingActions(t *testing.T) {
	text := strings.Replace(profileYAML, "actions: [{op: push, mode: config}]", `actions:
      - {op: require-lifecycle, value: operational, text: "Configuration unavailable\n"}
      - {op: set, path: [hostname], value: changed}
      - {op: save}
      - {op: push, mode: config}`, 1)
	d := validationDevice(t, load(t, text))
	s := attach(t, d)
	require.NoError(t, d.Inject(emulator.Event{Kind: "lifecycle", Text: "degraded"}))
	before := d.Snapshot()
	require.Equal(t, "configure terminal\r\nConfiguration unavailable\r\nsw#", input(t, s, "configure terminal\n"))
	require.Equal(t, before, d.Snapshot())
	require.NoError(t, d.Inject(emulator.Event{Kind: "lifecycle", Text: "operational"}))
	require.Contains(t, input(t, s, "configure terminal\n"), "changed(config)#")
	require.Equal(t, "changed", d.Snapshot().Startup["hostname"])
	for _, value := range []string{`{op: require-lifecycle, value: true, text: no}`, `{op: require-lifecycle, value: operational}`, `{op: require-lifecycle, value: "", text: no}`} {
		_, err := emulator.LoadProfile(strings.NewReader(strings.Replace(profileYAML, "{op: push, mode: config}", value, 1)), nil)
		require.ErrorContains(t, err, "require-lifecycle")
	}
}

func TestConsoleResetClearsSessionAndCancelsPendingWork(t *testing.T) {
	d := device(t, emulator.Options{})
	ssh := attach(t, d)
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	drain(s)
	input(t, s, "test\nsecret\nbegin\ndescription discarded\nexit\nshow slow\n")
	require.NoError(t, d.Inject(emulator.Event{Kind: "console-reset"}))
	require.Equal(t, "Username: ", drain(s))
	require.Empty(t, drain(ssh))
	require.NoError(t, d.Advance(time.Second))
	require.Empty(t, drain(s))
	require.Equal(t, "initial", d.Snapshot().Running["description"])
	for _, snap := range d.Snapshot().Sessions {
		if snap.Console == "tty0" {
			require.Nil(t, snap.Candidate)
			require.Empty(t, snap.Username)
			require.Equal(t, "username", snap.Interaction)
		}
	}
	input(t, s, "test\nsec")
	require.NoError(t, d.Inject(emulator.Event{Kind: "console-reset"}))
	require.Equal(t, "Username: ", drain(s))
	input(t, s, "test\n")
	require.Contains(t, input(t, s, "ret\n"), "Authentication failed") // Old secret prefix was discarded.
	require.Contains(t, input(t, s, "test\nsecret\n"), "sw#")
	require.NotContains(t, input(t, s, historyUp), "show slow")
	require.Contains(t, input(t, ssh, "show running\n"), "initial")
	require.NotContains(t, fmt.Sprint(d.Trace()), "secret")
}

func TestPasswordEntryTriggerDoesNotRepeatOnRedraw(t *testing.T) {
	scenario, err := emulator.LoadScenario(strings.NewReader(`apiVersion: cli-emulator/v1
triggers:
  - on: login:password
    event: {kind: log, route: session, policy: raw, text: interrupted}
`), nil)
	require.NoError(t, err)
	d := device(t, emulator.Options{Scenario: scenario})
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	drain(s)
	require.Equal(t, "test\r\nPassword: interrupted\r\n", input(t, s, "test\n"))
	require.Empty(t, input(t, s, "sec"))
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Text: "redraw", Route: "console", Policy: "redraw"}))
	require.Equal(t, "\r\x1b[2Kredraw\r\nPassword: ", drain(s))
	require.NoError(t, s.Close())
	s, err = d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Equal(t, "Password: ", drain(s))
	require.Equal(t, "\r\nsw#", input(t, s, "ret\n"))
}

func TestTimeZeroReadinessOnReboot(t *testing.T) {
	scenario := &emulator.Scenario{APIVersion: "cli-emulator/v1", Timeline: []emulator.Event{
		{Kind: "ready", Text: "false"}, {At: time.Second, Kind: "ready", Text: "true"},
	}}
	d := device(t, emulator.Options{Scenario: scenario})
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Empty(t, drain(s))
	require.NoError(t, d.Advance(time.Second))
	require.Equal(t, "Username: ", drain(s))
	input(t, s, "test\nsecret\n")
	require.NoError(t, d.Reboot())
	require.Empty(t, drain(s))
	require.False(t, d.Snapshot().LoginReady)
	require.Empty(t, input(t, s, "ignored\n"))
	require.NoError(t, d.Advance(time.Second))
	require.Equal(t, "Username: ", drain(s))
}

func TestConsoleResetValidation(t *testing.T) {
	for _, fields := range []string{"route: all", "route: session", "text: ignored", "policy: raw", "file: ignored.txt"} {
		_, err := emulator.LoadScenario(strings.NewReader("apiVersion: cli-emulator/v1\ntimeline:\n  - {kind: console-reset, "+fields+"}\n"), nil)
		require.Error(t, err, fields)
	}
}
