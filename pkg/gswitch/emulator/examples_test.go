package emulator_test

import (
	"os"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

func TestNoisyScenarioExampleProfiles(t *testing.T) {
	for _, tc := range []struct{ profile, prepare, command, prompt string }{
		{"iosxe.yaml", "enable\n", "show slow", "sw1#"},
		{"huawei.yaml", "", "display slow", "<sw1>"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			root, err := os.OpenRoot("../../../examples/gswitch")
			require.NoError(t, err)
			defer root.Close()
			f, err := root.Open(tc.profile)
			require.NoError(t, err)
			p, err := emulator.LoadProfile(f, root.FS())
			f.Close()
			require.NoError(t, err)
			f, err = root.Open("noisy.yaml")
			require.NoError(t, err)
			scenario, err := emulator.LoadScenario(f, root.FS())
			f.Close()
			require.NoError(t, err)
			d, err := emulator.New(p, emulator.Options{Scenario: scenario})
			require.NoError(t, err)
			defer d.Close()
			require.NoError(t, d.Advance(time.Second))
			s, err := d.Attach(emulator.AttachOptions{Authenticated: true, Username: "test"})
			require.NoError(t, err)
			drain(s)
			if tc.prepare != "" {
				input(t, s, tc.prepare)
			}
			require.Equal(t, tc.command+"\r\nHeader\r\nSYSLOG: event between command output chunks\r\n", input(t, s, tc.command+"\n"))
			require.NoError(t, d.Advance(time.Second))
			require.Equal(t, "Body\r\n"+tc.prompt, drain(s))
		})
	}
}

func TestNoisyScenarioDoesNotIgnoreUnknownCheckpoints(t *testing.T) {
	scenario := &emulator.Scenario{
		APIVersion: "cli-emulator/v1",
		Triggers:   []emulator.Trigger{{On: "checkpoint:typo", Event: emulator.Event{Kind: "log", Route: "session", Text: "must not silently disappear"}}},
	}
	_, err := emulator.New(load(t, profileYAML), emulator.Options{Scenario: scenario})
	require.ErrorContains(t, err, `unknown trigger checkpoint "checkpoint:typo"`)
}
