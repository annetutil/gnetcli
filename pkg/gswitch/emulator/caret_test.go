package emulator_test

import (
	"os"
	"strings"
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

func loadCaretProfile(t *testing.T, extraCommands string) *emulator.Profile {
	t.Helper()
	root, err := os.OpenRoot("../../../examples/gswitch")
	require.NoError(t, err)
	defer root.Close()
	f, err := root.ReadFile("huawei.yaml")
	require.NoError(t, err)
	source := strings.Replace(string(f), "hostname: sw1", "hostname: lab-vla-1s1", 1)
	if extraCommands != "" {
		source = strings.Replace(source, "\ndialogs:\n", "\n"+extraCommands+"dialogs:\n", 1)
	}
	p, err := emulator.LoadProfile(strings.NewReader(source), root.FS())
	require.NoError(t, err)
	return p
}

func caretSession(t *testing.T, d *emulator.Device) *emulator.Session {
	t.Helper()
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
	require.NoError(t, err)
	require.Equal(t, "<lab-vla-1s1>", drain(s))
	return s
}

func TestHuaweiCaretMatchesSuppliedIncompleteExample(t *testing.T) {
	p := loadCaretProfile(t, "")
	d := validationDevice(t, p)
	s := caretSession(t, d)
	_, err := p.Parse("user", "display")
	var pe *emulator.ParseError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, 7, pe.Offset) // Parser offsets remain relative to command bytes.
	want := "                     ^\r\nError: Incomplete command found at '^' position.\r\n<lab-vla-1s1>"
	require.Equal(t, "display\r\n"+want, input(t, s, "display\n"))
	require.Equal(t, "display \r\n"+want, input(t, s, "display \r\n"))
	require.Equal(t, "display   \r\n"+strings.Repeat(" ", 23)+"^\r\nError: Incomplete command found at '^' position.\r\n<lab-vla-1s1>", input(t, s, "display   \n"))
	// The error clears command input. Root '?' must still have its header/indent.
	help := input(t, s, "?")
	require.True(t, strings.HasPrefix(help, "?\r\nCurrent view commands:\r\n  display           Display current system information\r\n"))
	require.True(t, strings.HasSuffix(help, "\r\n\r\n<lab-vla-1s1>"))
}

func TestHuaweiCaretPointsToInvalidAndAmbiguousTokens(t *testing.T) {
	d := validationDevice(t, loadCaretProfile(t, ""))
	s := caretSession(t, d)
	for _, tc := range []struct {
		line, kind string
		column     int
	}{
		{"nonsense", "Unrecognized", 13},
		{"display nonexistent", "Unrecognized", 21},
		{"screen-length bad temporary", "Unrecognized", 27},
		{"s", "Ambiguous", 13},
	} {
		require.Equal(t, tc.line+"\r\n"+strings.Repeat(" ", tc.column)+"^\r\nError: "+tc.kind+" command found at '^' position.\r\n<lab-vla-1s1>", input(t, s, tc.line+"\n"))
	}
}

func TestHuaweiCaretIncludesConfigurationViewPrompt(t *testing.T) {
	d := validationDevice(t, loadCaretProfile(t, ""))
	s := caretSession(t, d)
	input(t, s, "system-view\ninterface GE0/0/1\n")
	require.Equal(t, "description\r\n"+strings.Repeat(" ", 34)+"^\r\nError: Incomplete command found at '^' position.\r\n[~lab-vla-1s1-GE0/0/1]", input(t, s, "description\n"))
}

func TestCaretUsesLastEmittedPromptNotChangedSharedHostname(t *testing.T) {
	p := loadCaretProfile(t, `  - id: rename-for-test
    modes: [user]
    syntax: "rename <name:word>"
    actions: [{op: set, path: [hostname], value: "{{ .Args.name }}"}]
`)
	d := validationDevice(t, p)
	a, b := caretSession(t, d), caretSession(t, d)
	input(t, a, "disp")
	input(t, b, "rename x\n")
	require.Equal(t, "lay\r\n                     ^\r\nError: Incomplete command found at '^' position.\r\n<x>", input(t, a, "lay\n"))
	require.Equal(t, "nonsense\r\n   ^\r\nError: Unrecognized command found at '^' position.\r\n<x>", input(t, a, "nonsense\n"))
}

func TestHuaweiCaretWithLineEchoAndRecalledInput(t *testing.T) {
	d := validationDevice(t, loadCaretProfile(t, ""))
	s := caretSession(t, d)
	input(t, s, "display\n")
	input(t, s, historyUp)
	require.Equal(t, "\r\n                     ^\r\nError: Incomplete command found at '^' position.\r\n<lab-vla-1s1>", input(t, s, "\n"))
	input(t, s, "terminal echo-mode line\n")
	require.Equal(t, "display\r\n                     ^\r\nError: Incomplete command found at '^' position.\r\n<lab-vla-1s1>", input(t, s, "display\n"))
}
