package emulator_test

import (
	"strings"
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

func TestHuaweiSysnameHelpAndCandidate(t *testing.T) {
	p := loadCaretProfile(t, "")
	require.Equal(t, "  TEXT<1-246>  Host name (1 to 246 characters)\n", p.RenderHelp("system", "sysname "))
	require.Equal(t, []string{"sysname"}, p.Help("system", "sys"))
	require.Equal(t, "sysname ", p.Complete("system", "sys").Line)
	require.Empty(t, p.Help("user", "sysname "))
	d := validationDevice(t, p)
	a, b := caretSession(t, d), caretSession(t, d)
	input(t, a, "system-view\n")
	before := d.Snapshot()
	require.Equal(t, "sysname ?\r\n  TEXT<1-246>  Host name (1 to 246 characters)\r\n\r\n[~lab-vla-1s1]sysname ", input(t, a, "sysname ?"))
	require.Equal(t, before, d.Snapshot())
	require.Equal(t, "\r\nTEXT<1-246>\r\n[~lab-vla-1s1]sysname ", input(t, a, "\t"))
	require.Equal(t, "Lab-SW2\r\n[*Lab-SW2]", input(t, a, "Lab-SW2\n"))
	require.Equal(t, "lab-vla-1s1", d.Snapshot().Running["hostname"])
	require.Contains(t, input(t, b, "display current-configuration\n"), "sysname lab-vla-1s1\r\n")
	require.Contains(t, input(t, a, "interface GE0/0/1\n"), "[*Lab-SW2-GE0/0/1]")
	require.Equal(t, "commit\r\n[~Lab-SW2-GE0/0/1]", input(t, a, "commit\n"))
	require.Equal(t, "Lab-SW2", d.Snapshot().Running["hostname"])
	require.Equal(t, "lab-vla-1s1", d.Snapshot().Startup["hostname"])
	require.Equal(t, "return\r\n<Lab-SW2>", input(t, a, "return\n"))
	require.Contains(t, input(t, b, "display current-configuration\n"), "sysname Lab-SW2\r\n")
	require.Equal(t, "\r\n<Lab-SW2>", input(t, b, "\n"))

	// Neither quitting the candidate nor declining save persists a new name.
	input(t, a, "system-view\nsysname discarded\nquit\n")
	require.Equal(t, "Lab-SW2", d.Snapshot().Running["hostname"])
	input(t, a, "system-view\nsysname discarded-again\nreturn\n")
	require.Equal(t, "Lab-SW2", d.Snapshot().Running["hostname"])
	input(t, a, "save\nn\n")
	require.Equal(t, "lab-vla-1s1", d.Snapshot().Startup["hostname"])
	input(t, a, "save\ny\n")
	require.Equal(t, "Lab-SW2", d.Snapshot().Startup["hostname"])
	require.NoError(t, d.Reboot())
	require.Equal(t, "Lab-SW2", d.Snapshot().Running["hostname"])
}

func TestHuaweiSysnameBoundsBeforeCandidateMutation(t *testing.T) {
	p := loadHuaweiHelpProfile(t)
	for _, name := range []string{"x", strings.Repeat("x", 246)} {
		m, err := p.Parse("system", "sysname "+name)
		require.NoError(t, err)
		require.Equal(t, name, m.Args["name"])
		d := validationDevice(t, p)
		s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
		require.NoError(t, err)
		drain(s)
		input(t, s, "system-view\n")
		require.Equal(t, "sysname "+name+"\r\n[*"+name+"]", input(t, s, "sysname "+name+"\n"))
		input(t, s, "commit\n")
		require.Equal(t, name, d.Snapshot().Running["hostname"])
	}
	d := validationDevice(t, p)
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
	require.NoError(t, err)
	drain(s)
	input(t, s, "system-view\n")
	for _, tc := range []struct {
		command, kind string
		offset        int
	}{
		{"sysname", "incomplete", 7},
		{"sysname ", "incomplete", 8},
		{"sysname " + strings.Repeat("x", 247), "invalid", 8},
		{"sysname two words", "invalid", 12},
	} {
		_, err := p.Parse("system", tc.command)
		var pe *emulator.ParseError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, tc.kind, pe.Kind)
		require.Equal(t, tc.offset, pe.Offset)
		before := d.Snapshot()
		out := input(t, s, tc.command+"\n")
		require.Contains(t, out, "Error:")
		require.True(t, strings.HasSuffix(out, "[~sw1]"))
		require.Equal(t, before, d.Snapshot())
	}
	invalid := "sysname " + strings.Repeat("x", 247)
	require.Contains(t, input(t, s, invalid+"\n"), "\r\n"+strings.Repeat(" ", len("[~sw1]sysname "))+"^\r\n")
	// An unsaved committed hostname is lost on reboot.
	input(t, s, "sysname unsaved\ncommit\n")
	require.NoError(t, d.Reboot())
	require.Equal(t, "sw1", d.Snapshot().Running["hostname"])
}
