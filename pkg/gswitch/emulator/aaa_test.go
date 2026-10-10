package emulator_test

import (
	"strings"
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const initialAAASection = "#\r\naaa\r\n" +
	" undo local-user policy security-enhance\r\n" +
	" default-domain admin localuser\r\n" +
	" service-type terminal force-domain default0\r\n#\r\n"

func TestHuaweiAAACapturedTranscript(t *testing.T) {
	p := loadCaretProfile(t, "")
	d := validationDevice(t, p)
	s := caretSession(t, d)
	input(t, s, "system-view\n")
	require.Equal(t, "aaa\r\n[~lab-vla-1s1-aaa]", input(t, s, "aaa\n"))
	before := d.Snapshot()
	require.Equal(t, "display ", input(t, s, "dis\t"))
	require.Equal(t, before, d.Snapshot())
	require.Equal(t, "this\r\n"+initialAAASection+"return\r\n[~lab-vla-1s1-aaa]", input(t, s, "this\n"))
	require.Equal(t, before, d.Snapshot())
	// Both abbreviated execution and the captured double space work.
	for _, command := range []string{"dis this", "display  this", "dis th"} {
		require.Equal(t, command+"\r\n"+initialAAASection+"return\r\n[~lab-vla-1s1-aaa]", input(t, s, command+"\n"))
	}
	require.Contains(t, input(t, s, "dis\n"), "Incomplete command")
	require.Equal(t, before, d.Snapshot())
	help := input(t, s, "?")
	require.Contains(t, help, "Current view commands:")
	require.Equal(t, 1, strings.Count(help, "  display "))
	require.NotContains(t, help, "sysname")
	require.NotContains(t, help, "Enter interface view")
	require.Contains(t, p.Help("aaa", "dis "), "this")
	require.Equal(t, []string{"<cr>"}, p.Help("aaa", "dis this "))
	require.Equal(t, "dis this ", p.Complete("aaa", "dis th").Line)
	require.Contains(t, input(t, s, "display version\n"), "Huawei VRP")
	require.Contains(t, input(t, s, "display current-configuration\n"), initialAAASection)
	require.Equal(t, "quit\r\n[~lab-vla-1s1]", input(t, s, "quit\n"))
	require.Equal(t, "aaa\r\n[~lab-vla-1s1-aaa]", input(t, s, "aaa\n"))
	require.Equal(t, "return\r\n<lab-vla-1s1>", input(t, s, "return\n"))
	for _, tc := range []struct{ mode, line string }{
		{"user", "aaa"}, {"user", "display this"}, {"aaa", "sysname other"},
		{"aaa", "interface GE0/0/1"}, {"system", "default-domain admin other"},
	} {
		_, err := p.Parse(tc.mode, tc.line)
		require.Error(t, err, tc)
	}
}

func TestHuaweiAAAUsesCommittedStateAndRetainsCandidateOnQuit(t *testing.T) {
	d := validationDevice(t, loadHuaweiHelpProfile(t))
	attachAAA := func() *emulator.Session {
		s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
		require.NoError(t, err)
		drain(s)
		require.Contains(t, input(t, s, "system-view\naaa\n"), "[~sw1-aaa]")
		return s
	}
	a, b := attachAAA(), attachAAA()
	before := d.Snapshot()
	input(t, a, "default-domain admin operators\nservice-type terminal force-domain terminal-test\nlocal-user policy security-enhance\n")
	require.Equal(t, before.Running, d.Snapshot().Running)
	require.Equal(t, "display this\r\n"+initialAAASection+"return\r\n[*sw1-aaa]", input(t, a, "display this\n"))
	require.Contains(t, input(t, b, "display this\n"), initialAAASection)
	// Leaving the AAA view is not leaving the candidate transaction.
	require.Equal(t, "quit\r\n[*sw1]", input(t, a, "quit\n"))
	require.Equal(t, "aaa\r\n[*sw1-aaa]", input(t, a, "aaa\n"))
	require.Equal(t, "commit\r\n[~sw1-aaa]", input(t, a, "commit\n"))
	want := "#\r\naaa\r\n local-user policy security-enhance\r\n default-domain admin operators\r\n service-type terminal force-domain terminal-test\r\n#\r\n"
	require.Contains(t, input(t, a, "display this\n"), want)
	// Even a stale candidate reads actual running state via display commands.
	require.Contains(t, input(t, b, "display this\n"), want)
	require.Contains(t, input(t, b, "commit\n"), "Candidate conflicts")
	require.Equal(t, before.Startup, d.Snapshot().Startup)
	input(t, a, "undo local-user policy security-enhance\ncommit\n")
	require.Contains(t, input(t, a, "display this\n"), " undo local-user policy security-enhance\r\n")
	input(t, a, "default-domain admin discarded\nreturn\n")
	require.Equal(t, "operators", d.Snapshot().Running["aaa"].(map[string]any)["adminDomain"])
	input(t, a, "save\ny\n")
	saved := d.Snapshot().Running
	require.NoError(t, d.Reboot())
	require.Equal(t, saved, d.Snapshot().Running)
	s := attachAAA()
	require.Contains(t, input(t, s, "display this\n"), " default-domain admin operators\r\n")
}

func TestHuaweiDisplayThisIncludesSystemTreeOrSelectedInterface(t *testing.T) {
	d := validationDevice(t, loadHuaweiHelpProfile(t))
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
	require.NoError(t, err)
	drain(s)
	input(t, s, "system-view\nsysname renamed\n")
	rootConfig := "#\r\nsysname sw1\r\n" + initialAAASection + "interface GE0/0/1\r\n description initial\r\n#\r\nreturn\r\n"
	require.Equal(t, "display this\r\n"+rootConfig+"[*renamed]", input(t, s, "display this\n"))
	input(t, s, "commit\n")
	require.Equal(t, "dis this\r\n"+strings.Replace(rootConfig, "sysname sw1", "sysname renamed", 1)+"[~renamed]", input(t, s, "dis this\n"))
	input(t, s, "interface GE0/0/1\ndescription pending\n")
	require.Equal(t, "display this\r\n#\r\ninterface GE0/0/1\r\n description initial\r\n#\r\nreturn\r\n[*renamed-GE0/0/1]", input(t, s, "display this\n"))
	input(t, s, "commit\n")
	require.Equal(t, "dis this\r\n#\r\ninterface GE0/0/1\r\n description pending\r\n#\r\nreturn\r\n[~renamed-GE0/0/1]", input(t, s, "dis this\n"))
	input(t, s, "undo description\ncommit\n")
	require.Equal(t, "dis this\r\n#\r\ninterface GE0/0/1\r\n#\r\nreturn\r\n[~renamed-GE0/0/1]", input(t, s, "dis this\n"))
	// An interface context without a committed object still renders safely.
	input(t, s, "quit\ninterface LoopBack 123\ndescription loopback\n")
	out := input(t, s, "dis this\n")
	require.Equal(t, "dis this\r\n#\r\ninterface LoopBack123\r\n#\r\nreturn\r\n[*renamed-LoopBack123]", out)
	input(t, s, "commit\n")
	require.Contains(t, input(t, s, "dis this\n"), " description loopback\r\n")
}

func TestHuaweiRootDisplayThisIncludesCommittedSubsections(t *testing.T) {
	d := validationDevice(t, loadHuaweiHelpProfile(t))
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
	require.NoError(t, err)
	drain(s)
	input(t, s, "system-view\naaa\ndefault-domain admin operators\nq\ninterface LoopBack 123\ndescription loopback\nq\n")
	before := d.Snapshot()
	out := input(t, s, "dis this\n")
	require.Contains(t, out, initialAAASection)
	require.Contains(t, out, "interface GE0/0/1\r\n description initial\r\n")
	require.NotContains(t, out, "operators")
	require.NotContains(t, out, "LoopBack123")
	require.Equal(t, before, d.Snapshot())

	input(t, s, "commit\n")
	before = d.Snapshot()
	out = input(t, s, "dis this\n")
	require.Contains(t, out, "sysname sw1\r\n")
	require.Contains(t, out, "\r\naaa\r\n")
	require.Contains(t, out, " default-domain admin operators\r\n")
	require.Contains(t, out, "interface GE0/0/1\r\n description initial\r\n")
	require.Contains(t, out, "interface LoopBack123\r\n description loopback\r\n")
	require.Equal(t, 1, strings.Count(out, "\r\nreturn\r\n"))
	require.Equal(t, before, d.Snapshot())

	// The root view and full running output must not drift apart as fields grow.
	current := input(t, s, "display current-configuration\n")
	current = strings.TrimSuffix(strings.TrimPrefix(current, "display current-configuration\r\n"), "[~sw1]")
	require.Equal(t, "dis this\r\n#\r\n"+current+"return\r\n[~sw1]", out)
	input(t, s, "aaa\n")
	out = input(t, s, "dis this\n")
	require.Contains(t, out, " default-domain admin operators\r\n")
	require.NotContains(t, out, "sysname")
	require.NotContains(t, out, "interface")
}
