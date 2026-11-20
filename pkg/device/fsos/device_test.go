package fsos

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/testutils"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPrompt(t *testing.T) {
	cases := [][]byte{
		// user mode ">" and enable mode "#"
		[]byte("\r\nswitch>"),
		[]byte("\r\nswitch#"),
		// identity may carry a custom prefix with ':' (observed on live S5810)
		[]byte("\r\nAccess:FS_BG_W060-Banjica>"),
		[]byte("\r\nAccess:FS_BG_W060-Banjica#"),
		// hostname with '-', '.', '/'
		[]byte("\r\nfs-sw01.lab/1>"),
		// trailing space is tolerated
		[]byte("\r\nswitch> "),
	}
	testutils.ExprTester(t, cases, promptExpression)
}

func TestErrors(t *testing.T) {
	cases := [][]byte{
		// FSOS rejects the Cisco/Eltex terminal/init commands this profile avoids
		[]byte("% Unknown command."),
		[]byte("            ^\r\n% Invalid input detected at '^' marker."),
		[]byte("% Ambiguous command:  \"sh\""),
		[]byte("% Incomplete command."),
		[]byte("% Unrecognized host or address.  Add it to the host table."),
		[]byte("% Access denied"),
	}
	testutils.ExprTester(t, cases, errorExpression)
}

func TestEcho(t *testing.T) {
	// FSOS terminates the command echo with an extra CR ("\r\r\n"); the echo
	// matcher must tolerate any number of CRs before the newline.
	cases := [][]byte{
		[]byte("show version\r\r\n"),
		[]byte("show version\r\n"),
		[]byte("show version\n"),
	}
	pattern := fmt.Sprintf(`%s\r*\n`, regexp.QuoteMeta("show version"))
	testutils.ExprTester(t, cases, pattern)
}

// FSOS sends no greeting banner and the profile runs no auto/init commands, so
// the session simply starts at the user-mode prompt.
var (
	fsosHello = []m.Action{
		m.Send("\r\nAccess:FS_BG_W060-Banjica>"),
	}
	// The terminating prompt carries no leading newline: the preceding command
	// output already ends in "\r\n", which is the boundary the prompt expression
	// matches on. (A leading newline here would instead leave that "\r\n" in the
	// output as a spurious trailing blank line.)
	fsosByeBye = []m.Action{
		m.Send("Access:FS_BG_W060-Banjica>"),
		m.Close(),
	}
)

func fsosDeviceMaker(connector streamer.Connector) device.Device {
	dev := NewDevice(connector)
	return &dev
}

func TestFSOSValidCommands(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		result  string
		dialog  [][]m.Action
	}{
		{
			name:    "show version in user mode (no enable)",
			command: "show version",
			result: "" +
				"System description      : FS Campus Switch (S5810-28FS) By FS.COM Inc\n" +
				"System software version : S5810_FSOS 11.4(1)B74S8, Release(10200711)\n" +
				"System uptime           : 0 days, 1 hours, 2 minutes",
			dialog: [][]m.Action{
				fsosHello,
				{
					m.Expect("show version\n"),
					// echo is terminated by an extra CR ("\r\r\n")
					m.SendEcho("show version\r\r\n"),
					m.Send("" +
						"System description      : FS Campus Switch (S5810-28FS) By FS.COM Inc\r\n" +
						"System software version : S5810_FSOS 11.4(1)B74S8, Release(10200711)\r\n" +
						"System uptime           : 0 days, 1 hours, 2 minutes\r\n"),
				},
				fsosByeBye,
			},
		},
		{
			name:    "show clock",
			command: "show clock",
			result:  "16:40:40 UTC Wed, Aug  5, 2026",
			dialog: [][]m.Action{
				fsosHello,
				{
					m.Expect("show clock\n"),
					m.SendEcho("show clock\r\r\n"),
					m.Send("16:40:40 UTC Wed, Aug  5, 2026\r\n"),
				},
				fsosByeBye,
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			m.RunDialogWithDefaultCreds(t, fsosDeviceMaker, actions, tc.command, tc.result)
		})
	}
}

// TestFSOSPager exercises the reactive "--More--" pager: FSOS has no
// pager-disable command, so genericcli must detect the prompt, answer with a
// space, and stitch the two pages back together. The newline that precedes
// "--More--" must survive (captured by the pager expression's "store" group),
// otherwise the last line of page one is glued to the first line of page two.
func TestFSOSPager(t *testing.T) {
	command := "show running-config"
	expected := "" +
		"hostname Access:FS_BG_W060-Banjica\n" +
		"vlan 100\n" +
		" name management\n" +
		"interface eth-0-1\n" +
		" switchport access vlan 100"

	dialog := [][]m.Action{
		fsosHello,
		{
			m.Expect("show running-config\n"),
			m.SendEcho("show running-config\r\r\n"),
			// page one, ending on the pager prompt (on its own line)
			m.Send("" +
				"hostname Access:FS_BG_W060-Banjica\r\n" +
				"vlan 100\r\n" +
				" name management\r\n" +
				" --More-- "),
			m.Expect(" "), // genericcli answers the pager with a single space
			// page two (the cosmetic erase of "--More--" is elided for clarity)
			m.Send("" +
				"interface eth-0-1\r\n" +
				" switchport access vlan 100\r\n"),
		},
		fsosByeBye,
	}

	actions := m.ConcatMultipleSlices(dialog)
	m.RunDialogWithDefaultCreds(t, fsosDeviceMaker, actions, command, expected)
}

func TestFSOSInvalidCommands(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		dialog  [][]m.Action
	}{
		{
			// The whole reason this profile exists: FSOS does not understand the
			// terminal/init commands a Cisco/Eltex profile would send.
			name:    "terminal command is unknown",
			command: "terminal length 0",
			dialog: [][]m.Action{
				fsosHello,
				{
					m.Expect("terminal length 0\n"),
					m.SendEcho("terminal length 0\r\r\n"),
					m.Send("% Unknown command.\r\n"),
				},
				fsosByeBye,
			},
		},
		{
			name:    "invalid input",
			command: "show verzion",
			dialog: [][]m.Action{
				fsosHello,
				{
					m.Expect("show verzion\n"),
					m.SendEcho("show verzion\r\r\n"),
					m.Send("" +
						"            ^\r\n" +
						"% Invalid input detected at '^' marker.\r\n"),
				},
				fsosByeBye,
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			m.RunInvalidDialog(t, fsosDeviceMaker, actions, tc.command)
		})
	}
}

// TestFSOSConsecutiveCommands runs two commands over a single session to make
// sure the prompt is re-synchronised between commands. It uses the lower-level
// RunCmd helper because RunDialog only runs a single command.
func TestFSOSConsecutiveCommands(t *testing.T) {
	logger := zap.NewNop()
	dialog := [][]m.Action{
		fsosHello,
		{
			m.Expect("show version\n"),
			m.SendEcho("show version\r\r\n"),
			m.Send("S5810_FSOS 11.4(1)B74S8\r\n"),
			m.Send("Access:FS_BG_W060-Banjica>"),
			m.Expect("show clock\n"),
			m.SendEcho("show clock\r\r\n"),
			m.Send("16:40:40 UTC Wed, Aug  5, 2026\r\n"),
		},
		fsosByeBye,
	}

	actions := m.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{cmd.NewCmd("show version"), cmd.NewCmd("show clock")}
	cmdRes, resErr, serverErr, err := m.RunCmd(fsosDeviceMaker, actions, cmds, logger)
	require.NoError(t, err)
	require.NoError(t, resErr)
	require.NoError(t, serverErr)
	require.Len(t, cmdRes, 2)
	require.Equal(t, 0, cmdRes[0].Status())
	require.Equal(t, "S5810_FSOS 11.4(1)B74S8", string(cmdRes[0].Output()))
	require.Equal(t, 0, cmdRes[1].Status())
	require.Equal(t, "16:40:40 UTC Wed, Aug  5, 2026", string(cmdRes[1].Output()))
}
