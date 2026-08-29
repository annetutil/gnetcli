package fortios

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

var (
	fortiHello = []m.Action{
		m.Send("Forti1 # "),
		// autocommands
		m.Expect("config system console\n"),
		m.SendEcho("config system console\r\r\n"),
		m.Send("\r\nForti1 (console) # "),
		m.Expect("set output standard\n"),
		m.SendEcho("set output standard\r\r\n"),
		m.Send("\r\nForti1 (console) # "),
		m.Expect("end\n"),
		m.SendEcho("end\r\r\n"),
		m.Send("\r\nForti1 # "),
	}
	fortiBye = []m.Action{
		m.Send("Forti1 # "),
		m.Close(),
	}
)

func TestFortiOS(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		result  string
		dialog  [][]m.Action
	}{
		{
			name:    "get system status",
			command: "get system status",
			result:  "Version: FortiGate-60F v7.2.5,build1517,230504 (GA.F)\nHostname: Forti1\n\n",
			dialog: [][]m.Action{
				fortiHello,
				{
					m.Expect("get system status\n"),
					m.SendEcho("get system status\r\r\n"),
					m.Send("Version: FortiGate-60F v7.2.5,build1517,230504 (GA.F)\r\nHostname: Forti1\r\n\r\n"),
				},
				fortiBye,
			},
		},
		{
			name:    "vdom prompt",
			command: "config vdom",
			result:  "\n",
			dialog: [][]m.Action{
				fortiHello,
				{
					m.Expect("config vdom\n"),
					m.SendEcho("config vdom\r\r\n"),
					m.Send("\r\nForti1 (vdom) # "),
				},
				{m.Close()},
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			m.RunDialogWithDefaultCreds(t, func(connector streamer.Connector) device.Device {
				dev := NewDevice(connector)
				return &dev
			}, actions, tc.command, tc.result)
		})
	}
}

func TestFortiOSError(t *testing.T) {
	dialog := m.ConcatMultipleSlices([][]m.Action{
		fortiHello,
		{
			m.Expect("reboot\n"),
			m.SendEcho("reboot\r\r\n"),
			m.Send("command parse error before 'reboot'\r\nCommand fail. Return code -61\r\n\r\n"),
		},
		fortiBye,
	})
	m.RunInvalidDialog(t, func(connector streamer.Connector) device.Device {
		dev := NewDevice(connector)
		return &dev
	}, dialog, "reboot")
}
