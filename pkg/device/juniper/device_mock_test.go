package juniper

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

var (
	everyDayHello = []m.Action{
		// Common Juniper greeting
		m.Send("Last login: Mon Oct 31 10:24:44 2022 from 2001:db8:1234:1234::1:23\r\n"),
		m.Send("--- JUNOS 21.2R3.8 Kernel 64-bit  JNPR-12.1-20220119.55d6bc7_buil\r\n"),
		m.Send("username@some-juniper> "),
		// autocommands
		m.Expect("set cli complete-on-space off\n"),
		m.SendEcho("set cli complete-on-space off \r\n"),
		m.Send("Disabling complete-on-space\r\n"),
		m.Send("\r\n"),
		m.Send("username@some-juniper> "),
		m.Expect("set cli screen-length 0\n"),
		m.SendEcho("set cli screen-length 0 \r\n"),
		m.Send("Screen length set to 0\r\n"),
		m.Send("\r\n"),
		m.Send("username@some-juniper> "),
		m.Expect("set cli screen-width 1024\n"),
		m.SendEcho("set cli screen-width 1024 \r\n"),
		m.Send("Screen width set to 1024\r\n"),
		m.Send("\r\n"),
		m.Send("username@some-juniper> "),
		m.Expect("set cli terminal ansi\n"),
		m.SendEcho("set cli terminal ansi \r\n"),
		m.Send("\r\n"),
		m.Send("username@some-juniper> "),
	}

	everyDayByeBye = []m.Action{
		m.Send("\r\n"),
		m.Send("username@some-juniper> "),
		m.Close(),
	}
)

func TestJuniperValidShowCommands(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		result  string
		dialog  [][]m.Action
	}{
		{
			name:    "Test show system uptime",
			command: "sh sys uptime",
			result: "" +
				"Current time: 2022-10-31 07:42:26 UTC\n" +
				"Time Source:  LOCAL CLOCK\n" +
				"System booted: 2022-08-17 11:14:13 UTC (10w4d 20:28 ago)\n" +
				"Protocols started: 2022-08-17 11:16:27 UTC (10w4d 20:25 ago)\n" +
				"Last configured: 2022-10-25 14:32:55 UTC (5d 17:09 ago) by a-loginlog\n" +
				"7:42AM  up 74 days, 20:28, 1 users, load averages: 0.21, 0.32, 0.37\n",
			dialog: [][]m.Action{
				everyDayHello,
				{
					m.Expect("sh sys uptime\n"),
					m.SendEcho("sh sys uptime \r\n"),
					m.Send("Current time: 2022-10-31 07:42:26 UTC\r\n"),
					m.Send("Time Source:  LOCAL CLOCK \r\n"),
					m.Send("System booted: 2022-08-17 11:14:13 UTC (10w4d 20:28 ago)\r\n"),
					m.Send("Protocols started: 2022-08-17 11:16:27 UTC (10w4d 20:25 ago)\r\n"),
					m.Send("Last configured: 2022-10-25 14:32:55 UTC (5d 17:09 ago) by a-loginlog\r\n"),
					m.Send("7:42AM  up 74 days, 20:28, 1 users, load averages: 0.21, 0.32, 0.37\r\n"),
				},
				everyDayByeBye,
			},
		},
		{
			name:    "Test show system uptime bulk",
			command: "sh sys uptime",
			result: "" +
				"Current time: 2022-10-31 07:42:26 UTC\n" +
				"Time Source:  LOCAL CLOCK\n" +
				"System booted: 2022-08-17 11:14:13 UTC (10w4d 20:28 ago)\n" +
				"Protocols started: 2022-08-17 11:16:27 UTC (10w4d 20:25 ago)\n" +
				"Last configured: 2022-10-25 14:32:55 UTC (5d 17:09 ago) by a-loginlog\n" +
				"7:42AM  up 74 days, 20:28, 1 users, load averages: 0.21, 0.32, 0.37\n",
			dialog: [][]m.Action{
				everyDayHello,
				{
					m.Expect("sh sys uptime\n"),
					m.SendEcho("sh sys uptime \r\n"),
					m.Send(
						"Current time: 2022-10-31 07:42:26 UTC\r\n" +
							"Time Source:  LOCAL CLOCK\r\n" +
							"System booted: 2022-08-17 11:14:13 UTC (10w4d 20:28 ago)\r\n" +
							"Protocols started: 2022-08-17 11:16:27 UTC (10w4d 20:25 ago)\r\n" +
							"Last configured: 2022-10-25 14:32:55 UTC (5d 17:09 ago) by a-loginlog\r\n" +
							"7:42AM  up 74 days, 20:28, 1 users, load averages: 0.21, 0.32, 0.37\r\n" +
							"\r\n" +
							"username@some-juniper> ",
					),
					m.Close(),
				},
			},
		},
		{
			name:    "Test show system users",
			command: "sh sys users",
			result: "" +
				" 1:26PM  up 76 days,  2:13, 1 users, load averages: 0.23, 0.39, 0.40\n" +
				"USER     TTY      FROM                              LOGIN@  IDLE WHAT\n" +
				"loginlogin pts/0  2001:db8:1200:3005:1234:5678:123b:1234 1:20PM     - -cli\n",
			dialog: [][]m.Action{
				everyDayHello,
				{
					m.Expect("sh sys users\n"),
					m.SendEcho("sh sys users \r\n"),
					m.Send(" 1:26PM  up 76 days,  2:13, 1 users, load averages: 0.23, 0.39, 0.40\r\n"),
					m.Send("USER     TTY      FROM                              LOGIN@  IDLE WHAT\r\n"),
					m.Send("loginlogin pts/0  2001:db8:1200:3005:1234:5678:123b:1234 1:20PM     - -cli\r\n"),
				},
				everyDayByeBye,
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

func TestInvalidShowCommands(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		dialog  [][]m.Action
	}{
		{
			name:    "Test invalid show version",
			command: "sh vor",
			dialog: [][]m.Action{
				everyDayHello,
				{
					m.Expect("sh vor\n"),
					m.SendEcho("sh vor\r\n"),
					m.Send("                                  ^\r\n"),
					m.Send("syntax error, expecting <command>.\r\n"),
				},
				everyDayByeBye,
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			m.RunInvalidDialog(t, func(connector streamer.Connector) device.Device {
				dev := NewDevice(connector)
				return &dev
			}, actions, tc.command)
		})
	}
}

func TestInvalidShowCommandsWithException(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		dialog  [][]m.Action
		err     error
	}{
		{
			name:    "Test unsupported dis clock",
			command: "dis clock",
			dialog: [][]m.Action{
				everyDayHello,
				{
					m.Expect("dis clock\n"),
					m.SendEcho("dis \r\n"),
					m.Send("                                  ^\r\n"),
					m.Send("unknown command.\r\n"),
				},
				everyDayByeBye,
			},
			err: device.ThrowEchoReadException([]byte("dis \r\n                                  ^\r\nunknown command.\r\n"), true),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			m.RunInvalidDialogWithException(t, func(connector streamer.Connector) device.Device {
				dev := NewDevice(connector)
				return &dev
			}, actions, tc.command, tc.err)
		})
	}
}

func TestFailedToEchoButFoundPromt(t *testing.T) {
	// ported from https://st.yandex-team.ru/NOCDEV-13497 input
	testCases := []struct {
		name    string
		command string
		dialog  [][]m.Action
		err     error
	}{
		{
			name:    "Test failed to echo, but found prompt",
			command: "set interfaces et-0/0/3 unit 0 description temp_description",
			dialog: [][]m.Action{
				everyDayHello,
				{
					m.Expect("set interfaces et-0/0/3 unit 0 description temp_description\n"),
					m.Send("set interfaces et-"),
					m.Send("0/0/3"),
					m.Send(" \rgescheit@sas-cpb3# set interfaces et-0/0/3    \u0008\u0008\u0008unit 0 description"),
					m.Send(" temp_description"),
					m.Send(" \r\n\r\n[edit]\r\n"),
					m.Send("gescheit@sas-cpb3# "),
				},
			},
			err: device.ThrowEchoReadException([]byte("set interfaces et-0/0/3 \rgescheit@sas-cpb3# set interfaces et-0/0/3    \b\b\bunit 0 description temp_description \r\n\r\n[edit]\r\ngescheit@sas-cpb3# "), true),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			m.RunInvalidDialogWithException(t, func(connector streamer.Connector) device.Device {
				dev := NewDevice(connector)
				return &dev
			}, actions, tc.command, tc.err)
		})
	}
}
