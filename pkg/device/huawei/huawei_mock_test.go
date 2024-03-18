package huawei

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

var (
	everyDayHuaweiHello = []m.Action{
		// Common Huawei Cloud Engine greeting
		m.Send("\r\n"),
		m.Send("Info: The max number of VTY users is 8, the number of current VTY users online is 2, and total number of terminal users is 2.\r\n"),
		m.Send("      The current login time is 2022-10-31 14:14:23+02:00.\r\n"),
		m.Send("      The last login time is 2022-10-28 17:33:49+02:00 from 2001:DB8:1234:1234::1:23 through SSH.\r\n"),
		m.Send("<some-device>"),
		// autocommands
		m.Expect("screen-length 0 temporary\n"),
		m.SendEcho("screen-length 0 temporary\r\n"),
		m.Send("Info: The configuration takes effect on the current user terminal interface only.\r\n"),
		m.Send("\r\n"),
		m.Send("<some-device>"),
		m.Expect("terminal echo-mode line\n"),
		m.SendEcho("terminal echo-mode line\r\n"),
		m.Send("\r\n"),
		m.Send("<some-device>"),
	}

	everyDayHuaweiByeBye = []m.Action{
		m.Send("<some-device>"),
		m.Close(),
	}
)

func TestHuaweiValidDisplayCommands(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		result  string
		dialog  [][]m.Action
	}{
		{
			name:    "Test display version",
			command: "dis ver",
			result: "" +
				"Huawei Versatile Routing Platform Software\n" +
				"VRP (R) software, Version 8.180 (CE8850EI V200R000C00SPC000)\n" +
				"Copyright (C) 2012-2018 Huawei Technologies Co., Ltd.\n" +
				"HUAWEI CE8850-64CQ-EI uptime is 3222 days, 3 hours, 31 minutes\n" +
				"Patch Version: V200R005SPH036\n" +
				"\n" +
				"CE8850-64CQ-EI(Master) 1 : uptime is  3222 days, 3 hours, 30 minutes\n" +
				"        StartupTime 2019/06/16   13:05:32+02:00\n" +
				"Memory    Size    : 4096 M bytes\n" +
				"Flash     Size    : 2048 M bytes\n" +
				"CE8850-64CQ-EI version information\n" +
				"1. PCB    Version : CEM64CQP01    VER A\n" +
				"2. MAB    Version : 1\n" +
				"3. Board  Type    : CE8850-64CQ-EI\n" +
				"4. CPLD1  Version : 100\n" +
				"5. CPLD2  Version : 100\n" +
				"6. BIOS   Version : 190",
			dialog: [][]m.Action{
				everyDayHuaweiHello,
				{
					m.Expect("dis ver\n"),
					m.SendEcho("dis ver\r\n"),
					m.Send("" +
						"Huawei Versatile Routing Platform Software\r\n" +
						"VRP (R) software, Version 8.180 (CE8850EI V200R000C00SPC000)\r\n" +
						"Copyright (C) 2012-2018 Huawei Technologies Co., Ltd.\r\n" +
						"HUAWEI CE8850-64CQ-EI uptime is 3222 days, 3 hours, 31 minutes\r\n" +
						"Patch Version: V200R005SPH036\r\n" +
						"\r\n" +
						"CE8850-64CQ-EI(Master) 1 : uptime is  3222 days, 3 hours, 30 minutes\r\n" +
						"        StartupTime 2019/06/16   13:05:32+02:00\r\n" +
						"Memory    Size    : 4096 M bytes\r\n" +
						"Flash     Size    : 2048 M bytes\r\n" +
						"CE8850-64CQ-EI version information\r\n" +
						"1. PCB    Version : CEM64CQP01    VER A\r\n" +
						"2. MAB    Version : 1\r\n" +
						"3. Board  Type    : CE8850-64CQ-EI\r\n" +
						"4. CPLD1  Version : 100\r\n" +
						"5. CPLD2  Version : 100\r\n" +
						"6. BIOS   Version : 190\r\n",
					),
				},
				everyDayHuaweiByeBye,
			},
		},
		{
			name:    "Test display clock",
			command: "dis clock",
			result: "" +
				"2022-10-20 15:32:26+02:00\n" +
				"Thursday\n" +
				"Time Zone(Europe/Someth) : UTC+02:00",
			dialog: [][]m.Action{
				everyDayHuaweiHello,
				{
					m.Expect("dis clock\n"),
					m.SendEcho("dis clock\r\n"),
					m.Send("" +
						"2022-10-20 15:32:26+02:00\r\n" +
						"Thursday\r\n" +
						"Time Zone(Europe/Someth) : UTC+02:00\r\n",
					),
				},
				everyDayHuaweiByeBye,
			},
		},
		{
			name:    "Test display pager",
			command: "dis lldp nei br",
			result: "" +
				"Local Interface         Exptime(s) Neighbor Interface      Neighbor Device\n" +
				"-------------------------------------------------------------------------------\n" +
				"100GE1/0/1                    120  100GE1/0/3              xdc-1s21\n" +
				"100GE1/0/2                    110  100GE1/0/3              xdc-1f23\n" +
				"100GE1/0/55                    97  100GE1/0/4              xdc-1fg1\n" +
				"100GE1/0/56                   110  100GE1/0/5              xdc-1fg1",
			dialog: [][]m.Action{
				everyDayHuaweiHello,
				{
					m.Expect("dis lldp nei br\n"),
					m.SendEcho("dis lldp nei br\r\n"),
					m.Send("" +
						"Local Interface         Exptime(s) Neighbor Interface      Neighbor Device\r\n" +
						"-------------------------------------------------------------------------------\r\n" +
						"100GE1/0/1                    120  100GE1/0/3              xdc-1s21\r\n" +
						"100GE1/0/2                    110  100GE1/0/3              xdc-1f23\r\n",
					),
					m.Send("  ---- More ----"),
					m.Expect(" "),
					m.Send("\u001b[16D                \u001b[16D"),
					m.Send("" +
						"100GE1/0/55                    97  100GE1/0/4              xdc-1fg1\r\n" +
						"100GE1/0/56                   110  100GE1/0/5              xdc-1fg1\r\n",
					),
				},
				everyDayHuaweiByeBye,
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

func TestHuaweiInvalidDisplayCommands(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		dialog  [][]m.Action
	}{
		{
			name:    "Test invalid display version",
			command: "dos ver",
			dialog: [][]m.Action{
				everyDayHuaweiHello,
				{
					m.Expect("dos ver\n"),
					m.SendEcho("dos ver\r\n"),
					m.Send("" +
						"          ^\r\n" +
						"Error: Unrecognized command found at '^' position.\r\n",
					),
				},
				everyDayHuaweiByeBye,
			},
		},
		{
			name:    "Test no permissions",
			command: "disp cur conf",
			dialog: [][]m.Action{
				everyDayHuaweiHello,
				{
					m.Expect("disp cur conf\n"),
					m.SendEcho("disp cur conf\r\n"),
					m.Send("\r\nError: You do not have permission to run the command or the command is incomplete.\r\n"),
				},
				everyDayHuaweiByeBye,
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
