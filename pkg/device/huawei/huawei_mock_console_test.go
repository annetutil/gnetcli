package huawei

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

func TestConsole(t *testing.T) {
	testCases := []struct {
		name    string
		command cmd.Cmd
		result  string
		dialog  [][]m.Action
	}{
		{
			name:    "Test password from the first try",
			command: cmd.NewCmd("dis clock"),
			result:  "2024-03-18 17:51:32\nMonday\nTime Zone(UTC) : UTC",
			dialog: [][]m.Action{
				{
					// Password part
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\n"),
				},
				everyDayHuaweiHello,
				{
					m.Expect("dis clock\n"),
					m.SendEcho("dis clock\r\n"),
					m.Send("2024-03-18 17:51:32\r\nMonday\r\nTime Zone(UTC) : UTC\r\n"),
				},
				everyDayHuaweiByeBye,
			},
		}, {
			name:    "Test login and password from the first try",
			command: cmd.NewCmd("dis clock"),
			result:  "2024-03-18 17:51:32\nMonday\nTime Zone(UTC) : UTC",
			dialog: [][]m.Action{
				{
					// Login part
					m.Send("\r\n\r\nUsername:"),
					m.Expect("admin\n"),
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\n"),
				},
				everyDayHuaweiHello,
				{
					m.Expect("dis clock\n"),
					m.SendEcho("dis clock\r\n"),
					m.Send("2024-03-18 17:51:32\r\nMonday\r\nTime Zone(UTC) : UTC\r\n"),
				},
				everyDayHuaweiByeBye,
			},
		}, {
			name:    "Test login and password retry",
			command: cmd.NewCmd("dis clock"),
			result:  "2024-03-18 17:51:32\nMonday\nTime Zone(UTC) : UTC",
			dialog: [][]m.Action{
				{
					// Login part
					m.Send("\r\n\r\nUsername:"),
					m.Expect("admin\n"),
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\n"),
					m.Send("Authentication fail\u0000\r\n"),
					// m.Sleep(1),
					m.Send("\r\nUsername:"),
					m.Expect("admin\n"),
					m.Send("\r\nPassword:"),
					m.Expect("password2\n"),
				},
				everyDayHuaweiHello,
				{
					m.Expect("dis clock\n"),
					m.SendEcho("dis clock\r\n"),
					m.Send("2024-03-18 17:51:32\r\nMonday\r\nTime Zone(UTC) : UTC\r\n"),
				},
				everyDayHuaweiByeBye,
			},
		}, {
			name:    "Test password retry only",
			command: cmd.NewCmd("dis clock"),
			result:  "2024-03-18 17:51:32\nMonday\nTime Zone(UTC) : UTC",
			dialog: [][]m.Action{
				{
					// Login part
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\n"),
					m.Send("Authentication fail\u0000\r\n"),
					// m.Sleep(1),
					m.Send("\r\nPassword:"),
					m.Expect("password2\n"),
				},
				everyDayHuaweiHello,
				{
					m.Expect("dis clock\n"),
					m.SendEcho("dis clock\r\n"),
					m.Send("2024-03-18 17:51:32\r\nMonday\r\nTime Zone(UTC) : UTC\r\n"),
				},
				everyDayHuaweiByeBye,
			},
		}, {
			name:    "Test password retry only with sleep",
			command: cmd.NewCmd("dis clock"),
			result:  "2024-03-18 17:51:32\nMonday\nTime Zone(UTC) : UTC",
			dialog: [][]m.Action{
				{
					// Login part
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\n"),
					m.Send("Authentication fail\u0000\r\n"),
					m.Sleep(5),
					m.Send("\r\nPassword:"),
					m.Expect("password2\n"),
				},
				everyDayHuaweiHello,
				{
					m.Expect("dis clock\n"),
					m.SendEcho("dis clock\r\n"),
					m.Send("2024-03-18 17:51:32\r\nMonday\r\nTime Zone(UTC) : UTC\r\n"),
				},
				everyDayHuaweiByeBye,
			},
		},
		{
			name: "Test question after echo with terminal control",
			command: cmd.NewCmd("port split dimension interface 400GE1/0/2 400GE1/0/4 400GE1/0/6 400GE1/0/8 400GE1/0/10 400GE1/0/12 400GE1/0/14 400GE1/0/16 400GE1/0/18 400GE1/0/20 400GE1/0/22 400GE1/0/24 400GE1/0/26 400GE1/0/28 400GE1/0/30 400GE1/0/32 split-type 2*200GE",
				cmd.WithAnswers(cmd.NewAnswerWithNL("Continue? [Y/N]:", "Y"))),
			result: "",
			dialog: [][]m.Action{
				{
					// Login part
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\n"),
				},
				everyDayHuaweiHello,
				// skip entering to system-view
				{
					m.Expect("port split dimension interface 400GE1/0/2 400GE1/0/4 400GE1/0/6 400GE1/0/8 400GE1/0/10 400GE1/0/12 400GE1/0/14 400GE1/0/16 400GE1/0/18 400GE1/0/20 400GE1/0/22 400GE1/0/24 400GE1/0/26 400GE1/0/28 400GE1/0/30 400GE1/0/32 split-type 2*200GE\n"),
					m.SendEcho("port split dimension interface 400GE1/0/2 400GE1/0/4 400GE1/0/6 400GE1/ \u001b[1D0/8 400GE1/0/10 400G"),
					m.SendEcho("E1/0/12 400GE1/0/14 400GE1/0/16 400GE1/0/18 400GE1/0/20 400G \u001b[1DE1/0/22 400GE1/0/24 400GE1/0/26"),
					m.SendEcho(" 400GE1/0/28 400GE1/0/30 400GE1/0/32 split-type 2 \u001b[1D*200GE\r\n"),
					m.SendEcho("Warning: This operation will delete current port(s)(400GE1/0/2 400GE1/0/4 400GE1/0/6 400GE1/0/8 "),
					m.SendEcho("400GE1/0/10 400GE1/0/12 400GE1/0/14 400GE1/0/16 400GE1/0/18 400GE1/0/20 400GE1/0/22 400GE1/0/24 "),
					m.SendEcho("400GE1/0/26 400GE1/0/28 400GE1/0/30 400GE1/0/32) and all configurations of the current port(s) w"),
					m.SendEcho("ill be cleared. After the operation is done, it may takes a few seconds before viewing the port "),
					m.SendEcho("information. Continue? [Y/N]:"),
					m.Expect("Y\n"),
					m.Send("[HUAWEI]"),
					m.Close(),
				},
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			creds := credentials.NewSimpleCredentials(credentials.WithUsername("admin"), credentials.WithPasswords([]credentials.Secret{"password1", "password2"}))
			m.RunDialogCMD(t, func(connector streamer.Connector) device.Device {
				dev := newConsoleDevice(connector)
				return &dev
			}, actions, tc.command, tc.result, creds)
		})
	}
}

func newConsoleDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithLoginExprs(
			expr.NewSimpleExprLast200().FromPattern(loginExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordErrorExpression),
		),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression),
		),
		genericcli.WithAutoCommands(autoCommands),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression),
		),
		genericcli.WithSFTPEnabled(),
		genericcli.WithTerminalParams(400, 0),
		genericcli.WithManualAuth(),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
