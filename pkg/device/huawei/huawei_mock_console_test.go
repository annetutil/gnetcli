package huawei

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

func TestPasswRetry(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		result  string
		dialog  [][]m.Action
	}{
		{
			name:    "Test password retry",
			command: "dis clock",
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
					m.Sleep(1),
					m.Send("\r\nUsername:"),
					m.Expect("admin\n"),
					m.Send("\r\nPassword:"),
					m.Expect("password2\n"),
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
					m.Expect("dis clock\n"),
					m.SendEcho("dis clock\r\n"),
					m.Send("2024-03-18 17:51:32\r\nMonday\r\nTime Zone(UTC) : UTC\r\n"),
				},
				everyDayHuaweiByeBye,
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			creds := credentials.NewSimpleCredentials(credentials.WithUsername("admin"), credentials.WithPasswords([]credentials.Secret{"password1", "password2"}))
			m.RunDialog(t, func(connector streamer.Connector) device.Device {
				dev := NewConsoleDevice(connector)
				return &dev
			}, actions, tc.command, tc.result, creds)
		})
	}
}

func NewConsoleDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200(promptExpression),
		expr.NewSimpleExprLast200(errorExpression),
		genericcli.WithLoginExprs(
			expr.NewSimpleExprLast200(loginExpression),
			expr.NewSimpleExprLast200(passwordExpression),
			expr.NewSimpleExprLast200(passwordErrorExpression),
		),
		genericcli.WithPager(
			expr.NewSimpleExprLast200(pagerExpression),
		),
		genericcli.WithAutoCommands(autoCommands),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200(questionExpression),
		),
		genericcli.WithSFTPEnabled(),
		genericcli.WithTerminalParams(400, 0),
		genericcli.WithManualAuth(),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
