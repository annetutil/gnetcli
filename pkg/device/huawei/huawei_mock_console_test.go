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
			name:    "Test password from the first try",
			command: "dis clock",
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
			command: "dis clock",
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
			command: "dis clock",
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
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			creds := credentials.NewSimpleCredentials(credentials.WithUsername("admin"), credentials.WithPasswords([]credentials.Secret{"password1", "password2"}))
			m.RunDialog(t, func(connector streamer.Connector) device.Device {
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
