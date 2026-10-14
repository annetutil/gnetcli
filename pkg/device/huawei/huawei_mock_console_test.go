package huawei

import (
	"context"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
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
			name:    "Test login with initial password change prompt",
			command: cmd.NewCmd("dis clock"),
			result:  "2024-03-18 17:51:32\nMonday\nTime Zone(UTC) : UTC",
			dialog: [][]m.Action{
				{
					m.Send("\r\n\r\nUsername:"),
					m.Expect("admin\n"),
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\nWarning: The initial password poses security risks.\r\nThe password needs to be changed. Change now? [Y/N]:"),
					m.Expect("N\n"),
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
		},
		{
			name:    "Test password login retry with callback",
			command: cmd.NewCmd("dis clock"),
			result:  "2024-03-18 17:51:32\nMonday\nTime Zone(UTC) : UTC",
			dialog: [][]m.Action{
				{
					// Login part
					m.Send("\r\nPassword:"),
					m.Expect("password1\n"),
					m.Send("\r\n"),
					m.Send("Authentication fail\u0000\r\n"),
					m.Send("\r\n\r\n\r\n\r\n\r\n\r\r\nUser interface con0 is available\r\n\r\n\r\n\r\nPlease Press ENTER.\r\n"),
					m.Expect("\n"),
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
		genericcli.WithLoginCallbacks([]cmd.ExprCallback{
			cmd.NewExprCallback(loginCallbackExpression, "\n"),
			cmd.NewExprCallback(passwordChangeCallbackExpression, "N\n"),
		}),
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

type consoleEOFConnector struct {
	streamer.Connector
	console bool
}

func (c *consoleEOFConnector) HasFeature(feature streamer.Const) bool {
	if feature == streamer.LoginInsteadEOF {
		return c.console
	}
	if feature == streamer.AutoLogin && c.console {
		return false
	}
	return c.Connector.HasFeature(feature)
}

func TestConsoleLogoutEOF(t *testing.T) {
	const readyScreen = "Info: The max number of VTY users is 8, and the number of current VTY users on line is 2.\x1b[2J\r\nUser interface con0 is available\r\n\r\n\r\nPlease Press ENTER.\r\n\r\n"
	for _, tc := range []struct {
		name    string
		console bool
		output  []string
		eof     string
		timeout bool
		result  string
	}{
		{name: "username", console: true, output: []string{"Username:"}, eof: "Username:"},
		{name: "ready screen", console: true, output: []string{readyScreen}, eof: "Please Press ENTER."},
		{name: "split ready screen", console: true, output: []string{"\r\nPlease Press ", "ENTER.\r\n\r\n"}, eof: "Please Press ENTER."},
		{name: "return to user view", console: true, output: []string{"<some-device>"}},
		{name: "text is not a logout screen", console: true, output: []string{"description Please Press ENTER.\r\n<some-device>"}, result: "description Please Press ENTER."},
		{name: "SSH waits for a real EOF", output: []string{"Please Press ENTER.\r\n"}, timeout: true},
		{name: "SSH does not detect console EOF", output: []string{"Please Press ENTER.\r\n<some-device>"}, result: "Please Press ENTER."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var dialog []m.Action
			if tc.console {
				// The same screen must still start authentication before the first command.
				dialog = append(dialog,
					m.Send("\r\nPlease Press ENTER.\r\n"), m.Expect("\n"),
					m.Send("Username:"), m.Expect("admin\n"),
					m.Send("\r\nPassword:"), m.Expect("password\n"),
				)
			}
			dialog = append(dialog, everyDayHuaweiHello...)
			dialog = append(dialog, m.Expect("q\n"), m.SendEcho("q\r\n"))
			for _, output := range tc.output {
				dialog = append(dialog, m.Send(output))
			}
			// Keep the transport open until ExecuteCtx returns. Otherwise a real
			// transport EOF could hide failure to recognize the logout screen.
			dialog = append(dialog, m.Expect("test-finished\n"), m.Send("test-finished-ok\n"))
			server, err := m.NewMockSSHServer(dialog)
			require.NoError(t, err)
			var group errgroup.Group
			group.Go(func() error { return server.Run(context.Background()) })
			host, port := server.GetAddress()
			creds := credentials.NewSimpleCredentials(credentials.WithUsername("admin"), credentials.WithPasswords([]credentials.Secret{"password"}))
			connector := &consoleEOFConnector{Connector: ssh.NewStreamer(host, creds, ssh.WithPort(port)), console: tc.console}
			dev := NewDevice(connector)
			defer dev.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, dev.Connect(ctx))
			res, execErr := dev.ExecuteCtx(ctx, cmd.NewCmd("q", cmd.WithReadTimeout(300*time.Millisecond), cmd.WithCmdTimeout(3*time.Second)))
			writeErr := connector.Write([]byte("test-finished\n"))
			_, ackErr := connector.ReadTo(ctx, expr.NewSimpleExpr().FromPattern("test-finished-ok\n"))
			dev.Close()
			require.NoError(t, writeErr)
			require.NoError(t, ackErr)
			require.NoError(t, group.Wait())
			if tc.eof != "" {
				var eof *streamer.EOFException
				require.ErrorAs(t, execErr, &eof)
				require.Contains(t, string(eof.LastRead), tc.eof)
				require.Nil(t, res)
			} else if tc.timeout {
				var timeout *streamer.ReadTimeoutException
				require.ErrorAs(t, execErr, &timeout)
			} else {
				require.NoError(t, execErr)
				require.Equal(t, tc.result, string(res.Output()))
			}
		})
	}
}
